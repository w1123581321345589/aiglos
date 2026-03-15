import type { Express } from "express";
import { createServer, type Server } from "http";
import session from "express-session";
import { WebSocketServer, WebSocket } from "ws";
import { createHash, randomBytes } from "crypto";
import { storage } from "./storage";
import { requireAuth, requireRole, loadUser, auditLog } from "./middleware";
import { hashPassword, verifyPassword } from "./auth";
import {
  insertTrustedServerSchema, insertPolicyRuleSchema,
  insertAlertDestinationSchema, insertDataRetentionPolicySchema,
  insertSecurityEventSchema, insertSessionSchema,
} from "@shared/schema";
import { z } from "zod";
import { getEngine, getEngineInstance } from "./engine";

function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

async function validateApiKey(apiKeyHeader: string | undefined): Promise<string | null> {
  if (!apiKeyHeader || typeof apiKeyHeader !== "string") return null;
  const keyHash = hashApiKey(apiKeyHeader);
  const apiKey = await storage.getApiKeyByHash(keyHash);
  if (!apiKey) return null;
  storage.updateApiKeyLastUsed(apiKey.id).catch(() => {});
  return apiKey.organizationId;
}

const connectedClients = new Map<WebSocket, string>();

async function notifyClients(type: string, data: any) {
  const orgId = data?.organizationId;
  const message = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
  for (const [client, clientOrgId] of connectedClients) {
    if (client.readyState === WebSocket.OPEN && (!orgId || clientOrgId === orgId)) {
      client.send(message);
    }
  }
}

async function dispatchAlerts(event: any) {
  try {
    const destinations = await storage.getAlertDestinations(event.organizationId);
    for (const dest of destinations) {
      if (!dest.enabled) continue;
      if (dest.severityFilter && dest.severityFilter.length > 0 && !dest.severityFilter.includes(event.severity)) continue;
      if (dest.eventTypeFilter && dest.eventTypeFilter.length > 0 && !dest.eventTypeFilter.includes(event.eventType)) continue;

      const config = dest.config as Record<string, any>;
      const webhookUrl = config?.webhookUrl || config?.url;

      if (webhookUrl) {
        try {
          await fetch(webhookUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              source: "aiglos-security",
              event: {
                id: event.id,
                type: event.eventType,
                severity: event.severity,
                title: event.title,
                description: event.description,
                timestamp: event.timestamp,
                sessionId: event.sessionId,
              },
              destination: dest.name,
            }),
            signal: AbortSignal.timeout(5000),
          });
          await storage.updateAlertDestination(dest.id, { lastTriggeredAt: new Date() });
        } catch {
          console.error(`Alert delivery failed for ${dest.name}`);
        }
      }
    }
  } catch {
    console.error("Alert dispatch error");
  }
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    console.warn("WARNING: SESSION_SECRET not set. Using fallback for development only.");
  }

  app.use(
    session({
      secret: sessionSecret || "aiglos-dev-fallback-" + randomBytes(16).toString("hex"),
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      },
    })
  );

  app.use(loadUser);

  app.get("/landing", (_req, res) => {
    res.sendFile("landing.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/aiglos", (_req, res) => {
    res.sendFile("aiglos.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/pricing", (_req, res) => {
    res.sendFile("pricing.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/scan", (_req, res) => {
    res.sendFile("scan.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/defense", (_req, res) => {
    res.sendFile("defense.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/docs", (_req, res) => {
    res.sendFile("docs.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/demo", (_req, res) => {
    res.sendFile("demo.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/changelog", (_req, res) => {
    res.sendFile("changelog.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/coding-agents", (_req, res) => {
    res.sendFile("coding-agents.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  app.get("/supernova-plan", (_req, res) => {
    res.sendFile("supernova-plan.html", { root: new URL("../client/public", import.meta.url).pathname });
  });

  const loginSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1),
  });

  app.post("/api/auth/login", async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: "Username and password required" });

    const user = await storage.getUserByUsername(parsed.data.username);
    if (!user || !verifyPassword(parsed.data.password, user.password)) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    await storage.updateUser(user.id, { lastLogin: new Date() });
    req.session.userId = user.id;
    await auditLog(req, "login", "auth", user.id);

    const { password: _, ...safeUser } = user;
    res.json(safeUser);
  });

  app.post("/api/auth/logout", (req, res) => {
    if (req.user) {
      auditLog(req, "logout", "auth", req.user.id);
    }
    req.session.destroy(() => {
      res.json({ message: "Logged out" });
    });
  });

  app.get("/api/auth/me", async (req, res) => {
    if (!req.user) return res.status(401).json({ message: "Not authenticated" });
    const { password: _, ...safeUser } = req.user;
    res.json(safeUser);
  });

  const registerSchema = z.object({
    username: z.string().min(3).max(50),
    password: z.string().min(6),
    role: z.enum(["admin", "analyst", "viewer"]).optional(),
    displayName: z.string().optional(),
    email: z.string().email().optional(),
  });

  app.post("/api/auth/register", requireAuth, requireRole("admin"), async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });

    const existing = await storage.getUserByUsername(parsed.data.username);
    if (existing) return res.status(409).json({ message: "Username already exists" });

    const user = await storage.createUser({
      username: parsed.data.username,
      password: hashPassword(parsed.data.password),
      role: parsed.data.role || "viewer",
      organizationId: req.user!.organizationId,
      displayName: parsed.data.displayName || null,
      email: parsed.data.email || null,
    });

    await auditLog(req, "create_user", "user", user.id, { username: user.username, role: user.role });
    const { password: _, ...safeUser } = user;
    res.status(201).json(safeUser);
  });

  app.get("/api/users", requireAuth, requireRole("admin"), async (req, res) => {
    const users = await storage.getUsers(req.user!.organizationId || undefined);
    const safeUsers = users.map(({ password: _, ...u }) => u);
    res.json(safeUsers);
  });

  app.patch("/api/users/:id", requireAuth, requireRole("admin"), async (req, res) => {
    const { role, displayName, email } = req.body;
    const updateData: any = {};
    if (role) updateData.role = role;
    if (displayName !== undefined) updateData.displayName = displayName;
    if (email !== undefined) updateData.email = email;

    const updated = await storage.updateUser(req.params.id, updateData);
    if (!updated) return res.status(404).json({ message: "User not found" });

    await auditLog(req, "update_user", "user", req.params.id, updateData);
    const { password: _, ...safeUser } = updated;
    res.json(safeUser);
  });

  app.delete("/api/users/:id", requireAuth, requireRole("admin"), async (req, res) => {
    if (req.params.id === req.user!.id) {
      return res.status(400).json({ message: "Cannot delete yourself" });
    }
    const deleted = await storage.deleteUser(req.params.id);
    if (!deleted) return res.status(404).json({ message: "User not found" });
    await auditLog(req, "delete_user", "user", req.params.id);
    res.json({ message: "User deleted" });
  });

  app.get("/api/dashboard/stats", requireAuth, async (req, res) => {
    const stats = await storage.getDashboardStats(req.user!.organizationId || undefined);
    res.json(stats);
  });

  app.get("/api/sessions", requireAuth, async (req, res) => {
    const activeOnly = req.query.active === "true";
    const result = await storage.getSessions(req.user!.organizationId || undefined, activeOnly);
    res.json(result);
  });

  app.get("/api/sessions/:id", requireAuth, async (req, res) => {
    const session = await storage.getSession(req.params.id);
    if (!session) return res.status(404).json({ message: "Session not found" });
    res.json(session);
  });

  app.get("/api/events", requireAuth, async (req, res) => {
    const filters: { severity?: string; type?: string; limit?: number; orgId?: string } = {};
    if (req.query.severity) filters.severity = req.query.severity as string;
    if (req.query.type) filters.type = req.query.type as string;
    if (req.query.limit) filters.limit = parseInt(req.query.limit as string);
    filters.orgId = req.user!.organizationId || undefined;
    const result = await storage.getSecurityEvents(filters);
    res.json(result);
  });

  app.get("/api/trust", requireAuth, async (req, res) => {
    const servers = await storage.getTrustedServers(req.user!.organizationId || undefined);
    res.json(servers);
  });

  app.post("/api/trust", requireAuth, requireRole("admin", "analyst"), async (req, res) => {
    const parsed = insertTrustedServerSchema.safeParse({ ...req.body, organizationId: req.user!.organizationId });
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const server = await storage.createTrustedServer(parsed.data);
    await auditLog(req, "create", "trusted_server", server.id, { host: server.host });
    res.status(201).json(server);
  });

  app.patch("/api/trust/:id", requireAuth, requireRole("admin", "analyst"), async (req, res) => {
    const updated = await storage.updateTrustedServer(req.params.id, req.body);
    if (!updated) return res.status(404).json({ message: "Server not found" });
    await auditLog(req, "update", "trusted_server", req.params.id, req.body);
    res.json(updated);
  });

  app.get("/api/policies", requireAuth, async (req, res) => {
    const policies = await storage.getPolicyRules(req.user!.organizationId || undefined);
    res.json(policies);
  });

  app.post("/api/policies", requireAuth, requireRole("admin", "analyst"), async (req, res) => {
    const parsed = insertPolicyRuleSchema.safeParse({ ...req.body, organizationId: req.user!.organizationId });
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const policy = await storage.createPolicyRule(parsed.data);
    await auditLog(req, "create", "policy_rule", policy.id, { name: policy.name });
    res.status(201).json(policy);
  });

  app.patch("/api/policies/:id", requireAuth, requireRole("admin", "analyst"), async (req, res) => {
    const updated = await storage.updatePolicyRule(req.params.id, req.body);
    if (!updated) return res.status(404).json({ message: "Policy not found" });
    await auditLog(req, "update", "policy_rule", req.params.id, req.body);
    res.json(updated);
  });

  app.get("/api/compliance", requireAuth, async (req, res) => {
    const data = await storage.getComplianceData(req.user!.organizationId || undefined);
    res.json(data);
  });

  app.get("/api/audit-logs", requireAuth, requireRole("admin"), async (req, res) => {
    const filters: { orgId?: string; userId?: string; resourceType?: string; limit?: number } = {};
    filters.orgId = req.user!.organizationId || undefined;
    if (req.query.userId) filters.userId = req.query.userId as string;
    if (req.query.resourceType) filters.resourceType = req.query.resourceType as string;
    if (req.query.limit) filters.limit = parseInt(req.query.limit as string);
    const logs = await storage.getAuditLogs(filters);
    res.json(logs);
  });

  app.get("/api/retention", requireAuth, requireRole("admin"), async (req, res) => {
    const policies = await storage.getDataRetentionPolicies(req.user!.organizationId || undefined);
    res.json(policies);
  });

  app.post("/api/retention", requireAuth, requireRole("admin"), async (req, res) => {
    const parsed = insertDataRetentionPolicySchema.safeParse({ ...req.body, organizationId: req.user!.organizationId });
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const policy = await storage.createDataRetentionPolicy(parsed.data);
    await auditLog(req, "create", "retention_policy", policy.id, { resourceType: policy.resourceType });
    res.status(201).json(policy);
  });

  app.patch("/api/retention/:id", requireAuth, requireRole("admin"), async (req, res) => {
    const updated = await storage.updateDataRetentionPolicy(req.params.id, req.body);
    if (!updated) return res.status(404).json({ message: "Retention policy not found" });
    await auditLog(req, "update", "retention_policy", req.params.id, req.body);
    res.json(updated);
  });

  app.delete("/api/retention/:id", requireAuth, requireRole("admin"), async (req, res) => {
    const deleted = await storage.deleteDataRetentionPolicy(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Retention policy not found" });
    await auditLog(req, "delete", "retention_policy", req.params.id);
    res.json({ message: "Deleted" });
  });

  app.post("/api/retention/purge", requireAuth, requireRole("admin"), async (req, res) => {
    const { resourceType, olderThanDays } = req.body;
    if (!resourceType || !olderThanDays) {
      return res.status(400).json({ message: "resourceType and olderThanDays required" });
    }
    const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
    const orgId = req.user!.organizationId || undefined;
    let deleted = 0;

    switch (resourceType) {
      case "security_events":
        deleted = await storage.deleteEventsBefore(cutoff, orgId);
        break;
      case "sessions":
        deleted = await storage.deleteSessionsBefore(cutoff, orgId);
        break;
      case "tool_calls":
        deleted = await storage.deleteToolCallsBefore(cutoff, orgId);
        break;
      case "audit_logs":
        deleted = await storage.deleteAuditLogsBefore(cutoff, orgId);
        break;
      default:
        return res.status(400).json({ message: "Invalid resource type" });
    }

    await auditLog(req, "purge", "data_retention", undefined, { resourceType, olderThanDays, deleted });
    res.json({ message: `Purged ${deleted} ${resourceType} records`, deleted });
  });

  app.get("/api/alerts", requireAuth, requireRole("admin", "analyst"), async (req, res) => {
    const destinations = await storage.getAlertDestinations(req.user!.organizationId || undefined);
    res.json(destinations);
  });

  app.post("/api/alerts", requireAuth, requireRole("admin"), async (req, res) => {
    const parsed = insertAlertDestinationSchema.safeParse({ ...req.body, organizationId: req.user!.organizationId });
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const dest = await storage.createAlertDestination(parsed.data);
    await auditLog(req, "create", "alert_destination", dest.id, { name: dest.name, type: dest.type });
    res.status(201).json(dest);
  });

  app.patch("/api/alerts/:id", requireAuth, requireRole("admin"), async (req, res) => {
    const updated = await storage.updateAlertDestination(req.params.id, req.body);
    if (!updated) return res.status(404).json({ message: "Alert destination not found" });
    await auditLog(req, "update", "alert_destination", req.params.id, req.body);
    res.json(updated);
  });

  app.delete("/api/alerts/:id", requireAuth, requireRole("admin"), async (req, res) => {
    const deleted = await storage.deleteAlertDestination(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Alert destination not found" });
    await auditLog(req, "delete", "alert_destination", req.params.id);
    res.json({ message: "Deleted" });
  });

  app.post("/api/alerts/:id/test", requireAuth, requireRole("admin"), async (req, res) => {
    const dest = await storage.getAlertDestination(req.params.id);
    if (!dest) return res.status(404).json({ message: "Alert destination not found" });

    const config = dest.config as Record<string, any>;
    const webhookUrl = config?.webhookUrl || config?.url;
    if (!webhookUrl) return res.status(400).json({ message: "No webhook URL configured" });

    try {
      const testResponse = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: "aiglos-security",
          test: true,
          message: "Test alert from Aiglos Security Dashboard",
          timestamp: new Date().toISOString(),
        }),
        signal: AbortSignal.timeout(10000),
      });
      res.json({ success: testResponse.ok, status: testResponse.status });
    } catch (e: any) {
      res.json({ success: false, error: e.message });
    }
  });

  app.get("/api/api-keys", requireAuth, requireRole("admin"), async (req, res) => {
    const keys = await storage.getApiKeys(req.user!.organizationId!);
    const safeKeys = keys.map(({ keyHash, ...k }) => k);
    res.json(safeKeys);
  });

  app.post("/api/api-keys", requireAuth, requireRole("admin"), async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: "Name required" });

    const rawKey = `aig_${randomBytes(32).toString("hex")}`;
    const keyHash = hashApiKey(rawKey);
    const keyPrefix = rawKey.substring(0, 8) + "...";

    const apiKey = await storage.createApiKey({
      organizationId: req.user!.organizationId!,
      name,
      keyHash,
      keyPrefix,
    });

    await auditLog(req, "create", "api_key", apiKey.id, { name });
    res.status(201).json({ ...apiKey, key: rawKey });
  });

  app.delete("/api/api-keys/:id", requireAuth, requireRole("admin"), async (req, res) => {
    const deleted = await storage.deleteApiKey(req.params.id);
    if (!deleted) return res.status(404).json({ message: "API key not found" });
    await auditLog(req, "delete", "api_key", req.params.id);
    res.json({ message: "API key deleted" });
  });

  app.get("/api/reports/events", requireAuth, async (req, res) => {
    const format = (req.query.format as string) || "json";
    const orgId = req.user!.organizationId || undefined;
    const events = await storage.getSecurityEvents({ orgId, limit: 1000 });
    await auditLog(req, "export", "report", undefined, { type: "events", format, count: events.length });

    if (format === "csv") {
      const headers = "ID,Timestamp,Session ID,Type,Severity,Title,Description,CMMC Controls,NIST Controls\n";
      const rows = events.map(e =>
        `"${e.id}","${e.timestamp}","${e.sessionId}","${e.eventType}","${e.severity}","${e.title.replace(/"/g, '""')}","${e.description.replace(/"/g, '""')}","${(e.cmmcControls || []).join(";")}","${(e.nistControls || []).join(";")}"`
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=aiglos-events-${Date.now()}.csv`);
      return res.send(headers + rows);
    }

    res.json({
      report: "Aiglos Security Events Report",
      generatedAt: new Date().toISOString(),
      organization: req.user!.organizationId,
      totalEvents: events.length,
      events,
    });
  });

  app.get("/api/reports/sessions", requireAuth, async (req, res) => {
    const format = (req.query.format as string) || "json";
    const orgId = req.user!.organizationId || undefined;
    const allSessions = await storage.getSessions(orgId);
    await auditLog(req, "export", "report", undefined, { type: "sessions", format, count: allSessions.length });

    if (format === "csv") {
      const headers = "ID,Model,Version,Initiated By,Goal,Integrity Score,Anomaly Score,Active,Start Time,End Time\n";
      const rows = allSessions.map(s =>
        `"${s.id}","${s.modelId}","${s.modelVersion}","${s.initiatedBy}","${s.authorizedGoal.replace(/"/g, '""')}",${s.goalIntegrityScore},${s.anomalyScore},${s.isActive},"${s.startTime}","${s.endTime || ''}"`
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=aiglos-sessions-${Date.now()}.csv`);
      return res.send(headers + rows);
    }

    res.json({
      report: "Aiglos Sessions Report",
      generatedAt: new Date().toISOString(),
      totalSessions: allSessions.length,
      sessions: allSessions,
    });
  });

  app.get("/api/reports/compliance", requireAuth, async (req, res) => {
    const orgId = req.user!.organizationId || undefined;
    const compliance = await storage.getComplianceData(orgId);
    await auditLog(req, "export", "report", undefined, { type: "compliance" });

    res.json({
      report: "Aiglos CMMC/NIST Compliance Report",
      generatedAt: new Date().toISOString(),
      organization: req.user!.organizationId,
      ...compliance,
    });
  });

  app.get("/api/reports/audit", requireAuth, requireRole("admin"), async (req, res) => {
    const format = (req.query.format as string) || "json";
    const orgId = req.user!.organizationId || undefined;
    const logs = await storage.getAuditLogs({ orgId, limit: 1000 });

    if (format === "csv") {
      const headers = "ID,Timestamp,User,Action,Resource Type,Resource ID,IP Address\n";
      const rows = logs.map(l =>
        `"${l.id}","${l.timestamp}","${l.username}","${l.action}","${l.resourceType}","${l.resourceId || ''}","${l.ipAddress || ''}"`
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=aiglos-audit-${Date.now()}.csv`);
      return res.send(headers + rows);
    }

    res.json({
      report: "Aiglos Audit Trail Report",
      generatedAt: new Date().toISOString(),
      totalEntries: logs.length,
      logs,
    });
  });

  const ingestLimiter = (await import("express-rate-limit")).default({
    windowMs: 60 * 1000,
    max: 100,
    message: { message: "Too many ingest requests" },
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.post("/api/ingest/event", ingestLimiter, async (req, res) => {
    const orgId = await validateApiKey(req.headers["x-api-key"] as string);
    if (!orgId) return res.status(401).json({ message: "Invalid or missing API key" });

    const parsed = insertSecurityEventSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });

    const eventData = { ...parsed.data, organizationId: orgId };
    const event = await storage.createSecurityEvent(eventData);
    await notifyClients("security_event", event);
    await dispatchAlerts(event);
    res.status(201).json(event);
  });

  app.post("/api/ingest/session", ingestLimiter, async (req, res) => {
    const orgId = await validateApiKey(req.headers["x-api-key"] as string);
    if (!orgId) return res.status(401).json({ message: "Invalid or missing API key" });

    const parsed = insertSessionSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });

    const sessionData = { ...parsed.data, organizationId: orgId };
    const newSession = await storage.createSession(sessionData);
    await notifyClients("session_update", newSession);
    res.status(201).json(newSession);
  });

  app.get("/api/ws/status", requireAuth, (_req, res) => {
    res.json({
      connectedClients: connectedClients.size,
      status: "running",
    });
  });

  app.get("/api/engine/status", requireAuth, (_req, res) => {
    const engine = getEngineInstance();
    if (!engine) return res.json({ state: "shutdown", threatLevel: "nominal", tasksDone: 0, tasksFailed: 0 });
    res.json(engine.getStatus());
  });

  app.post("/api/engine/start", requireAuth, requireRole("admin"), async (req, res) => {
    const existing = getEngineInstance();
    if (existing && existing.getStatus().state === "running") {
      return res.json({ message: "Engine already running", ...existing.getStatus() });
    }
    const engine = await getEngine(req.user?.organizationId);
    await engine.start();
    await auditLog(req, "engine", "start", "engine", {});
    res.json({ message: "Engine started", ...engine.getStatus() });
  });

  app.post("/api/engine/stop", requireAuth, requireRole("admin"), async (req, res) => {
    const engine = getEngineInstance();
    if (!engine || engine.getStatus().state !== "running") {
      return res.json({ message: "Engine not running" });
    }
    await engine.stop();
    await auditLog(req, "engine", "stop", "engine", {});
    res.json({ message: "Engine stopped" });
  });

  app.post("/api/engine/scan", requireAuth, requireRole("admin", "analyst"), async (req, res) => {
    const engine = await getEngine(req.user?.organizationId);
    if (engine.getStatus().state !== "running") {
      await engine.start();
    }
    try {
      const result = await engine.runScan();
      await auditLog(req, "engine", "manual_scan", "engine", { findings: result.findings.length });
      res.json(result);
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  app.post("/api/engine/intel", requireAuth, requireRole("admin", "analyst"), async (req, res) => {
    const engine = await getEngine(req.user?.organizationId);
    if (engine.getStatus().state !== "running") {
      await engine.start();
    }
    try {
      const result = await engine.runIntel();
      await auditLog(req, "engine", "manual_intel", "engine", { newRules: result.newRules });
      res.json(result);
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  app.get("/api/engine/findings", requireAuth, (_req, res) => {
    const engine = getEngineInstance();
    res.json(engine ? engine.getFindings() : []);
  });

  app.get("/api/engine/patterns", requireAuth, async (req, res) => {
    const engine = getEngineInstance() || await getEngine(req.user?.organizationId);
    res.json(engine.getThreatPatterns());
  });

  async function enforceRetentionPolicies() {
    try {
      const policies = await storage.getDataRetentionPolicies();
      for (const policy of policies) {
        if (!policy.enabled) continue;
        const cutoff = new Date(Date.now() - policy.retentionDays * 24 * 60 * 60 * 1000);
        const orgId = policy.organizationId || undefined;
        switch (policy.resourceType) {
          case "security_events":
            await storage.deleteEventsBefore(cutoff, orgId);
            break;
          case "sessions":
            await storage.deleteSessionsBefore(cutoff, orgId);
            break;
          case "tool_calls":
            await storage.deleteToolCallsBefore(cutoff, orgId);
            break;
          case "audit_logs":
            await storage.deleteAuditLogsBefore(cutoff, orgId);
            break;
        }
      }
    } catch (e) {
      console.error("Retention enforcement error:", e);
    }
  }

  setInterval(enforceRetentionPolicies, 6 * 60 * 60 * 1000);
  setTimeout(enforceRetentionPolicies, 60 * 1000);

  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", async (ws, req) => {
    const url = new URL(req.url || "", `http://${req.headers.host}`);
    const apiKeyParam = url.searchParams.get("apiKey");
    const orgId = await validateApiKey(apiKeyParam || undefined);

    if (!orgId) {
      ws.send(JSON.stringify({ type: "error", message: "Authentication required. Pass ?apiKey=YOUR_KEY" }));
      ws.close(4001, "Unauthorized");
      return;
    }

    connectedClients.set(ws, orgId);
    ws.send(JSON.stringify({ type: "connected", organizationId: orgId, timestamp: new Date().toISOString() }));

    ws.on("message", async (raw) => {
      try {
        const message = JSON.parse(raw.toString());

        if (message.type === "security_event") {
          const eventData = { ...message.data, organizationId: orgId };
          const event = await storage.createSecurityEvent(eventData);
          await notifyClients("security_event", event);
          await dispatchAlerts(event);
        } else if (message.type === "session_update") {
          const sessionData = { ...message.data, organizationId: orgId };
          const newSession = await storage.createSession(sessionData);
          await notifyClients("session_update", newSession);
        }
      } catch (e) {
        ws.send(JSON.stringify({ type: "error", message: "Invalid message format" }));
      }
    });

    ws.on("close", () => {
      connectedClients.delete(ws);
    });
  });

  return httpServer;
}
