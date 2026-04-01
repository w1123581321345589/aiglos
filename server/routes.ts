import type { Express } from "express";
import type { Server } from "http";
import session from "express-session";
import { WebSocketServer, WebSocket } from "ws";
import { randomBytes } from "crypto";
import { storage } from "./storage";
import { requireAuth, requireRole, loadUser, auditLog } from "./middleware";
import { hashPassword, verifyPassword } from "./auth";
import {
  insertTrustedServerSchema, insertPolicyRuleSchema,
  insertSecurityEventSchema, insertSessionSchema,
} from "@shared/schema";
import { z } from "zod";
import { getEngine, getEngineInstance } from "./engine";

const connectedClients = new Map<WebSocket, string>();

function broadcastEvent(event: any) {
  const message = JSON.stringify(event);
  connectedClients.forEach((_, ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  });
}

export async function registerRoutes(httpServer: Server, app: Express): Promise<void> {
  const sessionSecret = process.env.SESSION_SECRET;

  if (!sessionSecret) {
    console.warn("SESSION_SECRET not set — using random fallback (sessions won't persist across restarts)");
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

  const staticPages = new Set([
    "landing", "aiglos", "scan", "defense", "docs",
    "demo", "changelog", "pricing", "coding-agents",
    "intel", "skills", "govbench-paper", "nist-submission",
    "tutorial-openclaw-hardening", "tutorial-advanced",
    "tutorial-github-actions",
  ]);
  const publicRoot = new URL("../client/public", import.meta.url).pathname;

  app.get("/", (_req, res) => res.sendFile("landing.html", { root: publicRoot }));
  app.get("/supernova-plan", (_req, res) => res.redirect(301, "/landing"));
  app.get("/atlas", (_req, res) => res.sendFile("landing.html", { root: publicRoot }));
  app.get("/ghsa", (_req, res) => res.sendFile("landing.html", { root: publicRoot }));
  app.get("/superpowers", (_req, res) => res.sendFile("landing.html", { root: publicRoot }));
  app.get("/benchmark", (_req, res) => res.sendFile("landing.html", { root: publicRoot }));

  app.get("/:page", (req, res, next) => {
    if (staticPages.has(req.params.page)) {
      return res.sendFile(`${req.params.page}.html`, { root: publicRoot });
    }
    next();
  });

  app.get("/compare/clawkeeper", (_req, res) => {
    res.sendFile("compare-clawkeeper.html", { root: publicRoot });
  });
  app.get("/compare/openshell", (_req, res) => {
    res.sendFile("compare-openshell.html", { root: publicRoot });
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
  });

  app.post("/api/auth/register", requireAuth, async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });

    const existing = await storage.getUserByUsername(parsed.data.username);
    if (existing) return res.status(409).json({ message: "Username already exists" });

    const user = await storage.createUser({
      username: parsed.data.username,
      password: hashPassword(parsed.data.password),
    });
    await auditLog(req, "create_user", "user", user.id, { username: user.username });
    const { password: _, ...safeUser } = user;
    res.json(safeUser);
  });

  app.get("/api/dashboard/stats", requireAuth, async (_req, res) => {
    const stats = await storage.getDashboardStats();
    res.json(stats);
  });

  app.get("/api/sessions", requireAuth, async (req, res) => {
    const activeOnly = req.query.active === "true";
    const result = await storage.getSessions(activeOnly);
    res.json(result);
  });

  app.get("/api/sessions/:id", requireAuth, async (req, res) => {
    const id = req.params.id as string;
    const s = await storage.getSession(id);
    if (!s) return res.status(404).json({ message: "Session not found" });
    res.json(s);
  });

  app.get("/api/events", requireAuth, async (req, res) => {
    const filters: any = {};
    if (req.query.severity) filters.severity = req.query.severity;
    if (req.query.type) filters.type = req.query.type;
    if (req.query.limit) filters.limit = parseInt(req.query.limit as string);
    const result = await storage.getSecurityEvents(filters);
    res.json(result);
  });

  app.get("/api/trust", requireAuth, async (_req, res) => {
    const servers = await storage.getTrustedServers();
    res.json(servers);
  });

  app.post("/api/trust", requireAuth, async (req, res) => {
    const parsed = insertTrustedServerSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const server = await storage.createTrustedServer(parsed.data);
    await auditLog(req, "create", "trusted_server", server.id, { host: server.host });
    res.json(server);
  });

  app.patch("/api/trust/:id", requireAuth, async (req, res) => {
    const id = req.params.id as string;
    const updated = await storage.updateTrustedServer(id, req.body);
    await auditLog(req, "update", "trusted_server", id, req.body);
    res.json(updated);
  });

  app.get("/api/policies", requireAuth, async (_req, res) => {
    const policies = await storage.getPolicyRules();
    res.json(policies);
  });

  app.post("/api/policies", requireAuth, async (req, res) => {
    const parsed = insertPolicyRuleSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const policy = await storage.createPolicyRule(parsed.data);
    await auditLog(req, "create", "policy_rule", policy.id, { name: policy.name });
    res.json(policy);
  });

  app.patch("/api/policies/:id", requireAuth, async (req, res) => {
    const id = req.params.id as string;
    const updated = await storage.updatePolicyRule(id, req.body);
    await auditLog(req, "update", "policy_rule", id, req.body);
    res.json(updated);
  });

  app.get("/api/compliance", requireAuth, async (_req, res) => {
    const data = await storage.getComplianceData();
    res.json(data);
  });

  app.get("/api/engine/status", requireAuth, (_req, res) => {
    const engine = getEngineInstance();
    res.json(engine?.getStatus() || { state: "shutdown", uptime: 0, scansRun: 0, findingsTotal: 0, intelRefreshes: 0 });
  });

  app.post("/api/engine/start", requireAuth, async (_req, res) => {
    const engine = getEngine();
    await engine.start();
    res.json({ message: "Engine started" });
  });

  app.post("/api/engine/stop", requireAuth, async (_req, res) => {
    const engine = getEngineInstance();
    if (engine) {
      await engine.stop();
      res.json({ message: "Engine stopped" });
    } else {
      res.status(400).json({ message: "Engine not initialized" });
    }
  });

  app.post("/api/engine/scan", requireAuth, async (_req, res) => {
    const engine = getEngineInstance();
    if (engine) {
      const result = await engine.runScan();
      res.json(result);
    } else {
      res.status(400).json({ message: "Engine not initialized" });
    }
  });

  app.post("/api/engine/intel", requireAuth, async (_req, res) => {
    const engine = getEngineInstance();
    if (engine) {
      const result = await engine.runIntel();
      res.json(result);
    } else {
      res.status(400).json({ message: "Engine not initialized" });
    }
  });

  app.get("/api/engine/findings", requireAuth, (_req, res) => {
    const engine = getEngineInstance();
    res.json(engine?.getFindings() || []);
  });

  app.get("/api/engine/patterns", requireAuth, async (_req, res) => {
    const engine = getEngineInstance();
    res.json(engine?.getThreatPatterns() || []);
  });

  app.get("/api/ws/status", requireAuth, (_req, res) => {
    res.json({ clients: connectedClients.size, status: "active" });
  });

  app.post("/api/ingest/event", requireAuth, async (req, res) => {
    try {
      const parsed = insertSecurityEventSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
      const event = await storage.createSecurityEvent(parsed.data);
      broadcastEvent({ type: "security_event", data: event });
      res.status(201).json(event);
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  app.post("/api/ingest/session", requireAuth, async (req, res) => {
    try {
      const parsed = insertSessionSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
      const newSession = await storage.createSession(parsed.data);
      broadcastEvent({ type: "session_update", data: newSession });
      res.status(201).json(newSession);
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });
  wss.on("connection", (ws) => {
    const clientId = randomBytes(8).toString("hex");
    connectedClients.set(ws, clientId);
    ws.on("close", () => connectedClients.delete(ws));
    ws.on("error", () => connectedClients.delete(ws));
    ws.send(JSON.stringify({ type: "connected", clientId }));
  });
}
