import { storage } from "./storage";

export type EngineState = "initializing" | "running" | "suspended" | "shutdown";
export type TaskPriority = 0 | 1 | 2 | 3;
export type TaskStatus = "queued" | "running" | "completed" | "failed" | "retrying";
export type ThreatLevel = "nominal" | "elevated" | "critical";

interface ScanTask {
  id: string;
  name: string;
  goal: string;
  priority: TaskPriority;
  status: TaskStatus;
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  result?: any;
  error?: string;
  retryCount: number;
  maxRetries: number;
}

interface Finding {
  id: string;
  hunt: string;
  severity: string;
  title: string;
  description: string;
  evidence: Record<string, any>;
  remediation: string;
  cmmc: string[];
}

interface HuntResult {
  findings: Finding[];
  modules: string[];
  durationMs: number;
  sessionsScanned: number;
  toolCallsScanned: number;
}

interface IntelResult {
  newRules: number;
  newBlocked: number;
  totalPatterns: number;
  durationMs: number;
}

export const THREAT_PATTERNS = [
  {
    id: "tp-001", source: "internal", severity: "critical",
    title: "MCP Tool Poisoning via Hidden System Prompt",
    cveId: "",
    policyRule: {
      name: "block_tool_description_injection",
      pattern: "(?i)(ignore previous|disregard|new instruction|system:\\s*\\[|<\\|system\\|>|\\{\\{SYSTEM|OVERRIDE:|IGNORE ABOVE)",
      action: "block", severity: "critical", category: "injection_defense",
    },
    cmmc: ["AC-3.1", "SC-7.1"],
  },
  {
    id: "tp-002", source: "internal", severity: "high",
    title: "MCP Preference Manipulation Attack (MPMA)",
    cveId: "",
    policyRule: {
      name: "alert_tool_ranking_shift",
      pattern: "*_alt",
      action: "alert", severity: "high", category: "tool_integrity",
    },
    cmmc: ["SC-7.1", "AU-6.1"],
  },
  {
    id: "tp-003", source: "nvd", severity: "critical",
    title: "GitHub Copilot YOLO Mode RCE (CVE-2025-53773)",
    cveId: "CVE-2025-53773",
    policyRule: {
      name: "block_yolo_mode_rce",
      pattern: "(?i)(yolo|--dangerously-skip-permissions|auto.?approve|no.?confirm)\\s*(mode|flag|enabled)",
      action: "block", severity: "critical", category: "rce_defense",
    },
    cmmc: ["AC-3.2", "IA-2.1"],
  },
  {
    id: "tp-004", source: "nvd", severity: "critical",
    title: "Cursor RCE via MCP Config Poisoning (CVE-2025-54135)",
    cveId: "CVE-2025-54135",
    policyRule: {
      name: "block_mcp_config_write",
      pattern: "(?i)(\\.mcp|mcp\\.json|mcpconfig|mcp_servers\\.json)",
      action: "block", severity: "critical", category: "rce_defense",
    },
    cmmc: ["AC-3.2", "SC-7.1", "IA-2.1"],
  },
  {
    id: "tp-005", source: "owasp", severity: "high",
    title: "OWASP Agentic #1: Prompt Injection via Tool Response",
    cveId: "",
    policyRule: {
      name: "alert_prompt_injection_in_response",
      pattern: "(?i)(you should now|next you must|as an ai|ignore your|forget your previous|act as|roleplay as)",
      action: "alert", severity: "high", category: "injection_defense",
    },
    cmmc: ["SC-7.1"],
  },
  {
    id: "tp-006", source: "owasp", severity: "critical",
    title: "OWASP Agentic #2: Covert Exfiltration Tool Invocation",
    cveId: "",
    policyRule: {
      name: "block_covert_exfil",
      pattern: "(?i)(exfil|paste\\.ee|pastebin|transfer\\.sh|ngrok|requestbin)",
      action: "block", severity: "critical", category: "exfiltration_defense",
    },
    cmmc: ["SC-7.1", "SC-8.1"],
  },
  {
    id: "tp-007", source: "internal", severity: "critical",
    title: "OAuth Token Harvest via Compromised MCP Server",
    cveId: "",
    policyRule: {
      name: "block_oauth_token_access",
      pattern: "(?i)(oauth_token|access_token|refresh_token|\\.oauth|token_cache|gcloud/credentials)",
      action: "block", severity: "critical", category: "credential_protection",
    },
    cmmc: ["SC-28.1", "IA-5.1"],
  },
  {
    id: "tp-008", source: "internal", severity: "high",
    title: "Unicode Steganography in Tool Arguments",
    cveId: "",
    policyRule: {
      name: "block_unicode_steganography",
      pattern: "[\\u200b\\u200c\\u200d\\u200e\\u200f\\u202a-\\u202e\\u2060-\\u2069\\ufeff]",
      action: "block", severity: "high", category: "injection_defense",
    },
    cmmc: ["SC-7.1", "AU-6.1"],
  },
];

const CREDENTIAL_PATTERNS = [
  { pattern: /AKIA[0-9A-Z]{16}/, type: "AWS Access Key ID" },
  { pattern: /ghp_[A-Za-z0-9]{36}/, type: "GitHub PAT" },
  { pattern: /ghs_[A-Za-z0-9]{36}/, type: "GitHub Actions Token" },
  { pattern: /sk-ant-api\d{2}-[A-Za-z0-9\-_]{20,}/, type: "Anthropic API Key" },
  { pattern: /eyJ[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]+/, type: "JWT Token" },
  { pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/, type: "Slack Token" },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S{8,}/i, type: "Plaintext Password" },
];

const INJECTION_PATTERNS = [
  { pattern: /ignore.{0,20}(previous|above|all).{0,20}(instruction|prompt|context)/i, type: "ignore-instructions" },
  { pattern: /<\|system\|>|<s>|\{\{SYSTEM/i, type: "system-tag-injection" },
  { pattern: /you are now|pretend (you are|to be)|act as (a |an )?(different|new|evil|malicious)/i, type: "role-override" },
  { pattern: /[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e]/, type: "unicode-steganography" },
];

class ThreatHunter {
  private findingCounter = 0;

  private fid(): string {
    this.findingCounter++;
    return `hunt-${String(this.findingCounter).padStart(5, "0")}`;
  }

  async run(orgId?: string): Promise<HuntResult> {
    const start = Date.now();
    const allFindings: Finding[] = [];
    const modules: string[] = [];

    try {
      const f = await this.credentialHunt(orgId);
      allFindings.push(...f.findings);
      modules.push("cred_scan");
    } catch (e) { console.error("Hunt module cred_scan failed:", e); }

    try {
      const f = await this.injectionHunt(orgId);
      allFindings.push(...f.findings);
      modules.push("injection");
    } catch (e) { console.error("Hunt module injection failed:", e); }

    try {
      const f = await this.behavioralTrends(orgId);
      allFindings.push(...f.findings);
      modules.push("behavior");
    } catch (e) { console.error("Hunt module behavior failed:", e); }

    try {
      const f = await this.policyTrends(orgId);
      allFindings.push(...f.findings);
      modules.push("policy_trend");
    } catch (e) { console.error("Hunt module policy_trend failed:", e); }

    try {
      const f = await this.serverExposure(orgId);
      allFindings.push(...f.findings);
      modules.push("server_exposure");
    } catch (e) { console.error("Hunt module server_exposure failed:", e); }

    const durationMs = Date.now() - start;
    const result: HuntResult = {
      findings: allFindings,
      modules,
      durationMs,
      sessionsScanned: 0,
      toolCallsScanned: 0,
    };

    await this.persistFindings(allFindings, orgId);
    return result;
  }

  private async credentialHunt(orgId?: string): Promise<{ findings: Finding[] }> {
    const findings: Finding[] = [];
    const toolCalls = await storage.getToolCalls(undefined, orgId);
    for (const tc of toolCalls) {
      const blob = JSON.stringify(tc.arguments || {});
      for (const { pattern, type } of CREDENTIAL_PATTERNS) {
        if (pattern.test(blob)) {
          findings.push({
            id: this.fid(), hunt: "cred_scan", severity: "critical",
            title: `${type} in tool call log`,
            description: `Credential exposed in session ${tc.sessionId.substring(0, 8)}. Tool: ${tc.toolName}`,
            evidence: { sessionId: tc.sessionId.substring(0, 8), type, tool: tc.toolName },
            remediation: "Rotate credential immediately. Audit system prompt for data leakage.",
            cmmc: ["SC-28.1", "IA-5.1"],
          });
          break;
        }
      }
    }
    return { findings };
  }

  private async injectionHunt(orgId?: string): Promise<{ findings: Finding[] }> {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const events = await storage.getSecurityEvents({ orgId, limit: 500 });
    for (const ev of events) {
      const blob = JSON.stringify(ev.details || {}) + " " + ev.description;
      for (const { pattern, type } of INJECTION_PATTERNS) {
        const key = `${ev.sessionId}-${type}`;
        if (pattern.test(blob) && !seen.has(key)) {
          seen.add(key);
          findings.push({
            id: this.fid(), hunt: "injection", severity: "high",
            title: `Prompt injection pattern: ${type}`,
            description: `Pattern '${type}' detected in session ${ev.sessionId.substring(0, 8)}.`,
            evidence: { sessionId: ev.sessionId.substring(0, 8), pattern: type },
            remediation: "Review session for goal drift after this event.",
            cmmc: ["SC-7.1", "AU-6.1"],
          });
          break;
        }
      }
    }
    return { findings };
  }

  private async behavioralTrends(orgId?: string): Promise<{ findings: Finding[] }> {
    const findings: Finding[] = [];
    const sessions = await storage.getSessions(orgId);
    if (sessions.length < 3) return { findings };

    const highAnomaly = sessions.filter(s => s.anomalyScore > 0.7);
    const highDrift = sessions.filter(s => s.goalIntegrityScore < 0.4);

    if (highAnomaly.length >= 3) {
      findings.push({
        id: this.fid(), hunt: "behavior", severity: "high",
        title: `Anomaly spike: ${highAnomaly.length}/${sessions.length} sessions`,
        description: `${highAnomaly.length} sessions with anomaly score > 0.7. Pattern suggests coordinated attack or shared compromised system prompt.`,
        evidence: { count: highAnomaly.length, total: sessions.length },
        remediation: "Check for shared system prompt or MCP server across flagged sessions.",
        cmmc: ["AU-6.1", "SC-7.1"],
      });
    }
    if (highDrift.length >= 2) {
      findings.push({
        id: this.fid(), hunt: "behavior", severity: "critical",
        title: `Goal drift pattern: ${highDrift.length} sessions deviated`,
        description: `${highDrift.length} sessions with goal integrity < 0.4. Likely prompt injection as root cause.`,
        evidence: { count: highDrift.length },
        remediation: "Investigate prompt injection as root cause of drift.",
        cmmc: ["SC-7.1"],
      });
    }
    return { findings };
  }

  private async policyTrends(orgId?: string): Promise<{ findings: Finding[] }> {
    const findings: Finding[] = [];
    const events = await storage.getSecurityEvents({ orgId, limit: 1000 });
    const counts: Record<string, number> = {};
    for (const ev of events) {
      if (ev.eventType === "policy_violation") {
        const details = ev.details as Record<string, any> || {};
        const rule = details.rule || "unknown";
        counts[rule] = (counts[rule] || 0) + 1;
      }
    }
    for (const [rule, n] of Object.entries(counts)) {
      if (n >= 5) {
        findings.push({
          id: this.fid(), hunt: "policy_trend",
          severity: n >= 20 ? "critical" : "high",
          title: `Policy probe detected: '${rule}' triggered ${n}x`,
          description: `Rule '${rule}' hit ${n} times. Possible automated probing or fuzzing attack.`,
          evidence: { rule, count: n },
          remediation: `Tighten '${rule}' from ALERT to BLOCK if not already.`,
          cmmc: ["AU-6.1", "SC-7.1"],
        });
      }
    }
    return { findings };
  }

  private async serverExposure(orgId?: string): Promise<{ findings: Finding[] }> {
    const findings: Finding[] = [];
    const servers = await storage.getTrustedServers(orgId);
    for (const server of servers) {
      if (server.host === "0.0.0.0" && server.status === "allowed") {
        findings.push({
          id: this.fid(), hunt: "server_exposure", severity: "critical",
          title: `MCP server exposed to all interfaces: ${server.alias || server.host}`,
          description: `Server ${server.host}:${server.port} binds to 0.0.0.0 — network accessible from any interface.`,
          evidence: { host: server.host, port: server.port, alias: server.alias },
          remediation: "Change host binding to 127.0.0.1 or restrict with firewall rules.",
          cmmc: ["SC-7.1", "AC-17.1"],
        });
      }
      if (!server.toolManifestHash && server.status === "allowed") {
        findings.push({
          id: this.fid(), hunt: "server_exposure", severity: "high",
          title: `MCP server missing tool manifest hash: ${server.alias || server.host}`,
          description: `Server ${server.host}:${server.port} has no tool manifest hash — tool redefinition attacks possible.`,
          evidence: { host: server.host, port: server.port },
          remediation: "Pin tool manifest hash to detect tool redefinition attacks.",
          cmmc: ["CM-2.1", "SC-7.1"],
        });
      }
    }
    return { findings };
  }

  private async persistFindings(findings: Finding[], orgId?: string) {
    for (const f of findings) {
      try {
        await storage.createSecurityEvent({
          organizationId: orgId || null,
          sessionId: "aiglos-hunter",
          eventType: "anomaly_detected",
          severity: f.severity,
          title: `[HUNT] ${f.title}`,
          description: f.description,
          details: { ...f.evidence, hunt: f.hunt, remediation: f.remediation },
          cmmcControls: f.cmmc,
          nistControls: f.cmmc.map(c => c.split(".").slice(0, 1).join(".")),
        });
      } catch (e) {
        console.error("Failed to persist finding:", e);
      }
    }
  }
}

class ThreatIntelligenceEngine {
  private appliedPatterns = new Set<string>();

  async refresh(orgId?: string): Promise<IntelResult> {
    const start = Date.now();
    let newRules = 0;
    let newBlocked = 0;

    const existingPolicies = await storage.getPolicyRules(orgId);
    const existingNames = new Set(existingPolicies.map(p => p.name));

    for (const tp of THREAT_PATTERNS) {
      if (this.appliedPatterns.has(tp.id)) continue;
      if (existingNames.has(tp.policyRule.name)) {
        this.appliedPatterns.add(tp.id);
        continue;
      }

      try {
        await storage.createPolicyRule({
          organizationId: orgId || null,
          name: tp.policyRule.name,
          description: `[AUTO] ${tp.title}${tp.cveId ? ` (${tp.cveId})` : ""} — Source: ${tp.source}`,
          pattern: tp.policyRule.pattern,
          action: tp.policyRule.action,
          severity: tp.policyRule.severity,
          enabled: true,
          category: tp.policyRule.category,
        });
        newRules++;
        this.appliedPatterns.add(tp.id);
      } catch (e) {
        console.error(`Failed to create intel policy rule ${tp.policyRule.name}:`, e);
      }
    }

    return {
      newRules,
      newBlocked,
      totalPatterns: THREAT_PATTERNS.length,
      durationMs: Date.now() - start,
    };
  }
}

export class AiglosAutonomousEngine {
  private state: EngineState = "initializing";
  private startTime = 0;
  private taskCounter = 0;
  private doneTasks: ScanTask[] = [];
  private failedTasks: ScanTask[] = [];
  private activeTasks: Map<string, ScanTask> = new Map();
  private lastScan: number | null = null;
  private lastIntel: number | null = null;
  private lastHuntResult: HuntResult | null = null;
  private lastIntelResult: IntelResult | null = null;
  private threatLevel: ThreatLevel = "nominal";

  private scanIntervalMs: number;
  private intelIntervalMs: number;
  private scanTimer: NodeJS.Timeout | null = null;
  private intelTimer: NodeJS.Timeout | null = null;
  private watchdogTimer: NodeJS.Timeout | null = null;

  private hunter = new ThreatHunter();
  private intel = new ThreatIntelligenceEngine();
  private orgId?: string;

  constructor(options?: { scanIntervalMin?: number; intelIntervalMin?: number; orgId?: string }) {
    this.scanIntervalMs = (options?.scanIntervalMin || 5) * 60 * 1000;
    this.intelIntervalMs = (options?.intelIntervalMin || 60) * 60 * 1000;
    this.orgId = options?.orgId;
  }

  async start() {
    this.startTime = Date.now();
    this.state = "running";
    console.log(`[ENGINE] Aiglos Autonomous Engine started (scan every ${this.scanIntervalMs / 60000}m, intel every ${this.intelIntervalMs / 60000}m)`);

    await this.runScan();
    await this.runIntel();

    this.scanTimer = setInterval(() => this.runScan(), this.scanIntervalMs);
    this.intelTimer = setInterval(() => this.runIntel(), this.intelIntervalMs);
    this.watchdogTimer = setInterval(() => this.watchdog(), 60000);
  }

  async stop() {
    this.state = "shutdown";
    if (this.scanTimer) clearInterval(this.scanTimer);
    if (this.intelTimer) clearInterval(this.intelTimer);
    if (this.watchdogTimer) clearInterval(this.watchdogTimer);
    this.scanTimer = null;
    this.intelTimer = null;
    this.watchdogTimer = null;
    console.log("[ENGINE] Aiglos Autonomous Engine stopped");
  }

  async runScan(): Promise<HuntResult> {
    const taskId = `t${++this.taskCounter}`;
    const task: ScanTask = {
      id: taskId, name: "threat_scan",
      goal: "Scan session history and server registry for active threat indicators",
      priority: 2, status: "running", createdAt: Date.now(), startedAt: Date.now(),
      retryCount: 0, maxRetries: 2,
    };
    this.activeTasks.set(taskId, task);

    try {
      const result = await this.hunter.run(this.orgId);
      task.status = "completed";
      task.completedAt = Date.now();
      task.result = { findings: result.findings.length, modules: result.modules };
      this.doneTasks.push(task);
      this.lastScan = Date.now();
      this.lastHuntResult = result;
      this.updateThreatLevel();
      console.log(`[ENGINE] Scan complete: ${result.findings.length} findings in ${result.durationMs}ms`);
      return result;
    } catch (e: any) {
      task.status = "failed";
      task.error = e.message;
      this.failedTasks.push(task);
      throw e;
    } finally {
      this.activeTasks.delete(taskId);
    }
  }

  async runIntel(): Promise<IntelResult> {
    const taskId = `t${++this.taskCounter}`;
    const task: ScanTask = {
      id: taskId, name: "intel_refresh",
      goal: "Ingest CVE feeds and OWASP updates to extend detection policy",
      priority: 2, status: "running", createdAt: Date.now(), startedAt: Date.now(),
      retryCount: 0, maxRetries: 2,
    };
    this.activeTasks.set(taskId, task);

    try {
      const result = await this.intel.refresh(this.orgId);
      task.status = "completed";
      task.completedAt = Date.now();
      task.result = result;
      this.doneTasks.push(task);
      this.lastIntel = Date.now();
      this.lastIntelResult = result;
      console.log(`[ENGINE] Intel refresh: ${result.newRules} new rules in ${result.durationMs}ms`);
      return result;
    } catch (e: any) {
      task.status = "failed";
      task.error = e.message;
      this.failedTasks.push(task);
      throw e;
    } finally {
      this.activeTasks.delete(taskId);
    }
  }

  private watchdog() {
    const recentFails = this.failedTasks.filter(
      t => t.completedAt && Date.now() - t.completedAt < 300000
    ).length;

    if (recentFails >= 5) {
      console.error("[ENGINE] WATCHDOG: Repeated scan failures — possible active interference");
      this.threatLevel = "critical";
    }
  }

  private updateThreatLevel() {
    if (!this.lastHuntResult) return;
    const critical = this.lastHuntResult.findings.filter(f => f.severity === "critical").length;
    const high = this.lastHuntResult.findings.filter(f => f.severity === "high").length;
    if (critical >= 3) this.threatLevel = "critical";
    else if (critical >= 1 || high >= 3) this.threatLevel = "elevated";
    else this.threatLevel = "nominal";
  }

  getStatus() {
    return {
      state: this.state,
      threatLevel: this.threatLevel,
      uptimeMs: this.startTime > 0 ? Date.now() - this.startTime : 0,
      tasksDone: this.doneTasks.length,
      tasksFailed: this.failedTasks.length,
      activeTask: this.activeTasks.size > 0 ? Array.from(this.activeTasks.values())[0].name : null,
      lastScan: this.lastScan,
      lastIntel: this.lastIntel,
      lastHuntResult: this.lastHuntResult ? {
        findings: this.lastHuntResult.findings.length,
        critical: this.lastHuntResult.findings.filter(f => f.severity === "critical").length,
        high: this.lastHuntResult.findings.filter(f => f.severity === "high").length,
        modules: this.lastHuntResult.modules,
        durationMs: this.lastHuntResult.durationMs,
      } : null,
      lastIntelResult: this.lastIntelResult,
      threatPatterns: THREAT_PATTERNS.length,
      recentTasks: [...this.doneTasks.slice(-10), ...this.failedTasks.slice(-5)]
        .sort((a, b) => (b.completedAt || b.createdAt) - (a.completedAt || a.createdAt))
        .slice(0, 10),
    };
  }

  getFindings() {
    return this.lastHuntResult?.findings || [];
  }

  getThreatPatterns() {
    return THREAT_PATTERNS;
  }
}

let engineInstance: AiglosAutonomousEngine | null = null;

export async function getEngine(orgId?: string): Promise<AiglosAutonomousEngine> {
  if (!engineInstance) {
    let resolvedOrgId = orgId;
    if (!resolvedOrgId) {
      const orgs = await storage.getOrganizations();
      resolvedOrgId = orgs[0]?.id;
    }
    engineInstance = new AiglosAutonomousEngine({
      scanIntervalMin: 5,
      intelIntervalMin: 60,
      orgId: resolvedOrgId,
    });
  }
  return engineInstance;
}

export function getEngineInstance(): AiglosAutonomousEngine | null {
  return engineInstance;
}
