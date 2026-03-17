/**
 * aiglos/security_surfaces.ts
 *
 * v0.15.0–v0.17.0 security surface ports for TypeScript:
 *   T40 -- ContextDirectoryGuard
 *   T41 -- OutboundSecretGuard
 *   T43 -- HoneypotManager
 *   OverrideManager -- challenge-response Tier 3 overrides
 *   SourceReputationGraph -- URL/document reputation tracking
 */

// ─────────────────────────────────────────────────────────────────────────────
// T40 -- Context Directory Guard
// ─────────────────────────────────────────────────────────────────────────────

const PROTECTED_DIRS  = new Set([
  "context", "shared", "fleet", "coordination", "signals",
  "bus", "state", "cross-agent", "shared-memory", "agent-bus",
]);
const PROTECTED_FILES = new Set([
  "context", "fleet", "shared_state", "shared", "bus",
  "coordination", "agents", "shared_context",
]);
const PROTECTED_MD = new Set([
  "shared.md", "fleet.md", "agents.md", "context.md", "bus.md",
]);

const T40_PHRASES: Array<[string, number]> = [
  ["ignore previous instructions", 0.35],
  ["disregard your",               0.30],
  ["forget everything",            0.35],
  ["disable monitoring",           0.40],
  ["bypass security",              0.40],
  ["tell all agents",              0.35],
  ["broadcast to fleet",           0.40],
  ["override agent instructions",  0.40],
  ["fleet instruction",            0.35],
];

export interface ContextGuardResult {
  verdict:          "ALLOW" | "WARN" | "BLOCK";
  ruleId:           "T40";
  path:             string;
  score:            number;
  risk:             "LOW" | "MEDIUM" | "HIGH";
  signalsFound:     string[];
  isProtectedPath:  boolean;
}

export function isSharedContextPath(path: string): boolean {
  const p = path.toLowerCase().replace(/\\/g, "/");
  const parts = p.split("/");
  for (const part of parts.slice(0, -1)) {
    if (PROTECTED_DIRS.has(part)) return true;
  }
  const fname = parts[parts.length - 1] ?? "";
  if (PROTECTED_MD.has(fname)) return true;
  const stem = fname.includes(".") ? fname.split(".")[0] : fname;
  return PROTECTED_FILES.has(stem);
}

export function scoreContextContent(content: string): [number, string[]] {
  const lower   = content.toLowerCase();
  let   total   = 0;
  const signals: string[] = [];
  for (const [phrase, weight] of T40_PHRASES) {
    if (lower.includes(phrase)) { total += weight; signals.push(phrase); }
  }
  return [Math.min(total, 1.0), signals];
}

export class ContextDirectoryGuard {
  private mode: string;

  constructor(mode = "block") { this.mode = mode; }

  checkToolCall(
    toolName: string,
    args:     Record<string, unknown>,
  ): ContextGuardResult | null {
    const nameLower = toolName.toLowerCase();
    const isWrite   = nameLower.includes("write") || nameLower.includes("append")
                   || nameLower.includes("shell") || nameLower.includes("exec");
    if (!isWrite) return null;

    const path    = String(args.path ?? args.file ?? args.command ?? "");
    if (!path || !isSharedContextPath(path)) return null;

    const content          = String(args.content ?? args.text ?? args.body ?? "");
    const [score, signals] = scoreContextContent(content);
    const risk             = score >= 0.65 ? "HIGH" : score >= 0.30 ? "MEDIUM" : "LOW";
    const verdict          = score >= 0.65 && this.mode === "block" ? "BLOCK"
                           : score >= 0.30 ? "WARN" : "ALLOW";

    return { verdict, ruleId: "T40", path, score, risk, signalsFound: signals, isProtectedPath: true };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// T41 -- Outbound Secret Guard
// ─────────────────────────────────────────────────────────────────────────────

const SECRET_PATTERNS: Array<[string, RegExp, number]> = [
  ["anthropic_api_key", /sk-ant-api0[34]-[A-Za-z0-9_-]{95,}/,         1.0],
  ["openai_api_key",    /sk-(?:proj-)?[A-Za-z0-9]{48,}/,               1.0],
  ["aws_access_key",    /AKIA[0-9A-Z]{16}/,                            1.0],
  ["github_token",      /(?:ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}/, 1.0],
  ["stripe_key",        /sk_(?:live|test)_[A-Za-z0-9]{24,}/,           1.0],
  ["slack_token",       /xox[baprs]-(?:[0-9a-zA-Z]{10,}[-]?){2,}/,    1.0],
  ["huggingface_token", /hf_[A-Za-z0-9]{34,}/,                         0.95],
  ["generic_secret",    /(?:api.?key|token|secret)["\s:=]+[A-Za-z0-9\/+_-]{32,}/i, 0.80],
];

const PATH_PATTERNS: Array<[string, RegExp, number]> = [
  ["ssh_key_path",  /~?\/\.ssh\/(?:id_rsa|id_ed25519)/,      0.90],
  ["aws_creds",     /~?\/\.aws\/(?:credentials|config)/,      0.90],
  ["env_file",      /(?:^|[\s/])\.env(?:\.local|\.production)?(?:\s|$|["'])/i, 0.80],
  ["etc_passwd",    /\/etc\/(?:passwd|shadow|sudoers)/,       0.85],
];

const SEMANTIC_PATTERNS: Array<[string, RegExp, number]> = [
  ["key_reveal",     /here\s+is\s+(?:my|the)\s+(?:api\s+key|token|secret)/i, 0.65],
  ["exfil_ack",      /(?:sending|transmitting|forwarding)\s+(?:the\s+)?(?:key|token|credential)/i, 0.70],
  ["instr_comply",   /as\s+(?:requested|instructed|you\s+asked)/i,           0.35],
];

export interface OutboundScanResult {
  verdict:        "ALLOW" | "WARN" | "BLOCK";
  ruleId:         "T41";
  pattern:        string | null;
  score:          number;
  risk:           "LOW" | "MEDIUM" | "HIGH";
  signalsFound:   string[];
  contentPreview: string;
}

export class OutboundSecretGuard {
  private mode: string;

  constructor(mode = "block") { this.mode = mode; }

  scan(content: string, _destination = ""): OutboundScanResult {
    if (!content) {
      return { verdict: "ALLOW", ruleId: "T41", pattern: null,
               score: 0, risk: "LOW", signalsFound: [], contentPreview: "" };
    }

    let total = 0;
    const signals: string[] = [];
    let topPattern: string | null = null;
    let topScore = 0;

    for (const [name, pat, sev] of SECRET_PATTERNS) {
      if (pat.test(content)) {
        total += sev; signals.push(name);
        if (sev > topScore) { topScore = sev; topPattern = name; }
      }
    }
    for (const [name, pat, sev] of PATH_PATTERNS) {
      if (pat.test(content)) {
        total += sev; signals.push(name);
        if (sev > topScore) { topScore = sev; topPattern = name; }
      }
    }
    let semScore = 0;
    for (const [name, pat, sev] of SEMANTIC_PATTERNS) {
      if (pat.test(content)) { semScore += sev; signals.push(name); }
    }
    total += semScore > 0 && total > 0 ? semScore * 0.5 : semScore * 0.25;

    const score   = Math.min(Math.round(total * 10000) / 10000, 1.0);
    const risk    = score >= 0.75 ? "HIGH" : score >= 0.40 ? "MEDIUM" : "LOW";
    const verdict = score >= 0.75 && this.mode === "block" ? "BLOCK"
                  : score >= 0.40 ? "WARN" : "ALLOW";

    const preview = content.slice(0, 80).replace(
      /sk-ant-api0[34]-[A-Za-z0-9_-]{10,}/g, "[REDACTED]"
    );

    return { verdict, ruleId: "T41", pattern: topPattern, score, risk,
             signalsFound: signals, contentPreview: preview };
  }
}

export function containsSecret(content: string): boolean {
  return new OutboundSecretGuard().scan(content).verdict !== "ALLOW";
}

// ─────────────────────────────────────────────────────────────────────────────
// T43 -- Honeypot Manager
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_HONEYPOT_NAMES = [
  "system_auth_tokens.json", ".env.production", "aws_credentials_backup",
  "stripe_live_keys.txt", "anthropic_api_keys_backup.json",
  "ssh_key_archive.json", "database_credentials.json", "github_tokens.txt",
];

export interface HoneypotResult {
  triggered:      boolean;
  ruleId:         "T43";
  honeypotName:   string;
  toolName:       string;
  severity:       "CRITICAL";
  detectionMode:  "TOOL_CALL" | "CONTENT";
}

export class HoneypotManager {
  private names: Set<string> = new Set();
  private hits:  HoneypotResult[] = [];

  constructor(customNames: string[] = []) {
    [...DEFAULT_HONEYPOT_NAMES, ...customNames].forEach(n =>
      this.names.add(n.toLowerCase()));
  }

  checkToolCall(
    toolName: string,
    args:     Record<string, unknown>,
  ): HoneypotResult {
    const nameLower = toolName.toLowerCase();
    const isRead    = toolName.includes("read") || toolName.includes("cat")
                   || toolName.includes("stat") || nameLower.includes("shell")
                   || nameLower.includes("exec");
    if (!isRead) return this._clean(toolName);

    const toCheck = [
      String(args.path ?? args.file ?? args.filename ?? ""),
      String(args.command ?? args.cmd ?? ""),
    ].map(s => s.toLowerCase());

    for (const str of toCheck) {
      for (const name of this.names) {
        if (str.includes(name)) {
          const result: HoneypotResult = {
            triggered: true, ruleId: "T43",
            honeypotName: name, toolName,
            severity: "CRITICAL", detectionMode: "TOOL_CALL",
          };
          this.hits.push(result);
          return result;
        }
      }
    }
    return this._clean(toolName);
  }

  checkContent(content: string, toolName = ""): HoneypotResult {
    const lower = content.toLowerCase();
    for (const name of this.names) {
      if (lower.includes(name)) {
        const result: HoneypotResult = {
          triggered: true, ruleId: "T43",
          honeypotName: name, toolName,
          severity: "CRITICAL", detectionMode: "CONTENT",
        };
        this.hits.push(result);
        return result;
      }
    }
    return this._clean(toolName);
  }

  addCustom(name: string): void { this.names.add(name.toLowerCase()); }
  get hitCount(): number { return this.hits.length; }
  get activeNames(): string[] { return [...this.names]; }
  private _clean(toolName: string): HoneypotResult {
    return { triggered: false, ruleId: "T43", honeypotName: "",
             toolName, severity: "CRITICAL", detectionMode: "TOOL_CALL" };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Override Manager -- challenge-response Tier 3 overrides
// ─────────────────────────────────────────────────────────────────────────────

export interface OverrideChallenge {
  challengeId:  string;
  code:         string;
  ruleId:       string;
  toolName:     string;
  reason:       string;
  issuedAt:     number;
  expiresAt:    number;
  resolved:     boolean;
  approved:     boolean;
  attempts:     number;
}

export interface OverrideResult {
  approved:    boolean;
  challengeId: string;
  error?:      string;
}

const CODE_CHARS    = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";  // no 0/O/1/I
const CODE_LENGTH   = 6;
const EXPIRY_S      = 120;
const MAX_ATTEMPTS  = 3;

export class OverrideManager {
  private challenges: Map<string, OverrideChallenge> = new Map();

  request(
    ruleId:   string,
    toolName: string,
    reason  = "",
  ): OverrideChallenge {
    const code        = Array.from({ length: CODE_LENGTH })
      .map(() => CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)])
      .join("");
    const challengeId = "ovr_" + Math.random().toString(36).slice(2, 18);
    const now         = Date.now() / 1000;

    const challenge: OverrideChallenge = {
      challengeId, code, ruleId, toolName,
      reason: reason || `Override requested for ${ruleId}`,
      issuedAt:  now,
      expiresAt: now + EXPIRY_S,
      resolved: false, approved: false, attempts: 0,
    };

    this.challenges.set(challengeId, challenge);

    // Print to console for terminal visibility
    const remaining = EXPIRY_S;
    console.log(`\n  ┌─ Aiglos Override Required ${"─".repeat(25)}┐`);
    console.log(`  │  Rule blocked: ${ruleId.padEnd(42)} │`);
    console.log(`  │  Tool:         ${toolName.slice(0, 42).padEnd(42)} │`);
    console.log(`  │                                                          │`);
    console.log(`  │  Override code: ${code}   (expires in ${remaining}s)            │`);
    console.log(`  └${"─".repeat(58)}┘\n`);

    return challenge;
  }

  confirm(challengeId: string, code: string): OverrideResult {
    const ch = this._find(challengeId);
    if (!ch) return { approved: false, challengeId, error: "Challenge not found." };

    if (Date.now() / 1000 > ch.expiresAt)
      return { approved: false, challengeId, error: "Challenge expired." };

    if (ch.resolved)
      return { approved: false, challengeId, error: "Challenge already resolved." };

    ch.attempts++;
    if (code.trim().toUpperCase() === ch.code) {
      ch.resolved = true; ch.approved = true;
      return { approved: true, challengeId };
    }

    if (ch.attempts >= MAX_ATTEMPTS) {
      ch.resolved = true;
      return { approved: false, challengeId,
               error: `Max attempts (${MAX_ATTEMPTS}) exceeded.` };
    }

    return { approved: false, challengeId,
             error: `Incorrect code. ${MAX_ATTEMPTS - ch.attempts} attempt(s) remaining.` };
  }

  reject(challengeId: string): OverrideResult {
    const ch = this._find(challengeId);
    if (!ch) return { approved: false, challengeId, error: "Not found." };
    ch.resolved = true; ch.approved = false;
    return { approved: false, challengeId };
  }

  pending(): OverrideChallenge[] {
    const now = Date.now() / 1000;
    return [...this.challenges.values()]
      .filter(c => !c.resolved && c.expiresAt > now);
  }

  private _find(id: string): OverrideChallenge | undefined {
    if (this.challenges.has(id)) return this.challenges.get(id);
    for (const [k, v] of this.challenges) {
      if (k.startsWith(id)) return v;
    }
    return undefined;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Source Reputation Graph
// ─────────────────────────────────────────────────────────────────────────────

export type ReputationLevel = "CLEAN" | "SUSPICIOUS" | "HIGH_RISK" | "BLOCKED";

export interface SourceRecord {
  sourceKey:    string;
  sourceType:   "url" | "domain" | "document";
  eventCount:   number;
  maxScore:     number;
  avgScore:     number;
  lastSeen:     number;
  firstSeen:    number;
  ruleIds:      string[];
  level:        ReputationLevel;
}

export interface SourceRisk {
  sourceKey:         string;
  level:             ReputationLevel;
  score:             number;
  eventCount:        number;
  recommendation:    "NORMAL" | "ELEVATE_THRESHOLD" | "BLOCK";
  thresholdMultiplier: number;
  evidenceSummary:   string;
}

const SUSPICIOUS_THRESHOLD = 1;
const HIGH_RISK_THRESHOLD  = 3;
const BLOCKED_THRESHOLD    = 8;
const SCORE_DECAY_DAYS     = 30;

export class SourceReputationGraph {
  private cache: Map<string, SourceRecord> = new Map();

  recordEvent(
    sourceUrl: string | undefined,
    toolName:  string,
    score:     number,
    verdict:   string,
    ruleId   = "",
  ): void {
    if (score < 0.25) return;

    if (sourceUrl) {
      const norm   = this._normalizeUrl(sourceUrl);
      const domain = this._extractDomain(sourceUrl);
      this._update(norm, "url", score, ruleId);
      if (domain && domain !== norm) {
        this._update(domain, "domain", score * 0.7, ruleId);
      }
    }
  }

  getRisk(sourceUrl?: string): SourceRisk {
    const records: SourceRecord[] = [];

    if (sourceUrl) {
      const norm   = this._normalizeUrl(sourceUrl);
      const domain = this._extractDomain(sourceUrl);
      const r1 = this._get(norm);
      const r2 = this._get(domain);
      if (r1 && !this._isStale(r1)) records.push(r1);
      if (r2 && !this._isStale(r2)) records.push(r2);
    }

    if (!records.length) {
      return { sourceKey: sourceUrl ?? "", level: "CLEAN", score: 0,
               eventCount: 0, recommendation: "NORMAL",
               thresholdMultiplier: 1.0, evidenceSummary: "No history." };
    }

    const worst = records.reduce((a, b) => a.maxScore > b.maxScore ? a : b);
    const rec   = worst.recommendation ?? "NORMAL";

    return {
      sourceKey:    worst.sourceKey,
      level:        worst.level,
      score:        worst.maxScore,
      eventCount:   worst.eventCount,
      recommendation: worst.level === "BLOCKED" ? "BLOCK"
                    : worst.level !== "CLEAN"   ? "ELEVATE_THRESHOLD" : "NORMAL",
      thresholdMultiplier: worst.level === "BLOCKED" || worst.level === "HIGH_RISK"
                           ? 0.5 : worst.level === "SUSPICIOUS" ? 0.75 : 1.0,
      evidenceSummary: `${worst.level}: ${worst.eventCount} event(s), ` +
                       `max score ${worst.maxScore.toFixed(2)}.`,
    };
  }

  topRisky(limit = 10): SourceRecord[] {
    return [...this.cache.values()]
      .filter(r => r.level !== "CLEAN")
      .sort((a, b) => b.maxScore - a.maxScore)
      .slice(0, limit);
  }

  private _update(key: string, type: "url"|"domain"|"document",
                  score: number, ruleId: string): void {
    const now = Date.now() / 1000;
    const rec = this.cache.get(key);
    if (rec) {
      rec.eventCount++;
      rec.maxScore = Math.max(rec.maxScore, score);
      rec.avgScore = (rec.avgScore * (rec.eventCount - 1) + score) / rec.eventCount;
      rec.lastSeen = now;
      if (ruleId && !rec.ruleIds.includes(ruleId)) rec.ruleIds.push(ruleId);
      rec.level = this._computeLevel(rec);
    } else {
      const newRec: SourceRecord = {
        sourceKey: key, sourceType: type,
        eventCount: 1, maxScore: score, avgScore: score,
        lastSeen: now, firstSeen: now,
        ruleIds: ruleId ? [ruleId] : [],
        level: "SUSPICIOUS",
      };
      newRec.level = this._computeLevel(newRec);
      this.cache.set(key, newRec);
    }
  }

  private _computeLevel(r: SourceRecord): ReputationLevel {
    if (r.eventCount >= BLOCKED_THRESHOLD) return "BLOCKED";
    if (r.eventCount >= HIGH_RISK_THRESHOLD || r.maxScore >= 0.75) return "HIGH_RISK";
    if (r.eventCount >= SUSPICIOUS_THRESHOLD || r.maxScore >= 0.40) return "SUSPICIOUS";
    return "CLEAN";
  }

  private _isStale(r: SourceRecord): boolean {
    return (Date.now() / 1000 - r.lastSeen) > SCORE_DECAY_DAYS * 86400;
  }

  private _get(key: string): SourceRecord | undefined {
    return this.cache.get(key);
  }

  private _normalizeUrl(url: string): string {
    try {
      const u = new URL(url.toLowerCase().trim());
      return `${u.protocol}//${u.host}${u.pathname}`.replace(/\/$/, "");
    } catch { return url.toLowerCase().trim(); }
  }

  private _extractDomain(url: string): string {
    try { return new URL(url.toLowerCase().trim()).host; }
    catch { return url.toLowerCase().trim(); }
  }
}
