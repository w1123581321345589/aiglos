/**
 * aiglos -- AI agent security runtime for TypeScript/Node.js v0.17.0
 *
 * One import. Every agent action inspected before it runs.
 * MCP, HTTP/API, CLI, subprocess -- plus the full intelligence stack:
 * behavioral baseline, policy proposals, federation, honeypot,
 * challenge-response override, source reputation.
 *
 * @example
 * import aiglos from "aiglos";
 *
 * aiglos.attach({
 *   agentName:                 "my-agent",
 *   policy:                    "enterprise",
 *   interceptHttp:             true,
 *   enableBehavioralBaseline:  true,
 *   enablePolicyProposals:     true,
 *   enableHoneypot:            true,
 *   enableSourceReputation:    true,
 *   enableFederation:          true,
 *   federationApiKey:          "ak_live_...",
 * });
 */

// Core exports (unchanged from v0.10)
export * from "./types";
export * from "./http";
export * from "./subprocess";
export * from "./session";

// v0.11.0 -- Behavioral baseline
export {
  BaselineEngine,
  type BaselineScore,
  type SessionStats,
  type RiskLevel,
} from "./behavioral_baseline";

// v0.12.0 -- Policy proposals
export {
  PolicyProposalEngine,
  type PolicyProposal,
  type BlockPatternEvent,
  type ProposalType,
  type ProposalStatus,
} from "./policy_proposals";

// v0.13.0 -- Federation
export {
  FederationClient,
  type GlobalPrior,
  type FederationConfig,
} from "./federation";

// v0.15.0-v0.17.0 -- New security surfaces
export {
  ContextDirectoryGuard,
  isSharedContextPath,
  scoreContextContent,
  type ContextGuardResult,
  OutboundSecretGuard,
  containsSecret,
  type OutboundScanResult,
  HoneypotManager,
  type HoneypotResult,
  OverrideManager,
  type OverrideChallenge,
  type OverrideResult,
  SourceReputationGraph,
  type SourceRecord,
  type SourceRisk,
  type ReputationLevel,
} from "./security_surfaces";

import { AiglosConfig, SessionArtifact, SubprocScanResult } from "./types";
import { patchGlobalFetch } from "./http";
import { patchChildProcess, inspectCommand } from "./subprocess";
import { Session } from "./session";
import { BaselineEngine } from "./behavioral_baseline";
import { PolicyProposalEngine } from "./policy_proposals";
import { FederationClient } from "./federation";
import {
  HoneypotManager, OverrideManager, SourceReputationGraph,
  OutboundSecretGuard, ContextDirectoryGuard,
  type OverrideChallenge, type OverrideResult,
} from "./security_surfaces";

let _session:    Session | null              = null;
let _baseline:   BaselineEngine | null       = null;
let _proposals:  PolicyProposalEngine | null = null;
let _honeypot:   HoneypotManager | null      = null;
let _overrides:  OverrideManager | null      = null;
let _reputation: SourceReputationGraph | null = null;
let _outbound:   OutboundSecretGuard | null  = null;
let _ctxGuard:   ContextDirectoryGuard | null = null;
let _federation: FederationClient | null     = null;

export interface AiglosFullConfig extends AiglosConfig {
  enableBehavioralBaseline?:  boolean;
  enablePolicyProposals?:     boolean;
  enableHoneypot?:            boolean;
  honeypotCustomNames?:       string[];
  enableSourceReputation?:    boolean;
  enableFederation?:          boolean;
  federationApiKey?:          string;
  federationEndpoint?:        string;
}

export function attach(config: AiglosFullConfig = {}): Session {
  const {
    agentName               = "aiglos",
    policy                  = "enterprise",
    interceptHttp           = false,
    allowHttp               = [],
    interceptSubprocess     = false,
    subprocessTier3Mode     = "warn",
    sessionId,
    enableBehavioralBaseline = false,
    enablePolicyProposals    = false,
    enableHoneypot           = false,
    honeypotCustomNames      = [],
    enableSourceReputation   = false,
    enableFederation         = false,
    federationApiKey         = "",
    federationEndpoint,
  } = config;

  _session = new Session({ agentName, policy, sessionId });

  if (interceptHttp) {
    patchGlobalFetch({
      allowHttp, policy,
      onBlock: r => _session?.recordHttpEvent(r),
      onWarn:  r => _session?.recordHttpEvent(r),
    });
  }

  if (interceptSubprocess) {
    patchChildProcess({
      tier3Mode: subprocessTier3Mode,
      onBlock: r => _session?.recordSubprocEvent(r),
      onWarn:  r => _session?.recordSubprocEvent(r),
    });
  }

  if (enableBehavioralBaseline)  _baseline   = new BaselineEngine(agentName);
  if (enablePolicyProposals)     _proposals  = new PolicyProposalEngine();
  if (enableHoneypot) {
    _honeypot  = new HoneypotManager(honeypotCustomNames);
    _overrides = new OverrideManager();
  }
  if (enableSourceReputation) {
    _reputation = new SourceReputationGraph();
    _outbound   = new OutboundSecretGuard(policy === "enterprise" ? "block" : "warn");
    _ctxGuard   = new ContextDirectoryGuard(policy === "enterprise" ? "block" : "warn");
  }
  if (enableFederation && federationApiKey) {
    _federation = new FederationClient({ apiKey: federationApiKey, endpoint: federationEndpoint });
    _federation.pullPrior().catch(() => null);
  }

  console.info(
    `[Aiglos v${VERSION}] Attached -- agent=${agentName} policy=${policy} ` +
    `baseline=${enableBehavioralBaseline} honeypot=${enableHoneypot} ` +
    `reputation=${enableSourceReputation} federation=${enableFederation}`
  );

  return _session;
}

export function beforeToolCall(
  toolName: string, args: Record<string, unknown>
): { verdict: string; ruleId: string | null; reason: string } {
  if (_honeypot) {
    const hp = _honeypot.checkToolCall(toolName, args);
    if (hp.triggered) return { verdict: "BLOCK", ruleId: "T43",
      reason: `CRITICAL: Honeypot file accessed -- '${hp.honeypotName}'` };
  }
  if (_ctxGuard) {
    const ctx = _ctxGuard.checkToolCall(toolName, args);
    if (ctx && ctx.verdict !== "ALLOW") return { verdict: ctx.verdict, ruleId: "T40",
      reason: `Shared context write blocked: score=${ctx.score.toFixed(2)}` };
  }
  if (_reputation) {
    const url = String(args.url ?? args.endpoint ?? args.source_url ?? "");
    if (url) {
      const risk = _reputation.getRisk(url);
      if (risk.level === "BLOCKED") return { verdict: "BLOCK", ruleId: "T27",
        reason: `Source blocked by reputation: ${risk.evidenceSummary}` };
    }
  }
  return { verdict: "ALLOW", ruleId: null, reason: "" };
}

export function afterToolCall(toolName: string, output: unknown, sourceUrl?: string): void {
  if (_reputation && sourceUrl) {
    const content = typeof output === "string" ? output : JSON.stringify(output);
    const score   = _quickScore(content);
    if (score >= 0.25) _reputation.recordEvent(sourceUrl, toolName, score, "WARN");
  }
}

export function beforeSend(content: string): { blocked: boolean; pattern: string | null; score: number } {
  if (!_outbound) return { blocked: false, pattern: null, score: 0 };
  const r = _outbound.scan(content);
  return { blocked: r.verdict === "BLOCK", pattern: r.pattern, score: r.score };
}

export function requestOverride(ruleId: string, toolName: string, reason = ""): OverrideChallenge | null {
  if (!_overrides) _overrides = new OverrideManager();
  return _overrides.request(ruleId, toolName, reason);
}

export function confirmOverride(challengeId: string, code: string): OverrideResult {
  if (!_overrides) return { approved: false, challengeId, error: "No override manager." };
  return _overrides.confirm(challengeId, code);
}

export function check(cmd: string): SubprocScanResult { return inspectCommand(cmd, { mode: "block" }); }

export function close(): SessionArtifact {
  if (!_session) throw new Error("[Aiglos] No active session. Call attach() first.");
  const artifact = _session.close();
  _session = null;
  return artifact;
}

export function status() {
  return { version: VERSION, sessionActive: _session !== null,
           agentName: _session?.agentName ?? null,
           baselineEnabled: _baseline !== null, honeypotEnabled: _honeypot !== null,
           federationEnabled: _federation !== null, reputationEnabled: _reputation !== null };
}

function _quickScore(text: string): number {
  const lower = text.toLowerCase();
  const phrases = ["ignore previous instructions","disregard your","you are now","bypass security"];
  let score = 0;
  for (const p of phrases) if (lower.includes(p)) score += 0.35;
  return Math.min(score, 1.0);
}

export const VERSION = "0.17.0";
export default { attach, beforeToolCall, afterToolCall, beforeSend, requestOverride, confirmOverride, check, close, status, VERSION };
