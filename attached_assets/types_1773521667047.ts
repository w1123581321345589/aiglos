/**
 * aiglos/types.ts — core type definitions
 */

export type Verdict  = "ALLOW" | "WARN" | "BLOCK" | "PAUSE";
export type Tier     = 1 | 2 | 3;
export type Surface  = "mcp" | "http" | "subprocess";
export type Policy   = "permissive" | "enterprise" | "strict" | "federal";
export type SemanticRisk = "LOW" | "MEDIUM" | "HIGH";

export interface AiglosConfig {
  agentName?:             string;
  policy?:                Policy;
  logPath?:               string;
  interceptHttp?:         boolean;
  allowHttp?:             string[];
  interceptSubprocess?:   boolean;
  subprocessTier3Mode?:   "block" | "pause" | "warn";
  tier3ApprovalWebhook?:  string;
  enableMultiAgent?:      boolean;
  guardAgentDefs?:        boolean;
  sessionId?:             string;
  enableAdaptive?:        boolean;
  adaptiveDbPath?:        string;
}

export interface ScanResult {
  verdict:    Verdict;
  ruleId:     string;
  ruleName:   string;
  reason:     string;
  latencyMs:  number;
  matched?:   string;
}

export interface HttpScanResult extends ScanResult {
  url:        string;
  method:     string;
  allowListed: boolean;
  timestamp:  number;
}

export interface SubprocScanResult extends ScanResult {
  tier:       Tier;
  cmd:        string;
  timestamp:  number;
}

export interface AgentDefViolation {
  path:          string;
  violationType: "MODIFIED" | "ADDED" | "DELETED";
  originalHash:  string;
  currentHash:   string;
  detectedAt:    number;
  ruleId:        "T36_AGENTDEF";
  threatFamily:  string;
  semanticScore: number;
  semanticRisk:  SemanticRisk;
}

export interface SpawnEvent {
  eventType:        "AGENT_SPAWN";
  parentSessionId:  string;
  childSessionId:   string;
  agentName:        string;
  cmd:              string;
  spawnedAt:        number;
  policyPropagated: boolean;
  inheritedPolicy?: SessionPolicy | null;
  ruleId:           "T38";
  ruleName:         "AGENT_SPAWN";
}

export interface SessionPolicy {
  derivedFrom:           string;
  derivedAt:             number;
  evidenceSessions:      number;
  inheritedAllowHttp:    string[];
  tierOverrides:         Record<string, string>;
  suppressedRules:       string[];
  approvedAgentdefPaths: string[];
}

export interface SessionArtifact {
  sessionId?:            string;
  agentName:             string;
  aiglosVersion:         string;
  totalEvents:           number;
  blockedEvents:         number;
  httpEvents:            HttpScanResult[];
  subprocEvents:         SubprocScanResult[];
  agentdefViolations:    AgentDefViolation[];
  agentdefViolationCount: number;
  multiAgent:            MultiAgentTree;
  sessionIdentity:       SessionIdentityHeader;
}

export interface SessionIdentityHeader {
  sessionId:   string;
  agentName:   string;
  publicToken: string;
  createdAt:   number;
  eventCount:  number;
}

export interface MultiAgentTree {
  rootSessionId: string;
  rootAgentName: string;
  createdAt:     number;
  childCount:    number;
  spawns:        SpawnEvent[];
  children:      Record<string, ChildSession>;
}

export interface ChildSession {
  sessionId:  string;
  agentName:  string;
  parentId:   string;
  spawnedAt:  number;
  closedAt?:  number;
  eventCount: number;
  events:     ScanResult[];
}

export interface CampaignResult {
  patternId:      string;
  description:    string;
  sessionId:      string;
  confidence:     number;
  risk:           SemanticRisk;
  evidenceCount:  number;
  evidence:       ScanResult[];
  recommendation: string;
  detectedAt:     number;
  ruleId:         "T06";
  ruleName:       "GOAL_DRIFT";
  threatFamily:   "T06_CAMPAIGN";
}

export interface AiglosStatus {
  version:              string;
  httpLayerActive:      boolean;
  subprocessLayerActive: boolean;
  agentDefGuardActive:  boolean;
  multiAgentActive:     boolean;
  sessionIdentityActive: boolean;
  adaptiveActive:       boolean;
}

export class AiglosBlockedError extends Error {
  constructor(
    public readonly result: HttpScanResult | SubprocScanResult,
  ) {
    super(`[Aiglos] ${result.ruleId} ${result.ruleName}: ${result.reason}`);
    this.name = "AiglosBlockedError";
  }
}
