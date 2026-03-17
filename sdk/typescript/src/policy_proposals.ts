/**
 * aiglos/policy_proposals.ts
 *
 * Policy proposal engine for TypeScript agents -- v0.12.0 port.
 *
 * Replaces per-action webhook fatigue with evidence-backed policy decisions.
 * When a rule fires repeatedly, proposes adjusting the policy rather than
 * requiring manual approval for each individual action.
 */

export type ProposalType   = "LOWER_TIER" | "RAISE_THRESHOLD" | "ALLOW_LIST" | "SUPPRESS_PATTERN";
export type ProposalStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

export interface BlockPatternEvent {
  patternId:  string;
  agentName:  string;
  ruleId:     string;
  toolName:   string;
  args:       string;
  tier:       number;
  occurredAt: number;
}

export interface PolicyProposal {
  proposalId:    string;
  proposalType:  ProposalType;
  ruleId:        string;
  agentName:     string;
  confidence:    number;
  blockCount:    number;
  consistency:   number;
  evidenceDays:  number;
  status:        ProposalStatus;
  createdAt:     number;
  expiresAt:     number;
  approvedBy?:   string;
  approvedAt?:   number;
  rationale:     string;
}

// Thresholds matching Python implementation
const TIER_THRESHOLDS = {
  LOWER_TIER:       { minBlocks: 5,  minConf: 0.60 },
  RAISE_THRESHOLD:  { minBlocks: 8,  minConf: 0.70 },
  ALLOW_LIST:       { minBlocks: 10, minConf: 0.80 },
  SUPPRESS_PATTERN: { minBlocks: 15, minConf: 0.90 },
} as const;

const EXPIRY_DAYS  = 30;
const CONF_REP_W   = 0.40;
const CONF_CONS_W  = 0.40;
const CONF_BASE_W  = 0.20;

export class PolicyProposalEngine {
  private patterns:  Map<string, BlockPatternEvent[]> = new Map();
  private proposals: Map<string, PolicyProposal>      = new Map();

  recordBlock(event: BlockPatternEvent): PolicyProposal | null {
    const key = `${event.agentName}::${event.ruleId}::${event.toolName}`;
    if (!this.patterns.has(key)) this.patterns.set(key, []);
    this.patterns.get(key)!.push(event);
    return this._maybePropose(key, event);
  }

  private _maybePropose(
    key: string, event: BlockPatternEvent
  ): PolicyProposal | null {
    const events = this.patterns.get(key)!;
    const n      = events.length;

    // Check for existing pending proposal
    for (const p of this.proposals.values()) {
      if (p.ruleId === event.ruleId && p.agentName === event.agentName
          && p.status === "PENDING") return null;
    }

    const proposalType = this._selectType(n);
    if (!proposalType) return null;

    const threshold = TIER_THRESHOLDS[proposalType];
    if (n < threshold.minBlocks) return null;

    const consistency = this._consistency(events);
    const confidence  = Math.min(
      CONF_REP_W  * Math.min(n / 20, 1.0) +
      CONF_CONS_W * consistency +
      CONF_BASE_W * 0.5,
      1.0
    );

    if (confidence < threshold.minConf) return null;

    const now     = Date.now() / 1000;
    const proposal: PolicyProposal = {
      proposalId:   `prop_${Math.random().toString(36).slice(2, 14)}`,
      proposalType,
      ruleId:       event.ruleId,
      agentName:    event.agentName,
      confidence:   Math.round(confidence * 10000) / 10000,
      blockCount:   n,
      consistency:  Math.round(consistency * 10000) / 10000,
      evidenceDays: this._evidenceDays(events),
      status:       "PENDING",
      createdAt:    now,
      expiresAt:    now + EXPIRY_DAYS * 86400,
      rationale:    this._rationale(proposalType, n, confidence, event),
    };

    this.proposals.set(proposal.proposalId, proposal);
    return proposal;
  }

  approve(proposalId: string, approvedBy = "user"): PolicyProposal | null {
    const p = this.proposals.get(proposalId);
    if (!p || p.status !== "PENDING") return null;
    p.status     = "APPROVED";
    p.approvedBy = approvedBy;
    p.approvedAt = Date.now() / 1000;
    return p;
  }

  reject(proposalId: string): PolicyProposal | null {
    const p = this.proposals.get(proposalId);
    if (!p || p.status !== "PENDING") return null;
    p.status = "REJECTED";
    return p;
  }

  pendingProposals(): PolicyProposal[] {
    const now = Date.now() / 1000;
    return [...this.proposals.values()]
      .filter(p => p.status === "PENDING" && p.expiresAt > now);
  }

  private _selectType(n: number): ProposalType | null {
    if (n >= TIER_THRESHOLDS.SUPPRESS_PATTERN.minBlocks) return "SUPPRESS_PATTERN";
    if (n >= TIER_THRESHOLDS.ALLOW_LIST.minBlocks)       return "ALLOW_LIST";
    if (n >= TIER_THRESHOLDS.RAISE_THRESHOLD.minBlocks)  return "RAISE_THRESHOLD";
    if (n >= TIER_THRESHOLDS.LOWER_TIER.minBlocks)       return "LOWER_TIER";
    return null;
  }

  private _consistency(events: BlockPatternEvent[]): number {
    if (events.length < 2) return 0.5;
    const tools = events.map(e => e.toolName);
    const mode  = tools.sort((a, b) =>
      tools.filter(t => t === b).length - tools.filter(t => t === a).length
    )[0];
    return tools.filter(t => t === mode).length / tools.length;
  }

  private _evidenceDays(events: BlockPatternEvent[]): number {
    if (events.length < 2) return 0;
    const span = events[events.length - 1].occurredAt - events[0].occurredAt;
    return Math.round(span / 86400);
  }

  private _rationale(
    type: ProposalType, n: number, conf: number, e: BlockPatternEvent
  ): string {
    return `Rule ${e.ruleId} has fired ${n} times for ${e.toolName} ` +
           `(confidence=${(conf * 100).toFixed(0)}%). ` +
           `Proposal: ${type.replace(/_/g, " ").toLowerCase()}.`;
  }
}
