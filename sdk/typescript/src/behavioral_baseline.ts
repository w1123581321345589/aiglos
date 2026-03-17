/**
 * aiglos/behavioral_baseline.ts
 *
 * Behavioral baseline engine for TypeScript agents -- v0.11.0 port.
 *
 * Learns what normal looks like for a specific deployment.
 * Flags sessions that deviate from the learned baseline.
 * Gets more accurate with every session.
 */

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

export interface BaselineScore {
  composite:      number;        // 0.0–1.0 composite anomaly score
  rateComponent:  number;        // event rate z-score component
  surfaceComponent: number;      // surface mix chi-squared component
  rulesComponent: number;        // rule frequency KL-divergence component
  risk:           RiskLevel;
  baselineReady:  boolean;       // false until MIN_SESSIONS accumulated
  sessionsObserved: number;
  narrative:      string;
}

export interface SessionStats {
  sessionId:     string;
  agentName:     string;
  totalEvents:   number;
  mcpEvents:     number;
  httpEvents:    number;
  subprocEvents: number;
  blockedEvents: number;
  warnedEvents:  number;
  rulesCounts:   Record<string, number>;
  durationMs:    number;
}

const MIN_SESSIONS       = 5;
const LOW_THRESHOLD      = 0.25;
const HIGH_THRESHOLD     = 0.55;
const RATE_WEIGHT        = 0.40;
const SURFACE_WEIGHT     = 0.30;
const RULES_WEIGHT       = 0.30;

export class BaselineEngine {
  private agentName: string;
  private sessions:  SessionStats[] = [];

  constructor(agentName: string) {
    this.agentName = agentName;
  }

  record(stats: SessionStats): void {
    this.sessions.push(stats);
    // Keep rolling window of last 100 sessions
    if (this.sessions.length > 100) {
      this.sessions = this.sessions.slice(-100);
    }
  }

  score(current: SessionStats): BaselineScore {
    const n = this.sessions.length;
    const ready = n >= MIN_SESSIONS;

    if (!ready) {
      return {
        composite: 0.0, rateComponent: 0.0,
        surfaceComponent: 0.0, rulesComponent: 0.0,
        risk: "LOW", baselineReady: false,
        sessionsObserved: n,
        narrative: `Baseline building -- ${n}/${MIN_SESSIONS} sessions observed.`,
      };
    }

    const rateComp    = this._rateScore(current);
    const surfaceComp = this._surfaceScore(current);
    const rulesComp   = this._rulesScore(current);

    const composite = (
      rateComp    * RATE_WEIGHT +
      surfaceComp * SURFACE_WEIGHT +
      rulesComp   * RULES_WEIGHT
    );

    const risk: RiskLevel =
      composite >= HIGH_THRESHOLD ? "HIGH" :
      composite >= LOW_THRESHOLD  ? "MEDIUM" : "LOW";

    return {
      composite: Math.round(composite * 10000) / 10000,
      rateComponent: Math.round(rateComp * 10000) / 10000,
      surfaceComponent: Math.round(surfaceComp * 10000) / 10000,
      rulesComponent: Math.round(rulesComp * 10000) / 10000,
      risk,
      baselineReady: true,
      sessionsObserved: n,
      narrative: this._narrative(composite, risk, current),
    };
  }

  private _rates(): number[] {
    return this.sessions.map(s => s.durationMs > 0
      ? s.totalEvents / (s.durationMs / 1000) : 0);
  }

  private _rateScore(current: SessionStats): number {
    const rates = this._rates();
    const mean  = rates.reduce((a, b) => a + b, 0) / rates.length;
    const std   = Math.sqrt(rates.map(r => (r - mean) ** 2)
                    .reduce((a, b) => a + b, 0) / rates.length) || 1;
    const currentRate = current.durationMs > 0
      ? current.totalEvents / (current.durationMs / 1000) : 0;
    const z = Math.abs((currentRate - mean) / std);
    return Math.min(z / 4.0, 1.0);  // normalize: z=4 → score=1.0
  }

  private _surfaceScore(current: SessionStats): number {
    // Chi-squared distance between current surface mix and baseline mean
    const surfaces = ["mcpEvents", "httpEvents", "subprocEvents"] as const;
    let chi2 = 0;
    for (const surf of surfaces) {
      const baseline = this.sessions.map(s => s[surf]);
      const mean = baseline.reduce((a, b) => a + b, 0) / baseline.length || 1;
      chi2 += ((current[surf] - mean) ** 2) / mean;
    }
    return Math.min(chi2 / 20.0, 1.0);  // normalize
  }

  private _rulesScore(current: SessionStats): number {
    // Symmetric KL-divergence on rule frequency distributions
    const allRules = new Set<string>();
    this.sessions.forEach(s =>
      Object.keys(s.rulesCounts).forEach(r => allRules.add(r)));
    Object.keys(current.rulesCounts).forEach(r => allRules.add(r));

    const baselineFreq: Record<string, number> = {};
    for (const rule of allRules) {
      const vals = this.sessions.map(s => s.rulesCounts[rule] ?? 0);
      baselineFreq[rule] = vals.reduce((a, b) => a + b, 0) / vals.length + 1e-9;
    }
    const baselineTotal = Object.values(baselineFreq).reduce((a, b) => a + b, 0);
    const currentTotal  = Object.values(current.rulesCounts).reduce((a, b) => a + b, 0) || 1;

    let kl = 0;
    for (const rule of allRules) {
      const p = (baselineFreq[rule] ?? 1e-9) / baselineTotal;
      const q = ((current.rulesCounts[rule] ?? 0) + 1e-9) / currentTotal;
      kl += p * Math.log(p / q) + q * Math.log(q / p);
    }
    return Math.min(kl / 4.0, 1.0);
  }

  private _narrative(composite: number, risk: RiskLevel, s: SessionStats): string {
    if (risk === "LOW")    return "Session behavior within normal baseline.";
    if (risk === "MEDIUM") return `Moderate baseline deviation (score=${composite.toFixed(2)}). Monitoring.`;
    return `HIGH baseline anomaly (score=${composite.toFixed(2)}). Session pattern significantly differs from learned behavior.`;
  }

  get sessionCount(): number { return this.sessions.length; }
}
