/**
 * aiglos/federation.ts
 *
 * Federation client for TypeScript agents -- v0.13.0 port.
 *
 * Pushes anonymized transition counts to the global prior.
 * Pulls the global prior to warm-start intent prediction.
 * Laplace noise applied before any data leaves the deployment.
 */

export interface GlobalPrior {
  priorVersion:          string;
  trainedOnNDeployments: number;
  trainedAt:             number;
  transitions:           Record<string, Record<string, number>>;
  vocab:                 string[];
}

export interface FederationConfig {
  apiKey:    string;
  endpoint?: string;
  epsilon?:  number;    // Laplace noise parameter, default 0.1
  timeoutMs?: number;
}

const DEFAULT_ENDPOINT = "https://intel.aiglos.dev";
const DEFAULT_EPSILON  = 0.1;
const DEFAULT_TIMEOUT  = 8000;
const RATE_LIMIT_MS    = 600;

export class FederationClient {
  private apiKey:    string;
  private endpoint:  string;
  private epsilon:   number;
  private timeoutMs: number;
  private _lastPull: number = 0;
  private _lastPush: number = 0;
  private _cachedPrior: GlobalPrior | null = null;

  constructor(config: FederationConfig) {
    this.apiKey    = config.apiKey;
    this.endpoint  = (config.endpoint ?? DEFAULT_ENDPOINT).replace(/\/$/, "");
    this.epsilon   = config.epsilon   ?? DEFAULT_EPSILON;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT;
  }

  /** Pull the global prior from the federation server. */
  async pullPrior(): Promise<GlobalPrior | null> {
    try {
      const url      = `${this.endpoint}/v1/prior`;
      const response = await this._fetch(url, { method: "GET" });

      if (!response.ok) return null;
      const data = await response.json() as {
        prior_version: string;
        trained_on_n_deployments: number;
        trained_at: number;
        transitions: Record<string, Record<string, number>>;
        vocab: string[];
      };

      this._cachedPrior = {
        priorVersion:          data.prior_version,
        trainedOnNDeployments: data.trained_on_n_deployments,
        trainedAt:             data.trained_at,
        transitions:           data.transitions,
        vocab:                 data.vocab,
      };
      this._lastPull = Date.now();
      return this._cachedPrior;
    } catch {
      return null;   // graceful degradation -- never block the agent path
    }
  }

  /** Push anonymized transition counts to the federation server. */
  async pushTransitions(
    rawCounts: Record<string, Record<string, number>>,
    approxSessions: number,
  ): Promise<boolean> {
    // Rate limit
    if (Date.now() - this._lastPush < RATE_LIMIT_MS) return false;

    try {
      const noised = this._applyLaplaceNoise(rawCounts);
      const vocab  = new Set<string>();
      for (const [from, nexts] of Object.entries(noised)) {
        vocab.add(from);
        Object.keys(nexts).forEach(k => vocab.add(k));
      }

      const body = JSON.stringify({
        transitions:     noised,
        approx_sessions: Math.max(0, approxSessions + this._laplace(1 / this.epsilon)),
        vocab_size:      vocab.size,
        epsilon:         this.epsilon,
        aiglos_version:  "0.17.0",
      });

      const response = await this._fetch(`${this.endpoint}/v1/contribute`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });

      this._lastPush = Date.now();
      return response.ok;
    } catch {
      return false;
    }
  }

  get cachedPrior(): GlobalPrior | null { return this._cachedPrior; }

  /** Warm-start a local predictor from the global prior. */
  mergeIntoPrior(
    localCounts: Record<string, Record<string, number>>,
    localSessions: number,
    globalPrior?: GlobalPrior,
  ): Record<string, Record<string, number>> {
    const prior = globalPrior ?? this._cachedPrior;
    if (!prior) return localCounts;

    // Local weight schedule: 20% at 0 sessions → 80% at 100+ sessions
    const localWeight  = 0.20 + 0.60 * Math.min(localSessions / 100, 1.0);
    const globalWeight = 1.0 - localWeight;

    const merged: Record<string, Record<string, number>> = {};
    const allFrom = new Set([
      ...Object.keys(localCounts),
      ...Object.keys(prior.transitions),
    ]);

    for (const from of allFrom) {
      merged[from] = {};
      const local  = localCounts[from]       ?? {};
      const global = prior.transitions[from] ?? {};
      const allTo  = new Set([...Object.keys(local), ...Object.keys(global)]);

      for (const to of allTo) {
        merged[from][to] =
          (local[to]  ?? 0) * localWeight +
          (global[to] ?? 0) * globalWeight;
      }
    }

    return merged;
  }

  private _applyLaplaceNoise(
    counts: Record<string, Record<string, number>>
  ): Record<string, Record<string, number>> {
    const noised: Record<string, Record<string, number>> = {};
    for (const [from, nexts] of Object.entries(counts)) {
      noised[from] = {};
      for (const [to, count] of Object.entries(nexts)) {
        const noise = this._laplace(1 / this.epsilon);
        const val   = Math.max(0, count + noise);
        if (val > 0.01) noised[from][to] = Math.round(val * 10000) / 10000;
      }
    }
    return noised;
  }

  private _laplace(scale: number): number {
    // Inverse CDF method
    const u = Math.random() - 0.5;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }

  private async _fetch(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(url, {
        ...init,
        signal:  controller.signal,
        headers: {
          ...(init.headers ?? {}),
          "Authorization": `Bearer ${this.apiKey}`,
          "User-Agent":    "aiglos-ts/0.17.0",
        },
      });
    } finally {
      clearTimeout(timer);
    }
  }
}
