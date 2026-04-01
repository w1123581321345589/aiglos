/**
 * aiglos/session.ts — session artifact assembly and identity chain
 */

import * as crypto from "crypto";
import {
  AiglosConfig, SessionArtifact, SessionIdentityHeader,
  HttpScanResult, SubprocScanResult,
} from "./types";

export class Session {
  readonly sessionId:  string;
  readonly agentName:  string;
  readonly policy:     string;
  readonly createdAt:  number;

  private _httpEvents:    HttpScanResult[]    = [];
  private _subprocEvents: SubprocScanResult[] = [];
  private _secret:        Buffer;
  private _eventCount:    number              = 0;
  private _closed         = false;

  constructor(config: Pick<AiglosConfig, "agentName" | "policy" | "sessionId">) {
    this.agentName = config.agentName ?? "aiglos";
    this.policy    = config.policy    ?? "enterprise";
    this.sessionId = config.sessionId ?? crypto.randomBytes(16).toString("hex");
    this.createdAt = Date.now() / 1000;
    this._secret   = crypto.randomBytes(32);
  }

  // ── Event recording ──────────────────────────────────────────────────────

  recordHttpEvent(event: HttpScanResult): void {
    this._httpEvents.push(this._signEvent(event));
  }

  recordSubprocEvent(event: SubprocScanResult): void {
    this._subprocEvents.push(this._signEvent(event));
  }

  // ── HMAC signing (session identity chain) ────────────────────────────────

  private _signEvent<T extends object>(event: T): T & { sessionSig: string; sessionId: string; eventSeq: number } {
    this._eventCount++;
    const payload = JSON.stringify({
      session_id:  this.sessionId,
      event_count: this._eventCount,
      rule_id:     (event as any).ruleId ?? "",
      verdict:     (event as any).verdict ?? "",
      cmd:         (event as any).cmd ?? (event as any).url ?? "",
      ts:          (event as any).timestamp ?? Date.now() / 1000,
    });
    const sig = crypto.createHmac("sha256", this._secret).update(payload).digest("hex");
    return { ...event, sessionSig: sig, sessionId: this.sessionId, eventSeq: this._eventCount };
  }

  get publicToken(): string {
    return crypto.createHash("sha256").update(this._secret).digest("hex");
  }

  identityHeader(): SessionIdentityHeader {
    return {
      sessionId:   this.sessionId,
      agentName:   this.agentName,
      publicToken: this.publicToken,
      createdAt:   this.createdAt,
      eventCount:  this._eventCount,
    };
  }

  // ── Artifact assembly ────────────────────────────────────────────────────

  close(): SessionArtifact {
    if (this._closed) {
      throw new Error("[Aiglos] Session already closed.");
    }
    this._closed = true;
    return {
      sessionId:              this.sessionId,
      agentName:              this.agentName,
      aiglosVersion:          "0.4.0",
      totalEvents:            this._httpEvents.length + this._subprocEvents.length,
      blockedEvents:          [
        ...this._httpEvents,
        ...this._subprocEvents,
      ].filter(e => e.verdict === "BLOCK").length,
      httpEvents:             this._httpEvents,
      subprocEvents:          this._subprocEvents,
      agentdefViolations:     [],
      agentdefViolationCount: 0,
      multiAgent:             {
        rootSessionId: this.sessionId,
        rootAgentName: this.agentName,
        createdAt:     this.createdAt,
        childCount:    0,
        spawns:        [],
        children:      {},
      },
      sessionIdentity: this.identityHeader(),
    };
  }
}
