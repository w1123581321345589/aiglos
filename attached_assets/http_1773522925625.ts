/**
 * aiglos/http.ts — HTTP/API interception layer
 *
 * Ports Python http_intercept.py to TypeScript.
 * Works with fetch(), node-fetch, axios, and any http client
 * that accepts a custom fetch implementation or middleware.
 *
 * Usage (fetch wrapper):
 *   import { createSecureFetch } from "aiglos";
 *   const fetch = createSecureFetch({ allowHttp: ["api.openai.com"] });
 *
 * Usage (axios interceptor):
 *   import { createAxiosInterceptor } from "aiglos/http";
 *   createAxiosInterceptor(axiosInstance, { policy: "enterprise" });
 */

import { HttpScanResult, Verdict } from "./types";

// ── Threat patterns ────────────────────────────────────────────────────────

const T25_SSRF = /169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|::1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+/i;

const T22_RECON = /shodan\.io|censys\.io|greynoise\.io|hunter\.io|intelx\.io|haveibeenpwned\.com|ipinfo\.io\/\d/i;

const T20_PII = /"ssn"\s*:|"social_security|"credit_card|"card_number|"cvv"\s*:|"date_of_birth|"dob"\s*:|"passport_number/i;

const T19_CRED_HARVEST_BODY = /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|"password"\s*:\s*"[^"]{8,}"|"secret"\s*:\s*"[^"]{8,}"|"api_key"\s*:\s*"[^"]{8,}"|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48}/i;

// T37 FIN_EXEC
const T37_FIN_HOSTS_HARD = /api\.stripe\.com\/(v1\/charges|v1\/payment_intents|v1\/transfers|v1\/payouts)|api-m\.paypal\.com\/v[12]\/payments|connect\.squareup\.com\/v2\/payments|payments\.braintree-api\.com|api\.adyen\.com\/.*payment|api\.coinbase\.com\/v2\/transactions|api\.binance\.com\/api\/v3\/order|api\.kraken\.com\/.*\/AddOrder|api\.dwolla\.com\/transfers|api\.plaid\.com\/transfer/i;

const T37_FIN_HOSTS_RPC = /mainnet\.infura\.io|polygon-mainnet\.infura\.io|eth-mainnet\.alchemyapi\.io|arb-mainnet\.g\.alchemy\.com/i;

const T37_FIN_BODY_EXEC = /eth_sendTransaction|eth_sendRawTransaction|personal_sign.*0x/i;

const T34_ANALYTICS = /segment\.io\/v1\/(track|identify|group)|mixpanel\.com\/track|amplitude\.com\/httpapi|heap\.io\/api\/track|fullstory\.com\/api/i;

const T35_MODEL_EXFIL = /huggingface\.co\/api\/.*upload|storage\.googleapis\.com.*\.safetensors|s3\.amazonaws\.com.*model.*weights|roboflow\.com\/.*\/upload/i;

const T36_SUPPLY_CHAIN = /upload\.pypi\.org|registry\.npmjs\.org|hub\.docker\.com\/v2.*push|ghcr\.io.*push/i;

const EXFIL_STAGING = /ngrok\.io|ngrok\.app|requestbin\.com|webhook\.site|pipedream\.net|beeceptor\.com|hookdeck\.com|\.xyz\/|\.top\/|\.tk\//i;

// ── Allow-list matcher ─────────────────────────────────────────────────────

export function hostIsAllowed(host: string, allowList: string[]): boolean {
  const h = host.toLowerCase().replace(/\/$/, "");
  return allowList.some(pattern => {
    const p = pattern.toLowerCase();
    if (p.startsWith("*.")) {
      return h.endsWith(p.slice(1)) || h === p.slice(2);
    }
    return h === p || h.endsWith("." + p);
  });
}

// ── Core inspector ─────────────────────────────────────────────────────────

export interface InspectHttpOptions {
  method:    string;
  url:       string;
  body?:     string | null;
  headers?:  Record<string, string>;
  allowList?: string[];
  mode?:     "block" | "warn" | "audit";
}

export function inspectRequest(opts: InspectHttpOptions): HttpScanResult {
  const { method, url, body = null, allowList = [], mode = "block" } = opts;
  const t0    = performance.now();
  const upper = method.toUpperCase();
  const bodyStr = body ?? "";

  let urlObj: URL;
  try {
    urlObj = new URL(url);
  } catch {
    return _allow(url, method, false, performance.now() - t0);
  }

  const host    = urlObj.hostname;
  const allowed = hostIsAllowed(host, allowList);

  const _result = (
    ruleId: string,
    ruleName: string,
    reason: string,
    matched = "",
  ): HttpScanResult => {
    const verdict: Verdict = mode === "audit" ? "WARN" : "BLOCK";
    return {
      verdict, ruleId, ruleName, reason,
      url, method, allowListed: allowed,
      latencyMs: performance.now() - t0,
      timestamp: Date.now() / 1000,
      matched,
    };
  };

  // T25: SSRF — always block regardless of allow-list
  if (T25_SSRF.test(url)) {
    return _result("T25", "SSRF", `SSRF: request to internal/metadata endpoint: ${host}`);
  }

  // T22: Recon
  if (!allowed && T22_RECON.test(url)) {
    return _result("T22", "RECON", `OSINT/recon endpoint: ${host}`);
  }

  // T19: Credential harvest in body
  if (!allowed && bodyStr) {
    const m = T19_CRED_HARVEST_BODY.exec(bodyStr);
    if (m) {
      return _result("T19", "CRED_HARVEST", `Credential pattern in request body: ${m[0].slice(0, 40)}`);
    }
  }

  // T20: PII exfil
  if (!allowed && T20_PII.test(bodyStr)) {
    return _result("T20", "DATA_EXFIL", `PII pattern detected in request body to ${host}`);
  }

  // T34: Analytics with raw data
  if (T34_ANALYTICS.test(url) && bodyStr.length > 512) {
    return _result("T34", "DATA_AGENT", `Analytics API call with large body: ${host}`);
  }

  // T35: Model exfil
  if (T35_MODEL_EXFIL.test(url) && ["POST", "PUT"].includes(upper)) {
    return _result("T35", "MODEL_EXFIL", `Model/training data transfer to: ${url.slice(0, 80)}`);
  }

  // T36: Supply chain — package publish
  if (T36_SUPPLY_CHAIN.test(url) && ["POST", "PUT"].includes(upper)) {
    return _result("T36", "SUPPLY_CHAIN", `Package publish to registry: ${host}`);
  }

  // T37: Financial execution
  if (!allowed && ["POST", "PUT", "PATCH"].includes(upper)) {
    const hardMatch = T37_FIN_HOSTS_HARD.exec(url);
    if (hardMatch) {
      return _result("T37", "FIN_EXEC",
        `Autonomous financial transaction blocked: '${hardMatch[0].slice(0, 80)}'. Add to allowHttp if authorized.`
      );
    }
    const rpcMatch = T37_FIN_HOSTS_RPC.exec(url);
    if (rpcMatch && bodyStr && T37_FIN_BODY_EXEC.test(bodyStr)) {
      return _result("T37", "FIN_EXEC",
        `Blockchain transaction execution blocked on '${rpcMatch[0]}'`
      );
    }
  }

  // Exfil staging
  if (EXFIL_STAGING.test(url)) {
    return _result("T19", "CRED_HARVEST", `Known exfil staging host: ${host}`);
  }

  return _allow(url, method, allowed, performance.now() - t0);
}

function _allow(url: string, method: string, allowListed: boolean, latencyMs: number): HttpScanResult {
  return {
    verdict: "ALLOW", ruleId: "none", ruleName: "none",
    reason: "", url, method, allowListed,
    latencyMs, timestamp: Date.now() / 1000,
  };
}

// ── Secure fetch wrapper ───────────────────────────────────────────────────

export interface SecureFetchOptions {
  allowHttp?: string[];
  policy?:    "permissive" | "enterprise" | "strict" | "federal";
  onBlock?:   (result: HttpScanResult) => void;
  onWarn?:    (result: HttpScanResult) => void;
}

type FetchFn = typeof globalThis.fetch;

/**
 * Creates a fetch wrapper that inspects every request before sending.
 *
 * @example
 * const fetch = createSecureFetch({ allowHttp: ["api.openai.com"] });
 * const resp = await fetch("https://api.openai.com/v1/chat/completions", { ... });
 */
export function createSecureFetch(opts: SecureFetchOptions = {}): FetchFn {
  const { allowHttp = [], policy = "enterprise", onBlock, onWarn } = opts;
  const mode = policy === "permissive" ? "warn" : "block";

  const originalFetch: FetchFn = globalThis.fetch;

  return async function secureFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url    = input instanceof URL ? input.href : input instanceof Request ? input.url : String(input);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    let body: string | null = null;
    if (init?.body) {
      try { body = typeof init.body === "string" ? init.body : JSON.stringify(init.body); }
      catch { /* ignore */ }
    }

    const result = inspectRequest({ method, url, body, allowList: allowHttp, mode });

    if (result.verdict === "BLOCK") {
      if (onBlock) onBlock(result);
      const { AiglosBlockedError } = await import("./types");
      throw new AiglosBlockedError(result);
    }
    if (result.verdict === "WARN") {
      if (onWarn) onWarn(result);
      console.warn(`[Aiglos] WARN ${result.ruleId}: ${result.reason}`);
    }

    return originalFetch(input, init);
  };
}

/**
 * Patches globalThis.fetch in place.
 * All subsequent fetch() calls in the process will be inspected.
 *
 * @example
 * import { patchGlobalFetch } from "aiglos/http";
 * patchGlobalFetch({ allowHttp: ["api.openai.com"] });
 */
export function patchGlobalFetch(opts: SecureFetchOptions = {}): void {
  (globalThis as any).fetch = createSecureFetch(opts);
}
