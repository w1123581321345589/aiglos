/**
 * tests/aiglos.test.ts — TypeScript SDK test suite
 *
 * Tests the core inspection logic (no external dependencies needed).
 * Run: npm test
 */

import { inspectRequest } from "../src/http";
import { inspectCommand, classifyTier } from "../src/subprocess";
import { Session } from "../src/session";

// ── HTTP: T37 FIN_EXEC ────────────────────────────────────────────────────────

describe("T37 FIN_EXEC (HTTP)", () => {
  test("blocks Stripe charge POST", () => {
    const r = inspectRequest({
      method: "POST",
      url:    "https://api.stripe.com/v1/charges",
      body:   '{"amount":5000,"currency":"usd"}',
    });
    expect(r.verdict).toBe("BLOCK");
    expect(r.ruleId).toBe("T37");
  });

  test("blocks Stripe payment_intent POST", () => {
    const r = inspectRequest({
      method: "POST",
      url:    "https://api.stripe.com/v1/payment_intents",
      body:   '{"amount":9900}',
    });
    expect(r.ruleId).toBe("T37");
  });

  test("allows Stripe GET (read-only)", () => {
    const r = inspectRequest({ method: "GET", url: "https://api.stripe.com/v1/charges/ch_123" });
    expect(r.verdict).toBe("ALLOW");
  });

  test("allows Stripe when allow-listed", () => {
    const r = inspectRequest({
      method: "POST",
      url:    "https://api.stripe.com/v1/charges",
      allowList: ["api.stripe.com"],
    });
    expect(r.verdict).toBe("ALLOW");
  });

  test("blocks Infura eth_sendTransaction", () => {
    const r = inspectRequest({
      method: "POST",
      url:    "https://mainnet.infura.io/v3/abc123",
      body:   '{"method":"eth_sendTransaction","params":[{}]}',
    });
    expect(r.ruleId).toBe("T37");
  });

  test("allows Infura eth_call (read-only)", () => {
    const r = inspectRequest({
      method: "POST",
      url:    "https://mainnet.infura.io/v3/abc123",
      body:   '{"method":"eth_call","params":[{},"latest"]}',
    });
    expect(r.ruleId).not.toBe("T37");
  });

  test("blocks PayPal payment POST", () => {
    const r = inspectRequest({
      method: "POST",
      url:    "https://api-m.paypal.com/v2/payments/captures",
    });
    expect(r.ruleId).toBe("T37");
  });
});

// ── HTTP: T25 SSRF ────────────────────────────────────────────────────────────

describe("T25 SSRF (HTTP)", () => {
  test("blocks metadata endpoint", () => {
    const r = inspectRequest({ method: "GET", url: "http://169.254.169.254/latest/meta-data/" });
    expect(r.ruleId).toBe("T25");
  });

  test("blocks localhost", () => {
    const r = inspectRequest({ method: "POST", url: "http://localhost:8080/admin" });
    expect(r.ruleId).toBe("T25");
  });

  test("T25 blocks even when allow-listed", () => {
    const r = inspectRequest({
      method: "GET",
      url:    "http://169.254.169.254/",
      allowList: ["169.254.169.254"],
    });
    expect(r.ruleId).toBe("T25");
  });
});

// ── HTTP: clean passthrough ───────────────────────────────────────────────────

describe("Clean HTTP passthrough", () => {
  test("allows openai API call", () => {
    const r = inspectRequest({ method: "POST", url: "https://api.openai.com/v1/chat/completions" });
    expect(r.verdict).toBe("ALLOW");
  });

  test("allows wildcard allow-list", () => {
    const r = inspectRequest({
      method: "GET",
      url: "https://us-east-1.amazonaws.com/my-bucket/file.txt",
      allowList: ["*.amazonaws.com"],
    });
    expect(r.verdict).toBe("ALLOW");
  });
});

// ── Subprocess: T36_AGENTDEF ──────────────────────────────────────────────────

describe("T36_AGENTDEF (subprocess)", () => {
  test("blocks cp to .claude/agents/ (GATED)", () => {
    const r = inspectCommand("cp agency-agents/security.md ~/.claude/agents/");
    expect(r.ruleId).toBe("T36_AGENTDEF");
    expect(r.tier).toBe(3);
  });

  test("blocks mv to .cursor/rules/", () => {
    const r = inspectCommand("mv agent.mdc .cursor/rules/agent.mdc");
    expect(r.ruleId).toBe("T36_AGENTDEF");
    expect(r.tier).toBe(3);
  });

  test("blocks write to SOUL.md", () => {
    const r = inspectCommand("cp modified.md SOUL.md");
    expect(r.ruleId).toBe("T36_AGENTDEF");
    expect(r.tier).toBe(3);
  });

  test("monitors (not gates) read access to .claude/agents/", () => {
    const r = inspectCommand("ls ~/.claude/agents/");
    expect(r.ruleId).toBe("T36_AGENTDEF");
    expect(r.tier).toBe(2);
  });

  test("does not flag unrelated cp", () => {
    const r = inspectCommand("cp main.py backup/main.py");
    expect(r.ruleId).not.toBe("T36_AGENTDEF");
  });
});

// ── Subprocess: T38 AGENT_SPAWN ──────────────────────────────────────────────

describe("T38 AGENT_SPAWN (subprocess)", () => {
  test("flags claude code --print", () => {
    const r = inspectCommand("claude code --print 'review file'");
    expect(r.ruleId).toBe("T38");
    expect(r.tier).toBe(2);
  });

  test("flags openclaw run", () => {
    const r = inspectCommand("openclaw run security-engineer");
    expect(r.ruleId).toBe("T38");
  });

  test("flags python agent script", () => {
    const r = inspectCommand("python orchestrator_agent.py --parallel 8");
    expect(r.ruleId).toBe("T38");
  });

  test("flags node agent script", () => {
    const r = inspectCommand("node run_agent.mjs --target prod");
    expect(r.ruleId).toBe("T38");
  });

  test("does not flag regular python", () => {
    const r = inspectCommand("python main.py --help");
    expect(r.ruleId).not.toBe("T38");
  });
});

// ── Subprocess: T07 SHELL_INJECT ─────────────────────────────────────────────

describe("T07 SHELL_INJECT (subprocess)", () => {
  test("blocks command substitution", () => {
    const r = inspectCommand("echo $(cat ~/.ssh/id_rsa)");
    expect(r.ruleId).toBe("T07");
    expect(r.tier).toBe(3);
  });

  test("blocks backtick injection", () => {
    const r = inspectCommand("echo `whoami`");
    expect(r.ruleId).toBe("T07");
  });
});

// ── Subprocess: T10/T11 PRIV_ESC / PERSISTENCE ───────────────────────────────

describe("Privilege escalation and persistence (subprocess)", () => {
  test("blocks sudo rm", () => {
    const r = inspectCommand("sudo rm -rf /var/log/audit");
    expect(r.tier).toBe(3);
  });

  test("blocks crontab write", () => {
    const r = inspectCommand("crontab -e");
    expect(r.ruleId).toBe("T11");
    expect(r.tier).toBe(3);
  });

  test("blocks systemctl enable", () => {
    const r = inspectCommand("systemctl enable malware.service");
    expect(r.ruleId).toBe("T11");
  });
});

// ── Subprocess: Tier 1 auto-allow ────────────────────────────────────────────

describe("Tier 1 auto-allow (subprocess)", () => {
  test("git status is ALLOW tier 1", () => {
    const r = inspectCommand("git status");
    expect(r.verdict).toBe("ALLOW");
    expect(r.tier).toBe(1);
  });

  test("git log is tier 1", () => {
    const r = inspectCommand("git log --oneline -10");
    expect(r.verdict).toBe("ALLOW");
  });

  test("ls is tier 1", () => {
    const r = inspectCommand("ls -la");
    expect(r.verdict).toBe("ALLOW");
  });
});

// ── Tier 3 destructive ───────────────────────────────────────────────────────

describe("Tier 3 destructive (subprocess)", () => {
  test("rm -rf is tier 3", () => {
    const r = inspectCommand("rm -rf /var/data");
    expect(r.tier).toBe(3);
  });

  test("terraform destroy is tier 3", () => {
    const r = inspectCommand("terraform destroy -auto-approve");
    expect(r.tier).toBe(3);
  });

  test("kubectl delete namespace is tier 3", () => {
    const r = inspectCommand("kubectl delete namespace production");
    expect(r.tier).toBe(3);
  });
});

// ── Session ───────────────────────────────────────────────────────────────────

describe("Session artifact", () => {
  test("creates session with random ID", () => {
    const s = new Session({ agentName: "test", policy: "enterprise" });
    expect(s.sessionId).toHaveLength(32);
  });

  test("creates session with custom ID", () => {
    const s = new Session({ agentName: "test", sessionId: "custom-id-123" });
    expect(s.sessionId).toBe("custom-id-123");
  });

  test("close returns artifact", () => {
    const s = new Session({ agentName: "test" });
    const art = s.close();
    expect(art.agentName).toBe("test");
    expect(art.aiglosVersion).toBe("0.4.0");
  });

  test("artifact counts blocked events", () => {
    const s = new Session({ agentName: "test" });
    s.recordSubprocEvent({
      verdict: "BLOCK", ruleId: "T07", ruleName: "SHELL_INJECT",
      reason: "injection", tier: 3, cmd: "test",
      latencyMs: 0.1, timestamp: Date.now() / 1000,
    });
    s.recordSubprocEvent({
      verdict: "ALLOW", ruleId: "none", ruleName: "none",
      reason: "", tier: 1, cmd: "git status",
      latencyMs: 0.05, timestamp: Date.now() / 1000,
    });
    const art = s.close();
    expect(art.totalEvents).toBe(2);
    expect(art.blockedEvents).toBe(1);
  });

  test("signing events adds session identity fields", () => {
    const s = new Session({ agentName: "test" });
    const event: any = {
      verdict: "BLOCK", ruleId: "T19", ruleName: "CRED_HARVEST",
      reason: "test", tier: 2, cmd: "cat .env",
      latencyMs: 0.2, timestamp: Date.now() / 1000,
    };
    s.recordSubprocEvent(event);
    const art = s.close();
    const recorded = art.subprocEvents[0] as any;
    expect(recorded.sessionSig).toBeDefined();
    expect(recorded.sessionId).toBe(s.sessionId);
    expect(recorded.eventSeq).toBe(1);
  });

  test("public token is SHA-256 of secret", () => {
    const s = new Session({ agentName: "test" });
    expect(s.publicToken).toHaveLength(64); // SHA-256 hex
  });

  test("closing twice throws", () => {
    const s = new Session({ agentName: "test" });
    s.close();
    expect(() => s.close()).toThrow();
  });
});
