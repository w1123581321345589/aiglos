/**
 * aiglos/subprocess.ts — subprocess and shell command inspection
 *
 * Ports Python subprocess_intercept.py to TypeScript.
 * Works with child_process.exec, spawn, execSync, and
 * any wrapper that accepts a command string.
 *
 * Usage (manual inspection):
 *   import { inspectCommand, SubprocTier } from "aiglos/subprocess";
 *   const result = inspectCommand("rm -rf /var/data");
 *   if (result.verdict === "BLOCK") throw new AiglosBlockedError(result);
 *
 * Usage (patch child_process):
 *   import { patchChildProcess } from "aiglos/subprocess";
 *   patchChildProcess({ tier3Mode: "pause" });
 */

import { SubprocScanResult, Verdict } from "./types";

// ── Tier patterns ─────────────────────────────────────────────────────────

const TIER1_ALLOW = /^(cat\s|head\s|tail\s|less\s|wc\s|file\s|stat\s|du\s|df\s|find\s.*-name|ls(\s|$)|echo(\s|$)|pwd(\s|$)|date(\s|$)|whoami(\s|$)|uname\s|which\s|type\s|git\s+(status|log|diff|show|branch|tag|describe|fetch --dry-run|ls-files|blame|config --list)|python\s+-m\s+(pytest\s+.*-v|flake8|mypy|black --check|isort --check)|pip\s+(list|show|check|freeze)|npm\s+(list|outdated|audit))/i;

const TIER3_DESTRUCTIVE = /(rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s|rm\s+-rf\s|shred\s|wipe\s|dd\s+if=\/dev\/zero|DROP\s+(TABLE|DATABASE|SCHEMA)\s|TRUNCATE\s+(TABLE\s)?|DELETE\s+FROM\s+\w+\s*;|terraform\s+(destroy|taint)|kubectl\s+delete\s+(namespace|ns|pod|deployment|all)|helm\s+(delete|uninstall)\s|aws\s+(ec2|rds|s3)\s+delete\s|git\s+(push\s+.*--force|reset\s+--hard|clean\s+-[a-z]*f)|git\s+push\s+-f\s|sudo\s+rm\s|sudo\s+dd\s)/i;

// ── Threat patterns ───────────────────────────────────────────────────────

const T07_SHELL_INJECT = /(\$\([^)]{1,80}\)|`[^`]{1,80}`|[;&|]\s*(rm|dd|mkfs|wget|curl)\b|>\s*\/etc\/|\|\s*(bash|sh|zsh|dash)\b)/i;
const T08_PATH_TRAVERSAL = /(\.\.\/){2,}/;
const T10_PRIV_ESC = /^(sudo|su\s|doas\s|pkexec\s)|(sudo|pkexec)\s/i;
const T11_PERSISTENCE = /(crontab\s+(-[el]|\/)|\/etc\/cron\.(d|daily|weekly|monthly)|launchctl\s+(load|submit)\s|systemctl\s+(enable|daemon-reload)\s|\/etc\/init\.d\/|~\/.bashrc|~\/.bash_profile|~\/.profile|~\/.zshrc)/i;
const T12_LATERAL = /(ssh\s+\S+@\S+|nmap\s|masscan\s|zmap\s|nc\s+-[a-z]*l|netcat\s+)/i;
const T19_CRED_HARVEST = /(cat\s+.*\.ssh\/|cat\s+.*\.env\b|cat\s+.*credentials|cat\s+\/etc\/(passwd|shadow|sudoers)|aws\s+configure\s+export|printenv\s+.*SECRET)/i;
const T21_ENV_LEAK = /(env|printenv|export)\s*[|>]/i;
const T23_EXFIL = /(curl\s+.*-d\s.*(http|https):\/\/|wget\s+.*--post-(data|file)|nc\s+\S+\s+\d+\s*<)/i;

// T36 agent def paths
const T36_AGENTDEF_PATHS = /(~\/\.claude\/agents\/|\.claude\/agents\/|~\/\.github\/agents\/|\.github\/agents\/|~\/\.openclaw\/|\.openclaw\/|\.cursor\/rules\/|\.windsurfrules|\b(SOUL|IDENTITY|AGENTS|SKILL)\.md\b|~\/\.gemini\/agents\/)/i;
const T36_AGENTDEF_WRITE = /^(cp|mv|tee|install|rsync|ln)\s/i;

// T38 agent spawn
const T38_AGENT_SPAWN = /(\bclaude\s+(code|--print|-p)\b|\banthropic\s+claude\b|\bopenclaw\s+(run|start|spawn|agent)\b|\baider\s+--no-git\b|\bcursor\s+--headless\b|\bwindsurf\s+--agent\b|\bpython\s+.*agent.*\.py\b|\bnode\s+.*agent.*\.(js|mjs|ts)\b|\bconvert\.sh\b|\binstall\.sh\s+--tool\b)/i;

// ── Tier classifier ───────────────────────────────────────────────────────

export type SubprocTier = 1 | 2 | 3;

export function classifyTier(cmd: string): SubprocTier {
  if (TIER3_DESTRUCTIVE.test(cmd)) return 3;
  if (TIER1_ALLOW.test(cmd.trim())) return 1;
  return 2;
}

// ── Core inspector ────────────────────────────────────────────────────────

export interface InspectCommandOptions {
  mode?:       "block" | "warn" | "audit";
  tier3Mode?:  "block" | "pause" | "warn";
}

export function inspectCommand(cmd: string, opts: InspectCommandOptions = {}): SubprocScanResult {
  const { mode = "block", tier3Mode = "warn" } = opts;
  const t0   = performance.now();
  const tier = classifyTier(cmd);

  const _result = (
    ruleId: string,
    ruleName: string,
    reason: string,
    matched = "",
    forceTier?: SubprocTier,
  ): SubprocScanResult => {
    const t: SubprocTier = forceTier ?? tier;
    let verdict: Verdict;
    if (mode === "audit") {
      verdict = "WARN";
    } else if (t === 3) {
      verdict = tier3Mode === "pause" ? "PAUSE" : tier3Mode === "warn" ? "WARN" : "BLOCK";
    } else {
      verdict = mode === "warn" ? "WARN" : "BLOCK";
    }
    return {
      verdict, ruleId, ruleName, reason,
      tier: t, cmd: cmd.slice(0, 256),
      latencyMs: performance.now() - t0,
      timestamp: Date.now() / 1000,
      matched,
    };
  };

  // T36_AGENTDEF — early check (before tier1 auto-allow)
  const pathMatch = T36_AGENTDEF_PATHS.exec(cmd);
  if (pathMatch) {
    if (T36_AGENTDEF_WRITE.test(cmd.trim())) {
      return _result("T36_AGENTDEF", "AGENT_DEF_WRITE",
        `Write to agent definition path '${pathMatch[0]}' — silent reprogramming vector.`,
        pathMatch[0], 3
      );
    }
    return _result("T36_AGENTDEF", "AGENT_DEF_READ",
      `Access to agent definition path: ${pathMatch[0]}`,
      pathMatch[0], 2
    );
  }

  // T38_AGENT_SPAWN — early check
  const spawnMatch = T38_AGENT_SPAWN.exec(cmd);
  if (spawnMatch) {
    return _result("T38", "AGENT_SPAWN",
      `Sub-agent spawn detected: '${spawnMatch[0]}'. Register in session artifact.`,
      spawnMatch[0], 2
    );
  }

  // T07: Shell inject (always tier 3)
  const t07 = T07_SHELL_INJECT.exec(cmd);
  if (t07) return _result("T07", "SHELL_INJECT", "Shell metacharacter injection", t07[0], 3);

  // T08: Path traversal
  const t08 = T08_PATH_TRAVERSAL.exec(cmd);
  if (t08) return _result("T08", "PATH_TRAVERSAL", "Directory traversal sequence", t08[0]);

  // T10: Priv esc
  if (T10_PRIV_ESC.test(cmd)) return _result("T10", "PRIV_ESC", "Privilege escalation command", "", 3);

  // T11: Persistence
  const t11 = T11_PERSISTENCE.exec(cmd);
  if (t11) return _result("T11", "PERSISTENCE", `Persistence mechanism: ${t11[0]}`, t11[0], 3);

  // T12: Lateral movement
  const t12 = T12_LATERAL.exec(cmd);
  if (t12) return _result("T12", "LATERAL_MOVEMENT", `Lateral movement: ${t12[0]}`, t12[0]);

  // T19: Credential harvest
  const t19 = T19_CRED_HARVEST.exec(cmd);
  if (t19) return _result("T19", "CRED_HARVEST", `Command reads credential file: ${t19[0]}`, t19[0]);

  // T21: Env leak
  const t21 = T21_ENV_LEAK.exec(cmd);
  if (t21) return _result("T21", "ENV_LEAK", "Environment dump piped to external destination", t21[0]);

  // T23: Exfil via subprocess
  const t23 = T23_EXFIL.exec(cmd);
  if (t23) return _result("T23", "EXFIL_SUBPROCESS", `Data exfiltration via subprocess: ${t23[0]}`, t23[0]);

  // Tier 3 destructive (no specific rule match)
  if (tier === 3) return _result("T_DEST", "DESTRUCTIVE", `Destructive command: ${cmd.slice(0, 80)}`);

  // Tier 1 auto-allow
  if (tier === 1) {
    return {
      verdict: "ALLOW", ruleId: "none", ruleName: "none",
      reason: "", tier: 1, cmd: cmd.slice(0, 256),
      latencyMs: performance.now() - t0,
      timestamp: Date.now() / 1000,
    };
  }

  // Tier 2 monitored — allow with log
  return {
    verdict: "ALLOW", ruleId: "T2_MONITORED", ruleName: "MONITORED",
    reason: "Tier 2 monitored operation",
    tier: 2, cmd: cmd.slice(0, 256),
    latencyMs: performance.now() - t0,
    timestamp: Date.now() / 1000,
  };
}

// ── child_process patcher (Node.js only) ─────────────────────────────────

export interface PatchChildProcessOptions extends InspectCommandOptions {
  onBlock?: (result: SubprocScanResult) => void;
  onWarn?:  (result: SubprocScanResult) => void;
}

/**
 * Patches Node's child_process.exec and execSync to inspect commands
 * before execution.
 *
 * @example
 * import { patchChildProcess } from "aiglos/subprocess";
 * patchChildProcess({ tier3Mode: "pause" });
 * // Now child_process.exec("rm -rf /") throws AiglosBlockedError
 */
export function patchChildProcess(opts: PatchChildProcessOptions = {}): void {
  // Dynamic require so this module is still importable in browser/edge
  let cp: typeof import("child_process");
  try {
    cp = require("child_process");
  } catch {
    console.warn("[Aiglos] child_process not available — subprocess patching skipped.");
    return;
  }

  const { onBlock, onWarn, ...inspectOpts } = opts;
  const _origExec     = cp.exec.bind(cp);
  const _origExecSync = cp.execSync.bind(cp);
  const _origSpawn    = cp.spawn.bind(cp);

  function _check(cmd: string): void {
    const result = inspectCommand(cmd, inspectOpts);
    if (result.verdict === "BLOCK" || result.verdict === "PAUSE") {
      if (onBlock) onBlock(result);
      const { AiglosBlockedError } = require("./types");
      throw new AiglosBlockedError(result);
    }
    if (result.verdict === "WARN") {
      if (onWarn) onWarn(result);
      console.warn(`[Aiglos] WARN ${result.ruleId}: ${result.reason}`);
    }
  }

  (cp as any).exec = function(cmd: string, ...args: any[]) {
    _check(cmd);
    return _origExec(cmd, ...args);
  };

  (cp as any).execSync = function(cmd: string, ...args: any[]) {
    _check(cmd);
    return _origExecSync(cmd, ...args);
  };

  (cp as any).spawn = function(cmd: string, cmdArgs?: string[], ...rest: any[]) {
    const full = [cmd, ...(cmdArgs ?? [])].join(" ");
    _check(full);
    return _origSpawn(cmd, cmdArgs ?? [], ...rest);
  };
}
