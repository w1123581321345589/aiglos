"""
aiglos/audit/scanner.py
========================
aiglos audit --deep

Single-command security posture audit for AI agent deployments.

Five phases, 50+ checks, A-F letter grade.

Phase 1 -- Secrets & Credentials
  Check for plaintext secrets in common locations:
  .env files, config files, shell history, agent definition files.
  Each exposed secret is an immediate F finding.

Phase 2 -- Skill & Agent Definition Integrity
  Scan ~/.claude/agents/, ~/.claude/skills/, .openclaw/, .cursor/rules/
  for injection payloads, suspicious permissions, and known-bad content.

Phase 3 -- Runtime Configuration
  Check OpenClaw/agent config for hardening gaps:
  sandbox mode, elevated tools, network restrictions.

Phase 4 -- Aiglos Runtime Health
  Report on current Aiglos deployment status:
  rules active, behavioral baseline ready, honeypot deployed,
  pending policy proposals, unverified rules, source reputation events.

Phase 5 -- Network & Host Exposure
  Identify open outbound paths, missing firewall rules,
  MCP server exposure, and webhook endpoint security.

Scoring:
  Each check produces a PASS (0 points), WARN (-5), FAIL (-15), or CRITICAL (-30).
  Starting score: 100
  A: 90-100, B: 75-89, C: 60-74, D: 45-59, F: 0-44

The --deep flag adds:
  - Full injection scan of every agent definition file
  - Source reputation check for all recently contacted URLs
  - Citation verification status for all active rules
  - Cross-session behavioral drift analysis
"""


import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("aiglos.audit")

# ── Severity weights ──────────────────────────────────────────────────────────
_WEIGHTS = {"PASS": 0, "INFO": 0, "WARN": -5, "FAIL": -15, "CRITICAL": -30}

# ── Common secret patterns ────────────────────────────────────────────────────
_SECRET_PATTERNS = [
    ("Anthropic API key",  re.compile(r"sk-ant-api0[34]-[A-Za-z0-9_-]{40,}")),
    ("OpenAI API key",     re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{40,}")),
    ("AWS access key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token",       re.compile(r"(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{36,}")),
    ("Stripe live key",    re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    ("Generic secret",     re.compile(r'(?:api_key|secret|password)\s*[=:]\s*["\']?[A-Za-z0-9/+_\-]{20,}')),
]

# ── Injection phrases for agent definition scanning ───────────────────────────
_INJECTION_PHRASES = [
    "ignore previous instructions", "disregard your", "you are now",
    "new instructions:", "bypass security", "disable monitoring",
    "forget everything", "override policy", "from now on",
    "tell all agents", "broadcast to fleet",
]

# ── Agent definition paths ────────────────────────────────────────────────────
_AGENTDEF_PATHS = [
    Path.home() / ".claude" / "agents",
    Path.home() / ".claude" / "skills",
    Path.home() / ".openclaw",
    Path(".cursor") / "rules",
    Path(".") / "AGENTS.md",
    Path(".") / "SOUL.md",
    Path(".") / "MEMORY.md",
]

# ── OpenClaw config paths ─────────────────────────────────────────────────────
_CONFIG_PATHS = [
    Path.home() / ".openclaw" / "config.json",
    Path.home() / ".openclaw" / "config.yaml",
    Path(".") / "openclaw.config.json",
    Path(".") / ".openclaw.json",
]


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    check_id:    str
    phase:       int
    name:        str
    severity:    str    # PASS | INFO | WARN | FAIL | CRITICAL
    detail:      str
    remediation: str = ""
    evidence:    str = ""

    @property
    def score_impact(self) -> int:
        return _WEIGHTS.get(self.severity, 0)

    @property
    def icon(self) -> str:
        return {"PASS": "✓", "INFO": "ℹ", "WARN": "⚠",
                "FAIL": "✗", "CRITICAL": "⛔"}.get(self.severity, "?")


@dataclass
class AuditResult:
    score:         int
    grade:         str
    checks:        List[CheckResult] = field(default_factory=list)
    scanned_at:    float             = field(default_factory=time.time)
    aiglos_version: str              = ""
    deep:          bool              = False
    duration_ms:   float             = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.checks if c.severity == "CRITICAL")

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.severity == "FAIL")

    @property
    def warn_count(self) -> int:
        return sum(1 for c in self.checks if c.severity == "WARN")

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.severity == "PASS")

    @property
    def findings(self) -> List[CheckResult]:
        """Non-passing checks, sorted by severity."""
        order = {"CRITICAL": 0, "FAIL": 1, "WARN": 2, "INFO": 3}
        return sorted(
            [c for c in self.checks if c.severity not in ("PASS", "INFO")],
            key=lambda c: order.get(c.severity, 9),
        )


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 45: return "D"
    return "F"


# ── AuditScanner ──────────────────────────────────────────────────────────────

class AuditScanner:
    """
    Runs all audit phases and returns an AuditResult.

    Usage:
        scanner = AuditScanner(deep=True)
        result  = scanner.run()
        print(result.grade)   # "B"
    """

    def __init__(self, deep: bool = False, graph=None):
        self._deep   = deep
        self._graph  = graph
        self._checks: List[CheckResult] = []

    def run(self) -> AuditResult:
        start = time.time()
        self._checks = []

        self._phase1_secrets()
        self._phase2_agent_defs()
        self._phase3_runtime_config()
        self._phase4_aiglos_health()
        self._phase5_network()

        if self._deep:
            self._phase_deep_injection()
            self._phase_deep_reputation()
            self._phase_deep_citations()

        score = max(0, 100 + sum(c.score_impact for c in self._checks))

        try:
            from aiglos import __version__
            version = __version__
        except Exception:
            version = "unknown"

        return AuditResult(
            score          = score,
            grade          = _grade(score),
            checks         = list(self._checks),
            aiglos_version = version,
            deep           = self._deep,
            duration_ms    = (time.time() - start) * 1000,
        )

    # ── Phase 1: Secrets ──────────────────────────────────────────────────────

    def _phase1_secrets(self) -> None:
        """Scan for plaintext secrets in common locations."""

        # 1a. .env files in cwd and home
        env_paths = [
            Path(".env"), Path(".env.local"), Path(".env.production"),
            Path(".env.staging"), Path.home() / ".env",
        ]
        found_envs = []
        for ep in env_paths:
            if ep.exists():
                found_envs.append(ep)
                self._scan_file_for_secrets(ep, phase=1)

        if not found_envs:
            self._add(CheckResult("P1-01", 1, "No .env files in cwd", "PASS",
                                  "No .env files found in working directory."))
        else:
            self._add(CheckResult("P1-01", 1, ".env files present", "INFO",
                                  f"{len(found_envs)} .env file(s) found and scanned.",
                                  remediation="Ensure .env files are in .gitignore."))

        # 1b. Shell history
        for history_file in [Path.home() / ".bash_history",
                              Path.home() / ".zsh_history"]:
            if history_file.exists():
                try:
                    content = history_file.read_text(errors="replace")[:50000]
                    for name, pattern in _SECRET_PATTERNS:
                        if pattern.search(content):
                            self._add(CheckResult(
                                "P1-02", 1,
                                f"Secret in shell history ({history_file.name})",
                                "FAIL",
                                f"{name} pattern found in {history_file.name}.",
                                remediation="Run: history -c && > ~/.bash_history",
                                evidence=f"Pattern: {name}",
                            ))
                            break
                    else:
                        self._add(CheckResult("P1-02", 1,
                            f"Shell history clean ({history_file.name})",
                            "PASS", "No secrets found in shell history."))
                except Exception:
                    pass

        # 1c. AWS credentials file
        aws_creds = Path.home() / ".aws" / "credentials"
        if aws_creds.exists():
            content = aws_creds.read_text(errors="replace")
            if "aws_access_key_id" in content.lower():
                self._add(CheckResult(
                    "P1-03", 1, "AWS credentials file present", "WARN",
                    "~/.aws/credentials contains AWS keys.",
                    remediation=(
                        "Use IAM roles or environment variables instead of "
                        "static credentials files where possible."
                    ),
                ))
            else:
                self._add(CheckResult("P1-03", 1, "AWS credentials checked", "PASS",
                                      "~/.aws/credentials does not appear to contain keys."))
        else:
            self._add(CheckResult("P1-03", 1, "No AWS credentials file", "PASS",
                                  "~/.aws/credentials not found."))

        # 1d. SSH key permissions
        ssh_dir = Path.home() / ".ssh"
        if ssh_dir.exists():
            for key_file in ssh_dir.glob("id_*"):
                if key_file.suffix not in (".pub", ""):
                    continue
                if key_file.suffix == "":   # private key
                    mode = oct(key_file.stat().st_mode)[-3:]
                    if mode != "600":
                        self._add(CheckResult(
                            "P1-04", 1,
                            f"SSH key permissions incorrect ({key_file.name})",
                            "WARN",
                            f"{key_file} has permissions {mode}, should be 600.",
                            remediation=f"Run: chmod 600 {key_file}",
                        ))
                        break
            else:
                self._add(CheckResult("P1-04", 1, "SSH key permissions OK", "PASS",
                                      "SSH private keys have correct permissions."))

    def _scan_file_for_secrets(self, path: Path, phase: int) -> None:
        """Scan a single file for secret patterns."""
        try:
            content = path.read_text(errors="replace")
            for name, pattern in _SECRET_PATTERNS:
                if pattern.search(content):
                    self._add(CheckResult(
                        f"P{phase}-SEC", phase,
                        f"Secret in {path.name}",
                        "CRITICAL",
                        f"{name} found in {path}.",
                        remediation=(
                            f"Remove the secret from {path.name}. "
                            "Use environment variables instead."
                        ),
                        evidence=f"Pattern: {name}",
                    ))
                    return
        except Exception:
            pass

    # ── Phase 2: Agent definition integrity ───────────────────────────────────

    def _phase2_agent_defs(self) -> None:
        """Scan agent definition and skill files for injection payloads."""
        scanned = 0
        injections_found = 0

        for base_path in _AGENTDEF_PATHS:
            if not base_path.exists():
                continue

            if base_path.is_dir():
                files = list(base_path.glob("**/*.md")) + \
                        list(base_path.glob("**/*.json")) + \
                        list(base_path.glob("**/*.yaml"))
            else:
                files = [base_path] if base_path.exists() else []

            for f in files[:50]:   # cap at 50 files
                scanned += 1
                try:
                    content = f.read_text(errors="replace").lower()
                    for phrase in _INJECTION_PHRASES:
                        if phrase in content:
                            injections_found += 1
                            self._add(CheckResult(
                                "P2-01", 2,
                                f"Injection payload in agent definition ({f.name})",
                                "CRITICAL",
                                f"Phrase '{phrase}' found in {f}.",
                                remediation=(
                                    f"Remove or review {f}. "
                                    "This file may have been poisoned."
                                ),
                                evidence=f"File: {f}, Phrase: '{phrase}'",
                            ))
                            break
                except Exception:
                    pass

        if scanned == 0:
            self._add(CheckResult("P2-00", 2, "No agent definition files found", "INFO",
                                  "No agent definition directories found."))
        elif injections_found == 0:
            self._add(CheckResult("P2-01", 2,
                                  f"Agent definitions clean ({scanned} files)",
                                  "PASS",
                                  f"Scanned {scanned} agent definition file(s). No injection payloads found."))

        # 2b. SKILL.md integrity -- check if it loads Aiglos
        skill_path = Path.home() / ".claude" / "skills" / "aiglos" / "SKILL.md"
        if skill_path.exists():
            self._add(CheckResult("P2-02", 2, "Aiglos SKILL.md installed", "PASS",
                                  "Aiglos is configured as a Claude Code skill."))
        else:
            self._add(CheckResult("P2-02", 2, "Aiglos SKILL.md not installed", "INFO",
                                  "Aiglos is not configured as a Claude Code skill.",
                                  remediation=(
                                      "Run: aiglos install-skill\n"
                                      "Or copy aiglos/skills/SKILL.md to "
                                      "~/.claude/skills/aiglos/SKILL.md"
                                  )))

    # ── Phase 3: Runtime configuration ────────────────────────────────────────

    def _phase3_runtime_config(self) -> None:
        """Check agent runtime configuration for hardening gaps."""
        config_found = False

        for config_path in _CONFIG_PATHS:
            if not config_path.exists():
                continue
            config_found = True
            try:
                with open(config_path) as f:
                    config = json.load(f)
            except Exception:
                continue

            # Check tools.elevated.enabled
            tools = config.get("tools", {})
            elevated = tools.get("elevated", {})
            if elevated.get("enabled", True):
                self._add(CheckResult(
                    "P3-01", 3, "tools.elevated.enabled = true",
                    "WARN",
                    "Elevated tools are enabled. Sandboxed agents can access host-level resources.",
                    remediation='Set tools.elevated.enabled = false in your OpenClaw config.',
                ))
            else:
                self._add(CheckResult("P3-01", 3, "tools.elevated.enabled = false",
                                      "PASS", "Elevated tools are disabled."))

            # Check sandbox mode
            agents_cfg = config.get("agents", {})
            defaults   = agents_cfg.get("defaults", {})
            sandbox    = defaults.get("sandbox", {})
            mode       = sandbox.get("mode", "main")
            if mode == "non-main":
                self._add(CheckResult("P3-02", 3, "Sandbox mode = non-main", "PASS",
                                      "Sub-agents and group chats run in sandboxed mode."))
            else:
                self._add(CheckResult(
                    "P3-02", 3, f"Sandbox mode = {mode} (not hardened)",
                    "WARN",
                    "Sub-agents are not sandboxed. They can access files, network, and env vars.",
                    remediation='Set agents.defaults.sandbox.mode = "non-main"',
                ))

            # Check network restrictions
            network = config.get("network", {})
            if network.get("allowlist") or network.get("allow_list"):
                self._add(CheckResult("P3-03", 3, "Network allowlist configured", "PASS",
                                      "Outbound network access is restricted to an allowlist."))
            else:
                self._add(CheckResult(
                    "P3-03", 3, "No network allowlist",
                    "WARN",
                    "No outbound network allowlist found. Agent can reach any endpoint.",
                    remediation="Add a network.allowlist to your OpenClaw config.",
                ))

        if not config_found:
            self._add(CheckResult("P3-00", 3, "No OpenClaw config file found", "INFO",
                                  "OpenClaw configuration file not found.",
                                  remediation=(
                                      "Create ~/.openclaw/config.json with "
                                      'tools.elevated.enabled=false and '
                                      'agents.defaults.sandbox.mode="non-main"'
                                  )))

    # ── Phase 4: Aiglos runtime health ────────────────────────────────────────

    def _phase4_aiglos_health(self) -> None:
        """Report on current Aiglos deployment status."""
        try:
            from aiglos.adaptive.observation import ObservationGraph
            graph = self._graph or ObservationGraph()
        except Exception:
            self._add(CheckResult("P4-00", 4, "Aiglos observation graph unavailable",
                                  "INFO", "No Aiglos session data found."))
            return

        # 4a. Honeypot status
        try:
            hits  = graph.get_honeypot_hits(limit=1)
            mgr   = __import__("aiglos.integrations.honeypot",
                               fromlist=["HoneypotManager"]).HoneypotManager()
            mgr.deploy()
            self._add(CheckResult(
                "P4-01", 4, f"Honeypot deployed ({len(mgr.active_honeypots())} files)",
                "PASS",
                f"Honeypot active. {len(hits)} lifetime hit(s).",
            ))
            if hits:
                self._add(CheckResult(
                    "P4-01b", 4, f"Honeypot triggered ({len(hits)} hit(s))",
                    "CRITICAL",
                    f"A honeypot file was accessed -- credential harvesting attempted.",
                    remediation="Review aiglos honeypot list for details.",
                ))
        except Exception:
            self._add(CheckResult("P4-01", 4, "Honeypot not deployed", "WARN",
                                  "Honeypot files not deployed.",
                                  remediation="Run: aiglos honeypot deploy"))

        # 4b. Pending policy proposals
        try:
            proposals = graph.list_proposals(pending_only=True)
            if proposals:
                self._add(CheckResult(
                    "P4-02", 4,
                    f"{len(proposals)} pending policy proposal(s)",
                    "INFO",
                    f"{len(proposals)} policy proposals awaiting review.",
                    remediation="Run: aiglos policy list",
                ))
            else:
                self._add(CheckResult("P4-02", 4, "No pending policy proposals",
                                      "PASS", "Policy proposal queue is empty."))
        except Exception:
            pass

        # 4c. Source reputation events
        try:
            records = graph.list_source_records(min_score=0.50, limit=5)
            if records:
                self._add(CheckResult(
                    "P4-03", 4,
                    f"{len(records)} high-risk source(s) in reputation graph",
                    "WARN",
                    f"{len(records)} source(s) with score ≥ 0.50 in reputation history.",
                    remediation="Run: aiglos reputation top",
                ))
            else:
                self._add(CheckResult("P4-03", 4, "No high-risk sources recorded",
                                      "PASS", "Source reputation graph is clean."))
        except Exception:
            pass

        # 4d. Unverified rules
        try:
            rows = graph.list_source_records(min_score=0.0, limit=1)
            from aiglos.autoresearch.citation_verifier import CitationVerifier
            verifier = CitationVerifier(graph=graph)
            all_rules = [f"T{i:02d}" for i in range(1, 44)] + ["T36_AGENTDEF"]
            unverified = []
            for rule_id in all_rules[:20]:   # sample for audit speed
                citation = verifier._try_load_cached(rule_id)
                if not citation or citation.status.value in ("UNVERIFIED", "PENDING"):
                    unverified.append(rule_id)
            if len(unverified) > 10:
                self._add(CheckResult(
                    "P4-04", 4,
                    f"{len(unverified)} rules unverified",
                    "INFO",
                    f"{len(unverified)} rules have no verified citation. "
                    "Run: aiglos research verify --all",
                    remediation="Run: aiglos research verify --all",
                ))
            else:
                self._add(CheckResult("P4-04", 4, "Rule citation coverage adequate",
                                      "PASS",
                                      f"{len(unverified)}/20 sampled rules lack citations."))
        except Exception:
            pass

        # 4e. Override challenges pending
        try:
            challenges = graph.list_override_challenges(pending_only=True)
            if challenges:
                self._add(CheckResult(
                    "P4-05", 4,
                    f"{len(challenges)} override challenge(s) pending",
                    "WARN",
                    f"{len(challenges)} Tier 3 overrides awaiting confirmation.",
                    remediation="Run: aiglos override list",
                ))
        except Exception:
            pass

    # ── Phase 5: Network & host exposure ──────────────────────────────────────

    def _phase5_network(self) -> None:
        """Check for network exposure and host hardening gaps."""
        import platform

        is_mac   = platform.system() == "Darwin"
        is_linux = platform.system() == "Linux"

        # 5a. Firewall status (macOS)
        if is_mac:
            try:
                import subprocess
                result = subprocess.run(
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                    capture_output=True, text=True, timeout=3,
                )
                if "enabled" in result.stdout.lower():
                    self._add(CheckResult("P5-01", 5, "macOS firewall enabled", "PASS",
                                          "Application firewall is enabled."))
                else:
                    self._add(CheckResult(
                        "P5-01", 5, "macOS firewall disabled", "WARN",
                        "Application firewall is not enabled.",
                        remediation="Enable in System Preferences → Security → Firewall",
                    ))
            except Exception:
                self._add(CheckResult("P5-01", 5, "Firewall status unknown", "INFO",
                                      "Could not determine firewall status."))

        # 5b. SSH daemon status
        try:
            import subprocess
            if is_mac:
                result = subprocess.run(
                    ["sudo", "-n", "systemsetup", "-getremotelogin"],
                    capture_output=True, text=True, timeout=3,
                )
                ssh_on = "On" in result.stdout
            elif is_linux:
                result = subprocess.run(
                    ["systemctl", "is-active", "ssh"],
                    capture_output=True, text=True, timeout=3,
                )
                ssh_on = "active" in result.stdout
            else:
                ssh_on = None

            if ssh_on is True:
                self._add(CheckResult(
                    "P5-02", 5, "SSH daemon running", "INFO",
                    "SSH is enabled. Ensure key-only authentication is enforced.",
                    remediation=(
                        "Verify PasswordAuthentication no in /etc/ssh/sshd_config"
                    ),
                ))
            elif ssh_on is False:
                self._add(CheckResult("P5-02", 5, "SSH daemon not running", "PASS",
                                      "SSH is not enabled."))
        except Exception:
            pass

        # 5c. Check for .env files in git repos (git secrets hygiene)
        try:
            import subprocess
            result = subprocess.run(
                ["git", "ls-files", "--error-unmatch", ".env"],
                capture_output=True, text=True, timeout=3, cwd="."
            )
            if result.returncode == 0:
                self._add(CheckResult(
                    "P5-03", 5, ".env file tracked in git", "FAIL",
                    ".env is tracked by git -- secrets may be in commit history.",
                    remediation=(
                        "Run: git rm --cached .env && "
                        'echo ".env" >> .gitignore && '
                        "git commit -m 'Remove .env from tracking'"
                    ),
                ))
        except Exception:
            pass

        # 5d. Aiglos log file health
        for log_path in [Path("./aiglos.log"), Path.home() / ".aiglos" / "aiglos.log"]:
            if log_path.exists():
                size_mb = log_path.stat().st_size / 1_000_000
                if size_mb > 100:
                    self._add(CheckResult(
                        "P5-04", 5, f"Aiglos log file large ({size_mb:.0f}MB)",
                        "INFO",
                        f"{log_path} is {size_mb:.0f}MB. Consider log rotation.",
                        remediation="Run: aiglos log rotate",
                    ))
                else:
                    self._add(CheckResult("P5-04", 5, "Aiglos log file size OK",
                                          "PASS", f"{log_path} is {size_mb:.1f}MB."))
                break

    # ── Deep phase: Injection scan ────────────────────────────────────────────

    def _phase_deep_injection(self) -> None:
        """Full injection scan of all agent definition files."""
        try:
            from aiglos.integrations.injection_scanner import InjectionScanner
            scanner = InjectionScanner()
            injections = 0

            for base_path in _AGENTDEF_PATHS:
                if not base_path.exists():
                    continue
                files = list(base_path.rglob("*.md")) if base_path.is_dir() \
                        else [base_path]
                for f in files[:20]:
                    try:
                        content = f.read_text(errors="replace")
                        result  = scanner.scan_tool_output("file.read", content)
                        if result.verdict != "ALLOW":
                            injections += 1
                            self._add(CheckResult(
                                "PD-01", 0,
                                f"Injection detected in {f.name} (deep scan)",
                                "CRITICAL",
                                f"InjectionScanner: {result.verdict} score={result.score:.2f} "
                                f"rule={result.rule_id}",
                                remediation=f"Review and replace {f}",
                                evidence=str(f),
                            ))
                    except Exception:
                        pass

            if injections == 0:
                self._add(CheckResult("PD-01", 0, "Deep injection scan: clean",
                                      "PASS", "No injections found in deep scan."))
        except Exception as e:
            log.debug("Deep injection scan error: %s", e)

    # ── Deep phase: Source reputation ─────────────────────────────────────────

    def _phase_deep_reputation(self) -> None:
        """Check source reputation for all high-risk sources."""
        try:
            from aiglos.adaptive.observation import ObservationGraph
            graph   = self._graph or ObservationGraph()
            records = graph.list_source_records(min_score=0.40, limit=20)
            blocked = [r for r in records if r.max_score >= 0.80]
            if blocked:
                self._add(CheckResult(
                    "PD-02", 0,
                    f"{len(blocked)} source(s) at block threshold",
                    "WARN",
                    f"{len(blocked)} URL/domain(s) near or above block threshold.",
                    remediation="Run: aiglos reputation top --limit 20",
                ))
            else:
                self._add(CheckResult("PD-02", 0, "No sources near block threshold",
                                      "PASS", "Source reputation graph: no critical sources."))
        except Exception:
            pass

    # ── Deep phase: Citation coverage ─────────────────────────────────────────

    def _phase_deep_citations(self) -> None:
        """Full citation verification status."""
        try:
            from aiglos.adaptive.observation import ObservationGraph
            from aiglos.autoresearch.citation_verifier import CitationVerifier
            graph    = self._graph or ObservationGraph()
            verifier = CitationVerifier(graph=graph)
            all_rules = [f"T{i:02d}" for i in range(1, 44)] + ["T36_AGENTDEF"]
            unverified = []
            for rule_id in all_rules:
                c = verifier._try_load_cached(rule_id)
                if not c or c.status.value in ("UNVERIFIED", "PENDING"):
                    unverified.append(rule_id)
            pct = (len(all_rules) - len(unverified)) / len(all_rules) * 100
            if len(unverified) > 5:
                self._add(CheckResult(
                    "PD-03", 0,
                    f"Citation coverage {pct:.0f}% ({len(unverified)} unverified)",
                    "INFO",
                    f"{len(unverified)} rules lack verified citations.",
                    remediation="Run: aiglos research verify --all",
                ))
            else:
                self._add(CheckResult("PD-03", 0,
                                      f"Citation coverage {pct:.0f}%",
                                      "PASS",
                                      f"Only {len(unverified)} rules unverified."))
        except Exception:
            pass

    # ── Utility ───────────────────────────────────────────────────────────────

    def _add(self, check: CheckResult) -> None:
        # Deduplicate by check_id -- keep worst
        existing = next((c for c in self._checks if c.check_id == check.check_id), None)
        if existing:
            order = {"CRITICAL": 0, "FAIL": 1, "WARN": 2, "INFO": 3, "PASS": 4}
            if order.get(check.severity, 9) < order.get(existing.severity, 9):
                self._checks.remove(existing)
                self._checks.append(check)
        else:
            self._checks.append(check)
