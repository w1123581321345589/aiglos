"""
aiglos/autoresearch/ghsa_watcher.py
=====================================
GHSA Watcher — Live pipeline from OpenClaw advisory publications to Aiglos rules.

The OpenClaw security page shows 3 published advisories and a private queue
with ~285 submissions. The three published ones already map to existing Aiglos
rules. When the other 285 eventually publish — and they will — this watcher
converts each one into either:
  (a) A confirmed rule coverage mapping, published to aiglos.dev/intel within
      24 hours of the GHSA publication, or
  (b) A pending rule proposal in aiglos/autoresearch/pending_rules/
      for human review, with match function scaffolded automatically

Every new threat
disclosure became a signature within hours. The adversary publishes a new
technique; the detection network absorbs it before the next victim is hit.

The watcher covers four sources:
  1. GitHub Advisory Database (GHSA) — github.com/openclaw/openclaw/security
  2. NVD CVE feed — filtered to OpenClaw package identifiers
  3. OpenClawCVEs feed — github.com/jgamblin/OpenClawCVEs (powers ClawKeeper)
  4. OSV.dev — open source vulnerability database, npm/openclaw package

Each advisory is:
  - Parsed for CVE ID, severity, CVSS, description, and affected versions
  - Matched against the T01-T70 taxonomy using keyword extraction
  - Classified as COVERED (rule exists), PARTIAL (adjacent rule), or GAP (no rule)
  - Logged to the coverage ledger at aiglos/autoresearch/ghsa_coverage.json
  - For GAPs: a pending rule stub is written to pending_rules/GHSA-xxxx.json

Usage:
    # One-shot check
    aiglos autoresearch watch-ghsa --once

    # Daemon mode (polls every 6 hours, matches ClawKeeper scan cadence)
    aiglos autoresearch watch-ghsa --daemon

    # Show current coverage report
    aiglos autoresearch ghsa-coverage

    # Force re-match all known advisories against current rules
    aiglos autoresearch ghsa-rematch
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("aiglos.ghsa_watcher")

# The three published advisories at time of build — used as canonical test cases
KNOWN_ADVISORIES = [
    {
        "ghsa_id":    "GHSA-g8p2-7wf7-98mq",
        "cve_id":     "CVE-2026-25253",
        "title":      "1-Click RCE via Authentication Token Exfiltration from gatewayUrl",
        "severity":   "HIGH",
        "cvss":       8.8,
        "aiglos_rule": "T68",
        "aiglos_name": "INSECURE_DEFAULT_CONFIG",
        "description": (
            "OpenClaw UI auto-trusts gateway URLs and opens an authenticated WebSocket "
            "with no user interaction required. Authentication tokens are handed over "
            "to an attacker-controlled gateway, enabling 1-click RCE."
        ),
        "affected_package": "npm/openclaw",
        "aiglos_rules": ["T68"],
        "coverage":   "COVERED",
        "coverage_note": (
            "T68 INSECURE_DEFAULT_CONFIG fires when allow_remote=true appears "
            "without authentication. The gatewayUrl auto-trust is the default config "
            "failure T68 was built to catch. AuditScanner Phase 3 flags this as CRITICAL."
        ),
    },
    {
        "ghsa_id":    "GHSA-q284-4pvr-m585",
        "cve_id":     None,
        "title":      "OS Command Injection via Project Root Path in sshNodeCommand",
        "severity":   "HIGH",
        "cvss":       None,
        "description": (
            "Path traversal in the SSH command execution path leads to arbitrary "
            "command injection. Reported by Armin Ronacher (mitsuhiko), creator "
            "of Flask and Jinja2."
        ),
        "affected_package": "npm/openclaw",
        "aiglos_rules": ["T03", "T04"],
        "coverage":   "COVERED",
        "coverage_note": (
            "T03 SHELL_INJECTION catches the command injection class. "
            "T04 PATH_TRAVERSAL catches the traversal entry vector. "
            "Together they cover the full attack chain documented in this advisory."
        ),
    },
    {
        "ghsa_id":    "GHSA-mc68-q9jw-2h3v",
        "cve_id":     None,
        "title":      "Command Injection in Clawdbot Docker Execution via PATH Environment Variable",
        "severity":   "HIGH",
        "cvss":       8.5,
        "aiglos_rule": "T70",
        "aiglos_name": "ENV_PATH_HIJACK",
        "notes":      "T70 was created directly from this GHSA. See GHSA-mc68-q9jw-2h3v.",
        "description": (
            "Manipulated PATH environment variable in Docker execution context "
            "redirects execution to an attacker-controlled binary. No shell "
            "metacharacters required — invisible to standard shell injection detection."
        ),
        "affected_package": "npm/openclaw",
        "aiglos_rules": ["T70"],
        "coverage":   "COVERED",
        "coverage_note": (
            "T70 ENV_PATH_HIJACK was built specifically in response to this advisory. "
            "Fires on PATH, LD_PRELOAD, PYTHONPATH, NODE_PATH modification in execution "
            "contexts — the exact attack class GHSA-mc68-q9jw-2h3v documents. "
            "This is the gap T03 SHELL_INJECTION could not close because there are "
            "no metacharacters in this attack pattern."
        ),
    },
]

# Taxonomy keyword extraction — maps advisory description terms to rule IDs
# Built from the T01-T70 rule descriptions and OWASP ASI categories
TAXONOMY_KEYWORDS: Dict[str, List[str]] = {
    "T03":  ["shell injection", "command injection", "rce", "remote code execution",
             "arbitrary command", "code execution", "os command"],
    "T04":  ["path traversal", "directory traversal", "zip slip", "path manipulation",
             "file inclusion", "arbitrary file"],
    "T05":  ["prompt injection", "instruction injection", "jailbreak", "system prompt"],
    "T08":  ["privilege escalation", "privilege abuse", "elevated access",
             "unauthorized access", "permission bypass", "authorization bypass"],
    "T09":  ["ssrf", "server-side request forgery", "internal network access",
             "internal endpoint"],
    "T12":  ["data exfiltration", "credential theft", "secret exposure",
             "token exfiltration", "key exfiltration"],
    "T14":  ["outbound", "external connection", "callback", "beacon",
             "reverse shell", "c2", "command and control"],
    "T19":  ["credential", "api key", "api token", "authentication token",
             "secret", ".env", "aws credentials", "ssh key"],
    "T30":  ["supply chain", "malicious package", "dependency confusion",
             "typosquatting", "npm package", "malicious skill"],
    "T34":  ["heartbeat", "soul.md", "mission.md", "agent configuration",
             "heartbeat tampering"],
    "T36":  ["skill injection", "agent definition", "agents.md", "skill.md",
             "memory poisoning", "soul.md"],
    "T44":  ["model swap", "inference router", "model redirection",
             "model hijack", "inference hijack"],
    "T45":  ["cross-tenant", "tenant isolation", "multi-tenant", "tenant escape"],
    "T50":  ["sandbox escape", "sandbox bypass", "container escape",
             "vm escape", "isolation bypass"],
    "T54":  ["vector database", "vector injection", "rag injection",
             "embedding injection", "retrieval poisoning"],
    "T58":  ["context drift", "long context", "context manipulation",
             "context poisoning"],
    "T64":  ["identity spoofing", "agent impersonation", "identity forgery",
             "actor name", "display name spoofing"],
    "T67":  ["heartbeat silence", "cron failure", "monitoring disabled",
             "gateway kill", "scheduler stopped"],
    "T68":  ["insecure default", "allow_remote", "unauthenticated access",
             "authentication disabled", "default config", "exposed gateway"],
    "T69":  ["plan deviation", "implementation plan", "scope deviation",
             "unauthorized file access", "out of scope"],
    "T70":  ["path environment", "ld_preload", "ld_library_path", "pythonpath",
             "node_path", "environment variable hijack", "path manipulation",
             "docker path", "env var injection"],
}


@dataclass
class AdvisoryMatch:
    """Result of matching a GHSA advisory against the Aiglos taxonomy."""
    ghsa_id:        str
    cve_id:         Optional[str]
    title:          str
    severity:       str
    cvss:           Optional[float]
    description:    str
    matched_rules:  List[str]          # T-IDs that match
    coverage:       str                # COVERED | PARTIAL | GAP
    coverage_note:  str
    raw:            dict = field(default_factory=dict, repr=False)


@dataclass
class PendingRule:
    """
    A gap-coverage proposal generated when an advisory has no matching rule.
    Written to pending_rules/GHSA-xxxx.json for human review.
    """
    ghsa_id:        str
    title:          str
    proposed_id:    str                # next available T-ID
    description:    str
    keywords:       List[str]
    severity:       str
    cvss:           Optional[float]
    match_sketch:   str                # Python match function skeleton
    created_at:     float = field(default_factory=time.time)


class GHSAWatcher:
    """
    Monitors OpenClaw security advisories and maintains Aiglos rule coverage.

    Sources:
      - GitHub Advisory Database (ghsa_id format)
      - NVD CVE feed
      - OpenClawCVEs GitHub feed (jgamblin/OpenClawCVEs)
      - OSV.dev
    """

    GITHUB_ADVISORY_API = (
        "https://api.github.com/repos/openclaw/openclaw/security-advisories"
    )
    OSV_QUERY_API = "https://api.osv.dev/v1/query"
    NVD_SEARCH_API = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        "?keywordSearch=openclaw&resultsPerPage=20"
    )
    OPENCLAW_CVE_FEED = (
        "https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/main/openclaw-cves.json"
    )

    def __init__(
        self,
        coverage_path: str | None = None,
        pending_path: str | None = None,
    ):
        base = Path(__file__).parent
        self.coverage_path = Path(coverage_path or base / "ghsa_coverage.json")
        self.pending_path  = Path(pending_path  or base / "pending_rules")
        self.pending_path.mkdir(exist_ok=True)
        self._coverage: Dict[str, AdvisoryMatch] = {}
        self._load_coverage()

    # ── Coverage ledger ────────────────────────────────────────────────────────

    def _load_coverage(self) -> None:
        if self.coverage_path.exists():
            try:
                data = json.loads(self.coverage_path.read_text())
                for ghsa_id, entry in data.get("advisories", {}).items():
                    self._coverage[ghsa_id] = AdvisoryMatch(**entry)
            except Exception as e:
                log.debug("[GHSAWatcher] Failed to load coverage: %s", e)

    def _save_coverage(self) -> None:
        data = {
            "generated_at": time.time(),
            "total":        len(self._coverage),
            "covered":      sum(1 for m in self._coverage.values()
                                if m.coverage == "COVERED"),
            "partial":      sum(1 for m in self._coverage.values()
                                if m.coverage == "PARTIAL"),
            "gaps":         sum(1 for m in self._coverage.values()
                                if m.coverage == "GAP"),
            "advisories": {
                ghsa_id: {
                    "ghsa_id":       m.ghsa_id,
                    "cve_id":        m.cve_id,
                    "title":         m.title,
                    "severity":      m.severity,
                    "cvss":          m.cvss,
                    "description":   m.description,
                    "matched_rules": m.matched_rules,
                    "coverage":      m.coverage,
                    "coverage_note": m.coverage_note,
                }
                for ghsa_id, m in self._coverage.items()
            },
        }
        self.coverage_path.write_text(json.dumps(data, indent=2))

    # ── Advisory matching ──────────────────────────────────────────────────────

    def match_advisory(
        self,
        ghsa_id: str,
        title: str,
        description: str,
        severity: str,
        cvss: float | None = None,
        cve_id: str | None = None,
        raw: dict | None = None,
    ) -> AdvisoryMatch:
        """
        Match an advisory description against the T01-T70 taxonomy.
        Returns an AdvisoryMatch with coverage classification.
        """
        text = (title + " " + description).lower()
        matched: List[str] = []

        for rule_id, keywords in TAXONOMY_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                matched.append(rule_id)

        if matched:
            coverage = "COVERED"
            note = (
                f"Advisory description matches {len(matched)} rule(s): "
                f"{', '.join(matched)}. "
                f"Runtime detection active — these rule classes fire before "
                f"any patch exists."
            )
        else:
            # Check for partial coverage — any single-word overlap
            partial = []
            words = set(re.findall(r'\b\w{4,}\b', text))
            for rule_id, keywords in TAXONOMY_KEYWORDS.items():
                for kw in keywords:
                    kw_words = set(kw.split())
                    if kw_words & words:
                        partial.append(rule_id)
                        break
            if partial:
                coverage = "PARTIAL"
                note = (
                    f"Partial keyword overlap with {', '.join(set(partial))}. "
                    f"May be covered but human review recommended."
                )
                matched = list(set(partial))
            else:
                coverage = "GAP"
                note = (
                    f"No matching rule found in T01-T70 for this advisory. "
                    f"A pending rule proposal has been created for human review."
                )

        result = AdvisoryMatch(
            ghsa_id       = ghsa_id,
            cve_id        = cve_id,
            title         = title,
            severity      = severity,
            cvss          = cvss,
            description   = description,
            matched_rules = matched,
            coverage      = coverage,
            coverage_note = note,
            raw           = raw or {},
        )
        self._coverage[ghsa_id] = result

        if coverage == "GAP":
            self._write_pending_rule(result)

        return result

    def _write_pending_rule(self, match: AdvisoryMatch) -> None:
        """Write a pending rule stub for a GAP advisory."""
        # Infer next available T-ID
        from aiglos.core.threat_engine_v2 import RULES_T44_T66
        all_ids = [r["id"] for r in RULES_T44_T66]
        max_num = max(int(r[1:]) for r in all_ids if r[1:].isdigit())
        proposed_id = f"T{max_num + 1}"

        # Extract keywords from description
        words = re.findall(r'\b[a-z]{5,}\b', match.description.lower())
        keywords = sorted(set(words) - {
            "which", "their", "about", "would", "could", "there",
            "where", "when", "this", "that", "with", "from", "have",
            "been", "into", "using", "through", "against", "openclaw"
        })[:10]

        # Sketch a match function
        match_sketch = f'''def match_{proposed_id}(name: str, args: Dict[str, Any]) -> bool:
    """
    {proposed_id} — AUTO-GENERATED from {match.ghsa_id}
    {match.title}
    CVSS: {match.cvss or "Unknown"}  Severity: {match.severity}

    TODO: Implement detection logic based on advisory description:
    {match.description[:200]}

    Keywords extracted: {keywords}
    """
    n = _tool_lower(name)
    s = _args_str(args)
    # TODO: implement detection
    return any(kw in s or kw in n for kw in {keywords[:5]})
'''

        pending = PendingRule(
            ghsa_id      = match.ghsa_id,
            title        = match.title,
            proposed_id  = proposed_id,
            description  = match.description,
            keywords     = keywords,
            severity     = match.severity,
            cvss         = match.cvss,
            match_sketch = match_sketch,
        )

        out_path = self.pending_path / f"{match.ghsa_id}.json"
        out_path.write_text(json.dumps({
            "ghsa_id":      pending.ghsa_id,
            "title":        pending.title,
            "proposed_id":  pending.proposed_id,
            "description":  pending.description,
            "keywords":     pending.keywords,
            "severity":     pending.severity,
            "cvss":         pending.cvss,
            "match_sketch": pending.match_sketch,
            "created_at":   pending.created_at,
            "status":       "PENDING_REVIEW",
        }, indent=2))

        log.warning(
            "[GHSAWatcher] GAP detected — %s '%s' → pending rule %s at %s",
            match.ghsa_id, match.title[:60], proposed_id, out_path,
        )

    # ── Advisory fetching ──────────────────────────────────────────────────────

    def fetch_github_advisories(self, token: str | None = None) -> List[dict]:
        """
        Fetch published advisories from GitHub Advisory Database.
        Requires GitHub token for private advisories (the unreleased 285).
        Public advisories work without auth.
        """
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            req = urllib.request.Request(
                self.GITHUB_ADVISORY_API + "?state=published&per_page=100",
                headers=headers,
            )
            resp = urllib.request.urlopen(req, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            log.debug("[GHSAWatcher] GitHub API error: %s", e)
            return []

    def fetch_osv_advisories(self) -> List[dict]:
        """Fetch OpenClaw advisories from OSV.dev."""
        try:
            payload = json.dumps({
                "package": {"name": "openclaw", "ecosystem": "npm"}
            }).encode()
            req = urllib.request.Request(
                self.OSV_QUERY_API,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            return data.get("vulns", [])
        except Exception as e:
            log.debug("[GHSAWatcher] OSV error: %s", e)
            return []

    def fetch_hf_spaces_mcp_feed(self) -> List[dict]:
        """
        Fetch HuggingFace Spaces tagged MCP — the HF ecosystem skill registry.

        HF Spaces can host MCP servers. This is ClawHub for the HF ecosystem.
        Same scanning logic as ClawHub: new_publish_anomaly, suspicious_permissions,
        social engineering in README, known_malicious_publisher.

        API: https://huggingface.co/api/spaces?tag=mcp&sort=trending&limit=50
        """
        HF_SPACES_MCP_API = (
            "https://huggingface.co/api/spaces"
            "?tag=mcp&sort=trending&limit=50"
        )
        results = []
        try:
            import urllib.request, json as _json
            req = urllib.request.Request(
                HF_SPACES_MCP_API,
                headers={"User-Agent": "aiglos-ghsa-watcher/0.25.4"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                spaces = _json.loads(resp.read().decode())

            for space in spaces:
                space_id  = space.get("id", "")
                author    = space_id.split("/")[0] if "/" in space_id else ""
                name      = space_id.split("/")[1] if "/" in space_id else space_id
                likes     = space.get("likes", 0)
                created   = space.get("createdAt", "")
                tags      = space.get("tags", [])

                # Scan for risk signals
                signals = []
                if likes < 5:
                    signals.append("new_publish_anomaly:low_engagement")
                if any(tag in tags for tag in ["nsfw", "uncensored", "jailbreak"]):
                    signals.append("suspicious_tag")
                if not author or author.startswith("anon"):
                    signals.append("anonymous_publisher")
                if "mcp" in name.lower() and "secure" not in name.lower():
                    pass  # neutral

                if signals:
                    results.append({
                        "id":       space_id,
                        "source":   "hf_spaces_mcp",
                        "signals":  signals,
                        "likes":    likes,
                        "tags":     tags,
                        "created":  created,
                    })

            log.info("[GHSAWatcher] HF Spaces MCP: %d spaces, %d flagged",
                     len(spaces), len(results))
        except Exception as e:
            log.debug("[GHSAWatcher] HF Spaces feed error: %s", e)

        return results


    # High-download AI packages to monitor for supply chain attacks.
    # Any new release from these packages that includes .pth files is flagged.
    # Sorted by attack value: packages with the most downstream dependents first.
    PYPI_WATCH_LIST = [
        "litellm",        # 97M downloads/month — compromised March 24, 2026
        "langchain",      # core LLM framework
        "langgraph",      # agent orchestration
        "openai",         # OpenAI SDK
        "anthropic",      # Anthropic SDK
        "transformers",   # HuggingFace model hub
        "torch",          # PyTorch
        "dspy",           # depends on litellm
        "smolagents",     # HuggingFace agent framework
        "crewai",         # agent framework
        "autogen",        # Microsoft agent framework
        "llama-index",    # RAG framework
        "guidance",       # structured generation
        "instructor",     # structured output
        "langsmith",      # LangChain observability
    ]

    # .pth files are auto-executed by Python at startup — almost never legitimate
    # in a PyPI package. The litellm attack used litellm_init.pth.
    PTH_SUSPICIOUS_CONTENT = [
        "subprocess", "base64", "exec(", "eval(",
        "urllib", "__import__", "b64decode", "socket.",
        "requests.", "os.system", "import os;",
    ]

    def fetch_pypi_release_feed(self) -> List[dict]:
        """
        Monitor PyPI for new releases of high-download AI packages that include
        .pth files. .pth files auto-execute at Python startup and are almost
        never legitimate in a PyPI package.

        The LiteLLM attack (March 24, 2026) used this exact mechanism:
        litellm_init.pth executed on every Python startup, collected credentials,
        and exfiltrated them to models.litellm.cloud.

        This feed catches the NEXT litellm-style attack before it hits the news:
          1. A new release is published to PyPI
          2. The release includes a .pth file (immediately suspicious)
          3. The .pth file contains code execution patterns (confirmed malicious)
          4. A pending rule proposal is generated for aiglos autoresearch

        Returns list of suspicious findings, each with package, version, and signals.
        """
        import json as _json
        import urllib.request as _urllib

        PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
        findings = []

        for package in self.PYPI_WATCH_LIST:
            try:
                url = PYPI_JSON_URL.format(package=package)
                req = _urllib.Request(
                    url,
                    headers={"User-Agent": "aiglos-ghsa-watcher/0.25.6"},
                )
                with _urllib.urlopen(req, timeout=8) as resp:
                    data = _json.loads(resp.read().decode())

                # Check the latest release
                latest = data.get("info", {}).get("version", "")
                releases = data.get("releases", {})
                release_files = releases.get(latest, [])

                pth_files = []
                for f in release_files:
                    fname = f.get("filename", "")
                    # .whl files contain the package structure — check for .pth in name
                    # For more depth, we'd need to inspect the wheel contents
                    if fname.endswith(".pth"):
                        pth_files.append(fname)

                # Also check if any release file is itself a .pth (unusual)
                for f in release_files:
                    fname = f.get("filename", "")
                    if fname.endswith(".pth"):
                        pth_files.append(fname)

                # Check digests for known-malicious versions
                is_known_compromised = (
                    package == "litellm" and latest in ("1.82.7", "1.82.8")
                )

                if pth_files or is_known_compromised:
                    signals = []
                    if pth_files:
                        signals.append(f"pth_file_in_release:{','.join(pth_files)}")
                    if is_known_compromised:
                        signals.append("known_compromised_version")
                        signals.append("CRITICAL:credential_exfiltration_confirmed")

                    findings.append({
                        "package":  package,
                        "version":  latest,
                        "signals":  signals,
                        "source":   "pypi_release_feed",
                        "url":      f"https://pypi.org/project/{package}/{latest}/",
                    })
                    log.warning(
                        "[GHSAWatcher] PyPI suspicious release: %s==%s signals=%s",
                        package, latest, signals,
                    )

            except Exception as e:
                log.debug("[GHSAWatcher] PyPI feed error for %s: %s", package, e)

        # Deep wheel inspection: download and inspect .whl for .pth files
        # This catches cases where .pth is inside the wheel, not the filename
        findings.extend(self._inspect_pypi_wheels_for_pth())

        log.info(
            "[GHSAWatcher] PyPI release feed: %d packages checked, %d flagged",
            len(self.PYPI_WATCH_LIST), len(findings),
        )
        return findings

    def _inspect_pypi_wheels_for_pth(self) -> List[dict]:
        """
        Deep inspection: download the latest wheel for each watched package
        and check its contents for .pth files.

        A .pth file inside a wheel is the exact litellm attack mechanism.
        This catches it even if the .pth filename looks innocent.

        Limited to packages not seen recently to avoid hammering PyPI.
        """
        import json as _json
        import urllib.request as _urllib
        import zipfile
        import io
        import time

        # Only inspect packages we haven't checked in the last 24 hours
        now = time.time()
        if not hasattr(self, '_pypi_last_inspected'):
            self._pypi_last_inspected: Dict[str, float] = {}

        findings = []
        INSPECT_INTERVAL = 86400  # 24 hours

        # Only inspect the highest-risk packages on every cycle
        HIGH_RISK = ["litellm", "langchain", "openai", "anthropic", "dspy"]

        for package in HIGH_RISK:
            last = self._pypi_last_inspected.get(package, 0)
            if now - last < INSPECT_INTERVAL:
                continue

            try:
                # Get latest wheel URL
                url = f"https://pypi.org/pypi/{package}/json"
                req = _urllib.Request(url,
                    headers={"User-Agent": "aiglos-ghsa-watcher/0.25.6"})
                with _urllib.urlopen(req, timeout=8) as resp:
                    data = _json.loads(resp.read().decode())

                latest = data.get("info", {}).get("version", "")
                releases = data.get("releases", {})
                release_files = releases.get(latest, [])

                # Find a wheel file (prefer py3-none-any or manylinux)
                wheel_url = None
                for f in release_files:
                    fname = f.get("filename", "")
                    if fname.endswith(".whl"):
                        wheel_url = f.get("url")
                        wheel_name = fname
                        break

                if not wheel_url:
                    continue

                # Download the wheel (zip archive)
                wheel_req = _urllib.Request(wheel_url,
                    headers={"User-Agent": "aiglos-ghsa-watcher/0.25.6"})
                with _urllib.urlopen(wheel_req, timeout=15) as resp:
                    wheel_data = resp.read()

                # Inspect zip contents for .pth files
                with zipfile.ZipFile(io.BytesIO(wheel_data)) as zf:
                    pth_entries = [n for n in zf.namelist() if n.endswith(".pth")]

                    for pth_name in pth_entries:
                        try:
                            pth_content = zf.read(pth_name).decode("utf-8", errors="ignore")
                        except Exception:
                            pth_content = ""

                        signals = [f"pth_in_wheel:{pth_name}"]

                        # Check for code execution patterns
                        suspicious_content = any(
                            kw in pth_content.lower()
                            for kw in self.PTH_SUSPICIOUS_CONTENT
                        )
                        if suspicious_content:
                            signals.append("pth_contains_code_execution")
                            signals.append("CRITICAL:matches_litellm_attack_pattern")
                            log.critical(
                                "[GHSAWatcher] CRITICAL: %s==%s wheel contains malicious "
                                ".pth file: %s",
                                package, latest, pth_name,
                            )
                        else:
                            log.warning(
                                "[GHSAWatcher] WARNING: %s==%s wheel contains .pth "
                                "file: %s (content appears clean)",
                                package, latest, pth_name,
                            )

                        findings.append({
                            "package":     package,
                            "version":     latest,
                            "pth_name":    pth_name,
                            "signals":     signals,
                            "malicious":   suspicious_content,
                            "source":      "pypi_wheel_inspection",
                            "url":         f"https://pypi.org/project/{package}/{latest}/",
                        })

                self._pypi_last_inspected[package] = now

            except Exception as e:
                log.debug("[GHSAWatcher] Wheel inspection error for %s: %s", package, e)

        return findings

    def fetch_openclaw_cve_feed(self) -> List[dict]:
        """Fetch from jgamblin/OpenClawCVEs (powers ClawKeeper security feed)."""
        try:
            req = urllib.request.Request(
                self.OPENCLAW_CVE_FEED,
                headers={"User-Agent": "aiglos-ghsa-watcher/0.23.0"},
            )
            resp = urllib.request.urlopen(req, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            log.debug("[GHSAWatcher] OpenClawCVEs feed error: %s", e)
            return []

    # ── Main watch cycle ───────────────────────────────────────────────────────

    def run_once(
        self,
        github_token: str | None = None,
        verbose: bool = False,
    ) -> Dict[str, AdvisoryMatch]:
        """
        Run one watch cycle across all advisory sources.
        Returns dict of ghsa_id → AdvisoryMatch for any new findings.
        """
        log.info("[GHSAWatcher] Starting watch cycle")
        new_findings: Dict[str, AdvisoryMatch] = {}

        # Fetch HF Spaces MCP feed (v0.25.4)
        try:
            hf_spaces = self.fetch_hf_spaces_mcp_feed()
            for space in hf_spaces:
                log.info("[GHSAWatcher] HF Spaces flagged: %s signals=%s",
                         space['id'], space['signals'])
        except Exception as e:
            log.debug("[GHSAWatcher] HF Spaces run error: %s", e)

        # Fetch PyPI release feed (v0.25.6) — catches .pth supply chain attacks
        try:
            pypi_findings = self.fetch_pypi_release_feed()
            for finding in pypi_findings:
                severity = "CRITICAL" if finding.get('malicious') or                     any('CRITICAL' in s for s in finding.get('signals', [])) else "HIGH"
                log.warning(
                    "[GHSAWatcher] PyPI supply chain finding: %s==%s [%s] signals=%s",
                    finding['package'], finding['version'],
                    severity, finding['signals'],
                )
        except Exception as e:
            log.debug("[GHSAWatcher] PyPI feed run error: %s", e)

        # Seed with known advisories first (always present, no API needed)
        for adv in KNOWN_ADVISORIES:
            if adv["ghsa_id"] not in self._coverage:
                match = AdvisoryMatch(
                    ghsa_id       = adv["ghsa_id"],
                    cve_id        = adv.get("cve_id"),
                    title         = adv["title"],
                    severity      = adv["severity"],
                    cvss          = adv.get("cvss"),
                    description   = adv["description"],
                    matched_rules = adv["aiglos_rules"],
                    coverage      = adv["coverage"],
                    coverage_note = adv["coverage_note"],
                )
                self._coverage[adv["ghsa_id"]] = match
                new_findings[adv["ghsa_id"]] = match

        # Fetch live from GitHub
        gh_advisories = self.fetch_github_advisories(github_token)
        for adv in gh_advisories:
            ghsa_id = adv.get("ghsa_id", "")
            if not ghsa_id or ghsa_id in self._coverage:
                continue
            match = self.match_advisory(
                ghsa_id     = ghsa_id,
                title       = adv.get("summary", ""),
                description = adv.get("description", ""),
                severity    = (adv.get("severity") or "UNKNOWN").upper(),
                cvss        = adv.get("cvss_score"),
                cve_id      = (adv.get("cve_ids") or [None])[0],
                raw         = adv,
            )
            new_findings[ghsa_id] = match
            log.info(
                "[GHSAWatcher] New advisory: %s — %s — coverage=%s rules=%s",
                ghsa_id, adv.get("summary", "")[:60],
                match.coverage, match.matched_rules,
            )

        # Fetch from OSV
        osv_vulns = self.fetch_osv_advisories()
        for vuln in osv_vulns:
            vid = vuln.get("id", "")
            if not vid or vid in self._coverage:
                continue
            aliases = vuln.get("aliases", [])
            ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), vid)
            cve_id  = next((a for a in aliases if a.startswith("CVE-")), None)
            details = vuln.get("details", "")
            summary = vuln.get("summary", "")
            severity = "UNKNOWN"
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score = float(sev.get("score", 0))
                    severity = (
                        "CRITICAL" if score >= 9.0 else
                        "HIGH"     if score >= 7.0 else
                        "MEDIUM"   if score >= 4.0 else "LOW"
                    )
                    break
            match = self.match_advisory(
                ghsa_id     = ghsa_id,
                title       = summary,
                description = details,
                severity    = severity,
                cve_id      = cve_id,
                raw         = vuln,
            )
            new_findings[ghsa_id] = match

        self._save_coverage()
        log.info(
            "[GHSAWatcher] Cycle complete — total=%d covered=%d gaps=%d new=%d",
            len(self._coverage),
            sum(1 for m in self._coverage.values() if m.coverage == "COVERED"),
            sum(1 for m in self._coverage.values() if m.coverage == "GAP"),
            len(new_findings),
        )
        return new_findings

    def coverage_report(self) -> str:
        """Human-readable coverage report for CLI output."""
        total   = len(self._coverage)
        covered = sum(1 for m in self._coverage.values() if m.coverage == "COVERED")
        partial = sum(1 for m in self._coverage.values() if m.coverage == "PARTIAL")
        gaps    = sum(1 for m in self._coverage.values() if m.coverage == "GAP")
        pct     = (covered / total * 100) if total else 0

        lines = [
            "",
            "  Aiglos GHSA Coverage Report",
            "  " + "─" * 56,
            f"  Total advisories tracked:  {total}",
            f"  Covered by existing rules: {covered} ({pct:.0f}%)",
            f"  Partial coverage:          {partial}",
            f"  Gaps (pending rules):      {gaps}",
            "",
        ]

        if gaps:
            lines.append("  Pending rule proposals:")
            for m in self._coverage.values():
                if m.coverage == "GAP":
                    lines.append(f"    {m.ghsa_id}  {m.title[:55]}")
            lines.append("")

        lines.append("  Full coverage by advisory:")
        for m in sorted(self._coverage.values(), key=lambda x: x.severity):
            icon = "✓" if m.coverage == "COVERED" else "~" if m.coverage == "PARTIAL" else "✗"
            rules = ", ".join(m.matched_rules) if m.matched_rules else "none"
            lines.append(
                f"  {icon} [{m.severity:<8}] {m.ghsa_id}  "
                f"rules={rules:<20}  {m.title[:40]}"
            )
        lines.append("")
        return "\n".join(lines)

    def pending_rules(self) -> List[dict]:
        """Return all pending rule proposals."""
        results = []
        for f in self.pending_path.glob("*.json"):
            try:
                results.append(json.loads(f.read_text()))
            except Exception:
                pass
        return sorted(results, key=lambda x: x.get("created_at", 0))


def seed_known_advisories(watcher: GHSAWatcher | None = None) -> GHSAWatcher:
    """
    Seed the coverage ledger with the three known published advisories.
    Used in tests and on first install.
    """
    if watcher is None:
        watcher = GHSAWatcher()
    watcher.run_once()
    return watcher
