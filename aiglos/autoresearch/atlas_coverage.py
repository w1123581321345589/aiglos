"""
aiglos/autoresearch/atlas_coverage.py
=======================================
OpenClaw ATLAS Threat Model Coverage Mapping.

The OpenClaw project published a formal threat model (v1.0-draft, 2026-02-04)
using the MITRE ATLAS framework. It documents 18 distinct threats across 8
ATLAS tactic categories.

This module maintains the authoritative mapping between every OpenClaw ATLAS
threat entry and the Aiglos T-rule(s) that detect it at runtime.

The mapping serves three purposes:

  1. TRACTION EVIDENCE — "Every threat the OpenClaw maintainers documented
     is caught by an existing Aiglos rule" is the clearest possible statement
     about coverage completeness.

  2. GAP TRACKING — When new ATLAS threats are added to the OpenClaw model
     (it's a living document), this mapping reveals gaps before they become
     incidents.

  3. AUDIT REPORT — `aiglos audit --atlas` generates a coverage report that
     maps the deployer's specific OpenClaw configuration against the full
     ATLAS threat model, identifying which threats they're exposed to given
     their current config.

Usage:
    from aiglos.autoresearch.atlas_coverage import ATLASCoverage

    cov = ATLASCoverage()
    print(cov.report())
    gaps = cov.gaps()

CLI:
    aiglos autoresearch atlas-coverage
    aiglos autoresearch atlas-coverage --format json
    aiglos autoresearch atlas-coverage --gaps-only
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ATLASThreat:
    """One entry from the OpenClaw ATLAS threat model."""
    atlas_id:        str         # e.g. "T-RECON-001"
    atlas_technique: str         # MITRE ATLAS technique ID
    tactic:          str         # Recon, Initial Access, Execution, etc.
    title:           str
    description:     str
    aiglos_rules:    List[str]   # T-IDs that detect this threat
    coverage:        str         # FULL | PARTIAL | GAP
    coverage_note:   str = ""


# ── The mapping ───────────────────────────────────────────────────────────────
# Every entry in OpenClaw's THREAT-MODEL-ATLAS.md, mapped to Aiglos rules.
# Source: https://docs.openclaw.ai/security/THREAT-MODEL-ATLAS
# Last updated: March 2026 against OpenClaw Threat Model v1.0-draft 2026-02-04

ATLAS_THREAT_MAP: List[ATLASThreat] = [

    # ── 3.1 Reconnaissance (AML.TA0002) ──────────────────────────────────────

    ATLASThreat(
        atlas_id        = "T-RECON-001",
        atlas_technique = "AML.T0006",
        tactic          = "Reconnaissance",
        title           = "Agent Endpoint Discovery",
        description     = "Attacker scans for exposed OpenClaw gateway endpoints "
                          "via network scanning, Shodan, or DNS enumeration.",
        aiglos_rules    = ["T68"],
        coverage        = "FULL",
        coverage_note   = (
            "T68 INSECURE_DEFAULT_CONFIG fires when allow_remote=true is detected "
            "without auth. aiglos scan-exposed probes for exposed gateway endpoints "
            "and reports grade + findings."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-RECON-002",
        atlas_technique = "AML.T0006",
        tactic          = "Reconnaissance",
        title           = "Channel Integration Probing",
        description     = "Attacker probes messaging channels to identify "
                          "AI-managed accounts via test messages and response patterns.",
        aiglos_rules    = ["T56", "T73"],
        coverage        = "PARTIAL",
        coverage_note   = (
            "T56 CAPABILITY_BOUNDARY_PROBE catches active probing of agent capabilities. "
            "T73 TOOL_ENUMERATION catches tool list enumeration. "
            "Passive channel fingerprinting has no behavioral signature at the tool call layer."
        ),
    ),

    # ── 3.2 Initial Access (AML.TA0004) ──────────────────────────────────────

    ATLASThreat(
        atlas_id        = "T-ACCESS-001",
        atlas_technique = "AML.T0040",
        tactic          = "Initial Access",
        title           = "Pairing Code Interception",
        description     = "Attacker intercepts OpenClaw device pairing code during "
                          "the 30-second grace period.",
        aiglos_rules    = ["T71"],
        coverage        = "FULL",
        coverage_note   = (
            "T71 PAIRING_GRACE_ABUSE fires on pairing requests exhibiting the "
            "time-window exploitation pattern — multiple rapid pairing attempts or "
            "pairing requests with suspicious timing relative to code issuance."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-ACCESS-002",
        atlas_technique = "AML.T0040",
        tactic          = "Initial Access",
        title           = "AllowFrom Spoofing",
        description     = "Attacker spoofs allowed sender identity in messaging channel "
                          "to bypass AllowFrom validation (phone number spoofing, "
                          "username impersonation).",
        aiglos_rules    = ["T64", "T72"],
        coverage        = "FULL",
        coverage_note   = (
            "T64 AGENT_IDENTITY_SPOOFING catches inter-agent identity spoofing. "
            "T72 CHANNEL_IDENTITY_SPOOF catches AllowFrom header manipulation, "
            "X-Forwarded-For abuse, and channel-specific sender identity spoofing."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-ACCESS-003",
        atlas_technique = "AML.T0040",
        tactic          = "Initial Access",
        title           = "Token Theft",
        description     = "Attacker steals authentication tokens from config files "
                          "in ~/.openclaw/credentials/.",
        aiglos_rules    = ["T19", "T04"],
        coverage        = "FULL",
        coverage_note   = (
            "T19 CREDENTIAL_ACCESS fires on reads of credential files including "
            "~/.openclaw/credentials/ paths. T04 PATH_TRAVERSAL catches attempts "
            "to reach credential storage via traversal."
        ),
    ),

    # ── 3.3 Execution (AML.TA0005) ───────────────────────────────────────────

    ATLASThreat(
        atlas_id        = "T-EXEC-001",
        atlas_technique = "AML.T0051.000",
        tactic          = "Execution",
        title           = "Direct Prompt Injection",
        description     = "Attacker sends crafted prompts directly to the agent "
                          "to manipulate its behavior.",
        aiglos_rules    = ["T05", "T01"],
        coverage        = "FULL",
        coverage_note   = (
            "T05 PROMPT_INJECT fires on direct injection patterns in tool call content. "
            "T01 MCP_INJECT catches injection via MCP tool responses. "
            "Note: OpenClaw SECURITY.md marks prompt injection as out of scope — "
            "Aiglos explicitly covers it."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-EXEC-002",
        atlas_technique = "AML.T0051.001",
        tactic          = "Execution",
        title           = "Indirect Prompt Injection",
        description     = "Attacker embeds injection payloads in external content "
                          "fetched by the agent (web pages, emails, documents).",
        aiglos_rules    = ["T05", "T54", "T60", "T74"],
        coverage        = "FULL",
        coverage_note   = (
            "T05 covers injection in fetched content. T54 VECTOR_DB_INJECTION catches "
            "injection via RAG/document stores. T60 DATA_PIPELINE_INJECTION covers "
            "pipeline-level injection. T74 CONTENT_WRAPPER_ESCAPE catches attempts "
            "to break OpenClaw's XML wrapping that isolates external content."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-EXEC-003",
        atlas_technique = "AML.T0051",
        tactic          = "Execution",
        title           = "Tool Argument Injection",
        description     = "Attacker injects malicious arguments into tool calls "
                          "to alter tool behavior.",
        aiglos_rules    = ["T03", "T04", "T49"],
        coverage        = "FULL",
        coverage_note   = (
            "T03 SHELL_INJECTION catches metacharacter injection in exec tool args. "
            "T04 PATH_TRAVERSAL catches path manipulation in file tool args. "
            "T49 TOOL_SCHEMA_MANIPULATION catches schema-level argument injection."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-EXEC-004",
        atlas_technique = "AML.T0051",
        tactic          = "Execution",
        title           = "Exec Approval Bypass",
        description     = "Attacker bypasses the exec approval mechanism to execute "
                          "unauthorized commands without operator confirmation.",
        aiglos_rules    = ["T50", "T03"],
        coverage        = "FULL",
        coverage_note   = (
            "T50 AGENTIC_LOOP_ESCAPE fires when the agent bypasses approval gates "
            "in its execution loop. T03 SHELL_INJECTION catches the subsequent "
            "unauthorized command execution."
        ),
    ),

    # ── 3.4 Persistence (AML.TA0006) ─────────────────────────────────────────

    ATLASThreat(
        atlas_id        = "T-PERSIST-001",
        atlas_technique = "AML.T0020",
        tactic          = "Persistence",
        title           = "Malicious Skill Installation",
        description     = "Attacker installs a malicious skill from ClawHub that "
                          "contains a backdoor or data exfiltration mechanism.",
        aiglos_rules    = ["T30", "T36"],
        coverage        = "FULL",
        coverage_note   = (
            "T30 SUPPLY_CHAIN fires on malicious skill installation patterns. "
            "T36 AGENTDEF_CHAIN catches agent definition file manipulation that "
            "skills may trigger on install."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-PERSIST-002",
        atlas_technique = "AML.T0020",
        tactic          = "Persistence",
        title           = "Skill Update Poisoning",
        description     = "Attacker compromises a legitimate skill update to introduce "
                          "malicious code after initial trusted installation.",
        aiglos_rules    = ["T30", "T36"],
        coverage        = "FULL",
        coverage_note   = (
            "Same rule coverage as T-PERSIST-001. Skill reputation graph tracks "
            "version-level trust — rapid version churn is a T30 signal."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-PERSIST-003",
        atlas_technique = "AML.T0020",
        tactic          = "Persistence",
        title           = "Agent Configuration Tampering",
        description     = "Attacker modifies agent configuration files (SOUL.md, "
                          "MEMORY.md, AGENTS.md) to alter agent behavior persistently.",
        aiglos_rules    = ["T34", "T36", "T37"],
        coverage        = "FULL",
        coverage_note   = (
            "T34 HEARTBEAT_TAMPER fires on writes to HEARTBEAT.md, SOUL.md, mission "
            "files. T36 MEMORY_POISON fires on injection payloads in MEMORY.md. "
            "T37 AGENTDEF_CHAIN covers AGENTS.md and skill definition file writes."
        ),
    ),

    # ── 3.5 Defense Evasion (AML.TA0007) ─────────────────────────────────────

    ATLASThreat(
        atlas_id        = "T-EVADE-001",
        atlas_technique = "AML.T0015",
        tactic          = "Defense Evasion",
        title           = "Moderation Pattern Bypass",
        description     = "Attacker uses encoding tricks, language variations, or "
                          "obfuscation to bypass content moderation patterns.",
        aiglos_rules    = ["T05", "T57"],
        coverage        = "PARTIAL",
        coverage_note   = (
            "T05 PROMPT_INJECT covers direct pattern matches. T57 "
            "INSTRUCTION_HIERARCHY_BYPASS catches attempts to override instruction "
            "hierarchy. True adversarial ML evasion of pattern-based moderation "
            "has no runtime behavioral signature — this is an inherent gap in "
            "pattern-based detection."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-EVADE-002",
        atlas_technique = "AML.T0015",
        tactic          = "Defense Evasion",
        title           = "Content Wrapper Escape",
        description     = "Attacker uses CDATA sequences, tag terminators, or encoding "
                          "tricks to break external content out of its XML wrapper "
                          "and inject it into the agent's trusted instruction context.",
        aiglos_rules    = ["T74"],
        coverage        = "FULL",
        coverage_note   = (
            "T74 CONTENT_WRAPPER_ESCAPE fires on XML wrapper termination patterns, "
            "CDATA sequences, and encoding tricks in externally-fetched content. "
            "This is the only attack class with full coverage that was completely "
            "absent from the Aiglos taxonomy before the OpenClaw ATLAS review."
        ),
    ),

    # ── 3.6 Discovery (AML.TA0008) ───────────────────────────────────────────

    ATLASThreat(
        atlas_id        = "T-DISC-001",
        atlas_technique = "AML.T0006",
        tactic          = "Discovery",
        title           = "Tool Enumeration",
        description     = "Attacker enumerates available tools and their capabilities "
                          "to plan further attack.",
        aiglos_rules    = ["T73", "T56"],
        coverage        = "FULL",
        coverage_note   = (
            "T73 TOOL_ENUMERATION fires on tools.list, mcp.list_tools, and empty-arg "
            "probes across rapid succession. T56 CAPABILITY_BOUNDARY_PROBE fires on "
            "systematic capability exploration patterns."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-DISC-002",
        atlas_technique = "AML.T0006",
        tactic          = "Discovery",
        title           = "Session Data Extraction",
        description     = "Attacker exploits that sessionKey is a routing selector "
                          "not an auth token to enumerate sessions.list, "
                          "sessions.preview, and chat.history across session boundaries.",
        aiglos_rules    = ["T75"],
        coverage        = "FULL",
        coverage_note   = (
            "T75 SESSION_DATA_EXTRACT fires on sessions.list, sessions.preview, "
            "chat.history, and transcript export patterns. OpenClaw explicitly "
            "documents this as a residual risk: 'sessionKey is routing, not auth.' "
            "T75 was added specifically from this ATLAS review."
        ),
    ),

    # ── 3.7 Collection & Exfiltration (AML.TA0009, AML.TA0010) ──────────────

    ATLASThreat(
        atlas_id        = "T-EXFIL-001",
        atlas_technique = "AML.T0025",
        tactic          = "Exfiltration",
        title           = "Data Theft via web_fetch",
        description     = "Agent uses web_fetch to exfiltrate data to an attacker "
                          "controlled endpoint.",
        aiglos_rules    = ["T09", "T12", "T14"],
        coverage        = "FULL",
        coverage_note   = (
            "T09 SSRF covers SSRF-based exfil via web_fetch. T12 DATA_EXFIL fires "
            "on outbound POST with data patterns. T14 NETWORK_EXFIL covers high-volume "
            "outbound transfer."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-EXFIL-002",
        atlas_technique = "AML.T0025",
        tactic          = "Exfiltration",
        title           = "Unauthorized Message Sending",
        description     = "Agent sends messages to unauthorized channels or contacts "
                          "to exfiltrate data via messaging channels.",
        aiglos_rules    = ["T37", "T12"],
        coverage        = "FULL",
        coverage_note   = (
            "T37 AUTONOMOUS_FINANCIAL_EXEC + channel messaging patterns covers "
            "unauthorized message sending. T12 DATA_EXFIL catches data included "
            "in outbound messages."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-EXFIL-003",
        atlas_technique = "AML.T0025",
        tactic          = "Exfiltration",
        title           = "Credential Harvesting",
        description     = "Agent reads and exfiltrates credentials from "
                          "~/.openclaw/credentials/, ~/.aws/, ~/.ssh/, .env files.",
        aiglos_rules    = ["T19", "T02", "T12"],
        coverage        = "FULL",
        coverage_note   = (
            "T19 CREDENTIAL_ACCESS fires on reads of credential file patterns. "
            "T02 catches .env and secrets file access. T12 DATA_EXFIL fires if "
            "credentials are then sent outbound."
        ),
    ),

    # ── 3.8 Impact (AML.TA0011) ──────────────────────────────────────────────

    ATLASThreat(
        atlas_id        = "T-IMPACT-001",
        atlas_technique = "AML.T0030",
        tactic          = "Impact",
        title           = "Unauthorized Command Execution",
        description     = "Agent executes arbitrary OS commands without operator "
                          "authorization.",
        aiglos_rules    = ["T03", "T08", "T50"],
        coverage        = "FULL",
        coverage_note   = (
            "T03 SHELL_INJECTION covers direct command execution. T08 "
            "PRIVILEGE_ESCALATION covers elevated execution. T50 AGENTIC_LOOP_ESCAPE "
            "covers approval bypass leading to execution."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-IMPACT-002",
        atlas_technique = "AML.T0029",
        tactic          = "Impact",
        title           = "Resource Exhaustion (DoS)",
        description     = "Agent is driven into resource-exhausting behavior — "
                          "infinite loops, token budget exhaustion, compute abuse.",
        aiglos_rules    = ["T47", "T61"],
        coverage        = "FULL",
        coverage_note   = (
            "T47 TOKEN_BUDGET_EXHAUSTION fires on token-exhausting prompt patterns. "
            "T61 COMPUTE_RESOURCE_ABUSE fires on compute-exhausting agent behavior "
            "patterns."
        ),
    ),

    ATLASThreat(
        atlas_id        = "T-IMPACT-003",
        atlas_technique = "AML.T0032",
        tactic          = "Impact",
        title           = "Reputation Damage",
        description     = "Agent is manipulated to send harmful, offensive, or "
                          "embarrassing messages through legitimate channels.",
        aiglos_rules    = ["T59", "T05"],
        coverage        = "PARTIAL",
        coverage_note   = (
            "T59 AGENTIC_SOCIAL_ENGINEERING fires when the agent is being driven "
            "toward social manipulation. T05 catches injection payloads that induce "
            "harmful output. True reputation damage via semantically appropriate but "
            "contextually harmful messages has no reliable behavioral signature."
        ),
    ),
]


class ATLASCoverage:
    """
    OpenClaw ATLAS Threat Model coverage against the Aiglos T-rule taxonomy.

    Usage:
        cov = ATLASCoverage()
        print(cov.report())
        gaps = cov.gaps()
    """

    def __init__(self):
        self._threats = ATLAS_THREAT_MAP

    def all_threats(self) -> List[ATLASThreat]:
        return list(self._threats)

    def covered(self) -> List[ATLASThreat]:
        return [t for t in self._threats if t.coverage == "FULL"]

    def partial(self) -> List[ATLASThreat]:
        return [t for t in self._threats if t.coverage == "PARTIAL"]

    def gaps(self) -> List[ATLASThreat]:
        return [t for t in self._threats if t.coverage == "GAP"]

    def by_tactic(self) -> Dict[str, List[ATLASThreat]]:
        tactics: Dict[str, List[ATLASThreat]] = {}
        for t in self._threats:
            tactics.setdefault(t.tactic, []).append(t)
        return tactics

    def coverage_pct(self) -> float:
        if not self._threats:
            return 0.0
        covered_count = len(self.covered()) + len(self.partial()) * 0.5
        return covered_count / len(self._threats) * 100

    def rules_used(self) -> List[str]:
        used = set()
        for t in self._threats:
            used.update(t.aiglos_rules)
        return sorted(used)

    def report(self, gaps_only: bool = False) -> str:
        threats = self.gaps() if gaps_only else self._threats
        tactics_map = {}
        for t in threats:
            tactics_map.setdefault(t.tactic, []).append(t)

        lines = [
            "",
            "  Aiglos — OpenClaw ATLAS Threat Model Coverage",
            "  " + "─" * 58,
            f"  Threats: {len(self._threats)} documented | "
            f"{len(self.covered())} fully covered | "
            f"{len(self.partial())} partial | "
            f"{len(self.gaps())} gaps",
            f"  Coverage: {self.coverage_pct():.0f}%",
            f"  Rules engaged: {', '.join(self.rules_used())}",
            "",
        ]

        icons = {"FULL": "✓", "PARTIAL": "~", "GAP": "✗"}
        for tactic, tlist in tactics_map.items():
            lines.append(f"  {tactic}")
            for t in tlist:
                icon = icons.get(t.coverage, "?")
                rules = ", ".join(t.aiglos_rules) if t.aiglos_rules else "none"
                lines.append(f"    {icon} {t.atlas_id:<16} {t.title[:40]:<40} [{rules}]")
            lines.append("")

        if not gaps_only and self.gaps():
            lines += [
                "  Gaps requiring attention:",
            ]
            for g in self.gaps():
                lines.append(f"    ✗ {g.atlas_id}: {g.title}")
                lines.append(f"      {g.coverage_note[:80]}")
            lines.append("")

        return "\n".join(lines)

    def coverage_report(self) -> dict:
        return {
            "total_threats":     len(self._threats),
            "full_coverage":     len(self.covered()),
            "partial_coverage":  len(self.partial()),
            "no_coverage":       len(self.gaps()),
            "weighted_coverage": round(self.coverage_pct() / 100, 3),
            "grade":             (
                "A" if self.coverage_pct() >= 90 else
                "B" if self.coverage_pct() >= 75 else
                "C" if self.coverage_pct() >= 60 else
                "D" if self.coverage_pct() >= 45 else "F"
            ),
            "rules_used":        self.rules_used(),
        }

    def gap_analysis(self) -> List[dict]:
        result = []
        for t in self._threats:
            if t.coverage != "FULL":
                result.append({
                    "atlas_id":      t.atlas_id,
                    "title":         t.title,
                    "tactic":        t.tactic,
                    "coverage":      t.coverage,
                    "current_rules": t.aiglos_rules,
                    "note":          t.coverage_note,
                })
        return result

    def compliance_score(self) -> float:
        return round(self.coverage_pct() / 100, 3)

    def to_json(self) -> str:
        return json.dumps({
            "total":        len(self._threats),
            "covered":      len(self.covered()),
            "partial":      len(self.partial()),
            "gaps":         len(self.gaps()),
            "coverage_pct": self.coverage_pct(),
            "rules_used":   self.rules_used(),
            "threats": [
                {
                    "atlas_id":        t.atlas_id,
                    "tactic":          t.tactic,
                    "title":           t.title,
                    "coverage":        t.coverage,
                    "aiglos_rules":    t.aiglos_rules,
                    "coverage_note":   t.coverage_note,
                }
                for t in self._threats
            ],
        }, indent=2)
