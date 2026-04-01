"""
aiglos.adaptive.campaign
=========================
T06 GOAL_DRIFT — campaign-mode session analysis.

This is the capability that Onyx is building from the top down (intent
legibility via trained models). Aiglos builds it from the bottom up:
the observation graph already has every event from every session. T06
asks whether the sequence of events *across a session* forms a pattern
that looks like reconnaissance or a coordinated attack, even when each
individual event looks clean.

The insight: a single `git log` is Tier 1 AUTONOMOUS — auto-allowed.
A single `cat ~/.aws/credentials` fires T19. But a session that does:
  git log → ls -la → cat package.json → cat .env.example → cat .env
is a reconnaissance sweep even though no single call is catastrophic.

Campaign-mode analysis catches this by looking at sequences, not atoms.

Six campaign patterns:

  RECON_SWEEP          — sequential read of credential and config files
                         in a single session without any build/test activity
  CREDENTIAL_ACCUMULATE — multiple distinct credential access events in
                         one session (T19 fires 3+ times on different paths)
  EXFIL_SETUP          — internal reconnaissance followed by outbound
                         network setup in same session (T19/T08 → T23/T12)
  PERSISTENCE_CHAIN    — writes to startup paths after privilege check
                         (T10 → T11 in same session)
  LATERAL_PREP         — credential harvest + network scan + SSH spawn
                         pattern (T19 → T12 in same session)
  AGENTDEF_CHAIN       — agent def read followed by agent def write in
                         same session (T36_AGENTDEF READ → WRITE, suggests
                         the agent read its own definition before modifying it,
                         the exact pattern in the McKinsey/Lilli attack)

Each CampaignResult carries:
  - pattern_id: string identifier
  - confidence: 0.0-1.0
  - evidence: the specific events that triggered the pattern
  - session_id: which session
  - recommendation: what to do

Usage:
    from aiglos.adaptive.campaign import CampaignAnalyzer

    analyzer = CampaignAnalyzer(graph)

    # Analyze the most recent session
    results = analyzer.analyze_session(session_id)
    for r in results:
        print(r.pattern_id, r.confidence, r.recommendation)

    # Analyze all sessions in the last N hours
    results = analyzer.analyze_recent(hours=24)

    # Register T06 findings as inspection triggers
    triggers = analyzer.to_triggers(results)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("aiglos.adaptive.campaign")


# ── Campaign pattern definitions ──────────────────────────────────────────────

# Each pattern is a dict:
#   name:         string ID
#   description:  human-readable
#   sequence:     list of rule_id sets — each element is a set of rules,
#                 at least one of which must fire, in order
#   min_events:   minimum distinct events required
#   confidence:   base confidence when fully matched
#   surfaces:     which surfaces to look at (None = all)

_CAMPAIGN_PATTERNS = [
    {
        "name":        "RECON_SWEEP",
        "description": "Sequential read of credential/config files with no build activity",
        "sequence":    [
            {"T19"},          # credential file access
            {"T19", "T08"},   # another access or path traversal
        ],
        "min_events":  3,
        "confidence":  0.75,
        "surfaces":    {"subprocess"},
        "amplifiers":  {
            # If these rule_ids are ABSENT, confidence goes up (no legitimate work happening)
            "absent_rules": {"T2_MONITORED"},  # no build/install activity
        },
    },
    {
        "name":        "CREDENTIAL_ACCUMULATE",
        "description": "Multiple distinct credential access events in one session",
        "sequence":    [
            {"T19"},
            {"T19"},
            {"T19"},
        ],
        "min_events":  3,
        "confidence":  0.80,
        "surfaces":    {"subprocess", "http"},
        "amplifiers":  {},
    },
    {
        "name":        "EXFIL_SETUP",
        "description": "Internal recon followed by outbound network setup",
        "sequence":    [
            {"T19", "T08"},   # recon / path traversal
            {"T23", "T12"},   # exfil subprocess or lateral movement
        ],
        "min_events":  2,
        "confidence":  0.85,
        "surfaces":    None,  # any surface
        "amplifiers":  {},
    },
    {
        "name":        "PERSISTENCE_CHAIN",
        "description": "Privilege check followed by startup persistence write",
        "sequence":    [
            {"T10"},  # priv esc
            {"T11"},  # persistence
        ],
        "min_events":  2,
        "confidence":  0.90,
        "surfaces":    {"subprocess"},
        "amplifiers":  {},
    },
    {
        "name":        "LATERAL_PREP",
        "description": "Credential harvest + network scan pattern",
        "sequence":    [
            {"T19"},                # credential access
            {"T12", "T22"},         # lateral movement or recon
        ],
        "min_events":  2,
        "confidence":  0.85,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "AGENTDEF_CHAIN",
        "description": "Agent def read followed by write — McKinsey/Lilli pattern",
        "sequence":    [
            {"T36_AGENTDEF"},  # agent def read or write access
            {"T36_AGENTDEF"},  # second T36 event in same session
        ],
        "min_events":  2,
        "confidence":  0.88,
        "surfaces":    None,
        "amplifiers":  {
            # Confidence boost if one is READ and one is WRITE
            "read_then_write": True,
        },
    },
    {
        "name":        "METACOGNITIVE_POISON_CHAIN",
        "description": (
            "Self-improvement pipeline poison: adversarial content injected into "
            "memory or persistent state (T31/T79), then the improvement procedure "
            "reads that poisoned data when generating the next agent version (T82). "
            "Based on DGM-Hyperagents architecture (Facebook Research, March 2026): "
            "the meta-agent reads agent archive, evaluation results, and performance "
            "history when generating improved agents. If any of those stores are "
            "compromised, every future generation inherits the poison. "
            "The adversary does not attack each generated agent — they attack the "
            "process that creates them. One successful T31/T79 → T82 sequence means "
            "persistent influence over all future agent generations with no further "
            "effort. "
            "Confidence 0.95: T31 or T79 followed by T82 in the same session is "
            "the two-step attack. T82 alone could be a legitimate write; combined "
            "with a prior memory injection it confirms pipeline poisoning intent. "
            "T82 amplifier 2.0x: forward propagation to all future generations "
            "multiplies impact beyond any single-session attack. "
            "Architecture sources: "
            "(1) DGM-Hyperagents (Facebook Research, March 2026) — evolutionary agent "
            "pipelines where archive + eval results feed future generations. "
            "(2) The AI Scientist (Sakana AI, Nature 2026) — Automated Reviewer "
            "judgments feed back into paper generation. The scaling law of science "
            "(better foundation models → more convincing outputs) means a T82 "
            "injection into reviewer criteria becomes harder to detect over time, "
            "not easier — the attack scales with the underlying model capability."
        ),
        "sequence":    [
            {"T31", "T79"},         # in-session or persistent memory injection
            {"T82"},                # improvement procedure reads poisoned data
        ],
        "min_events":  2,
        "confidence":  0.95,
        "surfaces":    None,
        "amplifiers":  {"T82": 2.0},
    },
    {
        "name":        "REPO_TAKEOVER_CHAIN",
        "description": (
            "Supply chain compromise followed by credential harvest and subsequent "
            "supply chain republication. The full LiteLLM attack pattern (March 24, 2026): "
            "T30 SUPPLY_CHAIN (poisoned package installed) → T81 PTH_FILE_INJECT "
            "(persistence .pth file written) → T04 CRED_HARVEST (SSH keys, API tokens, "
            "AWS/GCP/Azure creds collected) → T41 OUTBOUND_SECRET_LEAK (credentials "
            "exfiltrated) → T30 again (attacker uses harvested GitHub/PyPI tokens to "
            "publish new poisoned releases or close security issues). "
            "The final T30 is the attacker becoming the maintainer — closing the "
            "GitHub issue as 'not planned' using the stolen GitHub token. "
            "Confidence 0.97 — T81 + T04 in the same session is near-certain "
            "malicious intent. The final T30 confirms full repository takeover."
        ),
        "sequence":    [
            {"T30", "T81"},              # supply chain install or .pth write
            {"T04", "T19", "T41"},       # credential harvest + exfil
            {"T30"},                     # attacker republishes using stolen tokens
        ],
        "min_events":  2,
        "confidence":  0.97,
        "surfaces":    None,
        "amplifiers":  {"T81": 2.0, "T04": 1.5},  # .pth + cred harvest = near-certain
    },
    {
        "name":        "GIGABRAIN_MEMORY_POISON",
        "description": (
            "Persistent memory injection sequence: T31 in-session memory test "
            "followed by T79 persistent store commit. The adversary tests the "
            "in-session injection path first (T31), then — if not caught — "
            "commits the adversarial content to the persistent memory backend "
            "via T79. Future sessions will receive the injected context "
            "automatically from Gigabrain, MemoryOS, or similar tools. "
            "Confidence 0.95: T31 + T79 in the same session is the two-step "
            "attack pattern, not a coincidence."
        ),
        "sequence":    [
            {"T31"},                # in-session memory probe
            {"T79"},                # commit to persistent store
        ],
        "min_events":  2,
        "confidence":  0.95,
        "surfaces":    None,
        "amplifiers":  {"T79": 1.5},  # persistence amplifies everything
    },
    {
        "name":        "NEMOCLAW_POLICY_HIJACK",
        "description": (
            "NemoClaw policy bypass followed by insecure config or exfil attempt. "
            "The agent modified its own NemoClaw OpenShell policy file (T76), then "
            "immediately attempted to access an insecure configuration or exfiltrate "
            "data. Policy modification is the setup; the subsequent action is the "
            "payoff. Confidence 0.96 — T76 can only fire on write operations to "
            "specific known policy paths, making false positive risk negligible."
        ),
        "sequence":    [
            {"T76"},                     # policy file write — governance escape setup
            {"T68", "T12", "T14", "T09"},# insecure config, data exfil, or SSRF
        ],
        "min_events":  2,
        "confidence":  0.96,
        "surfaces":    None,
        "amplifiers":  {"T76": 1.4},     # policy bypass amplifies everything downstream
    },
    {
        "name":        "SUPERPOWERS_PLAN_HIJACK",
        "description": (
            "Plan drift followed by data exfiltration or network exfil attempt. "
            "The agent deviated from the approved Superpowers implementation plan "
            "(T69) and then attempted to send data outbound. The plan drift is the "
            "setup; the exfil is the payoff. This two-step sequence — deviation "
            "from approved plan followed by outbound data — is the highest-confidence "
            "campaign signature possible when Superpowers is installed."
        ),
        "sequence":    [
            {"T69"},   # plan drift — agent outside approved scope
            {"T12", "T14", "T37"},  # data exfil / outbound POST / SSRF
        ],
        "min_events":  2,
        "confidence":  0.97,
        "surfaces":    None,
        "amplifiers":  {"T69": 1.3},  # plan drift amplifies all downstream events
    },
    {
        "name":        "SANDBOX_CONFIRMED_ESCAPE",
        "description": (
            "Tool call confirmed impossible in sandbox context followed by "
            "additional escape attempts. When sandbox_context=True, a single "
            "impossible call is already CRITICAL. A second attempt in the same "
            "session window confirms the agent is actively probing or has "
            "partially escaped — not a misconfiguration, a campaign."
        ),
        "sequence":    [
            {"T50"},   # agentic loop escape / sandbox escape confirmed
            {"T50"},   # second confirmed escape = active campaign
        ],
        "min_events":  2,
        "confidence":  0.96,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "SANDBOX_ESCAPE_ATTEMPT",
        "description": (
            "Three or more sandbox policy violations in one session. "
            "An agent blocked from filesystem access, shell execution, or "
            "external HTTP calls repeatedly attempting the same escape vector "
            "indicates an active escape campaign rather than accidental misconfiguration."
        ),
        "sequence":    [
            {"T07", "T36_AGENTDEF", "T03"},   # first escape attempt
            {"T07", "T36_AGENTDEF", "T03"},   # second attempt
            {"T07", "T36_AGENTDEF", "T03"},   # third confirms campaign
        ],
        "min_events":  3,
        "confidence":  0.87,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "SKILL_CHAIN",
        "description": (
            "Skill file write followed by instruction override — "
            "Context Hub skill poisoning pattern. A write to a SKILL.md "
            "or ~/.claude/skills/ file immediately followed by a prompt "
            "injection event indicates the attacker poisoned the skill "
            "definition to persist injection across all future sessions."
        ),
        "sequence":    [
            {"T36_AGENTDEF"},  # skill/agent def write (now includes skills/)
            {"T01", "T27"},   # prompt injection follows from poisoned skill
        ],
        "min_events":  2,
        "confidence":  0.91,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "GAAS_TAKEOVER",
        "description": (
            "GaaS tenant escalation followed by cross-tenant data access — "
            "the pattern of an agent that gains cross-tenant API key access "
            "and immediately begins harvesting data across tenant boundaries. "
            "T66 (tenant key confusion) → T45 (cross-tenant data access) → "
            "T22 (data exfiltration)."
        ),
        "sequence":    [
            {"T66"},            # tenant key confusion/escalation
            {"T45"},            # cross-tenant access
            {"T22", "T19"},     # exfiltration or credential harvest
        ],
        "min_events":  2,
        "confidence":  0.93,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "INFERENCE_HIJACK_CHAIN",
        "description": (
            "Model fingerprint probe followed by inference router hijack — "
            "attacker first learns what model is running (T51), then attempts "
            "to redirect inference to a different model or modify the system "
            "prompt (T44). Common in Dynamo/OpenShell enterprise deployments."
        ),
        "sequence":    [
            {"T51"},            # model fingerprint probe (reconnaissance)
            {"T44"},            # inference router hijack
        ],
        "min_events":  2,
        "confidence":  0.88,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "RAG_POISON_CHAIN",
        "description": (
            "Vector database injection followed by tool result forgery — "
            "the attacker first poisons the RAG retrieval store (T54), then "
            "when the agent retrieves the poisoned document and begins acting "
            "on it, forges tool results to cover the operation (T55)."
        ),
        "sequence":    [
            {"T54"},            # vector DB injection
            {"T55", "T27"},     # tool result forgery or prompt injection from retrieval
        ],
        "min_events":  2,
        "confidence":  0.87,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "MULTI_AGENT_IMPERSONATION",
        "description": (
            "Agent identity spoofing followed by privilege escalation — "
            "an agent claims to be a supervisor/admin agent (T64), then uses "
            "that claimed identity to attempt privilege escalation (T08) or "
            "cross-tenant access (T45)."
        ),
        "sequence":    [
            {"T64"},            # agent identity spoofing
            {"T08", "T45"},     # privilege escalation or cross-tenant access
        ],
        "min_events":  2,
        "confidence":  0.90,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "CAPABILITY_EXPLOIT_CHAIN",
        "description": (
            "Capability boundary probe followed by targeted exploit — "
            "systematic reconnaissance (T56) immediately followed by one of "
            "the confirmed-capable attack vectors. The probe tells the attacker "
            "exactly which tools are available; the exploit uses them."
        ),
        "sequence":    [
            {"T56"},                          # capability recon
            {"T07", "T10", "T37", "T19"},     # targeted exploit using confirmed capability
        ],
        "min_events":  2,
        "confidence":  0.85,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "MEMORY_PERSISTENCE_CHAIN",
        "description": "High-risk memory write followed by anomalous action — cross-session poison chain",
        "sequence":    [
            {"T31"},              # memory write (structured memory store/update)
            {"T19", "T37", "T23", "T07"},  # sensitive action following memory write
        ],
        "min_events":  2,
        "confidence":  0.82,
        "surfaces":    None,
        "amplifiers":  {
            "memory_high_risk": True,
        },
    },
    {
        "name":        "REWARD_MANIPULATION",
        "description": "Security-relevant operation followed by T39 reward signal — RL poisoning attempt",
        "sequence":    [
            {"T19", "T37", "T36_AGENTDEF", "T_DEST", "T07", "T11"},  # blocked/warned op
            {"T39"},              # reward signal for that op (REWARD_POISON or OPD_INJECTION)
        ],
        "min_events":  2,
        "confidence":  0.87,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "REPEATED_INJECTION_ATTEMPT",
        "description": "T27 INBOUND_INJECTION fires 3+ times on distinct tool sources — systematic injection campaign",
        "sequence":    [
            {"T27"},   # first inbound injection
            {"T27"},   # second
            {"T27"},   # third — distinct sources = deliberate campaign
        ],
        "min_events":  3,
        "confidence":  0.86,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "EXTERNAL_INSTRUCTION_CHANNEL",
        "description": "Persistence + unapproved external fetch + memory write — autonomous C2 channel setup",
        "sequence":    [
            {"T11"},          # persistence mechanism (cron, scheduler)
            {"T22", "T01"},   # external HTTP endpoint not in allow_http
            {"T31"},          # memory write saving the external URL/endpoint
        ],
        "min_events":  3,
        "confidence":  0.91,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name": "IP_CIRCUMVENTION_CHAIN",
        "description": (
            "AI-agent-assisted intellectual property circumvention sequence. "
            "Phase 1: agent enumerates and reads proprietary source code files "
            "across a target repository (T19/T22 filesystem reads at high volume). "
            "Phase 2: agent generates functionally equivalent code in a different "
            "language or with cosmetic modifications (T84 IP_TRANSFORMATION_EXFIL). "
            "Phase 3: agent writes or commits the transformed code to an external "
            "repository (T01 EXFIL or T41 OUTBOUND_SECRET_LEAK). "
            "Based on the claw-code incident (March 31, 2026): Codex rewrote "
            "Anthropic's Claude Code TypeScript source to Python."
        ),
        "sequence": [
            {"T19", "T22"},
            {"T84"},
            {"T01", "T41"},
        ],
        "min_events": 3,
        "confidence": 0.90,
        "surfaces":   None,
        "amplifiers": {
            "T84": 1.5,
            "T01": 1.3,
            "T41": 1.3,
        },
    },
    {
        "name": "MEMORY_ENTROPY_ATTACK",
        "description": (
            "High-volume low-signal writes to memory store preceding a consolidation "
            "pass, designed to ensure a malicious instruction survives compression "
            "while legitimate context is pruned. "
            "Mechanism: Claude Code's autoDream consolidation prunes memory to <200 "
            "lines with <150 chars per note (documented in consolidationPrompt.ts, "
            "March 2026 leak). An attacker floods the memory store with borderline "
            "T79 writes (individually below block threshold) to create context entropy."
        ),
        "sequence": [
            {"T79"},
            {"T79"},
            {"T31", "T79"},
        ],
        "min_events": 3,
        "confidence": 0.88,
        "surfaces":   None,
        "amplifiers": {
            "T79": 1.4,
            "T31": 1.5,
        },
    },
]


# ── Result type ────────────────────────────────────────────────────────────────

@dataclass
class CampaignResult:
    pattern_id:     str
    description:    str
    session_id:     str
    confidence:     float
    evidence:       List[dict]   # the events that triggered the pattern
    recommendation: str
    detected_at:    float = field(default_factory=time.time)

    @property
    def risk(self) -> str:
        if self.confidence >= 0.85:
            return "HIGH"
        if self.confidence >= 0.70:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "pattern_id":     self.pattern_id,
            "description":    self.description,
            "session_id":     self.session_id,
            "confidence":     round(self.confidence, 3),
            "risk":           self.risk,
            "evidence_count": len(self.evidence),
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "detected_at":    self.detected_at,
            "rule_id":        "T06",
            "rule_name":      "GOAL_DRIFT",
            "threat_family":  "T06_CAMPAIGN",
        }


# ── CampaignAnalyzer ──────────────────────────────────────────────────────────

class CampaignAnalyzer:
    """
    Analyzes event sequences within sessions to detect multi-step attack
    campaigns that are invisible to per-call rule matching.
    """

    def __init__(self, graph):
        self._graph = graph

    def analyze_session(self, session_id: str) -> List[CampaignResult]:
        """
        Analyze all events in a session for campaign patterns.
        Returns list of CampaignResults (empty = no campaigns detected).
        """
        events = self._load_session_events(session_id)
        if not events:
            return []

        results: List[CampaignResult] = []
        for pattern in _CAMPAIGN_PATTERNS:
            result = self._match_pattern(session_id, events, pattern)
            if result:
                results.append(result)

        if results:
            log.warning(
                "[CampaignAnalyzer] Session %s: %d campaign pattern(s) detected.",
                session_id[:12], len(results),
            )
        return results

    def analyze_recent(self, hours: int = 24) -> List[CampaignResult]:
        """Analyze all sessions ingested in the last N hours."""
        cutoff = time.time() - (hours * 3600)
        sessions = self._graph.recent_sessions(n=200)
        all_results: List[CampaignResult] = []
        for s in sessions:
            if (s.get("closed_at") or 0) >= cutoff:
                results = self.analyze_session(s["session_id"])
                all_results.extend(results)
        return all_results

    def analyze_all(self) -> List[CampaignResult]:
        """Analyze every ingested session."""
        sessions = self._graph.recent_sessions(n=10000)
        all_results: List[CampaignResult] = []
        for s in sessions:
            all_results.extend(self.analyze_session(s["session_id"]))
        return all_results

    def to_triggers(self, results: List[CampaignResult]):
        """Convert CampaignResults to InspectionTriggers for the amend engine."""
        from aiglos.adaptive.inspect import InspectionTrigger
        triggers = []
        for r in results:
            triggers.append(InspectionTrigger(
                trigger_type="T06_CAMPAIGN",
                rule_id="T06",
                severity=r.risk,
                evidence_summary=(
                    f"{r.pattern_id} detected in session {r.session_id[:12]} "
                    f"(confidence {r.confidence:.0%}): {r.description}"
                ),
                evidence_data=r.to_dict(),
                amendment_candidate=False,  # campaigns require human review
            ))
        return triggers

    # ── Pattern matching ───────────────────────────────────────────────────────

    def _match_pattern(
        self,
        session_id: str,
        events: List[dict],
        pattern: dict,
    ) -> Optional[CampaignResult]:
        """
        Check if a pattern's sequence is satisfied by the event list.
        Returns a CampaignResult if matched, None otherwise.
        """
        sequence   = pattern["sequence"]
        min_events = pattern["min_events"]
        surfaces   = pattern.get("surfaces")
        amplifiers = pattern.get("amplifiers", {})

        # Filter by surface if specified
        if surfaces:
            filtered = [e for e in events if e.get("surface") in surfaces]
        else:
            filtered = events

        if len(filtered) < min_events:
            return None

        # Check if the non-ALLOW events cover the sequence
        triggered_events = [e for e in filtered if e.get("verdict") != "ALLOW"]
        if len(triggered_events) < min_events:
            return None

        # Try to find the sequence satisfied in order
        matched_events, confidence = self._find_sequence(
            triggered_events, sequence, amplifiers
        )
        if not matched_events:
            return None

        return CampaignResult(
            pattern_id=pattern["name"],
            description=pattern["description"],
            session_id=session_id,
            confidence=min(confidence, 1.0),
            evidence=matched_events,
            recommendation=self._recommend(pattern["name"]),
        )

    def _find_sequence(
        self,
        events: List[dict],
        sequence: List[Set[str]],
        amplifiers: dict,
    ) -> Tuple[List[dict], float]:
        """
        Find events that satisfy the pattern sequence in temporal order.
        Returns (matched_events, confidence). matched_events is empty if no match.
        """
        matched: List[dict] = []
        seq_idx = 0
        rule_ids_seen: Set[str] = set()

        for ev in events:
            rule_id = ev.get("rule_id", "none")
            if seq_idx >= len(sequence):
                break
            target_set = sequence[seq_idx]
            if rule_id in target_set:
                matched.append(ev)
                rule_ids_seen.add(rule_id)
                seq_idx += 1

        # Sequence must be fully satisfied
        if seq_idx < len(sequence):
            return [], 0.0

        # Base confidence for matching the full sequence
        base = 0.70
        # Bonus for more distinct rule IDs seen (broader attack surface)
        distinct_bonus = min(len(rule_ids_seen) / len(sequence), 1.0) * 0.15
        confidence = base + distinct_bonus

        # Amplifier: AGENTDEF read-then-write
        if amplifiers.get("read_then_write"):
            verdicts = [e.get("rule_name", "") for e in matched]
            if "AGENT_DEF_READ" in verdicts and "AGENT_DEF_WRITE" in verdicts:
                confidence += 0.12

        # Amplifier: absence of legitimate activity raises confidence
        # (already handled by filtering to triggered events)

        return matched, confidence

    def _recommend(self, pattern_id: str) -> str:
        recs = {
            "RECON_SWEEP": (
                "Multiple credential/config file reads in one session. "
                "Review the session artifact for the specific paths accessed. "
                "Consider adding T19 CRED_HARVEST to tier3_mode='pause'."
            ),
            "CREDENTIAL_ACCUMULATE": (
                "Agent accessed credential files 3+ times in one session. "
                "Verify this is expected behavior. If not, block credential "
                "access paths via the T19 rule and add them to a watchlist."
            ),
            "EXFIL_SETUP": (
                "Internal reconnaissance followed by outbound network setup. "
                "This is the exact pattern of a credential exfiltration attempt. "
                "Review the session artifact immediately. Block T23 EXFIL_SUBPROCESS."
            ),
            "PERSISTENCE_CHAIN": (
                "Privilege escalation followed by persistence installation. "
                "This is a high-confidence attack sequence. "
                "The subprocess tier3_mode should be set to 'block' for T10 and T11."
            ),
            "LATERAL_PREP": (
                "Credential harvest followed by network scanning. "
                "Possible lateral movement preparation. "
                "Block T12 LATERAL_MOVEMENT and review session artifact."
            ),
            "AGENTDEF_CHAIN": (
                "Agent definition read followed by write in the same session. "
                "This matches the McKinsey/Lilli attack pattern: the agent read "
                "its own definition before the definition was modified. "
                "Treat as HIGH priority. Review the AgentDefGuard violation in the artifact."
            ),
            "MEMORY_PERSISTENCE_CHAIN": (
                "A HIGH-risk memory write (T31) was followed by a sensitive "
                "agent action in the same session. The write may have established a "
                "false belief the subsequent action relied on — authorization claim, "
                "endpoint redirect, or credential assertion. Review the memory guard "
                "provenance log for the written content. Clear any poisoned entries "
                "before the next session to prevent cross-session persistence."
            ),
            "REWARD_MANIPULATION": (
                "A security-relevant operation (blocked or warned by Aiglos) was "
                "followed by a T39 reward signal in the same session — indicating "
                "an attempt to provide positive RL training feedback for an unsafe "
                "operation. If running a live RL training loop, "
                "the quarantined reward signal should not reach the training pipeline. "
                "Check RLFeedbackGuard quarantine log and SecurityAwareReward override history."
            ),
            "REPEATED_INJECTION_ATTEMPT": (
                "T27 INBOUND_INJECTION fired 3+ times across distinct tool outputs "
                "in this session. This is not noise — it is a coordinated injection "
                "campaign targeting the agent's context window through multiple sources. "
                "Treat every tool output in this session as potentially compromised. "
                "Review the injection_flagged section of the artifact for the full "
                "payload list. Consider whether the content sources themselves have "
                "been compromised."
            ),
            "EXTERNAL_INSTRUCTION_CHANNEL": (
                "Persistence mechanism + unapproved external HTTP endpoint + memory write "
                "detected in the same session. This is the setup sequence for an autonomous "
                "external command-and-control channel: a scheduled job that fetches content "
                "from an external domain and injects it into the agent's context, indefinitely, "
                "without further user interaction. "
                "The attack often arrives disguised as a productivity tip or subscription "
                "instruction in a user message. "
                "Block the cron setup (T11), reject the external endpoint (T22), "
                "and clear any saved URLs from persistent memory (T31). "
                "Do not allow external domains to become recurring instruction sources "
                "unless they are explicitly in allow_http."
            ),
            "IP_CIRCUMVENTION_CHAIN": (
                "AI-agent-assisted intellectual property circumvention detected. "
                "The agent read proprietary source code, generated functionally "
                "equivalent code in a different language, and attempted to commit "
                "or transmit the transformed code. Review the session artifact for "
                "specific file reads and writes. Block T84 IP_TRANSFORMATION_EXFIL."
            ),
            "MEMORY_ENTROPY_ATTACK": (
                "High-volume memory writes followed by a consolidation-style write "
                "detected. This pattern exploits autoDream-style memory compression: "
                "flood with borderline writes, then embed a malicious instruction "
                "that survives pruning. Clear the memory store and review the final "
                "write for embedded constraint-redefining language."
            ),
        }
        return recs.get(pattern_id, "Review the session artifact for this event sequence.")

    # ── Data loading ───────────────────────────────────────────────────────────

    def _load_session_events(self, session_id: str) -> List[dict]:
        """Load all events for a session in temporal order."""
        try:
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT rule_id, rule_name, verdict, surface, tier,
                           cmd_preview, latency_ms, timestamp
                    FROM events
                    WHERE session_id = ?
                    ORDER BY timestamp ASC
                """, (session_id,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            log.debug("[CampaignAnalyzer] Failed to load events for %s: %s", session_id[:12], e)
            return []
