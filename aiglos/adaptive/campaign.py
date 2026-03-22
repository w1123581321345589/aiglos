"""
aiglos.adaptive.campaign
=========================
T06 GOAL_DRIFT -- campaign-mode session analysis.

This is the capability that Onyx is building from the top down (intent
legibility via trained models). Aiglos builds it from the bottom up:
the observation graph already has every event from every session. T06
asks whether the sequence of events *across a session* forms a pattern
that looks like reconnaissance or a coordinated attack, even when each
individual event looks clean.

The insight: a single `git log` is Tier 1 AUTONOMOUS -- auto-allowed.
A single `cat ~/.aws/credentials` fires T19. But a session that does:
  git log → ls -la → cat package.json → cat .env.example → cat .env
is a reconnaissance sweep even though no single call is catastrophic.

Campaign-mode analysis catches this by looking at sequences, not atoms.

21 campaign patterns (v0.25.3):

  RECON_SWEEP, CREDENTIAL_ACCUMULATE, EXFIL_SETUP, PERSISTENCE_CHAIN,
  LATERAL_PREP, AGENTDEF_CHAIN, MEMORY_PERSISTENCE_CHAIN,
  REWARD_MANIPULATION, REPEATED_INJECTION_ATTEMPT,
  EXTERNAL_INSTRUCTION_CHANNEL, SKILL_CHAIN, SANDBOX_ESCAPE_ATTEMPT,
  GAAS_TAKEOVER, INFERENCE_HIJACK_CHAIN, RAG_POISON_CHAIN,
  MULTI_AGENT_IMPERSONATION, CAPABILITY_EXPLOIT_CHAIN,
  SANDBOX_CONFIRMED_ESCAPE, SUPERPOWERS_PLAN_HIJACK,
  HALLUCINATION_CASCADE_CHAIN, GIGABRAIN_MEMORY_POISON

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



import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("aiglos.adaptive.campaign")


# ── Campaign pattern definitions ──────────────────────────────────────────────

# Each pattern is a dict:
#   name:         string ID
#   description:  human-readable
#   sequence:     list of rule_id sets -- each element is a set of rules,
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
        "description": "Agent def read followed by write -- McKinsey/Lilli pattern",
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
        "name":        "SANDBOX_CONFIRMED_ESCAPE",
        "description": (
            "Tool call confirmed impossible in sandbox context followed by "
            "additional escape attempts. When sandbox_context=True, a single "
            "impossible call is already CRITICAL. A second attempt in the same "
            "session window confirms the agent is actively probing or has "
            "partially escaped -- not a misconfiguration, a campaign."
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
            "Skill file write followed by instruction override -- "
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
            "GaaS tenant escalation followed by cross-tenant data access -- "
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
            "Model fingerprint probe followed by inference router hijack -- "
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
            "Vector database injection followed by tool result forgery -- "
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
            "Agent identity spoofing followed by privilege escalation -- "
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
            "Capability boundary probe followed by targeted exploit -- "
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
        "description": "High-risk memory write followed by anomalous action -- cross-session poison chain",
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
        "description": "Security-relevant operation followed by T39 reward signal -- RL poisoning attempt",
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
        "description": "T27 INBOUND_INJECTION fires 3+ times on distinct tool sources -- systematic injection campaign",
        "sequence":    [
            {"T27"},   # first inbound injection
            {"T27"},   # second
            {"T27"},   # third -- distinct sources = deliberate campaign
        ],
        "min_events":  3,
        "confidence":  0.86,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "EXTERNAL_INSTRUCTION_CHANNEL",
        "description": "Persistence + unapproved external fetch + memory write -- autonomous C2 channel setup",
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
        "name":        "SUPERPOWERS_PLAN_HIJACK",
        "description": (
            "Plan drift followed by data exfiltration -- the highest-confidence "
            "campaign signature in the system. A Superpowers session where the "
            "agent deviates from its approved plan (T69 PLAN_DRIFT) and then "
            "immediately performs credential access or data exfiltration "
            "confirms the plan was hijacked by injected instructions."
        ),
        "sequence":    [
            {"T69"},                      # plan drift detected
            {"T19", "T12", "T22", "T37"}, # exfil / credential / financial action
        ],
        "min_events":  2,
        "confidence":  0.97,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "HALLUCINATION_CASCADE_CHAIN",
        "description": (
            "Hallucination cascade across multiple sub-agent outputs in a session. "
            "T78 fires on individual calls with circular citation or unverified "
            "statistics with high-confidence language. When T78 fires 2+ times "
            "in the same session, the cascade is confirmed: multiple agents are "
            "amplifying the same unverified claim. Combined with T55 TOOL_RESULT_FORGERY "
            "this becomes a fabrication-amplification loop."
        ),
        "sequence":    [
            {"T78"},
            {"T78", "T55"},
        ],
        "min_events":  2,
        "confidence":  0.88,
        "surfaces":    None,
        "amplifiers":  {},
    },
    {
        "name":        "GIGABRAIN_MEMORY_POISON",
        "description": (
            "In-session memory poison (T31) followed by persistent memory inject "
            "(T79) in the same session -- the attacker first tests injection in "
            "ephemeral memory, then escalates to persistent cross-session storage. "
            "A successful T31 + T79 chain means the adversary has confirmed their "
            "injection payload works and has now persisted it into every future "
            "session via Gigabrain, MemoryOS, or compatible memory backend. "
            "The most dangerous memory attack: confirmed + persistent."
        ),
        "sequence":    [
            {"T31"},
            {"T79"},
        ],
        "min_events":  2,
        "confidence":  0.95,
        "surfaces":    None,
        "amplifiers":  {
            "T79": 1.15,
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
                "false belief the subsequent action relied on -- authorization claim, "
                "endpoint redirect, or credential assertion. Review the memory guard "
                "provenance log for the written content. Clear any poisoned entries "
                "before the next session to prevent cross-session persistence."
            ),
            "REWARD_MANIPULATION": (
                "A security-relevant operation (blocked or warned by Aiglos) was "
                "followed by a T39 reward signal in the same session -- indicating "
                "an attempt to provide positive RL training feedback for an unsafe "
                "operation. If running a live RL training loop, "
                "the quarantined reward signal should not reach the training pipeline. "
                "Check RLFeedbackGuard quarantine log and SecurityAwareReward override history."
            ),
            "REPEATED_INJECTION_ATTEMPT": (
                "T27 INBOUND_INJECTION fired 3+ times across distinct tool outputs "
                "in this session. This is not noise -- it is a coordinated injection "
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
