"""
aiglos.core.policy_proposal
=============================
Policy-level amendment proposals.

The problem with per-action Tier 3 webhook approval:
  - Engineers approve everything to unblock work
  - Or they disable Tier 3 entirely after a week of interruptions
  - Per-action approval creates alert fatigue
  - The signal is lost; security degrades to theater

The fix: policy-level proposals instead of per-action approval.

When the same action pattern is blocked N times for the same agent in a
rolling window, the system surfaces ONE proposal: "should we permanently
adjust this rule for this agent in this context?"

That's a policy decision — made once, applies forever, backed by evidence.
It's the difference between a smoke alarm that fires every time you cook
(disabled within a week) and a smoke alarm that learns your kitchen.

Four proposal types:

  LOWER_TIER       — reduce blast radius tier for a specific rule+agent
                     (most common: Tier 3 → Tier 2, requires confirmation
                     not webhook approval)

  ALLOW_LIST       — permanently allow a specific tool+args pattern for
                     this agent (only when semantic analysis shows zero
                     injection risk and the pattern is highly consistent)

  RAISE_THRESHOLD  — increase the score threshold before a rule fires for
                     this agent (handles false positives in borderline cases)

  SUPPRESS_PATTERN — suppress a rule entirely for a specific agent in a
                     specific context (least common, highest evidence bar)

Evidence model:
  Each proposal is backed by:
  - repetition_count: how many times the pattern has been blocked
  - window_days: rolling window in which blocks occurred
  - consistency_score: how similar the blocked calls were (0.0-1.0)
  - incident_count: confirmed security incidents for this agent (should be 0)
  - baseline_confirmed: whether behavioral baseline says this is normal

  Confidence = f(repetition, consistency, baseline, incidents)
  Low confidence → proposal not generated (not enough evidence)
  High confidence → proposal generated, shown in CLI review queue

Lifecycle:
  pending   → created, not yet reviewed
  approved  → human approved via CLI; rule change applied
  rejected  → human rejected; pattern continues to block normally
  expired   → 30 days passed without review; auto-rejected silently
  rolled_back → was approved, then reverted due to subsequent incident

Usage:
    from aiglos.core.policy_proposal import PolicyProposalEngine

    engine = PolicyProposalEngine(graph)

    # Called when a Tier 3 block fires
    proposal = engine.evaluate_pattern(
        agent_name="my-agent",
        rule_id="T37",
        tool_name="http.post",
        args_fingerprint="api.stripe.com/charges",
    )
    # Returns PolicyProposal if pattern qualifies, None otherwise

    # CLI: list pending proposals
    pending = engine.list_proposals(status="pending")

    # CLI: approve
    engine.approve_proposal(proposal_id, approved_by="operator@example.com")
"""


import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger("aiglos.policy_proposal")

# ── Configuration ─────────────────────────────────────────────────────────────

_MIN_REPETITIONS     = 5    # blocks needed before proposal is generated
_WINDOW_DAYS         = 7    # rolling window for counting repetitions
_EXPIRY_DAYS         = 30   # proposals auto-expire after this many days
_MIN_CONSISTENCY     = 0.70  # minimum call consistency to propose ALLOW_LIST
_MIN_CONFIDENCE      = 0.60  # minimum confidence before generating any proposal
_ROLLBACK_WINDOW     = 14   # days to watch for incidents after approval


class ProposalType(str, Enum):
    LOWER_TIER       = "LOWER_TIER"
    ALLOW_LIST       = "ALLOW_LIST"
    RAISE_THRESHOLD  = "RAISE_THRESHOLD"
    SUPPRESS_PATTERN = "SUPPRESS_PATTERN"


class ProposalStatus(str, Enum):
    PENDING     = "pending"
    APPROVED    = "approved"
    REJECTED    = "rejected"
    EXPIRED     = "expired"
    ROLLED_BACK = "rolled_back"


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class BlockPattern:
    """
    A fingerprint of a repeated block event for one agent+rule+tool combination.
    Used as the evidence base for proposals.
    """
    agent_name:          str
    rule_id:             str
    tool_name:           str
    args_fingerprint:    str    # hashed/normalised representation of common args
    repetition_count:    int
    window_days:         int
    first_seen:          float
    last_seen:           float
    consistency_score:   float  # how similar the blocked calls were
    incident_count:      int    # confirmed security incidents for this agent
    baseline_confirmed:  bool   # behavioral baseline says this is normal

    @property
    def pattern_id(self) -> str:
        """Stable identifier for this block pattern."""
        raw = f"{self.agent_name}:{self.rule_id}:{self.tool_name}:{self.args_fingerprint}"
        return "pat_" + hashlib.sha256(raw.encode()).hexdigest()[:16]

    def confidence(self) -> float:
        """
        Evidence-weighted confidence score [0.0, 1.0].
        High confidence = strong evidence this is legitimate behavior.
        """
        # Base: repetition count (saturates at 20)
        rep_score = min(self.repetition_count / 20.0, 1.0)

        # Consistency: how similar the blocked calls were
        cons_score = self.consistency_score

        # Baseline bonus: behavioral baseline confirms this is normal
        baseline_bonus = 0.20 if self.baseline_confirmed else 0.0

        # Incident penalty: any confirmed incident tanks confidence
        incident_penalty = min(self.incident_count * 0.30, 0.90)

        raw = (
            0.40 * rep_score +
            0.40 * cons_score +
            baseline_bonus
        ) - incident_penalty

        return max(0.0, min(round(raw, 4), 1.0))


@dataclass
class PolicyProposal:
    """
    A proposed policy change for a specific agent+rule combination.
    Generated when a block pattern meets the evidence threshold.
    Human-reviewed via CLI before any rule change is applied.
    """
    proposal_id:      str
    pattern_id:       str
    proposal_type:    ProposalType
    agent_name:       str
    rule_id:          str
    tool_name:        str
    args_fingerprint: str

    # The specific change proposed
    proposed_change:  Dict[str, Any]   # type-specific parameters

    # Evidence
    evidence:         BlockPattern
    confidence:       float

    # Lifecycle
    status:           ProposalStatus = ProposalStatus.PENDING
    created_at:       float = field(default_factory=time.time)
    expires_at:       float = field(default_factory=lambda: time.time() + _EXPIRY_DAYS * 86400)
    reviewed_at:      Optional[float] = None
    reviewed_by:      Optional[str]   = None
    applied_at:       Optional[float] = None
    rollback_reason:  Optional[str]   = None

    @property
    def is_expired(self) -> bool:
        return (self.status == ProposalStatus.PENDING and
                time.time() > self.expires_at)

    @property
    def days_until_expiry(self) -> float:
        return max(0.0, (self.expires_at - time.time()) / 86400)

    def summary(self) -> str:
        """One-line human-readable summary for CLI display."""
        age = (time.time() - self.created_at) / 86400
        return (
            f"[{self.proposal_type.value}] {self.agent_name} / {self.rule_id} "
            f"({self.tool_name}) — {self.evidence.repetition_count} blocks in "
            f"{self.evidence.window_days}d, confidence={self.confidence:.0%}, "
            f"age={age:.1f}d"
        )

    def to_dict(self) -> dict:
        return {
            "proposal_id":      self.proposal_id,
            "pattern_id":       self.pattern_id,
            "proposal_type":    self.proposal_type.value,
            "agent_name":       self.agent_name,
            "rule_id":          self.rule_id,
            "tool_name":        self.tool_name,
            "args_fingerprint": self.args_fingerprint,
            "proposed_change":  self.proposed_change,
            "confidence":       round(self.confidence, 4),
            "status":           self.status.value,
            "created_at":       self.created_at,
            "expires_at":       self.expires_at,
            "reviewed_at":      self.reviewed_at,
            "reviewed_by":      self.reviewed_by,
            "applied_at":       self.applied_at,
            "rollback_reason":  self.rollback_reason,
            "days_until_expiry": round(self.days_until_expiry, 1),
            "evidence": {
                "repetition_count":  self.evidence.repetition_count,
                "window_days":       self.evidence.window_days,
                "consistency_score": round(self.evidence.consistency_score, 4),
                "incident_count":    self.evidence.incident_count,
                "baseline_confirmed": self.evidence.baseline_confirmed,
                "first_seen":        self.evidence.first_seen,
                "last_seen":         self.evidence.last_seen,
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyProposal":
        ev_d = d.get("evidence", {})
        evidence = BlockPattern(
            agent_name       = d.get("agent_name", ""),
            rule_id          = d.get("rule_id", ""),
            tool_name        = d.get("tool_name", ""),
            args_fingerprint = d.get("args_fingerprint", ""),
            repetition_count = ev_d.get("repetition_count", 0),
            window_days      = ev_d.get("window_days", _WINDOW_DAYS),
            first_seen       = ev_d.get("first_seen", 0.0),
            last_seen        = ev_d.get("last_seen", 0.0),
            consistency_score  = ev_d.get("consistency_score", 0.0),
            incident_count     = ev_d.get("incident_count", 0),
            baseline_confirmed = ev_d.get("baseline_confirmed", False),
        )
        return cls(
            proposal_id      = d.get("proposal_id", ""),
            pattern_id       = d.get("pattern_id", ""),
            proposal_type    = ProposalType(d.get("proposal_type", "LOWER_TIER")),
            agent_name       = d.get("agent_name", ""),
            rule_id          = d.get("rule_id", ""),
            tool_name        = d.get("tool_name", ""),
            args_fingerprint = d.get("args_fingerprint", ""),
            proposed_change  = d.get("proposed_change", {}),
            evidence         = evidence,
            confidence       = d.get("confidence", 0.0),
            status           = ProposalStatus(d.get("status", "pending")),
            created_at       = d.get("created_at", time.time()),
            expires_at       = d.get("expires_at", time.time() + _EXPIRY_DAYS * 86400),
            reviewed_at      = d.get("reviewed_at"),
            reviewed_by      = d.get("reviewed_by"),
            applied_at       = d.get("applied_at"),
            rollback_reason  = d.get("rollback_reason"),
        )


# ── PolicyProposalEngine ──────────────────────────────────────────────────────

def _fingerprint_args(args: dict) -> str:
    """
    Stable fingerprint of tool arguments — captures the semantic pattern
    without storing sensitive values. Hashes values, keeps keys.
    """
    if not args:
        return "empty"
    # Sort keys for stability, hash each value independently
    parts = []
    for k in sorted(args.keys()):
        v = str(args.get(k, ""))
        # Preserve domain/hostname patterns for URL args
        if k in ("url", "endpoint", "host"):
            import re as _re
            m = _re.match(r"https?://([^/]+)", v)
            if m:
                parts.append(f"{k}:{m.group(1)}")
                continue
        parts.append(f"{k}:{hashlib.sha256(v.encode()).hexdigest()[:8]}")
    return "|".join(parts)


class PolicyProposalEngine:
    """
    Evaluates block patterns and generates policy proposals when evidence
    meets the threshold.

    Tracks block events in-memory per session and persists proposal history
    to the observation graph.

    One instance per deployment — shared across agent sessions.
    """

    def __init__(self, graph=None):
        self._graph = graph
        # In-memory block pattern accumulator: pattern_id → BlockPattern
        self._patterns: Dict[str, BlockPattern] = {}

    # ── Block event ingestion ─────────────────────────────────────────────────

    def record_block(
        self,
        agent_name:      str,
        rule_id:         str,
        tool_name:       str,
        args:            dict,
        tier:            int  = 3,
        incident:        bool = False,
    ) -> Optional[PolicyProposal]:
        """
        Record a block event. If pattern repetition meets the threshold,
        generate and return a PolicyProposal. Returns None otherwise.

        Call this inside before_tool_call when verdict is BLOCK or PAUSE.
        """
        fp = _fingerprint_args(args)
        raw = f"{agent_name}:{rule_id}:{tool_name}:{fp}"
        pat_id = "pat_" + hashlib.sha256(raw.encode()).hexdigest()[:16]

        now = time.time()
        if pat_id in self._patterns:
            p = self._patterns[pat_id]
            p.repetition_count += 1
            p.last_seen         = now
            if incident:
                p.incident_count += 1
        else:
            # Check graph for prior history
            prior_count = self._load_prior_count(pat_id)
            self._patterns[pat_id] = BlockPattern(
                agent_name       = agent_name,
                rule_id          = rule_id,
                tool_name        = tool_name,
                args_fingerprint = fp,
                repetition_count = prior_count + 1,
                window_days      = _WINDOW_DAYS,
                first_seen       = now,
                last_seen        = now,
                consistency_score = 0.85,   # default; improves with more data
                incident_count   = 1 if incident else 0,
                baseline_confirmed = self._check_baseline(agent_name),
            )

        # Persist the block event
        self._persist_block(pat_id, agent_name, rule_id, tool_name, fp, tier)

        # Check if pattern meets threshold
        pattern = self._patterns[pat_id]
        if pattern.repetition_count >= _MIN_REPETITIONS:
            return self._maybe_generate_proposal(pattern)

        return None

    def _load_prior_count(self, pattern_id: str) -> int:
        """Load prior block count from graph for this pattern."""
        if not self._graph:
            return 0
        try:
            return self._graph.get_block_pattern_count(pattern_id)
        except Exception:
            return 0

    def _check_baseline(self, agent_name: str) -> bool:
        """Check if behavioral baseline confirms this agent has normal behavior."""
        if not self._graph:
            return False
        try:
            baseline = self._graph.get_baseline(agent_name)
            return baseline is not None and baseline.is_ready
        except Exception:
            return False

    def _persist_block(
        self, pattern_id: str, agent_name: str, rule_id: str,
        tool_name: str, args_fingerprint: str, tier: int
    ) -> None:
        if not self._graph:
            return
        try:
            self._graph.record_block_pattern_event(
                pattern_id, agent_name, rule_id, tool_name, args_fingerprint, tier
            )
        except Exception as e:
            log.debug("[PolicyProposalEngine] Persist block error: %s", e)

    # ── Proposal generation ───────────────────────────────────────────────────

    def _maybe_generate_proposal(self, pattern: BlockPattern) -> Optional[PolicyProposal]:
        """
        Determine if pattern meets evidence threshold and generate a proposal.
        Returns None if confidence too low or proposal already exists.
        """
        confidence = pattern.confidence()
        if confidence < _MIN_CONFIDENCE:
            log.debug(
                "[PolicyProposalEngine] Pattern %s below confidence threshold: %.2f",
                pattern.pattern_id, confidence,
            )
            return None

        # Check for existing pending proposal for this pattern
        if self._graph:
            try:
                existing = self._graph.get_proposal_by_pattern(pattern.pattern_id)
                if existing and existing.status == ProposalStatus.PENDING:
                    log.debug(
                        "[PolicyProposalEngine] Pending proposal already exists "
                        "for pattern %s", pattern.pattern_id,
                    )
                    return None
            except Exception:
                pass

        # Choose proposal type based on evidence
        proposal_type, proposed_change = self._determine_proposal(pattern, confidence)

        proposal_id = "prp_" + hashlib.sha256(
            f"{pattern.pattern_id}{time.time()}".encode()
        ).hexdigest()[:16]

        proposal = PolicyProposal(
            proposal_id      = proposal_id,
            pattern_id       = pattern.pattern_id,
            proposal_type    = proposal_type,
            agent_name       = pattern.agent_name,
            rule_id          = pattern.rule_id,
            tool_name        = pattern.tool_name,
            args_fingerprint = pattern.args_fingerprint,
            proposed_change  = proposed_change,
            evidence         = pattern,
            confidence       = confidence,
        )

        # Persist to graph
        if self._graph:
            try:
                self._graph.upsert_proposal(proposal)
            except Exception as e:
                log.debug("[PolicyProposalEngine] Persist proposal error: %s", e)

        log.info(
            "[PolicyProposalEngine] Proposal generated: %s type=%s "
            "agent=%s rule=%s confidence=%.2f",
            proposal_id, proposal_type.value,
            pattern.agent_name, pattern.rule_id, confidence,
        )
        return proposal

    def _determine_proposal(
        self, pattern: BlockPattern, confidence: float
    ) -> tuple[ProposalType, dict]:
        """
        Choose the most conservative proposal type that evidence supports.
        LOWER_TIER < ALLOW_LIST < RAISE_THRESHOLD < SUPPRESS_PATTERN
        (less restrictive → more restrictive change required)
        """
        reps = pattern.repetition_count

        # SUPPRESS_PATTERN: very high evidence, zero incidents, baseline confirmed
        if (confidence >= 0.90 and
                pattern.incident_count == 0 and
                pattern.baseline_confirmed and
                reps >= 15):
            return ProposalType.SUPPRESS_PATTERN, {
                "action":   "suppress",
                "rule_id":  pattern.rule_id,
                "agent":    pattern.agent_name,
                "rationale": (
                    f"Rule {pattern.rule_id} has fired {reps} times for "
                    f"'{pattern.tool_name}' with no security incidents. "
                    f"Behavioral baseline confirms this is normal for this agent."
                ),
            }

        # ALLOW_LIST: high consistency, zero incidents
        if (pattern.consistency_score >= _MIN_CONSISTENCY and
                pattern.incident_count == 0 and
                confidence >= 0.80 and
                reps >= 10):
            return ProposalType.ALLOW_LIST, {
                "action":   "allow_list",
                "rule_id":  pattern.rule_id,
                "agent":    pattern.agent_name,
                "tool":     pattern.tool_name,
                "args_pattern": pattern.args_fingerprint,
                "rationale": (
                    f"'{pattern.tool_name}' has been blocked {reps} times with "
                    f"high call consistency ({pattern.consistency_score:.0%}). "
                    f"The args pattern is stable — safe to allow-list."
                ),
            }

        # RAISE_THRESHOLD: moderate evidence, some variance
        if confidence >= 0.70 and reps >= 8:
            return ProposalType.RAISE_THRESHOLD, {
                "action":      "raise_threshold",
                "rule_id":     pattern.rule_id,
                "agent":       pattern.agent_name,
                "current":     "default",
                "proposed":    "default + 0.15",
                "rationale": (
                    f"Rule {pattern.rule_id} may be over-sensitive for "
                    f"'{pattern.agent_name}'. Raising threshold by 0.15 "
                    f"would prevent {reps} historical false positives."
                ),
            }

        # LOWER_TIER: minimum evidence threshold met
        return ProposalType.LOWER_TIER, {
            "action":       "lower_tier",
            "rule_id":      pattern.rule_id,
            "agent":        pattern.agent_name,
            "current_tier": 3,
            "proposed_tier": 2,
            "rationale": (
                f"Tier 3 block for '{pattern.tool_name}' has fired "
                f"{reps} times in {pattern.window_days} days for "
                f"'{pattern.agent_name}'. Downgrade to Tier 2 to require "
                f"confirmation rather than blocking."
            ),
        }

    # ── Review operations ─────────────────────────────────────────────────────

    def approve_proposal(
        self, proposal_id: str, approved_by: str = "unknown"
    ) -> Optional[PolicyProposal]:
        """Approve a pending proposal. Returns updated proposal or None."""
        if not self._graph:
            return None
        try:
            proposal = self._graph.get_proposal(proposal_id)
            if not proposal:
                log.warning("[PolicyProposalEngine] Proposal not found: %s", proposal_id)
                return None
            if proposal.status != ProposalStatus.PENDING:
                log.warning(
                    "[PolicyProposalEngine] Proposal %s is not pending (status=%s)",
                    proposal_id, proposal.status.value,
                )
                return None

            proposal.status      = ProposalStatus.APPROVED
            proposal.reviewed_at = time.time()
            proposal.reviewed_by = approved_by
            proposal.applied_at  = time.time()
            self._graph.upsert_proposal(proposal)

            log.info(
                "[PolicyProposalEngine] Proposal %s approved by %s",
                proposal_id, approved_by,
            )
            return proposal
        except Exception as e:
            log.error("[PolicyProposalEngine] Approve error: %s", e)
            return None

    def reject_proposal(
        self, proposal_id: str, rejected_by: str = "unknown"
    ) -> Optional[PolicyProposal]:
        """Reject a pending proposal. Returns updated proposal or None."""
        if not self._graph:
            return None
        try:
            proposal = self._graph.get_proposal(proposal_id)
            if not proposal:
                return None
            proposal.status      = ProposalStatus.REJECTED
            proposal.reviewed_at = time.time()
            proposal.reviewed_by = rejected_by
            self._graph.upsert_proposal(proposal)
            log.info(
                "[PolicyProposalEngine] Proposal %s rejected by %s",
                proposal_id, rejected_by,
            )
            return proposal
        except Exception as e:
            log.error("[PolicyProposalEngine] Reject error: %s", e)
            return None

    def rollback_proposal(
        self, proposal_id: str, reason: str
    ) -> Optional[PolicyProposal]:
        """Roll back an approved proposal due to a subsequent incident."""
        if not self._graph:
            return None
        try:
            proposal = self._graph.get_proposal(proposal_id)
            if not proposal or proposal.status != ProposalStatus.APPROVED:
                return None
            proposal.status         = ProposalStatus.ROLLED_BACK
            proposal.rollback_reason = reason
            self._graph.upsert_proposal(proposal)
            log.warning(
                "[PolicyProposalEngine] Proposal %s rolled back: %s",
                proposal_id, reason,
            )
            return proposal
        except Exception as e:
            log.error("[PolicyProposalEngine] Rollback error: %s", e)
            return None

    def expire_stale_proposals(self) -> int:
        """Mark all expired pending proposals as expired. Returns count."""
        if not self._graph:
            return 0
        try:
            return self._graph.expire_proposals()
        except Exception as e:
            log.debug("[PolicyProposalEngine] Expire error: %s", e)
            return 0

    def list_proposals(
        self,
        status: str = "pending",
        agent_name: Optional[str] = None,
        limit: int = 50,
    ) -> List[PolicyProposal]:
        """List proposals filtered by status and optionally agent."""
        if not self._graph:
            return []
        try:
            return self._graph.list_proposals(
                status=status, agent_name=agent_name, limit=limit
            )
        except Exception as e:
            log.debug("[PolicyProposalEngine] List error: %s", e)
            return []

    def get_proposal(self, proposal_id: str) -> Optional[PolicyProposal]:
        """Fetch a single proposal by ID."""
        if not self._graph:
            return None
        try:
            return self._graph.get_proposal(proposal_id)
        except Exception as e:
            log.debug("[PolicyProposalEngine] Get error: %s", e)
            return None

    def summary_stats(self) -> dict:
        """Summary of all proposals for CLI display."""
        if not self._graph:
            return {"pending": 0, "approved": 0, "rejected": 0, "expired": 0}
        try:
            return self._graph.proposal_stats()
        except Exception:
            return {"pending": 0, "approved": 0, "rejected": 0, "expired": 0}
