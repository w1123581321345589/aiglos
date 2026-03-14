"""
aiglos.adaptive.amend
======================
Phase 4: Amendment proposals — evidence-based changes to allow-lists,
tier classifications, and rule patterns.

An amendment is generated when the inspection engine surfaces a trigger
with amendment_candidate=True. Each amendment has:
  - What it proposes to change
  - Why (the evidence that triggered it)
  - Status: pending | approved | rejected | rolled_back
  - Evaluation result (after approval and N sessions of data)

Amendments are stored in the observation graph's amendments table.
The `aiglos amend review` CLI surfaces pending amendments for human review.

No amendment is applied without explicit approval. The system can propose,
not decide.

Usage:
    from aiglos.adaptive.amend import AmendmentEngine

    engine = AmendmentEngine(graph)

    # Generate proposals from inspection triggers
    triggers = InspectionEngine(graph).run()
    proposals = engine.propose(triggers)

    # Review and approve
    for p in proposals:
        print(p.summary())
        if approved:
            engine.approve(p.amendment_id)

    # Get pending amendments
    pending = engine.pending()
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("aiglos.adaptive.amend")

# Amendment status values
PENDING    = "pending"
APPROVED   = "approved"
REJECTED   = "rejected"
ROLLED_BACK = "rolled_back"

# Amendment target types
TARGET_ALLOW_HTTP    = "allow_http"
TARGET_TIER_RECLASS  = "tier_reclassification"
TARGET_RULE_PATTERN  = "rule_pattern"
TARGET_POLICY_INHERIT = "policy_inheritance"

# ── Amendment dataclass ───────────────────────────────────────────────────────

@dataclass
class Amendment:
    amendment_id:   str
    trigger_type:   str
    rule_id:        Optional[str]
    target:         str           # what type of change is being proposed
    proposal:       dict          # the specific proposed change
    evidence:       dict          # data that drove the proposal
    rationale:      str           # human-readable explanation
    status:         str = PENDING
    created_at:     float = field(default_factory=time.time)
    resolved_at:    Optional[float] = None
    eval_sessions:  int = 0       # sessions evaluated after approval
    eval_outcome:   Optional[str] = None  # IMPROVED | NO_CHANGE | DEGRADED

    def summary(self) -> str:
        lines = [
            f"Amendment {self.amendment_id[:8]} [{self.status.upper()}]",
            f"  Rule:     {self.rule_id or 'n/a'}",
            f"  Target:   {self.target}",
            f"  Rationale: {self.rationale}",
            f"  Proposal: {json.dumps(self.proposal, indent=4)}",
            f"  Evidence: {json.dumps(self.evidence, indent=4)}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "amendment_id":  self.amendment_id,
            "trigger_type":  self.trigger_type,
            "rule_id":       self.rule_id,
            "target":        self.target,
            "proposal":      self.proposal,
            "evidence":      self.evidence,
            "rationale":     self.rationale,
            "status":        self.status,
            "created_at":    self.created_at,
            "resolved_at":   self.resolved_at,
            "eval_sessions": self.eval_sessions,
            "eval_outcome":  self.eval_outcome,
        }


# ── Amendment storage (extends ObservationGraph's DB) ────────────────────────

_AMENDMENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS amendments (
    amendment_id    TEXT PRIMARY KEY,
    trigger_type    TEXT NOT NULL,
    rule_id         TEXT,
    target          TEXT NOT NULL,
    proposal        TEXT NOT NULL,   -- JSON
    evidence        TEXT NOT NULL,   -- JSON
    rationale       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      REAL NOT NULL DEFAULT 0,
    resolved_at     REAL,
    eval_sessions   INTEGER NOT NULL DEFAULT 0,
    eval_outcome    TEXT
);
"""


# ── AmendmentEngine ───────────────────────────────────────────────────────────

class AmendmentEngine:
    """
    Generates, stores, reviews, and evaluates rule amendments.
    Uses the same SQLite DB as the ObservationGraph.
    """

    def __init__(self, graph):
        self._graph = graph
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._graph._conn() as conn:
            conn.executescript(_AMENDMENTS_SCHEMA)

    # ── Proposal generation ────────────────────────────────────────────────────

    def propose(self, triggers) -> List[Amendment]:
        """Generate amendment proposals from a list of InspectionTriggers."""
        proposals: List[Amendment] = []
        for trigger in triggers:
            if not trigger.amendment_candidate:
                continue
            amendment = self._generate(trigger)
            if amendment:
                self._store(amendment)
                proposals.append(amendment)
                log.info("[AmendmentEngine] Proposal %s: %s on %s",
                         amendment.amendment_id[:8], amendment.target,
                         amendment.rule_id or "n/a")
        return proposals

    def _generate(self, trigger) -> Optional[Amendment]:
        """Generate a specific amendment based on trigger type."""
        aid = str(uuid.uuid4())

        if trigger.trigger_type == "HIGH_OVERRIDE":
            return self._propose_allow_list_or_tier(trigger, aid)
        if trigger.trigger_type == "FIN_EXEC_BYPASS":
            return self._propose_fin_exec_allow(trigger, aid)
        if trigger.trigger_type == "SPAWN_NO_POLICY":
            return self._propose_policy_inheritance(trigger, aid)
        if trigger.trigger_type == "FALSE_POSITIVE":
            return self._propose_rule_tighten(trigger, aid)
        return None

    def _propose_allow_list_or_tier(self, trigger, aid: str) -> Amendment:
        stats = trigger.evidence_data
        return Amendment(
            amendment_id=aid,
            trigger_type=trigger.trigger_type,
            rule_id=trigger.rule_id,
            target=TARGET_TIER_RECLASS,
            proposal={
                "action":       "reclassify_to_tier2",
                "rule_id":      trigger.rule_id,
                "condition":    "deploy-specific",
                "justification": f"Rule has been overridden {stats.get('warns_total',0)} "
                                  f"times in {stats.get('fires_total',0)} fires.",
            },
            evidence=stats,
            rationale=(
                f"{trigger.rule_id} is being consistently overridden in this deployment. "
                "Reclassifying to Tier 2 (MONITORED) for this environment removes the friction "
                "without reducing visibility. The operation will still be logged and appear "
                "in the session artifact."
            ),
        )

    def _propose_fin_exec_allow(self, trigger, aid: str) -> Amendment:
        events = self._graph.events_for_rule("T37", limit=50)
        # Extract distinct cmd_preview patterns from warn events
        warn_previews = list({
            e["cmd_preview"] for e in events
            if e["verdict"] == "WARN" and e["cmd_preview"]
        })[:10]
        return Amendment(
            amendment_id=aid,
            trigger_type=trigger.trigger_type,
            rule_id="T37",
            target=TARGET_ALLOW_HTTP,
            proposal={
                "action":          "add_to_allow_http",
                "candidate_hosts": warn_previews,
                "review_required": True,
                "note":            "Operator must verify these are legitimately authorized "
                                   "financial endpoints before approving.",
            },
            evidence=trigger.evidence_data,
            rationale=(
                f"T37 FIN_EXEC has been bypassed {trigger.evidence_data.get('warns_total',0)} "
                "times. These financial endpoints appear to be legitimate for this deployment. "
                "Add them explicitly to allow_http to remove the bypass friction while "
                "keeping all other financial endpoints blocked."
            ),
        )

    def _propose_policy_inheritance(self, trigger, aid: str) -> Amendment:
        return Amendment(
            amendment_id=aid,
            trigger_type=trigger.trigger_type,
            rule_id="T38",
            target=TARGET_POLICY_INHERIT,
            proposal={
                "action":     "enable_policy_inheritance",
                "param":      "enable_multi_agent=True in attach()",
                "note":       "The parent session's learned allow-list and tier overrides "
                               "will propagate to all spawned child agents.",
            },
            evidence=trigger.evidence_data,
            rationale=(
                f"{trigger.evidence_data.get('spawn_count_no_policy',0)} child agents have "
                "spawned without inheriting their parent's learned policy. Each child starts "
                "from global defaults, which may be more restrictive or more permissive than "
                "the parent's calibrated policy for this deployment."
            ),
        )

    def _propose_rule_tighten(self, trigger, aid: str) -> Amendment:
        return Amendment(
            amendment_id=aid,
            trigger_type=trigger.trigger_type,
            rule_id=trigger.rule_id,
            target=TARGET_RULE_PATTERN,
            proposal={
                "action":       "tighten_pattern",
                "rule_id":      trigger.rule_id,
                "warn_rate":    trigger.evidence_data.get("warn_rate"),
                "next_step":    "Review recent WARN events for this rule to identify "
                                "the legitimate command patterns causing false positives.",
                "fires_sample": self._graph.events_for_rule(trigger.rule_id, limit=5),
            },
            evidence=trigger.evidence_data,
            rationale=(
                f"{trigger.rule_id} fires frequently but {trigger.evidence_data.get('warn_rate',0)*100:.0f}% "
                "result in WARNs rather than BLOCKs. This suggests the rule pattern is "
                "matching legitimate operations. The pattern should be tightened to reduce "
                "false positives without creating gaps in genuine attack detection."
            ),
        )

    # ── Storage ────────────────────────────────────────────────────────────────

    def _store(self, amendment: Amendment) -> None:
        # Check for duplicate proposals (same trigger type + rule_id + pending)
        with self._graph._conn() as conn:
            existing = conn.execute("""
                SELECT amendment_id FROM amendments
                WHERE trigger_type=? AND rule_id IS ? AND status='pending'
            """, (amendment.trigger_type, amendment.rule_id)).fetchone()

            if existing:
                log.debug("[AmendmentEngine] Duplicate proposal skipped: %s %s",
                          amendment.trigger_type, amendment.rule_id)
                return

            conn.execute("""
                INSERT INTO amendments
                    (amendment_id, trigger_type, rule_id, target, proposal,
                     evidence, rationale, status, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (amendment.amendment_id, amendment.trigger_type, amendment.rule_id,
                  amendment.target,
                  json.dumps(amendment.proposal),
                  json.dumps(amendment.evidence),
                  amendment.rationale,
                  amendment.status,
                  amendment.created_at))

    # ── Review API ─────────────────────────────────────────────────────────────

    def pending(self) -> List[Amendment]:
        """Return all pending amendments."""
        with self._graph._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM amendments WHERE status='pending' ORDER BY created_at ASC"
            ).fetchall()
        return [self._row_to_amendment(r) for r in rows]

    def all_amendments(self) -> List[Amendment]:
        with self._graph._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM amendments ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_amendment(r) for r in rows]

    def approve(self, amendment_id: str) -> bool:
        """Approve a pending amendment. Returns True if successful."""
        return self._set_status(amendment_id, APPROVED)

    def reject(self, amendment_id: str) -> bool:
        """Reject a pending amendment."""
        return self._set_status(amendment_id, REJECTED)

    def rollback(self, amendment_id: str) -> bool:
        """Roll back an approved amendment."""
        return self._set_status(amendment_id, ROLLED_BACK)

    def _set_status(self, amendment_id: str, status: str) -> bool:
        with self._graph._conn() as conn:
            result = conn.execute("""
                UPDATE amendments SET status=?, resolved_at=?
                WHERE amendment_id=?
            """, (status, time.time(), amendment_id))
        changed = result.rowcount > 0
        if changed:
            log.info("[AmendmentEngine] Amendment %s -> %s", amendment_id[:8], status)
        return changed

    def evaluate(self, amendment_id: str, sessions_since: int,
                 outcome: str) -> None:
        """Record the evaluation result for an approved amendment."""
        with self._graph._conn() as conn:
            conn.execute("""
                UPDATE amendments SET eval_sessions=?, eval_outcome=?
                WHERE amendment_id=?
            """, (sessions_since, outcome, amendment_id))

    def _row_to_amendment(self, row) -> Amendment:
        return Amendment(
            amendment_id=row["amendment_id"],
            trigger_type=row["trigger_type"],
            rule_id=row["rule_id"],
            target=row["target"],
            proposal=json.loads(row["proposal"]),
            evidence=json.loads(row["evidence"]),
            rationale=row["rationale"],
            status=row["status"],
            created_at=row["created_at"],
            resolved_at=row["resolved_at"],
            eval_sessions=row["eval_sessions"],
            eval_outcome=row["eval_outcome"],
        )

    def summary(self) -> dict:
        with self._graph._conn() as conn:
            rows = conn.execute("""
                SELECT status, COUNT(*) as c FROM amendments GROUP BY status
            """).fetchall()
        return {r["status"]: r["c"] for r in rows}
