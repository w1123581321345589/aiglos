import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"


@dataclass
class Amendment:
    amendment_id: str
    rule_id: str
    trigger_type: str
    target: str
    proposal: str
    rationale: str
    evidence: Dict = field(default_factory=dict)
    status: str = PENDING
    created_at: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "amendment_id": self.amendment_id,
            "rule_id": self.rule_id,
            "trigger_type": self.trigger_type,
            "target": self.target,
            "proposal": self.proposal,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "status": self.status,
            "created_at": self.created_at,
        }


_TARGET_MAP = {
    "HIGH_OVERRIDE": "tier_reclassification",
    "FALSE_POSITIVE": "rule_suppression",
    "SPAWN_NO_POLICY": "policy_propagation",
    "FIN_EXEC_BYPASS": "financial_lockdown",
    "REWARD_DRIFT": "reward_quarantine",
}


class AmendmentEngine:

    def __init__(self, graph):
        self._graph = graph
        self._ensure_schema()

    def _ensure_schema(self):
        with self._graph._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS amendments (
                    amendment_id TEXT PRIMARY KEY,
                    rule_id TEXT,
                    trigger_type TEXT,
                    target TEXT,
                    proposal TEXT,
                    rationale TEXT,
                    evidence TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at REAL,
                    eval_outcome TEXT DEFAULT '',
                    eval_sessions INTEGER DEFAULT 0
                )
            """)

    def propose(self, triggers) -> List[Amendment]:
        candidates = [t for t in triggers if t.amendment_candidate]
        if not candidates:
            return []
        results = []
        for t in candidates:
            aid = hashlib.sha256(f"{t.trigger_type}:{t.rule_id}".encode()).hexdigest()[:16]
            with self._graph._conn() as conn:
                existing = conn.execute(
                    "SELECT 1 FROM amendments WHERE amendment_id=?", (aid,)
                ).fetchone()
                if existing:
                    continue
            target = _TARGET_MAP.get(t.trigger_type, "review")
            proposal = f"Adjust {t.rule_id} based on {t.trigger_type} evidence"
            rationale = t.evidence_summary
            now = time.time()
            amendment = Amendment(
                amendment_id=aid, rule_id=t.rule_id, trigger_type=t.trigger_type,
                target=target, proposal=proposal, rationale=rationale,
                evidence=t.evidence_data, status=PENDING, created_at=now,
            )
            with self._graph._conn() as conn:
                conn.execute(
                    "INSERT INTO amendments (amendment_id, rule_id, trigger_type, target, proposal, rationale, evidence, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (aid, t.rule_id, t.trigger_type, target, proposal, rationale,
                     str(t.evidence_data), PENDING, now),
                )
            results.append(amendment)
        return results

    def approve(self, amendment_id: str) -> bool:
        with self._graph._conn() as conn:
            conn.execute(
                "UPDATE amendments SET status=? WHERE amendment_id=?",
                (APPROVED, amendment_id),
            )
        return True

    def reject(self, amendment_id: str) -> bool:
        with self._graph._conn() as conn:
            conn.execute(
                "UPDATE amendments SET status=? WHERE amendment_id=?",
                (REJECTED, amendment_id),
            )
        return True

    def rollback(self, amendment_id: str) -> bool:
        with self._graph._conn() as conn:
            conn.execute(
                "UPDATE amendments SET status='rolled_back' WHERE amendment_id=?",
                (amendment_id,),
            )
        return True

    def evaluate(self, amendment_id: str, sessions_since: int = 0, outcome: str = ""):
        with self._graph._conn() as conn:
            conn.execute(
                "UPDATE amendments SET eval_outcome=?, eval_sessions=? WHERE amendment_id=?",
                (outcome, sessions_since, amendment_id),
            )

    def pending(self) -> List[Amendment]:
        return [a for a in self.all_amendments() if a.status == PENDING]

    def all_amendments(self) -> List[Amendment]:
        with self._graph._conn() as conn:
            rows = conn.execute("SELECT * FROM amendments ORDER BY created_at").fetchall()
        return [Amendment(
            amendment_id=r["amendment_id"], rule_id=r["rule_id"],
            trigger_type=r["trigger_type"], target=r["target"],
            proposal=r["proposal"], rationale=r["rationale"],
            evidence={}, status=r["status"], created_at=r["created_at"],
        ) for r in rows]

    def summary(self) -> Dict:
        all_a = self.all_amendments()
        return {
            "total": len(all_a),
            "pending": sum(1 for a in all_a if a.status == PENDING),
            "approved": sum(1 for a in all_a if a.status == APPROVED),
            "rejected": sum(1 for a in all_a if a.status == REJECTED),
        }
