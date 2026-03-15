from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class InspectionTrigger:
    trigger_type: str
    rule_id: str
    severity: str = "MEDIUM"
    evidence_summary: str = ""
    evidence_data: Dict = field(default_factory=dict)
    amendment_candidate: bool = False

    def to_dict(self) -> Dict:
        return {
            "trigger_type": self.trigger_type,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "evidence_summary": self.evidence_summary,
            "evidence_data": self.evidence_data,
            "amendment_candidate": self.amendment_candidate,
        }


_FIN_RULES = {"T37", "T38"}
_FIN_URLS = {"stripe.com", "paypal.com", "braintree", "plaid.com", "square.com"}


class InspectionEngine:

    def __init__(self, graph=None, **kwargs):
        self._graph = graph
        self.HIGH_OVERRIDE_MIN = kwargs.get("HIGH_OVERRIDE_MIN", 5)
        self.AGENTDEF_REPEAT_MIN = kwargs.get("AGENTDEF_REPEAT_MIN", 3)
        self.SPAWN_NO_POLICY_MIN = kwargs.get("SPAWN_NO_POLICY_MIN", 3)
        self.FIN_BYPASS_MIN = kwargs.get("FIN_BYPASS_MIN", 3)
        self.FALSE_POSITIVE_WARN_RATE = kwargs.get("FALSE_POSITIVE_WARN_RATE", 0.7)
        self.REWARD_DRIFT_MIN_SIGNALS = kwargs.get("REWARD_DRIFT_MIN_SIGNALS", 5)
        self.REWARD_DRIFT_THRESHOLD = kwargs.get("REWARD_DRIFT_THRESHOLD", 0.50)

    def run(self) -> List[InspectionTrigger]:
        if self._graph is None:
            return []
        triggers: List[InspectionTrigger] = []
        triggers.extend(self._check_high_override())
        triggers.extend(self._check_agentdef_repeat())
        triggers.extend(self._check_spawn_no_policy())
        triggers.extend(self._check_fin_exec_bypass())
        triggers.extend(self._check_false_positive())
        triggers.extend(self._check_reward_drift())
        return triggers

    def _check_high_override(self) -> List[InspectionTrigger]:
        results = []
        for s in self._graph.all_rule_stats():
            if s.warns_total >= self.HIGH_OVERRIDE_MIN:
                results.append(InspectionTrigger(
                    trigger_type="HIGH_OVERRIDE",
                    rule_id=s.rule_id,
                    severity="MEDIUM",
                    evidence_summary=f"{s.rule_id} overridden {s.warns_total} times",
                    evidence_data={"warns_total": s.warns_total, "fires_total": s.fires_total},
                    amendment_candidate=True,
                ))
        return results

    def _check_agentdef_repeat(self) -> List[InspectionTrigger]:
        results = []
        with self._graph._conn() as conn:
            rows = conn.execute(
                "SELECT path, COUNT(DISTINCT session_id) as cnt, MAX(semantic_risk) as max_risk "
                "FROM agentdef_observations GROUP BY path"
            ).fetchall()
        for r in rows:
            if r["cnt"] >= self.AGENTDEF_REPEAT_MIN:
                severity = "HIGH" if r["max_risk"] == "HIGH" else "MEDIUM"
                results.append(InspectionTrigger(
                    trigger_type="AGENTDEF_REPEAT",
                    rule_id="T36_AGENTDEF",
                    severity=severity,
                    evidence_summary=f"{r['path']} violated in {r['cnt']} sessions",
                    evidence_data={"path": r["path"], "session_count": r["cnt"]},
                    amendment_candidate=False,
                ))
        return results

    def _check_spawn_no_policy(self) -> List[InspectionTrigger]:
        with self._graph._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM spawn_events WHERE policy_propagated=0"
            ).fetchone()
        if row["cnt"] >= self.SPAWN_NO_POLICY_MIN:
            return [InspectionTrigger(
                trigger_type="SPAWN_NO_POLICY",
                rule_id="T38",
                severity="MEDIUM",
                evidence_summary=f"{row['cnt']} spawns without policy propagation",
                evidence_data={"spawn_count_no_policy": row["cnt"]},
                amendment_candidate=True,
            )]
        return []

    def _check_fin_exec_bypass(self) -> List[InspectionTrigger]:
        results = []
        for s in self._graph.all_rule_stats():
            if s.rule_id in _FIN_RULES and s.warns_total >= self.FIN_BYPASS_MIN:
                results.append(InspectionTrigger(
                    trigger_type="FIN_EXEC_BYPASS",
                    rule_id=s.rule_id,
                    severity="HIGH",
                    evidence_summary=f"{s.rule_id} financial bypass {s.warns_total} warns",
                    evidence_data={"warns_total": s.warns_total, "fires_total": s.fires_total},
                    amendment_candidate=True,
                ))
                continue
            events = self._graph.events_for_rule(s.rule_id)
            fin_warns = sum(1 for e in events if e.get("verdict") == "WARN" and
                           any(fu in (e.get("url", "") + e.get("cmd", "")) for fu in _FIN_URLS))
            if fin_warns >= self.FIN_BYPASS_MIN:
                results.append(InspectionTrigger(
                    trigger_type="FIN_EXEC_BYPASS",
                    rule_id=s.rule_id,
                    severity="HIGH",
                    evidence_summary=f"{s.rule_id} financial bypass {fin_warns} warns",
                    evidence_data={"warns_total": fin_warns, "fires_total": s.fires_total},
                    amendment_candidate=True,
                ))
        return results

    def _check_false_positive(self) -> List[InspectionTrigger]:
        results = []
        for s in self._graph.all_rule_stats():
            if s.fires_total >= 5 and s.warns_total > 0:
                warn_rate = s.warns_total / s.fires_total
                if warn_rate >= self.FALSE_POSITIVE_WARN_RATE:
                    results.append(InspectionTrigger(
                        trigger_type="FALSE_POSITIVE",
                        rule_id=s.rule_id,
                        severity="LOW",
                        evidence_summary=f"{s.rule_id} warn rate {warn_rate:.0%}",
                        evidence_data={
                            "fires_total": s.fires_total,
                            "warns_total": s.warns_total,
                            "blocks_total": s.blocks_total,
                            "warn_rate": warn_rate,
                        },
                        amendment_candidate=True,
                    ))
        return results

    def _check_reward_drift(self) -> List[InspectionTrigger]:
        try:
            stats = self._graph.reward_signal_stats()
        except Exception:
            return []
        total = stats.get("total_signals", 0)
        if total < self.REWARD_DRIFT_MIN_SIGNALS:
            return []
        quarantined = stats.get("quarantined", 0)
        rate = quarantined / total if total else 0
        if rate >= self.REWARD_DRIFT_THRESHOLD:
            return [InspectionTrigger(
                trigger_type="REWARD_DRIFT",
                rule_id="T39",
                severity="HIGH",
                evidence_summary=f"Reward quarantine rate {rate:.0%} over {total} signals",
                evidence_data={"quarantine_rate": rate, "total_signals": total, "quarantined": quarantined},
                amendment_candidate=True,
            )]
        return []
