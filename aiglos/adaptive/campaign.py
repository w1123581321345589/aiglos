from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class CampaignResult:
    pattern_id: str
    confidence: float = 0.0
    matched_rules: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            "pattern_id": self.pattern_id,
            "confidence": self.confidence,
            "matched_rules": self.matched_rules,
            "recommendation": self.recommendation,
        }


_CAMPAIGN_PATTERNS = [
    {"name": "RECON_SWEEP", "requires": [{"T01", "T02"}, {"T01", "T03"}], "rec": "Block reconnaissance tools"},
    {"name": "CREDENTIAL_ACCUMULATE", "requires": [{"T19", "T07"}], "rec": "Revoke credential access"},
    {"name": "EXFIL_SETUP", "requires": [{"T13", "T07"}, {"T13", "T19"}], "rec": "Block exfiltration channels"},
    {"name": "PERSISTENCE_CHAIN", "requires": [{"T34", "T07"}, {"T34", "T30"}], "rec": "Remove persistence mechanisms"},
    {"name": "LATERAL_PREP", "requires": [{"T07", "T13"}, {"T38", "T07"}], "rec": "Isolate lateral movement"},
    {"name": "AGENTDEF_CHAIN", "requires": [{"T36", "T07"}, {"T36_AGENTDEF", "T07"}, {"T36", "T19"}, {"T36_AGENTDEF", "T19"}], "rec": "Lock agent definitions"},
    {"name": "MEMORY_PERSISTENCE_CHAIN", "requires": [{"T31", "T37"}, {"T31", "T19"}, {"T31", "T23"}], "rec": "Enable ByteRover memory guard and audit memory writes"},
    {"name": "REWARD_MANIPULATION", "requires": [{"T37", "T39"}, {"T19", "T39"}, {"T36_AGENTDEF", "T39"}, {"T07", "T39"}, {"T_DEST", "T39"}], "rec": "Halt RL training pipeline and audit reward signals"},
]


class CampaignAnalyzer:

    def __init__(self, graph):
        self._graph = graph

    def analyze_session(self, session_id: str) -> List[CampaignResult]:
        events = []
        with self._graph._conn() as conn:
            rows = conn.execute(
                "SELECT rule_id, verdict FROM events WHERE session_id=?", (session_id,)
            ).fetchall()
        for r in rows:
            events.append({"rule_id": r["rule_id"], "verdict": r["verdict"]})

        rule_ids = {e["rule_id"] for e in events}
        results = []
        for pattern in _CAMPAIGN_PATTERNS:
            for req_set in pattern["requires"]:
                if req_set.issubset(rule_ids):
                    confidence = min(1.0, len(req_set & rule_ids) / len(req_set))
                    results.append(CampaignResult(
                        pattern_id=pattern["name"],
                        confidence=confidence,
                        matched_rules=sorted(req_set & rule_ids),
                        recommendation=pattern["rec"],
                    ))
                    break
        return results

    def analyze_all(self) -> List[CampaignResult]:
        all_results = []
        with self._graph._conn() as conn:
            sids = [r[0] for r in conn.execute("SELECT session_id FROM sessions").fetchall()]
        for sid in sids:
            all_results.extend(self.analyze_session(sid))
        return all_results
