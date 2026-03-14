from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class SessionPolicy:
    derived_from: str = ""
    evidence_sessions: int = 0
    inherited_allow_http: List[str] = field(default_factory=list)
    tier_overrides: Dict[str, str] = field(default_factory=dict)
    suppressed_rules: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return (not self.inherited_allow_http and
                not self.tier_overrides and
                not self.suppressed_rules)

    def to_dict(self) -> Dict:
        return {
            "derived_from": self.derived_from,
            "evidence_sessions": self.evidence_sessions,
            "inherited_allow_http": self.inherited_allow_http,
            "tier_overrides": self.tier_overrides,
            "suppressed_rules": self.suppressed_rules,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "SessionPolicy":
        return cls(
            derived_from=d.get("derived_from", ""),
            evidence_sessions=d.get("evidence_sessions", 0),
            inherited_allow_http=d.get("inherited_allow_http", []),
            tier_overrides=d.get("tier_overrides", {}),
            suppressed_rules=d.get("suppressed_rules", []),
        )

    @classmethod
    def empty(cls, parent_id: str) -> "SessionPolicy":
        return cls(derived_from=parent_id)


class PolicySerializer:

    def __init__(self, graph):
        self._graph = graph

    def derive(self, parent_id: str) -> SessionPolicy:
        stats = self._graph.all_rule_stats()
        sessions = self._graph.session_count()
        tier_overrides = {}
        suppressed = []
        allow_http: List[str] = []
        for s in stats:
            if s.fires_total >= 5 and s.warns_total > 0:
                warn_rate = s.warns_total / s.fires_total if s.fires_total else 0
                if warn_rate >= 0.6:
                    tier_overrides[s.rule_id] = "tier2"
                if warn_rate >= 0.8 and s.blocks_total == 0:
                    suppressed.append(s.rule_id)
        return SessionPolicy(
            derived_from=parent_id,
            evidence_sessions=sessions,
            inherited_allow_http=allow_http,
            tier_overrides=tier_overrides,
            suppressed_rules=suppressed,
        )
