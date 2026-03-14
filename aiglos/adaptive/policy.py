from dataclasses import dataclass, field, asdict
from typing import List, Dict


@dataclass
class SessionPolicy:
    derived_from: str = ""
    evidence_sessions: int = 0
    inherited_allow_http: list[str] = field(default_factory=list)
    tier_overrides: dict[str, str] = field(default_factory=dict)
    suppressed_rules: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return (not self.inherited_allow_http and
                not self.tier_overrides and
                not self.suppressed_rules)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SessionPolicy":
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
    """Derives child-session policies from historical observation data."""

    def __init__(self, graph):
        self._graph = graph

    def derive(self, parent_id: str) -> SessionPolicy:
        stats = self._graph.all_rule_stats()
        sessions = self._graph.session_count()
        tier_overrides: dict[str, str] = {}
        suppressed: list[str] = []
        # TODO: populate allow_http from observed safe hosts in parent session
        allow_http: list[str] = []
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
