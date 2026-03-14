"""
aiglos.adaptive
================
Adaptive security layer for Aiglos — the cognee-skills-inspired feedback loop
that makes threat detection rules living components rather than static files.

observe → inspect → amend → evaluate

Components:
  ObservationGraph   — SQLite-backed session history (Phase 1)
  InspectionEngine   — trigger conditions that surface rules needing attention (Phase 2)
  AmendmentEngine    — evidence-based proposals to rules/allow-lists (Phase 4)
  PolicySerializer   — derive child agent policies from parent history (Phase 5)

Semantic scoring (Phase 3) lives in aiglos.integrations.multi_agent.AgentDefGuard.

Quick start:
    from aiglos.adaptive import AdaptiveEngine

    engine = AdaptiveEngine()          # uses ~/.aiglos/observations.db
    engine.ingest(artifact)            # call after aiglos.close()
    report = engine.run()              # inspect + propose amendments
    print(report)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from aiglos.adaptive.observation import ObservationGraph, RuleStats
from aiglos.adaptive.inspect import InspectionEngine, InspectionTrigger
from aiglos.adaptive.amend import AmendmentEngine, Amendment
from aiglos.adaptive.policy import PolicySerializer, SessionPolicy

log = logging.getLogger("aiglos.adaptive")

__all__ = [
    "AdaptiveEngine",
    "ObservationGraph",
    "InspectionEngine",
    "AmendmentEngine",
    "PolicySerializer",
    "RuleStats",
    "InspectionTrigger",
    "Amendment",
    "SessionPolicy",
]


class AdaptiveEngine:
    """
    Facade that wires the full adaptive loop: observe → inspect → amend.

    One object for teams that want the full system without managing each
    component individually.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.graph    = ObservationGraph(db_path=db_path)
        self.inspector = InspectionEngine(self.graph)
        self.amender   = AmendmentEngine(self.graph)
        self.policy    = PolicySerializer(self.graph)

    def ingest(self, artifact: Any) -> str:
        """Ingest a SessionArtifact. Returns session_id."""
        return self.graph.ingest(artifact)

    def run(self) -> dict:
        """
        Run a full adaptive cycle: inspect + generate amendment proposals.

        Returns a summary report dict.
        """
        triggers  = self.inspector.run()
        proposals = self.amender.propose(triggers)
        summary   = self.graph.summary()

        report = {
            "graph_summary":   summary,
            "triggers_fired":  len(triggers),
            "triggers":        [t.to_dict() for t in triggers],
            "proposals_made":  len(proposals),
            "proposals":       [p.to_dict() for p in proposals],
            "pending_amendments": len(self.amender.pending()),
        }
        if triggers:
            log.warning("[AdaptiveEngine] %d inspection trigger(s), %d proposal(s).",
                        len(triggers), len(proposals))
        return report

    def derive_child_policy(self, parent_session_id: str) -> SessionPolicy:
        """Derive a policy for a spawned child agent from parent history."""
        return self.policy.derive(parent_session_id)

    def stats(self) -> dict:
        """Return the current observation graph summary."""
        return self.graph.summary()
