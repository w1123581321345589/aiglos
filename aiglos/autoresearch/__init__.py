"""
aiglos.autoresearch — Threat intelligence wiki engine.

Self-improving knowledge base that compiles raw security intelligence into
structured wiki pages and machine-readable T-rule proposals.

Components:
    ThreatWiki   — Core wiki engine: INGEST, PROPOSE, LINT, EVOLVE
    FeedManager  — Ingest connectors: NVD, GHSA, MITRE, RSS
    RawItem      — Normalized raw intelligence envelope
    RuleProposal — Structured rule recommendation
"""

from aiglos.autoresearch.wiki import ThreatWiki, RuleProposal, IngestResult, LintReport
from aiglos.autoresearch.feeds import FeedManager, RawItem, FetchResult

__all__ = [
    "ThreatWiki",
    "RuleProposal",
    "IngestResult",
    "LintReport",
    "FeedManager",
    "RawItem",
    "FetchResult",
]
