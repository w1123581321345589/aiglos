"""
tests/test_citation_verifier.py
=================================
Aiglos v0.14.0 — Verified Threat Intelligence

Tests cover:
  - CitationVerifier: OWASP lookup, MITRE ATLAS lookup, internal fallback
  - CitationVerifier: NVD mock, rate limiting, graceful network failure
  - VerifiedCitation: construction, lifecycle, serialization
  - ThreatLiteratureSearch: relevance scoring, rule suggestion, mock scans
  - VerifiedRuleEngine: run_with_verification, citation coverage, unverified rules
  - ComplianceReportGenerator: report generation, markdown output, JSON output
  - ObservationGraph: rule_citations table, threat_signals table, CRUD
  - InspectionEngine: UNVERIFIED_RULE_ACTIVE trigger (14th)
  - Module API: v0.14.0 version, exports
"""

import os
import sys
import time
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiglos
from aiglos.adaptive.observation import ObservationGraph
from aiglos.autoresearch.citation_verifier import (
    CitationVerifier,
    CitationStatus,
    VerifiedCitation,
    _OWASP_ASI,
    _MITRE_ATLAS,
    _MIN_CONFIDENCE,
    _INTERNAL_FALLBACK_BLOCKS,
)
from aiglos.autoresearch.threat_literature import (
    ThreatLiteratureSearch,
    ThreatSignal,
)
from aiglos.autoresearch.verified_rule_engine import (
    VerifiedRuleEngine,
    VerifiedRunResult,
)
from aiglos.autoresearch.compliance_report import (
    ComplianceReportGenerator,
    ComplianceReport,
    _NDAA_1513_REQUIREMENTS,
    _EU_AI_ACT_REQUIREMENTS,
    _NIST_600_1_CATEGORIES,
)


# =============================================================================
# Helpers
# =============================================================================

def _make_graph(tmp_path) -> ObservationGraph:
    return ObservationGraph(db_path=str(tmp_path / "obs.db"))


def _make_citation(
    rule_id="T37",
    source="OWASP_ASI",
    reference_id="ASI-02",
    confidence=0.90,
    status=CitationStatus.VERIFIED,
) -> VerifiedCitation:
    return VerifiedCitation(
        rule_id        = rule_id,
        source         = source,
        reference_id   = reference_id,
        reference_name = f"OWASP {reference_id}",
        reference_url  = "https://owasp.org/",
        confidence     = confidence,
        status         = status,
        evidence_summary = "Test citation",
    )


def _make_signal(
    rule_id="T37",
    source="NVD",
    reference_id="CVE-2026-25253",
    relevance=0.85,
) -> ThreatSignal:
    import hashlib
    sig_id = "sig_" + hashlib.sha256(reference_id.encode()).hexdigest()[:12]
    return ThreatSignal(
        signal_id        = sig_id,
        source           = source,
        reference_id     = reference_id,
        title            = f"Test signal for {rule_id}",
        description      = "AI agent security vulnerability test",
        published_at     = "2026-03-01T00:00:00Z",
        relevance_score  = relevance,
        suggested_rule   = rule_id,
        keywords_matched = ["AI agent", "prompt injection"],
    )


# =============================================================================
# VerifiedCitation
# =============================================================================

class TestVerifiedCitation:

    def test_construction(self):
        c = _make_citation()
        assert c.rule_id      == "T37"
        assert c.source       == "OWASP_ASI"
        assert c.reference_id == "ASI-02"
        assert c.confidence   == 0.90

    def test_is_verified_true_for_verified(self):
        c = _make_citation(status=CitationStatus.VERIFIED)
        assert c.is_verified is True

    def test_is_verified_true_for_internal(self):
        c = _make_citation(status=CitationStatus.INTERNAL)
        assert c.is_verified is True

    def test_is_verified_false_for_pending(self):
        c = _make_citation(status=CitationStatus.PENDING)
        assert c.is_verified is False

    def test_is_verified_false_for_unverified(self):
        c = _make_citation(status=CitationStatus.UNVERIFIED)
        assert c.is_verified is False

    def test_to_dict_has_required_keys(self):
        d = _make_citation().to_dict()
        for key in ["rule_id", "source", "reference_id", "confidence", "status"]:
            assert key in d

    def test_from_dict_roundtrip(self):
        c1 = _make_citation()
        d  = c1.to_dict()
        c2 = VerifiedCitation.from_dict(d)
        assert c2.rule_id      == c1.rule_id
        assert c2.source       == c1.source
        assert c2.reference_id == c1.reference_id
        assert c2.status       == c1.status
        assert abs(c2.confidence - c1.confidence) < 0.001

    def test_from_dict_tolerates_missing_keys(self):
        c = VerifiedCitation.from_dict({"rule_id": "T01"})
        assert c.rule_id == "T01"
        assert c.confidence == 0.0


# =============================================================================
# CitationVerifier — OWASP
# =============================================================================

class TestCitationVerifierOWASP:

    def test_owasp_check_finds_rule_in_mapping(self):
        verifier = CitationVerifier()
        citation = verifier._check_owasp("T37")
        assert citation is not None
        assert citation.source == "OWASP_ASI"
        assert citation.reference_id.startswith("ASI-")

    def test_owasp_check_returns_none_for_unknown_rule(self):
        verifier = CitationVerifier()
        citation = verifier._check_owasp("T99")
        assert citation is None

    def test_owasp_confidence_above_threshold(self):
        verifier = CitationVerifier()
        citation = verifier._check_owasp("T27")
        assert citation is not None
        assert citation.confidence >= _MIN_CONFIDENCE

    def test_every_mapped_rule_has_owasp_or_atlas(self):
        """Every rule in OWASP/ATLAS mappings should resolve."""
        verifier = CitationVerifier()
        for asi_id, data in _OWASP_ASI.items():
            for rule_id in data["aiglos_rules"]:
                c = verifier._check_owasp(rule_id)
                assert c is not None, f"OWASP check failed for {rule_id}"

    def test_owasp_evidence_summary_not_empty(self):
        verifier = CitationVerifier()
        citation = verifier._check_owasp("T01")
        assert citation is not None
        assert len(citation.evidence_summary) > 20


# =============================================================================
# CitationVerifier — MITRE ATLAS
# =============================================================================

class TestCitationVerifierMITRE:

    def test_atlas_check_finds_rule(self):
        verifier = CitationVerifier()
        citation = verifier._check_mitre_atlas("T01")
        assert citation is not None
        assert citation.source == "MITRE_ATLAS"
        assert "AML.T" in citation.reference_id

    def test_atlas_check_returns_none_for_unmapped(self):
        verifier = CitationVerifier()
        # T13 is not in the MITRE ATLAS mapping
        citation = verifier._check_mitre_atlas("T13")
        assert citation is None

    def test_atlas_confidence_above_threshold(self):
        verifier = CitationVerifier()
        citation = verifier._check_mitre_atlas("T27")
        if citation:
            assert citation.confidence >= _MIN_CONFIDENCE

    def test_atlas_url_format(self):
        verifier = CitationVerifier()
        citation = verifier._check_mitre_atlas("T19")
        if citation:
            assert "atlas.mitre.org" in citation.reference_url


# =============================================================================
# CitationVerifier — internal fallback
# =============================================================================

class TestCitationVerifierInternal:

    def test_internal_check_returns_none_without_graph(self):
        verifier = CitationVerifier(graph=None)
        result   = verifier._check_internal("T37")
        assert result is None

    def test_internal_check_below_threshold_returns_none(self, tmp_path):
        graph    = _make_graph(tmp_path)
        verifier = CitationVerifier(graph=graph)
        # Add fewer blocks than threshold
        for _ in range(_INTERNAL_FALLBACK_BLOCKS - 1):
            graph.record_block_pattern_event(
                "pat_x", "agent", "T37", "http.post", "x", tier=3
            )
        result = verifier._check_internal("T37")
        assert result is None

    def test_internal_check_above_threshold_returns_citation(self, tmp_path):
        graph    = _make_graph(tmp_path)
        verifier = CitationVerifier(graph=graph)
        for _ in range(_INTERNAL_FALLBACK_BLOCKS + 5):
            graph.record_block_pattern_event(
                "pat_int", "agent", "T19", "subprocess.run", "x", tier=3
            )
        result = verifier._check_internal("T19")
        assert result is not None
        assert result.status  == CitationStatus.INTERNAL
        assert result.source  == "INTERNAL"
        assert result.confidence >= _MIN_CONFIDENCE

    def test_internal_confidence_scales_with_blocks(self, tmp_path):
        graph = _make_graph(tmp_path)
        for rule_id, count in [("T07", 25), ("T08", 100)]:
            for _ in range(count):
                graph.record_block_pattern_event(
                    f"pat_{rule_id}", "agent", rule_id, "t", "x", tier=3
                )
        v     = CitationVerifier(graph=graph)
        c25   = v._check_internal("T07")
        c100  = v._check_internal("T08")
        if c25 and c100:
            assert c100.confidence >= c25.confidence


# =============================================================================
# CitationVerifier — NVD (mocked)
# =============================================================================

class TestCitationVerifierNVD:

    def _mock_nvd_response(self, cve_id="CVE-2026-25253", description="AI agent RCE"):
        import json, io
        data = {
            "vulnerabilities": [{
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": description}],
                    "published": "2026-03-01T00:00:00.000",
                }
            }]
        }
        mock = MagicMock()
        mock.getcode.return_value = 200
        mock.read.return_value    = json.dumps(data).encode("utf-8")
        mock.__enter__ = lambda s: mock
        mock.__exit__  = MagicMock(return_value=False)
        return mock

    def test_nvd_returns_citation_on_success(self):
        verifier = CitationVerifier()
        with patch("urllib.request.urlopen",
                   return_value=self._mock_nvd_response()):
            citation = verifier._check_nvd("T36_AGENTDEF", "AGENTDEF")
        assert citation is not None
        assert citation.source        == "NVD"
        assert citation.reference_id  == "CVE-2026-25253"

    def test_nvd_returns_none_on_network_error(self):
        from urllib.error import URLError
        verifier = CitationVerifier()
        with patch("urllib.request.urlopen",
                   side_effect=URLError("refused")):
            result = verifier._check_nvd("T37", "FIN_EXEC")
        assert result is None

    def test_nvd_returns_none_for_empty_results(self):
        import json
        mock = MagicMock()
        mock.getcode.return_value = 200
        mock.read.return_value    = json.dumps({"vulnerabilities": []}).encode()
        mock.__enter__ = lambda s: mock
        mock.__exit__  = MagicMock(return_value=False)
        verifier = CitationVerifier()
        with patch("urllib.request.urlopen", return_value=mock):
            result = verifier._check_nvd("T01", "INJECT")
        assert result is None


# =============================================================================
# CitationVerifier — verify_rule integration
# =============================================================================

class TestCitationVerifierVerifyRule:

    def test_verify_rule_returns_citation_for_owasp_mapped_rule(self):
        verifier = CitationVerifier(graph=None)
        citation = verifier.verify_rule("T27", "INJECT")
        assert citation is not None
        assert citation.rule_id == "T27"

    def test_verify_rule_never_raises(self):
        verifier = CitationVerifier(graph=None)
        for rule_id in ["T01", "T19", "T37", "T99", "INVALID"]:
            result = verifier.verify_rule(rule_id)
            assert result is not None

    def test_verify_rule_uses_graph_cache(self, tmp_path):
        graph    = _make_graph(tmp_path)
        verifier = CitationVerifier(graph=graph)
        citation = _make_citation(rule_id="T01")
        graph.upsert_citation(citation)
        loaded = verifier.verify_rule("T01")
        assert loaded.rule_id == "T01"

    def test_citation_summary_correct_counts(self):
        verifier  = CitationVerifier(graph=None)
        citations = {
            "T01": _make_citation("T01", status=CitationStatus.VERIFIED),
            "T02": _make_citation("T02", status=CitationStatus.INTERNAL),
            "T03": _make_citation("T03", status=CitationStatus.PENDING),
            "T04": _make_citation("T04", status=CitationStatus.UNVERIFIED),
        }
        summary = verifier.citation_summary(citations)
        assert summary["verified"]   == 1
        assert summary["internal"]   == 1
        assert summary["pending"]    == 1
        assert summary["unverified"] == 1
        assert summary["total"]      == 4
        assert summary["coverage"]   == 0.50


# =============================================================================
# ObservationGraph — citation and signal tables
# =============================================================================

class TestObservationGraphCitations:

    def test_upsert_and_get_citation(self, tmp_path):
        graph    = _make_graph(tmp_path)
        citation = _make_citation()
        graph.upsert_citation(citation)
        loaded = graph.get_citation("T37")
        assert loaded is not None
        assert loaded.rule_id     == "T37"
        assert loaded.source      == "OWASP_ASI"
        assert loaded.status      == CitationStatus.VERIFIED

    def test_get_citation_returns_none_for_unknown(self, tmp_path):
        graph = _make_graph(tmp_path)
        assert graph.get_citation("T99") is None

    def test_upsert_citation_updates_on_conflict(self, tmp_path):
        graph = _make_graph(tmp_path)
        c1    = _make_citation(confidence=0.70)
        c2    = _make_citation(confidence=0.95)
        graph.upsert_citation(c1)
        graph.upsert_citation(c2)
        loaded = graph.get_citation("T37")
        assert abs(loaded.confidence - 0.95) < 0.01

    def test_get_rule_block_count(self, tmp_path):
        graph = _make_graph(tmp_path)
        for _ in range(7):
            graph.record_block_pattern_event(
                "pat_count", "agent", "T19", "subprocess", "x", tier=3
            )
        count = graph.get_rule_block_count("T19")
        assert count == 7

    def test_upsert_and_get_threat_signal(self, tmp_path):
        graph  = _make_graph(tmp_path)
        signal = _make_signal()
        graph.upsert_threat_signal(signal)
        signals = graph.get_threat_signals(rule_id="T37")
        assert len(signals) == 1
        assert signals[0].reference_id == "CVE-2026-25253"

    def test_list_threat_signals(self, tmp_path):
        graph = _make_graph(tmp_path)
        for i in range(5):
            s = _make_signal(reference_id=f"CVE-2026-{i:05d}")
            graph.upsert_threat_signal(s)
        signals = graph.list_threat_signals(limit=3)
        assert len(signals) == 3


# =============================================================================
# ThreatLiteratureSearch
# =============================================================================

class TestThreatLiteratureSearch:

    def test_score_relevance_zero_for_unrelated_text(self):
        searcher = ThreatLiteratureSearch()
        score, _ = searcher._score_relevance("nothing about AI here")
        assert score == 0.0

    def test_score_relevance_nonzero_for_ai_agent_text(self):
        searcher = ThreatLiteratureSearch()
        score, matched = searcher._score_relevance(
            "prompt injection in AI agent via MCP tool call"
        )
        assert score > 0.0
        assert len(matched) > 0

    def test_score_relevance_high_for_specific_keywords(self):
        searcher = ThreatLiteratureSearch()
        score, _ = searcher._score_relevance(
            "claude code cursor AI agent prompt injection mcp vulnerability"
        )
        assert score >= 0.50

    def test_suggest_rule_returns_correct_rule(self):
        searcher = ThreatLiteratureSearch()
        assert searcher._suggest_rule("prompt injection AI") == "T01"
        assert searcher._suggest_rule("credential access SSH keys") == "T19"
        assert searcher._suggest_rule("supply chain malicious package npm") == "T30"

    def test_suggest_rule_returns_none_for_unrelated(self):
        searcher = ThreatLiteratureSearch()
        result = searcher._suggest_rule("completely unrelated text here")
        assert result is None

    def test_scan_new_threats_graceful_on_network_failure(self):
        from urllib.error import URLError
        searcher = ThreatLiteratureSearch(graph=None)
        with patch("urllib.request.urlopen",
                   side_effect=URLError("network unavailable")):
            signals = searcher.scan_new_threats(since_days=7)
        assert isinstance(signals, list)   # never raises

    def test_threat_signal_summary(self):
        signal = _make_signal()
        s = signal.summary()
        assert "NVD" in s
        assert "CVE-2026-25253" in s

    def test_threat_signal_to_dict(self):
        signal = _make_signal()
        d      = signal.to_dict()
        assert d["rule_id"]      == "T37"
        assert d["source"]       == "NVD"
        assert d["relevance_score"] == 0.85


# =============================================================================
# VerifiedRuleEngine
# =============================================================================

class TestVerifiedRuleEngine:

    def test_run_with_verification_returns_result(self, tmp_path):
        graph  = _make_graph(tmp_path)
        engine = VerifiedRuleEngine(
            graph=graph,
            output_dir=str(tmp_path / "research"),
        )
        # Patch out the heavy autoresearch loop and network calls
        with patch.object(engine._literature, "scan_new_threats", return_value=[]), \
             patch.object(engine._verifier, "verify_rule",
                          side_effect=lambda r, c="", force_refresh=False:
                          _make_citation(r, status=CitationStatus.VERIFIED)):
            result = engine.run_with_verification(
                category="CRED_ACCESS", rounds=0,
                adversarial=False, scan_literature=True,
            )

        assert isinstance(result, VerifiedRunResult)
        assert result.category == "CRED_ACCESS"

    def test_citation_coverage_calculation(self):
        from aiglos.autoresearch.citation_verifier import CitationStatus
        citations = {
            "T01": _make_citation("T01", status=CitationStatus.VERIFIED),
            "T02": _make_citation("T02", status=CitationStatus.INTERNAL),
            "T03": _make_citation("T03", status=CitationStatus.PENDING),
            "T04": _make_citation("T04", status=CitationStatus.UNVERIFIED),
        }
        result = VerifiedRunResult(
            category="TEST", rounds=0, adversarial=False,
            best_fitness=0.0, best_rule_code="",
            citations=citations,
        )
        assert result.citation_coverage == 0.50
        assert "T03" in result.unverified_rules
        assert "T04" in result.unverified_rules
        assert "T01" not in result.unverified_rules

    def test_verify_single_rule(self, tmp_path):
        graph    = _make_graph(tmp_path)
        engine   = VerifiedRuleEngine(graph=graph)
        citation = engine.verify_single_rule("T27", "INJECT")
        assert citation is not None
        assert citation.rule_id == "T27"

    def test_citation_status_all_returns_all_rules(self, tmp_path):
        graph  = _make_graph(tmp_path)
        engine = VerifiedRuleEngine(graph=graph)
        status = engine.citation_status_all()
        assert "T01"         in status
        assert "T37"         in status
        assert "T36_AGENTDEF" in status


# =============================================================================
# ComplianceReportGenerator
# =============================================================================

class TestComplianceReportGenerator:

    def test_generate_returns_report(self, tmp_path):
        graph = _make_graph(tmp_path)
        gen   = ComplianceReportGenerator(
            graph=graph, output_dir=str(tmp_path / "reports")
        )
        report = gen.generate(save=False)
        assert isinstance(report, ComplianceReport)
        assert report.total_rules > 0

    def test_markdown_contains_ndaa_section(self, tmp_path):
        graph  = _make_graph(tmp_path)
        gen    = ComplianceReportGenerator(
            graph=graph, output_dir=str(tmp_path / "reports")
        )
        report = gen.generate(save=False)
        md     = report.markdown()
        assert "NDAA" in md
        assert "§1513" in md

    def test_markdown_contains_eu_ai_act_section(self, tmp_path):
        graph  = _make_graph(tmp_path)
        gen    = ComplianceReportGenerator(
            graph=graph, output_dir=str(tmp_path / "reports")
        )
        report = gen.generate(save=False)
        md     = report.markdown()
        assert "EU AI Act" in md
        assert "Annex III" in md

    def test_markdown_contains_nist_section(self, tmp_path):
        graph  = _make_graph(tmp_path)
        gen    = ComplianceReportGenerator(
            graph=graph, output_dir=str(tmp_path / "reports")
        )
        report = gen.generate(save=False)
        md     = report.markdown()
        assert "NIST" in md
        assert "600-1" in md

    def test_json_is_valid(self, tmp_path):
        import json as _json
        graph  = _make_graph(tmp_path)
        gen    = ComplianceReportGenerator(
            graph=graph, output_dir=str(tmp_path / "reports")
        )
        report = gen.generate(save=False)
        data   = _json.loads(report.to_json())
        assert "ndaa_1513"  in data
        assert "eu_ai_act"  in data
        assert "nist_600_1" in data

    def test_executive_summary_contains_coverage(self, tmp_path):
        graph  = _make_graph(tmp_path)
        gen    = ComplianceReportGenerator(
            graph=graph, output_dir=str(tmp_path / "reports")
        )
        report = gen.generate(save=False)
        summary = report.executive_summary()
        assert "NDAA" in summary
        assert "EU AI Act" in summary
        assert "NIST" in summary

    def test_report_saved_to_disk(self, tmp_path):
        report_dir = tmp_path / "reports"
        graph      = _make_graph(tmp_path)
        gen        = ComplianceReportGenerator(
            graph=graph, output_dir=str(report_dir)
        )
        gen.generate(save=True)
        files = list(report_dir.glob("compliance_*.md"))
        assert len(files) >= 1

    def test_ndaa_has_four_requirements(self):
        assert len(_NDAA_1513_REQUIREMENTS) == 4

    def test_eu_ai_act_has_four_requirements(self):
        assert len(_EU_AI_ACT_REQUIREMENTS) == 4

    def test_nist_has_four_categories(self):
        assert len(_NIST_600_1_CATEGORIES) == 4


# =============================================================================
# UNVERIFIED_RULE_ACTIVE inspection trigger (14th)
# =============================================================================

class TestUnverifiedRuleTrigger:

    def test_trigger_does_not_fire_without_block_history(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        graph = _make_graph(tmp_path)
        ie    = InspectionEngine(graph)
        triggers = ie.run()
        t14 = [t for t in triggers if t.trigger_type == "UNVERIFIED_RULE_ACTIVE"]
        assert len(t14) == 0

    def test_trigger_fires_for_rule_with_blocks_but_no_citation(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        graph = _make_graph(tmp_path)
        # Add enough blocks to meet threshold
        for _ in range(15):
            graph.record_block_pattern_event(
                "pat_uv", "agent", "T37", "http.post", "x", tier=3
            )
        ie       = InspectionEngine(graph)
        triggers = ie.run()
        t14 = [t for t in triggers if t.trigger_type == "UNVERIFIED_RULE_ACTIVE"]
        assert len(t14) >= 1

    def test_trigger_does_not_fire_when_citation_verified(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        graph = _make_graph(tmp_path)
        for _ in range(15):
            graph.record_block_pattern_event(
                "pat_v", "agent", "T27", "mcp.call", "x", tier=3
            )
        # Add a verified citation
        citation = _make_citation("T27", status=CitationStatus.VERIFIED)
        graph.upsert_citation(citation)

        ie       = InspectionEngine(graph)
        triggers = ie.run()
        t14 = [t for t in triggers
               if t.trigger_type == "UNVERIFIED_RULE_ACTIVE"
               and t.rule_id == "T27"]
        assert len(t14) == 0

    def test_trigger_evidence_data_has_action(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        graph = _make_graph(tmp_path)
        for _ in range(15):
            graph.record_block_pattern_event(
                "pat_act", "agent", "T19", "subprocess", "x", tier=3
            )
        ie       = InspectionEngine(graph)
        triggers = ie.run()
        t14 = [t for t in triggers if t.trigger_type == "UNVERIFIED_RULE_ACTIVE"]
        if t14:
            assert "action" in t14[0].evidence_data

    def test_trigger_is_not_amendment_candidate(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        graph = _make_graph(tmp_path)
        for _ in range(15):
            graph.record_block_pattern_event(
                "pat_na2", "agent", "T07", "subprocess", "x", tier=3
            )
        ie       = InspectionEngine(graph)
        triggers = ie.run()
        for t in triggers:
            if t.trigger_type == "UNVERIFIED_RULE_ACTIVE":
                assert t.amendment_candidate is False


# =============================================================================
# Module API
# =============================================================================

class TestV0140ModuleAPI:

    def test_version_is_0140(self):
        assert aiglos.__version__ == "0.19.0"

    def test_citation_verifier_in_all(self):
        assert "CitationVerifier" in aiglos.__all__

    def test_verified_citation_in_all(self):
        assert "VerifiedCitation" in aiglos.__all__

    def test_threat_literature_search_in_all(self):
        assert "ThreatLiteratureSearch" in aiglos.__all__

    def test_threat_signal_in_all(self):
        assert "ThreatSignal" in aiglos.__all__

    def test_verified_rule_engine_in_all(self):
        assert "VerifiedRuleEngine" in aiglos.__all__

    def test_compliance_report_in_all(self):
        assert "ComplianceReport" in aiglos.__all__

    def test_compliance_report_generator_in_all(self):
        assert "ComplianceReportGenerator" in aiglos.__all__

    def test_all_exports_importable(self):
        missing = [e for e in aiglos.__all__ if not hasattr(aiglos, e)]
        assert missing == [], f"Missing exports: {missing}"

    def test_citation_verifier_importable(self):
        from aiglos import CitationVerifier
        assert CitationVerifier is not None

    def test_compliance_report_generator_importable(self):
        from aiglos import ComplianceReportGenerator
        assert ComplianceReportGenerator is not None
