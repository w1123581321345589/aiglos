"""
tests/test_t80_t81_scandeps.py
==============================
Tests for:
  T80 UNCENSORED_MODEL_ROUTE
  T81 PTH_FILE_INJECT
  REPO_TAKEOVER_CHAIN campaign pattern
  aiglos.cli.scan_deps module
"""

import sys
import os
import types

import pytest
from conftest import EXPECTED_RULE_COUNT

from aiglos.core.threat_engine_v2 import RULES_T44_T66
from aiglos.adaptive.campaign import _CAMPAIGN_PATTERNS
from aiglos.cli.scan_deps import (
    scan,
    ScanResult,
    COMPROMISED_PACKAGES,
    TRANSITIVE_EXPOSURE,
    MALICIOUS_PTH_FILES,
    print_scan_report,
)
import aiglos


def _rule(rule_id: str):
    return next((r for r in RULES_T44_T66 if r["id"] == rule_id), None)


def _campaign(name: str):
    return next((p for p in _CAMPAIGN_PATTERNS if p["name"] == name), None)


class TestT80UncensoredModelRoute:
    def test_exists_in_rules(self):
        assert _rule("T80") is not None

    def test_name(self):
        assert _rule("T80")["name"] == "UNCENSORED_MODEL_ROUTE"

    def test_score(self):
        assert _rule("T80")["score"] == 0.78

    def test_has_desc(self):
        desc = _rule("T80")["desc"]
        assert "uncensored" in desc.lower()

    def test_has_required_fields(self):
        r = _rule("T80")
        for field in ("id", "name", "score", "desc"):
            assert field in r, f"T80 missing field: {field}"


class TestT81PthFileInject:
    def test_exists_in_rules(self):
        assert _rule("T81") is not None

    def test_name(self):
        assert _rule("T81")["name"] == "PTH_FILE_INJECT"

    def test_score(self):
        assert _rule("T81")["score"] == 0.98

    def test_score_is_high(self):
        t81 = _rule("T81")
        assert t81["score"] >= 0.95

    def test_desc_mentions_pth(self):
        assert ".pth" in _rule("T81")["desc"]

    def test_desc_mentions_litellm(self):
        assert "litellm" in _rule("T81")["desc"].lower()

    def test_has_required_fields(self):
        r = _rule("T81")
        for field in ("id", "name", "score", "desc"):
            assert field in r


class TestRepoTakeoverChainCampaign:
    def test_exists(self):
        assert _campaign("REPO_TAKEOVER_CHAIN") is not None

    def test_has_required_fields(self):
        c = _campaign("REPO_TAKEOVER_CHAIN")
        for field in ("name", "sequence", "min_events", "confidence"):
            assert field in c, f"REPO_TAKEOVER_CHAIN missing field: {field}"

    def test_sequence_not_empty(self):
        c = _campaign("REPO_TAKEOVER_CHAIN")
        assert len(c["sequence"]) > 0

    def test_has_amplifiers(self):
        c = _campaign("REPO_TAKEOVER_CHAIN")
        assert "amplifiers" in c
        assert "T81" in c["amplifiers"]

    def test_23_campaign_patterns_total(self):
        assert len(_CAMPAIGN_PATTERNS) == 29


class TestScanResult:
    def test_empty_result_is_clean(self):
        r = ScanResult()
        assert r.risk_level == "CLEAN"
        assert r.is_compromised is False

    def test_compromised_package_is_critical(self):
        r = ScanResult()
        r.compromised_packages = [{"pkg": "litellm", "version": "1.82.8"}]
        assert r.risk_level == "CRITICAL"
        assert r.is_compromised is True

    def test_pth_is_critical(self):
        r = ScanResult()
        r.malicious_pth_files = [{"path": "/tmp/test.pth"}]
        assert r.risk_level == "CRITICAL"
        assert r.is_compromised is True

    def test_persistence_is_high(self):
        r = ScanResult()
        r.persistence_found = [{"path": "/tmp/sysmon.py"}]
        assert r.risk_level == "HIGH"
        assert r.is_compromised is True

    def test_transitive_is_medium(self):
        r = ScanResult()
        r.transitive_exposure = [{"pkg": "dspy"}]
        assert r.risk_level == "MEDIUM"
        assert r.is_compromised is False

    def test_to_dict_keys(self):
        r = ScanResult()
        d = r.to_dict()
        for k in (
            "risk_level",
            "is_compromised",
            "compromised_packages",
            "malicious_pth_files",
            "persistence_found",
            "transitive_exposure",
            "recommendations",
        ):
            assert k in d


class TestCompromisedPackages:
    def test_litellm_present(self):
        assert "litellm" in COMPROMISED_PACKAGES

    def test_litellm_has_1_82_8(self):
        assert "1.82.8" in COMPROMISED_PACKAGES["litellm"]

    def test_litellm_has_1_82_7(self):
        assert "1.82.7" in COMPROMISED_PACKAGES["litellm"]

    def test_severity_is_critical(self):
        for ver, info in COMPROMISED_PACKAGES["litellm"].items():
            assert info["severity"] == "CRITICAL"


class TestTransitiveExposure:
    def test_dspy_exposed(self):
        assert "dspy" in TRANSITIVE_EXPOSURE

    def test_smolagents_exposed(self):
        assert "smolagents" in TRANSITIVE_EXPOSURE

    def test_entries_have_exposure_field(self):
        for pkg, info in TRANSITIVE_EXPOSURE.items():
            assert "exposure" in info, f"{pkg} missing 'exposure' field"


class TestMaliciousPthFiles:
    def test_litellm_init_pth(self):
        assert "litellm_init.pth" in MALICIOUS_PTH_FILES

    def test_at_least_one_known(self):
        assert len(MALICIOUS_PTH_FILES) >= 1


class TestScanFunction:
    def test_scan_returns_scan_result(self):
        result = scan(quick=True)
        assert isinstance(result, ScanResult)

    def test_scan_specific_package(self):
        result = scan(package="nonexistent_package_xyz", quick=True)
        assert isinstance(result, ScanResult)

    def test_scan_clean_env(self):
        result = scan(package="nonexistent_package_xyz", quick=True)
        assert result.risk_level in ("CLEAN", "MEDIUM")


class TestExportsInInit:
    def test_scan_deps_exported(self):
        assert "scan_deps" in aiglos.__all__
        assert hasattr(aiglos, "scan_deps")

    def test_scan_deps_result_exported(self):
        assert "ScanDepsResult" in aiglos.__all__
        assert hasattr(aiglos, "ScanDepsResult")

    def test_compromised_packages_exported(self):
        assert "COMPROMISED_PACKAGES" in aiglos.__all__
        assert hasattr(aiglos, "COMPROMISED_PACKAGES")

    def test_transitive_exposure_exported(self):
        assert "TRANSITIVE_EXPOSURE" in aiglos.__all__
        assert hasattr(aiglos, "TRANSITIVE_EXPOSURE")

    def test_malicious_pth_files_exported(self):
        assert "MALICIOUS_PTH_FILES" in aiglos.__all__
        assert hasattr(aiglos, "MALICIOUS_PTH_FILES")

    def test_print_scan_report_exported(self):
        assert "print_scan_report" in aiglos.__all__
        assert hasattr(aiglos, "print_scan_report")


class TestThreatFamilyCounts:
    def test_39_rules_in_table(self):
        assert len(RULES_T44_T66) == EXPECTED_RULE_COUNT

    def test_82_total_threat_families(self):
        ids = {r["id"] for r in RULES_T44_T66}
        assert len(ids) == EXPECTED_RULE_COUNT
        for n in range(44, 99):
            assert f"T{n}" in ids
