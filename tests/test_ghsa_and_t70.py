"""
tests/test_ghsa_and_t70.py
============================
Aiglos v0.24.0 -- T69 PLAN_DRIFT + T70 ENV_PATH_HIJACK + GHSA Watcher

Tests for:
  Build 1 -- T70 ENV_PATH_HIJACK (GHSA-mc68-q9jw-2h3v proof case)
  Build 2 -- GHSAWatcher (advisory seeding, matching, pending rule generation)
  Build 3 -- generate_coverage_artifact (3/3 advisory coverage)
  Build 4 -- Module API v0.24.0
"""

import os, sys, json, tempfile, pathlib
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiglos
from aiglos.core.threat_engine_v2 import match_T70, RULES_T44_T66
from aiglos.autoresearch.ghsa_watcher import (
    GHSAWatcher, KNOWN_ADVISORIES, TAXONOMY_KEYWORDS, seed_known_advisories
)
from aiglos.autoresearch.ghsa_coverage import generate_coverage_artifact


# =============================================================================
# Build 1 -- T70 ENV_PATH_HIJACK
# =============================================================================

class TestT70EnvPathHijack:

    def test_path_injection_in_shell_command(self):
        assert match_T70("shell.execute",
                         {"command": "PATH=/tmp/evil:$PATH node server.js"}) is True

    def test_ld_preload_in_docker_env(self):
        assert match_T70("docker.run",
                         {"env": {"LD_PRELOAD": "/tmp/evil.so"}}) is True

    def test_pythonpath_injection(self):
        assert match_T70("shell.execute",
                         {"command": "PYTHONPATH=/tmp/malicious python app.py"}) is True

    def test_node_path_injection(self):
        assert match_T70("shell.execute",
                         {"env": {"NODE_PATH": "/tmp/inject"}}) is True

    def test_path_override_in_exec_context(self):
        assert match_T70("docker.run",
                         {"env": {"PATH": "/custom/bin:/usr/bin"}}) is True

    def test_ld_library_path_injection(self):
        assert match_T70("shell.execute",
                         {"env": {"LD_LIBRARY_PATH": "/tmp/lib"}}) is True

    def test_dotdot_path_traversal(self):
        assert match_T70("shell.execute",
                         {"env": {"PYTHONPATH": "../../malicious/lib"}}) is True

    def test_home_dotfile_path(self):
        assert match_T70("shell.execute",
                         {"env": {"LD_PRELOAD": "/home/user/.malware/lib.so"}}) is True

    def test_clean_pytest(self):
        assert match_T70("shell.execute", {"command": "pytest tests/"}) is False

    def test_clean_file_read(self):
        assert match_T70("filesystem.read_file",
                         {"path": "/usr/local/bin/python"}) is False

    def test_clean_normal_docker(self):
        assert match_T70("docker.run", {"image": "node:22"}) is False

    def test_clean_safe_pythonpath(self):
        assert match_T70("filesystem.write_file",
                         {"env": {"PYTHONPATH": "/app/src"}}) is False

    def test_clean_normal_path_in_file_read(self):
        assert match_T70("filesystem.read_file",
                         {"path": "/usr/local/path/to/config.json"}) is False

    def test_t70_in_rules_table(self):
        ids = [r["id"] for r in RULES_T44_T66]
        assert "T70" in ids

    def test_t70_score_0_88(self):
        t70 = next(r for r in RULES_T44_T66 if r["id"] == "T70")
        assert t70["score"] == 0.88

    def test_t70_is_critical(self):
        t70 = next(r for r in RULES_T44_T66 if r["id"] == "T70")
        assert t70["critical"] is True

    def test_t70_ghsa_reference_in_desc(self):
        t70 = next(r for r in RULES_T44_T66 if r["id"] == "T70")
        assert "GHSA-mc68-q9jw-2h3v" in t70["desc"]


# =============================================================================
# Build 2 -- GHSAWatcher
# =============================================================================

class TestGHSAWatcher:
    def test_seed_known_advisories(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        w.run_once(local_only=True)
        assert len(w._coverage) == 3

    def test_all_known_covered(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        w.run_once(local_only=True)
        for ghsa_id, m in w._coverage.items():
            assert m.coverage == "COVERED", f"{ghsa_id} not covered"

    def test_ghsa_g8p2_maps_to_t68(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        w.run_once(local_only=True)
        m = w._coverage.get("GHSA-g8p2-7wf7-98mq")
        assert m is not None
        assert "T68" in m.matched_rules

    def test_ghsa_q284_maps_to_t03_t04(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        w.run_once(local_only=True)
        m = w._coverage.get("GHSA-q284-4pvr-m585")
        assert m is not None
        assert "T03" in m.matched_rules
        assert "T04" in m.matched_rules

    def test_ghsa_mc68_maps_to_t70(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        w.run_once(local_only=True)
        m = w._coverage.get("GHSA-mc68-q9jw-2h3v")
        assert m is not None
        assert "T70" in m.matched_rules

    def test_coverage_persists(self, tmp_path):
        path = str(tmp_path / "coverage.json")
        w1 = GHSAWatcher(coverage_path=path, pending_path=str(tmp_path / "p"))
        w1.run_once(local_only=True)
        w2 = GHSAWatcher(coverage_path=path, pending_path=str(tmp_path / "p"))
        assert len(w2._coverage) == 3

    def test_match_advisory_covered(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        m = w.match_advisory(
            ghsa_id     = "GHSA-test-0001",
            title       = "OS Command Injection via shell metacharacters",
            description = "Arbitrary command execution through shell injection",
            severity    = "HIGH",
        )
        assert m.coverage in ("COVERED", "PARTIAL")
        assert len(m.matched_rules) > 0

    def test_match_advisory_gap_creates_pending(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        m = w.match_advisory(
            ghsa_id     = "GHSA-test-9999",
            title       = "Florble zorbification in widget frobnication module",
            description = "Blorp zorbification triggers unexpected widget state",
            severity    = "LOW",
        )
        assert m.coverage == "GAP"
        pending_file = tmp_path / "pending" / "GHSA-test-9999.json"
        assert pending_file.exists()
        data = json.loads(pending_file.read_text())
        assert data["ghsa_id"] == "GHSA-test-9999"
        assert "proposed_id" in data
        assert data["status"] == "PENDING_REVIEW"

    def test_pending_rule_has_match_sketch(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        w.match_advisory(
            ghsa_id="GHSA-test-8888",
            title="Florble zorbification widget frobnication",
            description="Blorp zorbification triggers unexpected state in widget module",
            severity="MEDIUM",
        )
        pending = w.pending_rules()
        assert len(pending) >= 1
        rule = pending[0]
        assert "match_sketch" in rule
        assert "def match_" in rule["match_sketch"]

    def test_coverage_report_output(self, tmp_path):
        w = GHSAWatcher(
            coverage_path=str(tmp_path / "coverage.json"),
            pending_path=str(tmp_path / "pending"),
        )
        w.run_once(local_only=True)
        report = w.coverage_report()
        assert "3" in report
        assert "COVERED" in report or "100%" in report

    def test_taxonomy_keywords_covers_t70(self):
        assert "T70" in TAXONOMY_KEYWORDS
        assert any("path" in kw for kw in TAXONOMY_KEYWORDS["T70"])

    def test_taxonomy_keywords_covers_all_major_rules(self):
        required = ["T03", "T04", "T05", "T12", "T19", "T30", "T68", "T69", "T70"]
        for rule_id in required:
            assert rule_id in TAXONOMY_KEYWORDS, f"{rule_id} not in TAXONOMY_KEYWORDS"


# =============================================================================
# Build 3 -- Coverage Artifact
# =============================================================================

class TestCoverageArtifact:
    def test_generates_without_error(self):
        artifact = generate_coverage_artifact()
        assert artifact is not None

    def test_three_entries(self):
        artifact = generate_coverage_artifact()
        assert artifact.total_ghsa == 3

    def test_all_covered(self):
        artifact = generate_coverage_artifact()
        assert artifact.total_covered == 3
        assert artifact.coverage_pct == 100.0

    def test_ghsa_ids_present(self):
        artifact = generate_coverage_artifact()
        ids = [e.ghsa_id for e in artifact.entries]
        assert "GHSA-g8p2-7wf7-98mq" in ids
        assert "GHSA-q284-4pvr-m585" in ids
        assert "GHSA-mc68-q9jw-2h3v" in ids

    def test_t70_in_mc68_entry(self):
        artifact = generate_coverage_artifact()
        mc68 = next(e for e in artifact.entries if e.ghsa_id == "GHSA-mc68-q9jw-2h3v")
        assert "T70" in mc68.rules

    def test_mitsuhiko_credited(self):
        artifact = generate_coverage_artifact()
        q284 = next(e for e in artifact.entries if e.ghsa_id == "GHSA-q284-4pvr-m585")
        assert "mitsuhiko" in q284.disclosed_by.lower() or "ronacher" in q284.note.lower()

    def test_markdown_output(self):
        artifact = generate_coverage_artifact()
        md = artifact.to_markdown()
        assert "GHSA Coverage Report" in md
        assert "100%" in md
        assert "T68" in md
        assert "T70" in md

    def test_json_output_valid(self):
        artifact = generate_coverage_artifact()
        data = json.loads(artifact.to_json())
        assert data["coverage_pct"] == 100.0
        assert len(data["entries"]) == 3

    def test_version_matches(self):
        artifact = generate_coverage_artifact()
        assert artifact.version == aiglos.__version__


# =============================================================================
# Build 4 -- Module API v0.24.0
# =============================================================================

class TestV0230ModuleAPI:
    def test_version(self):
        assert aiglos.__version__ == "0.25.8"

    def test_ghsa_watcher_exported(self):
        assert "GHSAWatcher" in aiglos.__all__
        assert hasattr(aiglos, "GHSAWatcher")

    def test_generate_coverage_artifact_exported(self):
        assert "generate_coverage_artifact" in aiglos.__all__
        assert hasattr(aiglos, "generate_coverage_artifact")

    def test_32_rules_in_v2(self):
        assert len(RULES_T44_T66) == 39

    def test_t75_present(self):
        ids = [r["id"] for r in RULES_T44_T66]
        assert "T75" in ids

    def test_all_exports_importable(self):
        missing = [e for e in aiglos.__all__ if not hasattr(aiglos, e)]
        assert missing == [], f"Missing exports: {missing}"

    def test_coverage_artifact_via_module(self):
        artifact = aiglos.generate_coverage_artifact()
        assert artifact.coverage_pct == 100.0
