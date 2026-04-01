"""
tests/test_honeypot_override.py
================================
Aiglos v0.16.0 -- Honeypot & Override System

Tests cover:
  - HoneypotManager: deploy, path detection, check_tool_call, content check
  - T43 HONEYPOT_ACCESS: fires CRITICAL with no threshold
  - OverrideManager: request_override, confirm_override, expiry, max attempts
  - OverrideChallenge: lifecycle, terminal_prompt, to_dict
  - OverrideResult: approved/rejected states
  - ObservationGraph: honeypot_hits table, override_challenges table
  - OpenClawGuard: enable_honeypot(), request_override(), confirm_override()
  - Module API: v0.16.0, exports
"""

import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiglos
from aiglos.adaptive.observation import ObservationGraph
from aiglos.integrations.honeypot import (
    HoneypotManager,
    HoneypotResult,
    _DEFAULT_HONEYPOT_FILES,
)
from aiglos.integrations.override import (
    OverrideManager,
    OverrideChallenge,
    OverrideResult,
    _EXPIRY_SECONDS,
    _MAX_ATTEMPTS,
    _CODE_LENGTH,
)


# =============================================================================
# Helpers
# =============================================================================

def _make_graph(tmp_path) -> ObservationGraph:
    return ObservationGraph(db_path=str(tmp_path / "obs.db"))


def _make_manager(tmp_path, deployed=True) -> HoneypotManager:
    mgr = HoneypotManager(
        honeypot_dir = tmp_path / "honeypots",
        agent_name   = "test-agent",
        session_id   = "sess-test",
    )
    if deployed:
        mgr.deploy()
    return mgr


# =============================================================================
# HoneypotManager -- deployment
# =============================================================================

class TestHoneypotDeploy:

    def test_deploy_creates_files(self, tmp_path):
        mgr = _make_manager(tmp_path)
        hp_dir = tmp_path / "honeypots"
        files = list(hp_dir.glob("*"))
        assert len(files) >= len(_DEFAULT_HONEYPOT_FILES)

    def test_deploy_marks_deployed(self, tmp_path):
        mgr = _make_manager(tmp_path)
        assert mgr.deployed is True

    def test_deploy_returns_path_list(self, tmp_path):
        mgr = HoneypotManager(honeypot_dir=tmp_path / "hp")
        paths = mgr.deploy()
        assert len(paths) >= len(_DEFAULT_HONEYPOT_FILES)

    def test_deploy_registers_names(self, tmp_path):
        mgr = _make_manager(tmp_path)
        names = mgr.active_honeypots()
        assert "system_auth_tokens.json" in names

    def test_add_custom_deploys_file(self, tmp_path):
        mgr  = _make_manager(tmp_path)
        path = mgr.add_custom("myapp_secrets.json")
        assert path is not None
        assert path.exists()

    def test_add_custom_registers_for_detection(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.add_custom("custom_creds.json")
        result = mgr.check_tool_call("filesystem.read_file",
                                      {"path": "custom_creds.json"})
        assert result.triggered is True

    def test_files_are_read_only(self, tmp_path):
        mgr = _make_manager(tmp_path)
        hp_dir = tmp_path / "honeypots"
        for f in hp_dir.glob("*"):
            # 0o444 on Unix
            mode = oct(f.stat().st_mode)[-3:]
            assert mode == "444"

    def test_deploy_idempotent(self, tmp_path):
        mgr = _make_manager(tmp_path)
        count1 = len(mgr.active_honeypots())
        mgr.deploy()   # deploy again
        count2 = len(mgr.active_honeypots())
        assert count2 == count1   # no duplicates


# =============================================================================
# HoneypotManager -- detection
# =============================================================================

class TestHoneypotDetection:

    def test_read_of_honeypot_file_triggers(self, tmp_path):
        mgr    = _make_manager(tmp_path)
        result = mgr.check_tool_call(
            "filesystem.read_file",
            {"path": str(tmp_path / "honeypots" / "system_auth_tokens.json")},
        )
        assert result.triggered is True
        assert result.rule_id == "T43"
        assert result.severity == "CRITICAL"

    def test_filename_match_triggers(self, tmp_path):
        mgr    = _make_manager(tmp_path)
        result = mgr.check_tool_call(
            "filesystem.read_file",
            {"path": "~/some/path/system_auth_tokens.json"},
        )
        assert result.triggered is True

    def test_clean_read_does_not_trigger(self, tmp_path):
        mgr    = _make_manager(tmp_path)
        result = mgr.check_tool_call(
            "filesystem.read_file",
            {"path": "/usr/local/bin/python3"},
        )
        assert result.triggered is False

    def test_write_tool_does_not_trigger(self, tmp_path):
        """Writes to honeypot files are handled by T40, not T43."""
        mgr    = _make_manager(tmp_path)
        result = mgr.check_tool_call(
            "filesystem.write_file",
            {"path": str(tmp_path / "honeypots" / "system_auth_tokens.json"),
             "content": "test"},
        )
        assert result.triggered is False

    def test_shell_execute_with_honeypot_path_triggers(self, tmp_path):
        mgr    = _make_manager(tmp_path)
        result = mgr.check_tool_call(
            "shell.execute",
            {"command": f"cat {tmp_path}/honeypots/system_auth_tokens.json"},
        )
        assert result.triggered is True

    def test_content_check_finds_honeypot_name(self, tmp_path):
        mgr    = _make_manager(tmp_path)
        result = mgr.check_content(
            "I need to read the file system_auth_tokens.json for the task",
            tool_name="shell.execute",
        )
        assert result.triggered is True
        assert result.detection_mode == "CONTENT"

    def test_content_check_clean_content_not_triggered(self, tmp_path):
        mgr    = _make_manager(tmp_path)
        result = mgr.check_content("Reading the main application config file")
        assert result.triggered is False

    def test_hit_count_increments(self, tmp_path):
        mgr = _make_manager(tmp_path)
        assert mgr.hit_count == 0
        mgr.check_tool_call("filesystem.read_file",
                             {"path": "system_auth_tokens.json"})
        assert mgr.hit_count == 1

    def test_summary_returns_correct_counts(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.check_tool_call("filesystem.read_file",
                             {"path": "system_auth_tokens.json"})
        s = mgr.summary()
        assert s["hit_count"]       == 1
        assert s["rule_id"]         == "T43"
        assert s["deployed"]        is True
        assert s["honeypot_count"]  >= len(_DEFAULT_HONEYPOT_FILES)

    def test_network_intelligence_factory(self, tmp_path):
        mgr = HoneypotManager.from_network_intelligence(
            targeted_names=["targeted_secrets.json", "prod_api_keys.txt"],
            honeypot_dir=tmp_path / "net_hp",
        )
        assert mgr.deployed is True
        result = mgr.check_tool_call(
            "filesystem.read_file",
            {"path": "targeted_secrets.json"},
        )
        assert result.triggered is True


# =============================================================================
# ObservationGraph -- honeypot and override tables
# =============================================================================

class TestObservationGraphHoneypotOverride:

    def test_record_honeypot_hit(self, tmp_path):
        graph  = _make_graph(tmp_path)
        result = HoneypotResult(
            triggered      = True,
            honeypot_name  = "system_auth_tokens.json",
            tool_name      = "filesystem.read_file",
            agent_name     = "test-agent",
            session_id     = "sess-123",
        )
        graph.record_honeypot_hit(result)
        hits = graph.get_honeypot_hits(agent_name="test-agent")
        assert len(hits) == 1
        assert hits[0]["honeypot_name"] == "system_auth_tokens.json"

    def test_get_honeypot_hits_unfiltered(self, tmp_path):
        graph = _make_graph(tmp_path)
        for i in range(3):
            graph.record_honeypot_hit(HoneypotResult(
                triggered=True,
                honeypot_name=f"file_{i}.json",
                agent_name="agent",
            ))
        hits = graph.get_honeypot_hits()
        assert len(hits) == 3

    def test_upsert_and_list_override_challenges(self, tmp_path):
        graph     = _make_graph(tmp_path)
        challenge = OverrideChallenge(
            challenge_id = "ovr_test001",
            code         = "A7X2K9",
            rule_id      = "T37",
            tool_name    = "http.post",
            tool_args    = {},
            reason       = "Test override",
            agent_name   = "test-agent",
            session_id   = "sess-123",
        )
        graph.upsert_override_challenge(challenge)
        rows = graph.list_override_challenges(pending_only=True)
        assert len(rows) >= 1
        assert any(r["challenge_id"] == "ovr_test001" for r in rows)

    def test_override_challenge_approved_update(self, tmp_path):
        graph     = _make_graph(tmp_path)
        challenge = OverrideChallenge(
            challenge_id = "ovr_approve",
            code         = "B8Y3L5",
            rule_id      = "T37",
            tool_name    = "http.post",
            tool_args    = {},
            reason       = "Test",
            agent_name   = "agent",
            session_id   = "sess",
        )
        graph.upsert_override_challenge(challenge)
        challenge.resolved   = True
        challenge.approved   = True
        challenge.resolved_at = time.time()
        graph.upsert_override_challenge(challenge)
        rows = graph.list_override_challenges()
        target = next((r for r in rows if r["challenge_id"] == "ovr_approve"), None)
        assert target is not None
        assert target["approved"] == 1


# =============================================================================
# OverrideManager -- challenge issuance
# =============================================================================

class TestOverrideManagerIssuance:

    def test_request_override_returns_challenge(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        assert isinstance(challenge, OverrideChallenge)
        assert challenge.rule_id   == "T37"
        assert challenge.tool_name == "http.post"

    def test_code_is_correct_length(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        assert len(challenge.code) == _CODE_LENGTH

    def test_code_contains_only_safe_chars(self):
        mgr = OverrideManager()
        for _ in range(20):
            ch = mgr.request_override("T37", "http.post", {})
            assert "0" not in ch.code
            assert "O" not in ch.code
            assert "1" not in ch.code
            assert "I" not in ch.code

    def test_challenge_id_starts_with_prefix(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        assert challenge.challenge_id.startswith("ovr_")

    def test_challenge_expires_correctly(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        assert challenge.seconds_remaining > 0
        assert challenge.seconds_remaining <= _EXPIRY_SECONDS
        assert not challenge.is_expired

    def test_terminal_prompt_contains_code(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {}, reason="Test reason")
        prompt    = challenge.terminal_prompt()
        assert challenge.code in prompt
        assert "T37" in prompt

    def test_to_dict_has_required_keys(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        d         = challenge.to_dict()
        for key in ["challenge_id", "rule_id", "tool_name", "issued_at",
                    "expires_at", "resolved", "approved"]:
            assert key in d


# =============================================================================
# OverrideManager -- confirmation
# =============================================================================

class TestOverrideManagerConfirmation:

    def test_correct_code_approves(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        result    = mgr.confirm_override(challenge.challenge_id, challenge.code)
        assert result.approved is True

    def test_wrong_code_rejects(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        result    = mgr.confirm_override(challenge.challenge_id, "WRONG1")
        assert result.approved is False
        assert "Incorrect code" in result.error

    def test_code_is_case_insensitive(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        result    = mgr.confirm_override(
            challenge.challenge_id,
            challenge.code.lower(),
        )
        assert result.approved is True

    def test_unknown_challenge_id_returns_error(self):
        mgr    = OverrideManager()
        result = mgr.confirm_override("ovr_does_not_exist", "A7X2K9")
        assert result.approved is False
        assert "not found" in result.error.lower()

    def test_max_attempts_invalidates_challenge(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        for _ in range(_MAX_ATTEMPTS):
            mgr.confirm_override(challenge.challenge_id, "WRONG1")
        result = mgr.confirm_override(challenge.challenge_id, challenge.code)
        assert result.approved is False

    def test_expired_challenge_rejects(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        challenge.expires_at = time.time() - 1   # manually expire
        result    = mgr.confirm_override(challenge.challenge_id, challenge.code)
        assert result.approved is False
        assert "expired" in result.error.lower()

    def test_prefix_match_works(self):
        """Partial challenge_id prefix should resolve correctly."""
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        prefix    = challenge.challenge_id[:12]
        result    = mgr.confirm_override(prefix, challenge.code)
        assert result.approved is True

    def test_reject_override_marks_rejected(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        result    = mgr.reject_override(challenge.challenge_id)
        assert result.approved is False
        assert challenge.resolved is True

    def test_cannot_confirm_after_approval(self):
        mgr       = OverrideManager()
        challenge = mgr.request_override("T37", "http.post", {})
        mgr.confirm_override(challenge.challenge_id, challenge.code)
        result = mgr.confirm_override(challenge.challenge_id, challenge.code)
        assert result.approved is False   # already resolved

    def test_summary_counts(self):
        mgr = OverrideManager()
        c1  = mgr.request_override("T37", "http.post", {})
        c2  = mgr.request_override("T19", "subprocess.run", {})
        mgr.confirm_override(c1.challenge_id, c1.code)   # approve
        mgr.reject_override(c2.challenge_id)              # reject
        s   = mgr.summary()
        assert s["approved"] == 1
        assert s["rejected"] == 1
        assert s["pending"]  == 0


# =============================================================================
# OpenClawGuard -- enable_honeypot, request_override, confirm_override
# =============================================================================

class TestOpenClawGuardHoneypotOverride:

    def test_enable_honeypot_method_exists(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        assert hasattr(g, "enable_honeypot")
        assert callable(g.enable_honeypot)

    def test_enable_honeypot_creates_manager(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        g.enable_honeypot(honeypot_dir=str(tmp_path / "hp"))
        assert hasattr(g, "_honeypot_mgr")
        assert g._honeypot_mgr.deployed is True

    def test_honeypot_blocks_in_before_tool_call(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        g.enable_honeypot(honeypot_dir=str(tmp_path / "hp"))
        result = g.before_tool_call(
            "filesystem.read_file",
            {"path": "system_auth_tokens.json"},
        )
        assert result is not None
        assert result.threat_class == "T43"
        assert result.verdict.value == "BLOCK"
        assert result.score == 1.0

    def test_request_override_method_exists(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        assert hasattr(g, "request_override")
        assert hasattr(g, "confirm_override")

    def test_request_override_returns_challenge(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        challenge = g.request_override(
            rule_id="T37",
            tool_name="http.post",
            args={"url": "https://api.stripe.com"},
            reason="Contract renewal",
        )
        assert challenge is not None
        assert challenge.rule_id == "T37"
        assert len(challenge.code) == _CODE_LENGTH

    def test_confirm_override_approves_correct_code(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g         = OpenClawGuard("test", "enterprise",
                                  log_path=str(tmp_path / "t.log"))
        challenge = g.request_override("T37", "http.post", {})
        result    = g.confirm_override(challenge.challenge_id, challenge.code)
        assert result is not None
        assert result.approved is True

    def test_attach_kwarg_enables_honeypot(self, tmp_path):
        aiglos.attach(
            agent_name     = "hp-kwarg-test",
            policy         = "enterprise",
            enable_honeypot = True,
            honeypot_dir   = str(tmp_path / "kwarg_hp"),
        )
        art = aiglos.close()
        assert art is not None


# =============================================================================
# Module API
# =============================================================================

class TestV0160ModuleAPI:

    def test_version_is_0160(self):
        assert aiglos.__version__ == "0.25.19"

    def test_honeypot_manager_in_all(self):
        assert "HoneypotManager" in aiglos.__all__

    def test_honeypot_result_in_all(self):
        assert "HoneypotResult" in aiglos.__all__

    def test_override_manager_in_all(self):
        assert "OverrideManager" in aiglos.__all__

    def test_override_challenge_in_all(self):
        assert "OverrideChallenge" in aiglos.__all__

    def test_override_result_in_all(self):
        assert "OverrideResult" in aiglos.__all__

    def test_all_exports_importable(self):
        missing = [e for e in aiglos.__all__ if not hasattr(aiglos, e)]
        assert missing == [], f"Missing exports: {missing}"

    def test_honeypot_manager_importable(self):
        from aiglos import HoneypotManager
        assert HoneypotManager is not None

    def test_override_manager_importable(self):
        from aiglos import OverrideManager
        assert OverrideManager is not None
