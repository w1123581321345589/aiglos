"""
tests/test_openShell.py
=========================
Aiglos v0.25.1 -- OpenShell Agent-Agnostic Integration Tests

Tests for:
  is_inside_openShell() -- env var detection
  openShell_context() -- full context extraction
  openshell_detect() -- auto-configure from environment
  attach_openShell() -- explicit attach for any agent
  attach_for_claude_code / codex / cursor / openclaw
  Agent-agnostic: same YAML policy, different agents
  Module API v0.25.1
"""

import os, sys, tempfile, pathlib
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiglos
from aiglos.integrations.openShell import (
    is_inside_openShell,
    openShell_context,
    openshell_detect,
    attach_openShell,
    attach_for_claude_code,
    attach_for_codex,
    attach_for_cursor,
    attach_for_openclaw,
    KNOWN_AGENTS,
    ENV_SANDBOX_ID,
    ENV_POLICY_PATH,
    ENV_AGENT,
    ENV_VERSION,
)
from aiglos.integrations.openclaw import OpenClawGuard


SAMPLE_POLICY_YAML = """
network:
  allow:
    - api.openai.com
    - api.anthropic.com
  deny:
    - "*"
filesystem:
  workspace: /home/user/projects/
  allow_read:
    - /home/user/projects/
  deny_write:
    - /home/user/.ssh/
tools:
  allowed:
    - filesystem
    - web_search
  denied:
    - sessions.list
privacy:
  strip_pii: true
  local_only: false
"""


def _guard(tmp_path) -> OpenClawGuard:
    return OpenClawGuard(
        agent_name="test-agent",
        policy="enterprise",
        log_path=str(tmp_path / "test.log"),
    )


def _policy_file(tmp_path) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text(SAMPLE_POLICY_YAML)
    return str(p)


def _set_openShell_env(sandbox_id="sandbox-test", agent="claude-code",
                       policy_path=None, version="0.1.0-alpha"):
    os.environ[ENV_SANDBOX_ID] = sandbox_id
    os.environ[ENV_AGENT]      = agent
    os.environ[ENV_VERSION]    = version
    if policy_path:
        os.environ[ENV_POLICY_PATH] = policy_path


def _clear_openShell_env():
    for key in [ENV_SANDBOX_ID, ENV_AGENT, ENV_VERSION, ENV_POLICY_PATH]:
        os.environ.pop(key, None)


class TestIsInsideOpenShell:

    def setup_method(self):
        _clear_openShell_env()

    def teardown_method(self):
        _clear_openShell_env()

    def test_false_without_env(self):
        assert is_inside_openShell() is False

    def test_true_with_sandbox_id(self):
        os.environ[ENV_SANDBOX_ID] = "sandbox-abc"
        assert is_inside_openShell() is True

    def test_false_after_clear(self):
        os.environ[ENV_SANDBOX_ID] = "sandbox-abc"
        del os.environ[ENV_SANDBOX_ID]
        assert is_inside_openShell() is False

    def test_works_for_any_agent(self):
        """The detection is agent-agnostic -- same env var regardless of agent."""
        os.environ[ENV_SANDBOX_ID] = "sandbox-claude"
        assert is_inside_openShell() is True
        os.environ[ENV_SANDBOX_ID] = "sandbox-codex"
        assert is_inside_openShell() is True
        os.environ[ENV_SANDBOX_ID] = "sandbox-cursor"
        assert is_inside_openShell() is True


class TestOpenShellContext:

    def setup_method(self):
        _clear_openShell_env()

    def teardown_method(self):
        _clear_openShell_env()

    def test_none_without_env(self):
        assert openShell_context() is None

    def test_returns_dict_with_env(self):
        _set_openShell_env()
        ctx = openShell_context()
        assert isinstance(ctx, dict)

    def test_includes_sandbox_id(self):
        _set_openShell_env(sandbox_id="test-sandbox-123")
        ctx = openShell_context()
        assert ctx["sandbox_id"] == "test-sandbox-123"

    def test_includes_agent(self):
        _set_openShell_env(agent="claude-code")
        ctx = openShell_context()
        assert ctx["agent"] == "claude-code"

    def test_resolves_agent_name_claude_code(self):
        _set_openShell_env(agent="claude-code")
        ctx = openShell_context()
        assert "Claude Code" in ctx["agent_name"]
        assert "Anthropic" in ctx["agent_name"]

    def test_resolves_agent_name_codex(self):
        _set_openShell_env(agent="codex")
        ctx = openShell_context()
        assert "Codex" in ctx["agent_name"]
        assert "OpenAI" in ctx["agent_name"]

    def test_resolves_agent_name_cursor(self):
        _set_openShell_env(agent="cursor")
        ctx = openShell_context()
        assert "Cursor" in ctx["agent_name"]

    def test_resolves_agent_name_openclaw(self):
        _set_openShell_env(agent="openclaw")
        ctx = openShell_context()
        assert "OpenClaw" in ctx["agent_name"]

    def test_policy_path_none_without_env(self):
        _set_openShell_env()
        ctx = openShell_context()
        assert ctx["policy_path"] is None

    def test_policy_path_from_env(self, tmp_path):
        p = _policy_file(tmp_path)
        _set_openShell_env(policy_path=p)
        ctx = openShell_context()
        assert ctx["policy_path"] == p

    def test_version_included(self):
        _set_openShell_env(version="0.1.0-alpha")
        ctx = openShell_context()
        assert ctx["version"] == "0.1.0-alpha"

    def test_unknown_agent_uses_raw_value(self):
        _set_openShell_env(agent="my-custom-agent")
        ctx = openShell_context()
        assert ctx["agent"] == "my-custom-agent"


class TestOpenShellDetect:

    def setup_method(self):
        _clear_openShell_env()
        from aiglos.core.threat_engine_v2 import _SUPERPOWERS_PLAN
        _SUPERPOWERS_PLAN.clear()

    def teardown_method(self):
        _clear_openShell_env()
        from aiglos.core.threat_engine_v2 import _SUPERPOWERS_PLAN
        _SUPERPOWERS_PLAN.clear()

    def test_returns_none_outside_sandbox(self, tmp_path):
        g = _guard(tmp_path)
        result = openshell_detect(guard=g)
        assert result is None

    def test_returns_none_without_policy_path(self, tmp_path):
        _set_openShell_env()
        g = _guard(tmp_path)
        result = openshell_detect(guard=g)
        assert result is None

    def test_sets_sandbox_context_even_without_policy(self, tmp_path):
        _set_openShell_env()
        g = _guard(tmp_path)
        openshell_detect(guard=g)
        assert g.sandbox_context is True
        assert g.sandbox_type == "openShell"

    def test_returns_session_with_policy(self, tmp_path):
        p = _policy_file(tmp_path)
        _set_openShell_env(policy_path=p)
        g = _guard(tmp_path)
        session = openshell_detect(guard=g)
        assert session is not None

    def test_session_id_matches_sandbox_id(self, tmp_path):
        p = _policy_file(tmp_path)
        _set_openShell_env(sandbox_id="my-sandbox-42", policy_path=p)
        g = _guard(tmp_path)
        session = openshell_detect(guard=g)
        assert session.session_id == "my-sandbox-42"

    def test_guard_attached_after_detect(self, tmp_path):
        p = _policy_file(tmp_path)
        _set_openShell_env(policy_path=p)
        g = _guard(tmp_path)
        openshell_detect(guard=g)
        assert g.nemoclaw_session() is not None

    def test_agent_agnostic_claude_code(self, tmp_path):
        """Same policy works for Claude Code."""
        p = _policy_file(tmp_path)
        _set_openShell_env(agent="claude-code", policy_path=p)
        g = _guard(tmp_path)
        session = openshell_detect(guard=g)
        assert session is not None

    def test_agent_agnostic_codex(self, tmp_path):
        """Same policy works for Codex."""
        p = _policy_file(tmp_path)
        _set_openShell_env(agent="codex", policy_path=p)
        g = _guard(tmp_path)
        session = openshell_detect(guard=g)
        assert session is not None

    def test_agent_agnostic_cursor(self, tmp_path):
        """Same policy works for Cursor."""
        p = _policy_file(tmp_path)
        _set_openShell_env(agent="cursor", policy_path=p)
        g = _guard(tmp_path)
        session = openshell_detect(guard=g)
        assert session is not None


class TestAttachOpenShell:

    def setup_method(self):
        _clear_openShell_env()
        from aiglos.core.threat_engine_v2 import _SUPERPOWERS_PLAN
        _SUPERPOWERS_PLAN.clear()

    def teardown_method(self):
        _clear_openShell_env()
        from aiglos.core.threat_engine_v2 import _SUPERPOWERS_PLAN
        _SUPERPOWERS_PLAN.clear()

    def test_explicit_policy_file(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        session = attach_openShell(g, policy_path=p, agent="claude-code")
        assert session is not None

    def test_sets_sandbox_type_openShell(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        attach_openShell(g, policy_path=p)
        assert g.sandbox_type == "openShell"

    def test_sets_sandbox_context(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        attach_openShell(g, policy_path=p)
        assert g.sandbox_context is True

    def test_agent_name_stored(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        attach_openShell(g, policy_path=p, agent="cursor")
        assert hasattr(g, "_openShell_agent")
        assert g._openShell_agent == "Cursor"

    def test_missing_policy_graceful(self, tmp_path):
        """Missing policy file should not crash -- just log warning."""
        g = _guard(tmp_path)
        result = attach_openShell(g, policy_path="/nonexistent/policy.yaml")
        assert result is None
        assert g.sandbox_context is True

    def test_reads_policy_path_from_env(self, tmp_path):
        p = _policy_file(tmp_path)
        os.environ[ENV_POLICY_PATH] = p
        g = _guard(tmp_path)
        session = attach_openShell(g, agent="codex")
        assert session is not None

    def test_reads_sandbox_id_from_env(self, tmp_path):
        p = _policy_file(tmp_path)
        os.environ[ENV_SANDBOX_ID] = "env-sandbox-99"
        g = _guard(tmp_path)
        session = attach_openShell(g, policy_path=p)
        assert session.session_id == "env-sandbox-99"


class TestAgentSpecificHelpers:

    def setup_method(self):
        _clear_openShell_env()
        from aiglos.core.threat_engine_v2 import _SUPERPOWERS_PLAN
        _SUPERPOWERS_PLAN.clear()

    def teardown_method(self):
        _clear_openShell_env()
        from aiglos.core.threat_engine_v2 import _SUPERPOWERS_PLAN
        _SUPERPOWERS_PLAN.clear()

    def test_attach_for_claude_code(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        session = attach_for_claude_code(g, policy_path=p)
        assert session is not None
        assert "Claude Code" in g._openShell_agent

    def test_attach_for_codex(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        session = attach_for_codex(g, policy_path=p)
        assert session is not None
        assert "Codex" in g._openShell_agent

    def test_attach_for_cursor(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        session = attach_for_cursor(g, policy_path=p)
        assert session is not None
        assert "Cursor" in g._openShell_agent

    def test_attach_for_openclaw(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        session = attach_for_openclaw(g, policy_path=p)
        assert session is not None
        assert "OpenClaw" in g._openShell_agent

    def test_all_agents_same_policy_same_enforcement(self, tmp_path):
        """
        The YAML policy is agent-agnostic.
        All four agents produce identical enforcement behavior from the same policy.
        """
        p = _policy_file(tmp_path)
        sessions = []
        for attach_fn in [attach_for_claude_code, attach_for_codex,
                          attach_for_cursor, attach_for_openclaw]:
            from aiglos.core.threat_engine_v2 import _SUPERPOWERS_PLAN
            _SUPERPOWERS_PLAN.clear()
            g = _guard(tmp_path)
            session = attach_fn(g, policy_path=p)
            sessions.append(session)

        hashes = {s.policy_hash for s in sessions if s}
        assert len(hashes) == 1, \
            f"Same policy file produced different hashes: {hashes}"


class TestKnownAgents:

    def test_claude_code_known(self):
        assert "claude-code" in KNOWN_AGENTS

    def test_codex_known(self):
        assert "codex" in KNOWN_AGENTS

    def test_cursor_known(self):
        assert "cursor" in KNOWN_AGENTS

    def test_openclaw_known(self):
        assert "openclaw" in KNOWN_AGENTS

    def test_windsurf_known(self):
        assert "windsurf" in KNOWN_AGENTS

    def test_aider_known(self):
        assert "aider" in KNOWN_AGENTS

    def test_all_agents_have_human_names(self):
        for key, name in KNOWN_AGENTS.items():
            assert len(name) > 2, f"{key} has no human name"


class TestNeMoClawSession:

    def test_session_has_policy_hash(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert len(session.policy_hash) == 16

    def test_session_has_policy_data(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert "network" in session.policy_data

    def test_session_allowed_hosts(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert "api.openai.com" in session.allowed_hosts

    def test_session_denied_hosts(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert "*" in session.denied_hosts

    def test_session_workspace(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert session.workspace == "/home/user/projects/"

    def test_session_allowed_tools(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert "filesystem" in session.allowed_tools

    def test_session_denied_tools(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert "sessions.list" in session.denied_tools

    def test_session_check_host_scope(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        assert session.check_host_scope("api.openai.com") is True

    def test_session_artifact_data(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p, session_id="test-sess")
        data = session.artifact_data()
        assert data["session_id"] == "test-sess"
        assert "policy_hash" in data

    def test_session_record_event(self, tmp_path):
        p = _policy_file(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(policy_path=p)
        session.record_event("test", {"key": "value"})
        assert len(session.events) == 1

    def test_file_not_found_raises(self):
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        with pytest.raises(FileNotFoundError):
            mark_as_nemoclaw_session(policy_path="/no/such/file.yaml")

    def test_guard_attached(self, tmp_path):
        p = _policy_file(tmp_path)
        g = _guard(tmp_path)
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        mark_as_nemoclaw_session(policy_path=p, guard=g)
        assert g.nemoclaw_session() is not None
        assert g.sandbox_context is True
        assert g.sandbox_type == "openShell"


class TestV0251ModuleAPI:

    def test_version(self):
        assert aiglos.__version__ == "0.25.23"

    def test_is_inside_openShell_exported(self):
        assert hasattr(aiglos, "is_inside_openShell")
        assert "is_inside_openShell" in aiglos.__all__

    def test_openShell_context_exported(self):
        assert hasattr(aiglos, "openShell_context")

    def test_openshell_detect_exported(self):
        assert hasattr(aiglos, "openshell_detect")
        assert "openshell_detect" in aiglos.__all__

    def test_attach_openShell_exported(self):
        assert hasattr(aiglos, "attach_openShell")
        assert "attach_openShell" in aiglos.__all__

    def test_attach_for_claude_code_exported(self):
        assert hasattr(aiglos, "attach_for_claude_code")

    def test_attach_for_codex_exported(self):
        assert hasattr(aiglos, "attach_for_codex")

    def test_attach_for_cursor_exported(self):
        assert hasattr(aiglos, "attach_for_cursor")

    def test_all_exports_importable(self):
        missing = [e for e in aiglos.__all__ if not hasattr(aiglos, e)]
        assert missing == [], f"Missing exports: {missing}"
