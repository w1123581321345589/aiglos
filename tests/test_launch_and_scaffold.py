"""Tests for aiglos.cli.launch and aiglos.cli.scaffold."""

import pytest
import json
from pathlib import Path


class TestLaunchConfig:

    def test_launch_config_defaults(self):
        from aiglos.cli.launch import LaunchConfig
        c = LaunchConfig()
        assert c.agent_name == "my-agent"
        assert c.tools == []
        assert c.multi_agent is False
        assert c.heartbeat_mins == 30
        assert c.policy == "enterprise"

    def test_launch_config_all_hosts(self):
        from aiglos.cli.launch import LaunchConfig
        c = LaunchConfig()
        c.tools = ["twitter", "github"]
        c.tool_meta = {
            "twitter": {"hosts": ["api.twitter.com", "api.x.com"]},
            "github":  {"hosts": ["api.github.com", "github.com"]},
        }
        hosts = c.all_hosts()
        assert "api.twitter.com" in hosts
        assert "api.github.com" in hosts
        assert len(hosts) == 4

    def test_launch_config_to_dict(self):
        from aiglos.cli.launch import LaunchConfig
        c = LaunchConfig()
        c.agent_name = "test-agent"
        d = c.to_dict()
        assert d["agent_name"] == "test-agent"
        assert "tools" in d
        assert "policy" in d


class TestKnownTools:

    def test_known_tools_not_empty(self):
        from aiglos.cli.launch import KNOWN_TOOLS
        assert len(KNOWN_TOOLS) >= 25

    def test_known_tools_have_surface_and_hosts(self):
        from aiglos.cli.launch import KNOWN_TOOLS
        for name, meta in KNOWN_TOOLS.items():
            assert "surface" in meta, f"{name} missing surface"
            assert "hosts" in meta, f"{name} missing hosts"

    def test_known_models_coverage(self):
        from aiglos.cli.launch import KNOWN_MODELS
        assert "claude-opus" in KNOWN_MODELS
        assert "kimi" in KNOWN_MODELS
        assert "gpt-5" in KNOWN_MODELS
        assert len(KNOWN_MODELS) >= 8


class TestTemplateGenerators:

    def _make_config(self):
        from aiglos.cli.launch import LaunchConfig
        c = LaunchConfig()
        c.agent_name = "scout"
        c.description = "Research AI news and post to Twitter"
        c.tools = ["twitter", "github", "notion"]
        c.tool_meta = {
            "twitter": {"surface": "social",  "hosts": ["api.twitter.com"]},
            "github":  {"surface": "code",    "hosts": ["api.github.com"]},
            "notion":  {"surface": "docs",    "hosts": ["api.notion.com"]},
        }
        c.multi_agent = True
        c.agents = [
            {"name": "ceo-agent",       "role": "decisions", "model": "claude-opus-4-6", "can_push_main": True,  "index": 1},
            {"name": "assistant-agent", "role": "research",  "model": "moonshot-v1",     "can_push_main": False, "index": 2},
        ]
        c.heartbeat_mins = 30
        c.policy = "enterprise"
        return c

    def test_generate_files_returns_seven_files(self):
        from aiglos.cli.launch import generate_files
        config = self._make_config()
        files = generate_files(config)
        assert len(files) == 7
        expected = {"soul.md", "learnings.md", "heartbeat.md", "crons.md",
                    "tools.md", "agents.md", "config.py"}
        assert set(files.keys()) == expected

    def test_soul_md_contains_hard_bans(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        soul = files["soul.md"]
        assert "fabricate_data" in soul
        assert "No hallucinations" in soul
        assert "scout" in soul

    def test_soul_md_contains_tools(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        soul = files["soul.md"]
        assert "twitter" in soul
        assert "notion" in soul

    def test_learnings_md_has_t79_protection(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        learnings = files["learnings.md"]
        assert "T79" in learnings
        assert "PERSISTENT_MEMORY_INJECT" in learnings

    def test_heartbeat_md_has_t67(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        hb = files["heartbeat.md"]
        assert "T67" in hb
        assert "HEARTBEAT_SILENCE" in hb
        assert "30 minutes" in hb

    def test_crons_md_has_t77(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        crons = files["crons.md"]
        assert "T77" in crons
        assert "OVERNIGHT_JOB_INJECTION" in crons

    def test_tools_md_lockdown(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        tools = files["tools.md"]
        assert "T69" in tools
        assert "PLAN_DRIFT" in tools
        assert "Twitter" in tools
        assert "lockdown" in tools.lower()

    def test_agents_md_multi_agent(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        agents = files["agents.md"]
        assert "ceo-agent" in agents
        assert "assistant-agent" in agents
        assert "T38" in agents

    def test_agents_md_single_agent(self):
        from aiglos.cli.launch import LaunchConfig, generate_files
        c = LaunchConfig()
        c.multi_agent = False
        c.agents = [{"name": "solo", "role": "all", "model": "opus", "can_push_main": True, "index": 1}]
        files = generate_files(c)
        agents = files["agents.md"]
        assert "Single agent" in agents

    def test_config_py_has_guard(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        config = files["config.py"]
        assert "OpenClawGuard" in config
        assert "gigabrain_autodetect" in config
        assert "declare_memory_backend" in config
        assert "enterprise" in config

    def test_config_py_has_subagent_declarations(self):
        from aiglos.cli.launch import generate_files
        files = generate_files(self._make_config())
        config = files["config.py"]
        assert "declare_subagent" in config
        assert "ceo-agent" in config
        assert "assistant-agent" in config

    def test_config_py_federal_policy(self):
        from aiglos.cli.launch import LaunchConfig, generate_files
        c = LaunchConfig()
        c.policy = "federal"
        c.compliance = ["ndaa_1513"]
        files = generate_files(c)
        config = files["config.py"]
        assert "federal" in config
        assert "NDAA" in config


class TestConfigFromDescription:

    def test_from_description_infers_tools(self):
        from aiglos.cli.launch import _config_from_description
        c = _config_from_description("Research AI news and post to Twitter every morning")
        assert "twitter" in c.tools

    def test_from_description_sets_name(self):
        from aiglos.cli.launch import _config_from_description
        c = _config_from_description("Scout agent that monitors GitHub")
        assert c.agent_name == "scout"

    def test_from_description_defaults_single_agent(self):
        from aiglos.cli.launch import _config_from_description
        c = _config_from_description("A research agent")
        assert len(c.agents) == 1
        assert c.agents[0]["can_push_main"] is True


class TestPolicyPresets:

    def test_policy_presets_exist(self):
        from aiglos.cli.launch import POLICY_PRESETS
        assert "standard" in POLICY_PRESETS
        assert "dod" in POLICY_PRESETS
        assert "enterprise" in POLICY_PRESETS

    def test_dod_policy_is_federal(self):
        from aiglos.cli.launch import POLICY_PRESETS
        assert POLICY_PRESETS["dod"]["policy"] == "federal"


class TestScaffold:

    def test_agent_spec_from_ceo_description(self):
        from aiglos.cli.scaffold import AgentSpec
        spec = AgentSpec("CEO agent using Opus for decisions, push rights to main", is_first=True)
        assert "ceo" in spec.raw_name
        assert spec.model == "claude-opus-4-6"
        assert spec.can_push is True
        assert "fabricate_data" in spec.hard_bans

    def test_agent_spec_from_assistant_description(self):
        from aiglos.cli.scaffold import AgentSpec
        spec = AgentSpec("Assistant agent using Kimi for research, side branches only", is_first=False)
        assert "assistant" in spec.raw_name
        assert spec.model == "moonshot-v1"
        assert spec.can_push is False
        assert "push_to_main" in spec.hard_bans

    def test_scaffold_from_descriptions(self):
        from aiglos.cli.scaffold import scaffold_from_descriptions
        result = scaffold_from_descriptions([
            "CEO agent using Opus, push rights to main",
            "Assistant agent using Kimi, research only",
        ])
        assert "declare_subagent" in result
        assert "ceo" in result
        assert "assistant" in result
        assert "AgentPhase" in result

    def test_agent_spec_to_python(self):
        from aiglos.cli.scaffold import AgentSpec
        spec = AgentSpec("CEO agent using Opus", is_first=True)
        code = spec.to_python()
        assert "guard.declare_subagent(" in code
        assert 'model="claude-opus-4-6"' in code

    def test_json_list(self):
        from aiglos.cli.scaffold import json_list
        assert json_list([]) == "[]"
        assert json_list(["a"]) == '["a"]'
        assert json_list(["a", "b"]) == '["a", "b"]'

    def test_infer_role(self):
        from aiglos.cli.scaffold import _infer_role
        assert _infer_role("a research agent") == "research"
        assert _infer_role("coding engineer") == "coding"
        assert _infer_role("content writer") == "content"

    def test_infer_tools_includes_git(self):
        from aiglos.cli.scaffold import _infer_tools
        tools = _infer_tools("push to main branch on github")
        assert "git.push" in tools
        assert "git.merge" in tools

    def test_infer_model_kimi(self):
        from aiglos.cli.scaffold import _infer_model
        assert _infer_model("using kimi for research") == "moonshot-v1"

    def test_infer_model_default(self):
        from aiglos.cli.scaffold import _infer_model
        assert _infer_model("just a regular agent") == "claude-sonnet-4-6"


class TestRoleTools:

    def test_role_tools_coverage(self):
        from aiglos.cli.scaffold import ROLE_TOOLS
        assert len(ROLE_TOOLS) >= 15
        assert "research" in ROLE_TOOLS
        assert "coding" in ROLE_TOOLS
        assert "ceo" in ROLE_TOOLS
        assert "finance" in ROLE_TOOLS

    def test_hard_ban_keywords(self):
        from aiglos.cli.scaffold import HARD_BAN_KEYWORDS
        assert "research" in HARD_BAN_KEYWORDS
        assert "fabricate_data" in HARD_BAN_KEYWORDS["research"]

    def test_model_keywords(self):
        from aiglos.cli.scaffold import MODEL_KEYWORDS
        assert len(MODEL_KEYWORDS) >= 8
        assert MODEL_KEYWORDS["opus"] == "claude-opus-4-6"


class TestExportsFromInit:

    def test_launch_exported(self):
        from aiglos import launch, LaunchConfig, generate_files
        assert callable(launch)
        assert LaunchConfig is not None

    def test_scaffold_exported(self):
        from aiglos import scaffold_from_descriptions, AgentSpec, ROLE_TOOLS
        assert callable(scaffold_from_descriptions)
        assert AgentSpec is not None
        assert len(ROLE_TOOLS) >= 15

    def test_known_tools_exported(self):
        from aiglos import LAUNCH_KNOWN_TOOLS, LAUNCH_KNOWN_MODELS
        assert len(LAUNCH_KNOWN_TOOLS) >= 25
        assert len(LAUNCH_KNOWN_MODELS) >= 8
