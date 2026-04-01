"""
Tests for declare_studio_pipeline(), STUDIO_ROLE_TOOLS, and v0.25.8 exports.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from aiglos.integrations.gigabrain import (
    declare_studio_pipeline,
    STUDIO_ROLE_TOOLS,
)


class FakeSubagentRegistry:
    def __init__(self):
        self.declared = []


class FakeGuard:
    def __init__(self):
        self._subagent_registry = FakeSubagentRegistry()
        self._declared_subagents = []

    def declare_subagent(self, name, tools=None, scope_files=None,
                         hard_bans=None, **kwargs):
        self._declared_subagents.append({
            "name": name,
            "tools": tools or [],
            "scope_files": scope_files,
            "hard_bans": hard_bans or [],
        })


class TestStudioRoleTools:

    def test_25_roles_defined(self):
        non_default = [r for r in STUDIO_ROLE_TOOLS if not r.startswith("_")]
        assert len(non_default) == 24

    def test_default_fallback_exists(self):
        assert "_default" in STUDIO_ROLE_TOOLS

    def test_every_role_has_tools(self):
        for role, config in STUDIO_ROLE_TOOLS.items():
            assert "tools" in config, f"{role} missing tools"
            assert len(config["tools"]) > 0, f"{role} has empty tools"

    def test_every_role_has_bans(self):
        for role, config in STUDIO_ROLE_TOOLS.items():
            assert "bans" in config, f"{role} missing bans"
            assert len(config["bans"]) > 0, f"{role} has empty bans"

    def test_every_role_has_scope(self):
        for role, config in STUDIO_ROLE_TOOLS.items():
            assert "scope" in config, f"{role} missing scope"

    def test_art_director_readonly(self):
        art = STUDIO_ROLE_TOOLS["art-director"]
        assert "filesystem.read" in art["tools"]
        assert "filesystem.write" not in art["tools"]
        assert "deploy" in art["bans"]

    def test_qa_tester_no_write(self):
        qa = STUDIO_ROLE_TOOLS["qa-tester"]
        assert "filesystem.write" in qa["bans"]

    def test_lead_programmer_has_shell(self):
        lead = STUDIO_ROLE_TOOLS["lead-programmer"]
        assert "shell.execute" in lead["tools"]
        assert "git.push" in lead["tools"]

    def test_sound_designer_scoped_to_audio(self):
        sd = STUDIO_ROLE_TOOLS["sound-designer"]
        assert any("audio" in s for s in sd["scope"])
        assert "push_to_main" in sd["bans"]

    def test_researcher_no_write(self):
        r = STUDIO_ROLE_TOOLS["researcher"]
        assert "filesystem.write" in r["bans"]


class TestDeclareStudioPipeline:

    def test_registers_all_roles(self):
        guard = FakeGuard()
        declared = declare_studio_pipeline(guard, studio_name="test-studio")
        assert len(declared) == 24
        assert all("test-studio/" in name for name in declared)

    def test_registers_specific_roles(self):
        guard = FakeGuard()
        roles = ["art-director", "qa-lead", "sound-designer"]
        declared = declare_studio_pipeline(guard, roles=roles, studio_name="indie")
        assert len(declared) == 3
        assert "indie/art-director" in declared
        assert "indie/qa-lead" in declared

    def test_subagent_calls_made(self):
        guard = FakeGuard()
        roles = ["art-director", "qa-lead"]
        declare_studio_pipeline(guard, roles=roles, studio_name="s")
        assert len(guard._declared_subagents) == 2
        names = [s["name"] for s in guard._declared_subagents]
        assert "s/art-director" in names
        assert "s/qa-lead" in names

    def test_hard_bans_include_fabricate(self):
        guard = FakeGuard()
        declare_studio_pipeline(guard, roles=["art-director"], studio_name="s")
        sub = guard._declared_subagents[0]
        assert "fabricate_data" in sub["hard_bans"]
        assert "unverified_claims" in sub["hard_bans"]

    def test_allow_deploys_overrides(self):
        guard = FakeGuard()
        declare_studio_pipeline(
            guard,
            roles=["lead-programmer"],
            allow_deploys=["lead-programmer"],
            studio_name="s",
        )
        sub = guard._declared_subagents[0]
        assert "deploy" not in sub["hard_bans"]

    def test_coordinator_gets_write(self):
        guard = FakeGuard()
        declare_studio_pipeline(
            guard,
            roles=["art-director"],
            coordinator_role="art-director",
            studio_name="s",
        )
        sub = guard._declared_subagents[0]
        assert "filesystem.write" in sub["tools"]

    def test_unknown_role_uses_default(self):
        guard = FakeGuard()
        declare_studio_pipeline(
            guard,
            roles=["unknown-role"],
            studio_name="s",
        )
        sub = guard._declared_subagents[0]
        assert "filesystem.read" in sub["tools"]
        assert "deploy" in sub["hard_bans"]


class TestOpenShellKnownAgents:

    def test_17_known_agents(self):
        from aiglos.integrations.openShell import KNOWN_AGENTS
        assert len(KNOWN_AGENTS) == 17

    def test_game_studio_agents_present(self):
        from aiglos.integrations.openShell import KNOWN_AGENTS
        assert "claude-code-game-studios" in KNOWN_AGENTS
        assert "ccgs" in KNOWN_AGENTS
        assert "game-studio" in KNOWN_AGENTS

    def test_core_agents_still_present(self):
        from aiglos.integrations.openShell import KNOWN_AGENTS
        assert "claude-code" in KNOWN_AGENTS
        assert "codex" in KNOWN_AGENTS
        assert "cursor" in KNOWN_AGENTS
        assert "openclaw" in KNOWN_AGENTS
        assert "smolagents" in KNOWN_AGENTS


class TestScaffoldGameStudioRoles:

    def test_game_studio_roles_in_scaffold(self):
        from aiglos.cli.scaffold import ROLE_TOOLS
        assert "art-director" in ROLE_TOOLS
        assert "level-designer" in ROLE_TOOLS
        assert "qa-lead" in ROLE_TOOLS
        assert "sound-designer" in ROLE_TOOLS
        assert "programmer" in ROLE_TOOLS
        assert "producer" in ROLE_TOOLS
        assert "writer" in ROLE_TOOLS

    def test_scaffold_from_descriptions(self):
        from aiglos.cli.scaffold import scaffold_from_descriptions
        result = scaffold_from_descriptions([
            "CEO agent using Opus for decisions, push to main",
            "Research assistant using Kimi, side branches only",
        ])
        assert "declare_subagent" in result
        assert "ceo" in result.lower()

    def test_agent_spec_basic(self):
        from aiglos.cli.scaffold import AgentSpec
        spec = AgentSpec("CEO agent using Opus for decisions", is_first=True)
        assert spec.model == "claude-opus-4-6"
        assert spec.can_push is True


class TestV0258Exports:

    def test_studio_pipeline_from_init(self):
        import aiglos
        assert hasattr(aiglos, "declare_studio_pipeline")
        assert callable(aiglos.declare_studio_pipeline)

    def test_studio_role_tools_from_init(self):
        import aiglos
        assert hasattr(aiglos, "STUDIO_ROLE_TOOLS")
        assert isinstance(aiglos.STUDIO_ROLE_TOOLS, dict)

    def test_version(self):
        import aiglos
        assert aiglos.__version__ == "0.25.16"
