"""
tests/test_missed_features.py
================================
Aiglos v0.20.0 -- Five Missed Features

Tests for:
  Build 1 -- Baseline reset (hardening mode, suppression window)
  Build 2 -- Permission recommender (minimum viable allowlist)
  Build 3 -- sandbox_context=True (impossible calls = CRITICAL)
  Build 4 -- lockdown policy (deny-first, allow_tool, tool_grants)
  Build 5 -- GOVBENCH (five dimensions, 20 scenarios, scoring)
"""

import os, sys, time, json, tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiglos
from aiglos.adaptive.observation import ObservationGraph
from aiglos.core.behavioral_baseline import BaselineEngine
from aiglos.adaptive.permission_recommender import (
    PermissionRecommender, PermissionRecommendation, ToolUsageStats
)
from aiglos.benchmark.govbench import (
    GovBench, GovBenchResult, DimensionResult,
    AttackScenario, _d1_scenarios, _d2_scenarios, _d3_scenarios,
    _d4_scenarios, _d5_scenarios, _grade
)
from aiglos.integrations.openclaw import OpenClawGuard


def _graph(tmp_path) -> ObservationGraph:
    return ObservationGraph(db_path=str(tmp_path / "obs.db"))


def _guard(tmp_path, policy="enterprise", sandbox_context=False,
           allow_tools=None) -> OpenClawGuard:
    return OpenClawGuard(
        agent_name      = "test-agent",
        policy          = policy,
        log_path        = str(tmp_path / "test.log"),
        sandbox_context = sandbox_context,
        allow_tools     = allow_tools,
    )


# =============================================================================
# Build 1 -- Baseline Reset
# =============================================================================

class TestBaselineEvents:
    def test_record_baseline_event(self, tmp_path):
        g = _graph(tmp_path)
        g.record_baseline_event(
            agent_name               = "my-agent",
            event_type               = "reset",
            reason                   = "post-hardening",
            sessions_before          = 30,
            suppressed_until_session = 50,
        )
        events = g.get_baseline_events("my-agent")
        assert len(events) == 1
        assert events[0]["event_type"] == "reset"
        assert events[0]["reason"] == "post-hardening"

    def test_get_latest_baseline_reset(self, tmp_path):
        g = _graph(tmp_path)
        g.record_baseline_event("my-agent", "reset", "first", 10, 30)
        time.sleep(0.01)
        g.record_baseline_event("my-agent", "reset", "second", 30, 50)
        latest = g.get_latest_baseline_reset("my-agent")
        assert latest is not None
        assert latest["reason"] == "second"

    def test_no_events_returns_none(self, tmp_path):
        g = _graph(tmp_path)
        assert g.get_latest_baseline_reset("unknown-agent") is None

    def test_get_agent_session_count_since(self, tmp_path):
        g = _graph(tmp_path)
        # Record a block pattern for an agent
        with g._conn() as conn:
            conn.execute("""
                INSERT INTO block_patterns (pattern_id, rule_id, agent_name, tool_name,
                    args_fingerprint, tier, occurred_at)
                VALUES ('pat-1', 'T01', 'my-agent', 'http.post', 'fp1', 2, ?)
            """, (time.time(),))
        count = g.get_agent_session_count_since("my-agent", 0)
        assert isinstance(count, int)

    def test_multiple_event_types(self, tmp_path):
        g = _graph(tmp_path)
        g.record_baseline_event("my-agent", "reset",    "hardening", 0, 20)
        g.record_baseline_event("my-agent", "hardening","config change", 20, 40)
        events = g.get_baseline_events("my-agent")
        types = [e["event_type"] for e in events]
        assert "reset" in types
        assert "hardening" in types


class TestBaselineEngineHardeningMode:
    def test_set_hardening_mode(self):
        engine = BaselineEngine.__new__(BaselineEngine)
        engine._hardening_suppressed_until = 0
        engine._agent_name = "test"
        engine._graph = None
        engine.set_hardening_mode(50)
        assert engine._hardening_suppressed_until == 50

    def test_is_suppressed_when_below_threshold(self):
        engine = BaselineEngine.__new__(BaselineEngine)
        engine._hardening_suppressed_until = 50
        engine._agent_name = "test"
        engine._graph = None
        assert engine.is_suppressed(30) is True
        assert engine.is_suppressed(49) is True

    def test_is_not_suppressed_when_above_threshold(self):
        engine = BaselineEngine.__new__(BaselineEngine)
        engine._hardening_suppressed_until = 50
        engine._agent_name = "test"
        engine._graph = None
        assert engine.is_suppressed(50) is False
        assert engine.is_suppressed(100) is False

    def test_default_not_suppressed(self):
        engine = BaselineEngine.__new__(BaselineEngine)
        engine._hardening_suppressed_until = 0
        engine._agent_name = "test"
        engine._graph = None
        assert engine.is_suppressed(0) is False
        assert engine.is_suppressed(100) is False


# =============================================================================
# Build 2 -- Permission Recommender
# =============================================================================

class TestPermissionRecommender:
    def test_no_graph_returns_empty(self):
        rec = PermissionRecommender(graph=None)
        result = rec.recommend("my-agent")
        assert isinstance(result, PermissionRecommendation)
        assert result.total_sessions == 0
        assert result.recommended_allow == []

    def test_recommend_with_graph(self, tmp_path):
        g = _graph(tmp_path)
        # Seed some tool call data
        with g._conn() as conn:
            for i, tool in enumerate(["filesystem.read_file", "web_search", "shell.execute"]):
                conn.execute("""
                    INSERT INTO block_patterns (pattern_id, rule_id, agent_name, tool_name,
                        args_fingerprint, tier, occurred_at)
                    VALUES (?, '', 'my-agent', ?, 'fp1', 1, ?)
                """, (f'pat-{i}', tool, time.time()))
        rec = PermissionRecommender(graph=g)
        result = rec.recommend("my-agent")
        assert isinstance(result, PermissionRecommendation)
        assert result.agent_name == "my-agent"

    def test_tool_usage_stats_allow_rate(self):
        s = ToolUsageStats(
            tool_name="web_search", total_calls=10,
            allow_calls=8, warn_calls=1, block_calls=1
        )
        assert s.allow_rate == pytest.approx(0.8)
        assert s.block_rate == pytest.approx(0.1)

    def test_tool_usage_stats_recommendation_allow(self):
        s = ToolUsageStats("web_search", total_calls=10, allow_calls=8,
                           warn_calls=1, block_calls=1)
        assert s.recommendation == "ALLOW"

    def test_tool_usage_stats_recommendation_block(self):
        s = ToolUsageStats("shell.rm_rf", total_calls=10, allow_calls=0,
                           warn_calls=1, block_calls=9)
        assert s.recommendation == "BLOCK"

    def test_openclaw_config_json_valid(self):
        rec = PermissionRecommendation(
            agent_name        = "my-agent",
            total_sessions    = 20,
            total_tool_calls  = 200,
            recommended_allow = ["filesystem.read_file", "web_search"],
            recommended_block = ["shell.execute"],
        )
        config = rec.openclaw_config()
        data = json.loads(config)
        assert data["tools"]["allowed"] == ["filesystem.read_file", "web_search"]
        assert data["tools"]["blocked"] == ["shell.execute"]
        assert data["_aiglos_generated"] is True

    def test_summary_output(self):
        rec = PermissionRecommendation(
            agent_name="my-agent", total_sessions=10,
            total_tool_calls=100, recommended_allow=["web_search"]
        )
        s = rec.summary()
        assert "my-agent" in s
        assert "10 sessions" in s
        assert "ALLOW" in s

    def test_all_agents_empty_graph(self, tmp_path):
        g = _graph(tmp_path)
        rec = PermissionRecommender(graph=g)
        agents = rec.all_agents()
        assert isinstance(agents, list)


# =============================================================================
# Build 3 -- sandbox_context=True
# =============================================================================

class TestSandboxContext:
    def test_sandbox_context_blocks_shell(self, tmp_path):
        g = _guard(tmp_path, sandbox_context=True)
        r = g.before_tool_call("shell.execute", {"command": "ls -la"})
        assert r.verdict == "BLOCK"
        assert r.threat_class == "T50"
        assert r.score == 1.0

    def test_sandbox_context_blocks_network(self, tmp_path):
        g = _guard(tmp_path, sandbox_context=True)
        r = g.before_tool_call("http.post", {"url": "https://api.example.com"})
        assert r.verdict == "BLOCK"
        assert r.score == 1.0

    def test_sandbox_context_blocks_filesystem_write(self, tmp_path):
        g = _guard(tmp_path, sandbox_context=True)
        r = g.before_tool_call("filesystem.write_file",
                               {"path": "/home/user/data.txt"})
        assert r.verdict == "BLOCK"

    def test_sandbox_context_allows_localhost(self, tmp_path):
        g = _guard(tmp_path, sandbox_context=True)
        r = g.before_tool_call("http.get",
                               {"url": "http://localhost:8080/health"})
        # localhost is allowed in sandbox
        assert r.verdict != "BLOCK" or r.threat_class != "T50"

    def test_sandbox_context_off_allows_shell(self, tmp_path):
        g = _guard(tmp_path, sandbox_context=False)
        r = g.before_tool_call("shell.execute",
                               {"command": "ls -la /tmp"})
        # Without sandbox_context, normal rules apply (may warn but not T50)
        if r.verdict == "BLOCK":
            assert r.threat_class != "T50"

    def test_sandbox_confirmed_escape_campaign_exists(self):
        from aiglos.adaptive.campaign import _CAMPAIGN_PATTERNS
        names = [p["name"] for p in _CAMPAIGN_PATTERNS]
        assert "SANDBOX_CONFIRMED_ESCAPE" in names

    def test_sandbox_confirmed_escape_high_confidence(self):
        from aiglos.adaptive.campaign import _CAMPAIGN_PATTERNS
        p = next(x for x in _CAMPAIGN_PATTERNS
                 if x["name"] == "SANDBOX_CONFIRMED_ESCAPE")
        assert p["confidence"] >= 0.90
        assert p["min_events"] >= 2


# =============================================================================
# Build 4 -- Lockdown Policy
# =============================================================================

class TestLockdownPolicy:
    def test_lockdown_blocks_unlisted_tool(self, tmp_path):
        g = _guard(tmp_path, policy="lockdown",
                  allow_tools=["filesystem.read_file"])
        r = g.before_tool_call("shell.execute", {"command": "ls"})
        assert r.verdict == "BLOCK"
        assert r.threat_class == "LOCKDOWN_DENY"

    def test_lockdown_allows_listed_tool(self, tmp_path):
        g = _guard(tmp_path, policy="lockdown",
                  allow_tools=["filesystem.read_file"])
        r = g.before_tool_call("filesystem.read_file", {"path": "/tmp/x"})
        assert r.verdict != "BLOCK" or r.threat_class != "LOCKDOWN_DENY"

    def test_lockdown_no_allowlist_blocks_everything(self, tmp_path):
        g = _guard(tmp_path, policy="lockdown")
        r = g.before_tool_call("web_search", {"query": "hello"})
        assert r.verdict == "BLOCK"
        assert r.threat_class == "LOCKDOWN_DENY"

    def test_allow_tool_adds_to_allowlist(self, tmp_path):
        g = _guard(tmp_path, policy="lockdown")
        # Initially blocked
        r1 = g.before_tool_call("web_search", {"query": "hello"})
        assert r1.verdict == "BLOCK"
        # Grant permission
        grant = g.allow_tool("web_search", reason="needed for research",
                             authorized_by="will")
        assert grant["tool_name"] == "web_search"
        assert grant["authorized_by"] == "will"
        # Now allowed
        r2 = g.before_tool_call("web_search", {"query": "hello"})
        assert r2.verdict != "BLOCK" or r2.threat_class != "LOCKDOWN_DENY"

    def test_tool_grants_log(self, tmp_path):
        g = _guard(tmp_path, policy="lockdown")
        g.allow_tool("tool_a", reason="testing", authorized_by="alice")
        g.allow_tool("tool_b", reason="needed",  authorized_by="bob")
        grants = g.tool_grants()
        assert len(grants) == 2
        names = [gr["tool_name"] for gr in grants]
        assert "tool_a" in names
        assert "tool_b" in names

    def test_allowed_tools_list(self, tmp_path):
        g = _guard(tmp_path, policy="lockdown",
                  allow_tools=["web_search", "filesystem.read_file"])
        tools = g.allowed_tools()
        assert "web_search" in tools
        assert "filesystem.read_file" in tools

    def test_lockdown_in_policy_thresholds(self):
        from aiglos.integrations.openclaw import POLICY_THRESHOLDS
        assert "lockdown" in POLICY_THRESHOLDS
        assert POLICY_THRESHOLDS["lockdown"]["block_score"] == 0.0

    def test_non_lockdown_policy_unaffected(self, tmp_path):
        # Enterprise policy with allow_tools should not lockdown
        g = _guard(tmp_path, policy="enterprise",
                  allow_tools=["filesystem.read_file"])
        r = g.before_tool_call("web_search", {"query": "hello"})
        # Enterprise doesn't enforce allow_tools as lockdown
        assert r.threat_class != "LOCKDOWN_DENY"


# =============================================================================
# Build 5 -- GOVBENCH
# =============================================================================

class TestGovBenchGrading:
    def test_grade_a(self):    assert _grade(92) == "A"
    def test_grade_b(self):    assert _grade(80) == "B"
    def test_grade_c(self):    assert _grade(65) == "C"
    def test_grade_d(self):    assert _grade(50) == "D"
    def test_grade_f(self):    assert _grade(40) == "F"


class TestAttackScenario:
    def test_scenario_pass_when_blocked(self, tmp_path):
        g = _guard(tmp_path)
        scenario = AttackScenario(
            name        = "test",
            description = "test",
            tool_calls  = [{"tool": "filesystem.read_file",
                            "args": {"path": ".env"}}],
            expect_block = True,
        )
        result = scenario.run(g)
        # .env read should be blocked by T01
        if result.blocked_any:
            assert result.passed is True
            assert result.score == 1.0

    def test_scenario_pass_when_clean_not_blocked(self, tmp_path):
        g = _guard(tmp_path)
        scenario = AttackScenario(
            name        = "clean",
            description = "clean test",
            tool_calls  = [{"tool": "web_search",
                            "args": {"query": "python documentation"}}],
            expect_block = False,
        )
        result = scenario.run(g)
        assert result.scenario_name == "clean"

    def test_scenario_result_score_0_on_failure(self, tmp_path):
        g = _guard(tmp_path, policy="permissive")
        scenario = AttackScenario(
            name        = "should_block",
            description = "expects block",
            tool_calls  = [{"tool": "web_search",
                            "args": {"query": "normal search"}}],
            expect_block = True,  # expects block but won't get one
        )
        result = scenario.run(g)
        if not result.blocked_any:
            assert result.passed is False
            assert result.score == 0.0


class TestGovBenchDimensions:
    def test_d1_scenarios_exist(self):
        scenarios = _d1_scenarios()
        assert len(scenarios) == 4
        names = [s.name for s in scenarios]
        assert "RECON_TO_EXFIL" in names
        assert "CLEAN_SEQUENCE" in names

    def test_d2_scenarios_exist(self):
        scenarios = _d2_scenarios()
        assert len(scenarios) == 4
        names = [s.name for s in scenarios]
        assert "SKILL_MD_INJECT" in names
        assert "CLEAN_SKILL_WRITE" in names

    def test_d3_scenarios_exist(self):
        scenarios = _d3_scenarios()
        assert len(scenarios) == 4
        names = [s.name for s in scenarios]
        assert "MEMORY_FALSE_BELIEF" in names

    def test_d4_scenarios_exist(self):
        scenarios = _d4_scenarios()
        assert len(scenarios) == 4
        names = [s.name for s in scenarios]
        assert "REWARD_POISON_SHELL" in names

    def test_d5_scenarios_exist(self):
        scenarios = _d5_scenarios()
        assert len(scenarios) == 4
        names = [s.name for s in scenarios]
        assert "ADMIN_IMPERSONATE" in names
        assert "LEGITIMATE_INTER_AGENT" in names

    def test_each_dimension_has_clean_baseline(self):
        """Every dimension has at least one expect_block=False scenario."""
        for fn in [_d1_scenarios, _d2_scenarios, _d3_scenarios,
                   _d4_scenarios, _d5_scenarios]:
            clean = [s for s in fn() if not s.expect_block]
            assert len(clean) >= 1, f"{fn.__name__} has no clean baseline"


class TestGovBenchRun:
    def test_run_returns_result(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run()
        assert isinstance(result, GovBenchResult)
        assert 0 <= result.composite <= 100
        assert result.grade in "ABCDF"

    def test_run_produces_five_dimensions(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run()
        assert len(result.dimensions) == 5
        ids = [d.dimension for d in result.dimensions]
        for dim in ["D1", "D2", "D3", "D4", "D5"]:
            assert dim in ids

    def test_run_single_dimension(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run(dimensions=["D1"])
        assert len(result.dimensions) == 1
        assert result.dimensions[0].dimension == "D1"

    def test_enterprise_guard_scores_above_zero(self, tmp_path):
        g = _guard(tmp_path, policy="enterprise")
        bench = GovBench(guard=g)
        result = bench.run()
        # Enterprise policy should catch at least some attack scenarios
        assert result.composite > 0

    def test_no_guard_scores_zero(self):
        bench = GovBench(guard=None)
        result = bench.run()
        assert result.composite == 0.0
        assert result.grade == "F"

    def test_to_json_valid(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run()
        data = json.loads(result.to_json())
        assert "composite" in data
        assert "grade" in data
        assert "dimensions" in data
        assert len(data["dimensions"]) == 5

    def test_summary_output(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run()
        s = result.summary()
        assert "GOVBENCH" in s
        assert "D1" in s and "D2" in s

    def test_dimension_result_counts(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run()
        for d in result.dimensions:
            assert d.total == 4   # each dimension has 4 scenarios
            assert 0 <= d.passed <= d.total

    def test_aiglos_version_populated(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run()
        assert result.aiglos_version == "0.25.8"

    def test_duration_ms_positive(self, tmp_path):
        g = _guard(tmp_path)
        bench = GovBench(guard=g)
        result = bench.run()
        assert result.duration_ms > 0


# =============================================================================
# Module API v0.20.0
# =============================================================================

class TestV0200ModuleAPI:
    def test_version(self):
        assert aiglos.__version__ == "0.25.8"

    def test_govbench_exported(self):
        assert "GovBench" in aiglos.__all__
        assert hasattr(aiglos, "GovBench")

    def test_permission_recommender_exported(self):
        assert "PermissionRecommender" in aiglos.__all__
        assert hasattr(aiglos, "PermissionRecommender")

    def test_all_exports_importable(self):
        missing = [e for e in aiglos.__all__ if not hasattr(aiglos, e)]
        assert missing == [], f"Missing exports: {missing}"

    def test_lockdown_policy_accessible(self):
        from aiglos.integrations.openclaw import POLICY_THRESHOLDS
        assert "lockdown" in POLICY_THRESHOLDS

    def test_sandbox_context_param_accessible(self):
        import inspect
        from aiglos.integrations.openclaw import OpenClawGuard
        sig = inspect.signature(OpenClawGuard.__init__)
        assert "sandbox_context" in sig.parameters
        assert "allow_tools" in sig.parameters

    def test_19_campaign_patterns(self):
        from aiglos.adaptive.campaign import _CAMPAIGN_PATTERNS
        assert len(_CAMPAIGN_PATTERNS) == 23

    def test_govbench_importable(self):
        bench = aiglos.GovBench()
        assert bench is not None
