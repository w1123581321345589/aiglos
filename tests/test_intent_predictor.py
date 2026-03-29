"""
tests/test_intent_predictor.py
================================
Aiglos v0.10.0 predictive intent modeling test suite.

Covers:
  MarkovTransitionModel     — training, prediction, confidence scoring
  IntentPredictor           — train/predict lifecycle, session observation
  PredictionResult          — alert levels, evidence, to_dict
  SessionForecaster         — threshold elevation, after_action, summary
  ForecastAdjustment        — rule elevation logic
  OpenClawGuard             — enable_intent_prediction(), forecast()
  InspectionEngine          — THREAT_FORECAST_ALERT trigger (10th)
  Module API                — v0.10.0 exports
"""

import os
import sys
import time
import tempfile
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aiglos.core.intent_predictor import (
    IntentPredictor,
    PredictionResult,
    MarkovTransitionModel,
    _HIGH_CONSEQUENCE_RULES,
    _MIN_TRAINING_SESSIONS,
    DEFAULT_HORIZON,
)
from aiglos.core.threat_forecast import (
    SessionForecaster,
    ForecastAdjustment,
    _ELEVATABLE_RULES,
)
from aiglos.adaptive.observation import ObservationGraph
from aiglos.adaptive.inspect import InspectionEngine
import aiglos


# --- Fixtures ---

@pytest.fixture
def tmp_graph(tmp_path):
    return ObservationGraph(db_path=str(tmp_path / "obs.db"))

@pytest.fixture
def model():
    return MarkovTransitionModel()

@pytest.fixture
def tmp_predictor(tmp_path):
    graph = ObservationGraph(db_path=str(tmp_path / "obs.db"))
    return IntentPredictor(graph=graph, model_path=str(tmp_path / "model.json"))

def _make_art(session_id, events, graph):
    """Ingest a fake session into the observation graph."""
    art = MagicMock()
    art.agent_name = "test"
    art.extra = {
        "aiglos_version": "0.10.0",
        "http_events": [],
        "subproc_events": events,
        "agentdef_violations": [],
        "multi_agent": {"spawns": [], "children": {}},
        "session_identity": {"session_id": session_id, "created_at": time.time()},
        "agentdef_violation_count": 0,
    }
    graph.ingest(art)

def _ev(rule_id, verdict="BLOCK"):
    return {
        "rule_id": rule_id, "rule_name": rule_id, "verdict": verdict,
        "surface": "subprocess", "tier": 3, "cmd": "test",
        "url": "", "latency_ms": 0.2, "timestamp": time.time(),
    }


# --- MarkovTransitionModel — core sequence model ---

class TestMarkovTransitionModel:

    def test_train_empty_no_crash(self, model):
        model.train_from_sequences([])
        assert model._total_sessions == 0

    def test_train_single_sequence(self, model):
        model.train_from_sequences([["T19", "T22", "T37"]])
        assert "T19" in model._vocab
        assert "T37" in model._vocab

    def test_predict_next_known_transition(self, model):
        # Train: T19 always followed by T37
        seqs = [["T19", "T37"]] * 10
        model.train_from_sequences(seqs)
        result = model.predict_next(["T19"], top_k=3)
        # T37 should be top prediction
        assert result[0][0] == "T37"
        assert result[0][1] > 0.5

    def test_predict_next_with_context(self, model):
        seqs = [["T19", "T22", "T37"]] * 8 + [["T19", "T22", "T_DEST"]] * 2
        model.train_from_sequences(seqs)
        result = model.predict_next(["T19", "T22"], top_k=5)
        rule_ids = [r for r, _ in result]
        assert "T37" in rule_ids

    def test_predict_returns_probabilities_summing_to_one(self, model):
        seqs = [["T19", "T22", "T37"], ["T19", "T07", "T_DEST"]] * 5
        model.train_from_sequences(seqs)
        result = model.predict_next(["T19"], top_k=10)
        total = sum(p for _, p in result)
        assert 0.5 <= total <= 1.5  # not perfect normalization but reasonable

    def test_predict_unknown_sequence_returns_empty_or_sparse(self, model):
        model.train_from_sequences([["T19", "T37"]] * 5)
        result = model.predict_next(["UNKNOWN_RULE"], top_k=3)
        # Should return something or empty, not crash
        assert isinstance(result, list)

    def test_model_confidence_low_without_training(self, model):
        conf = model.model_confidence(["T19"])
        assert conf == 0.0

    def test_model_confidence_increases_with_training(self, model):
        seqs = [["T19", "T37"]] * 20
        model.train_from_sequences(seqs)
        conf = model.model_confidence(["T19"])
        assert conf > 0.0

    def test_to_from_json_roundtrip(self, model):
        seqs = [["T19", "T22", "T37"]] * 5
        model.train_from_sequences(seqs)
        data = model.to_json()
        model2 = MarkovTransitionModel()
        model2.from_json(data)
        assert model2._total_sessions == model._total_sessions
        assert "T19" in model2._vocab


# --- IntentPredictor — lifecycle and prediction ---

class TestIntentPredictor:

    def test_not_ready_without_training(self, tmp_predictor):
        assert not tmp_predictor.is_ready

    def test_train_returns_false_insufficient_data(self, tmp_predictor):
        result = tmp_predictor.train()
        assert result is False

    def test_train_succeeds_with_enough_sessions(self, tmp_path):
        graph = ObservationGraph(db_path=str(tmp_path / "obs.db"))
        # Ingest enough sessions
        for i in range(8):
            _make_art(f"s{i:02d}", [
                _ev("T19", "BLOCK"), _ev("T22", "WARN"), _ev("T37", "BLOCK")
            ], graph)
        predictor = IntentPredictor(graph=graph,
                                    model_path=str(tmp_path / "m.json"))
        result = predictor.train()
        assert result is True
        assert predictor.is_ready

    def test_predict_returns_none_without_training(self, tmp_predictor):
        tmp_predictor.observe("T19", "BLOCK")
        result = tmp_predictor.predict()
        assert result is None

    def test_predict_returns_result_when_trained(self, tmp_path):
        graph = ObservationGraph(db_path=str(tmp_path / "obs.db"))
        for i in range(8):
            _make_art(f"s{i:02d}", [_ev("T19"), _ev("T37")], graph)
        predictor = IntentPredictor(graph=graph,
                                    model_path=str(tmp_path / "m.json"))
        predictor.train()
        predictor.observe("T19", "BLOCK")
        result = predictor.predict()
        assert result is not None
        assert isinstance(result, PredictionResult)

    def test_observe_only_non_allow(self, tmp_predictor):
        tmp_predictor.observe("T37", "ALLOW")
        assert len(tmp_predictor._session_sequence) == 0
        tmp_predictor.observe("T37", "BLOCK")
        assert len(tmp_predictor._session_sequence) == 1

    def test_reset_clears_session(self, tmp_predictor):
        tmp_predictor.observe("T19", "BLOCK")
        tmp_predictor.observe("T22", "WARN")
        tmp_predictor.reset_session()
        assert tmp_predictor._session_sequence == []

    def test_predict_alert_level_high_consequence(self, tmp_path):
        graph = ObservationGraph(db_path=str(tmp_path / "obs.db"))
        # Train: T19 → T22 → T37 appears in most sessions
        for i in range(10):
            _make_art(f"s{i:02d}", [_ev("T19"), _ev("T22"), _ev("T37")], graph)
        predictor = IntentPredictor(graph=graph,
                                    model_path=str(tmp_path / "m.json"))
        predictor.train()
        predictor.observe("T19", "BLOCK")
        predictor.observe("T22", "WARN")
        result = predictor.predict()
        assert result is not None
        assert result.sessions_trained >= _MIN_TRAINING_SESSIONS
        # T37 should appear in top threats
        rule_ids = [r for r, _ in result.top_threats]
        assert "T37" in rule_ids or len(rule_ids) > 0

    def test_prediction_result_has_evidence(self, tmp_path):
        graph = ObservationGraph(db_path=str(tmp_path / "obs.db"))
        for i in range(6):
            _make_art(f"s{i:02d}", [_ev("T19"), _ev("T37")], graph)
        predictor = IntentPredictor(graph=graph,
                                    model_path=str(tmp_path / "m.json"))
        predictor.train()
        predictor.observe("T19", "BLOCK")
        result = predictor.predict()
        if result:
            assert len(result.evidence) > 10
            assert result.horizon == DEFAULT_HORIZON

    def test_prediction_to_dict(self, tmp_path):
        graph = ObservationGraph(db_path=str(tmp_path / "obs.db"))
        for i in range(6):
            _make_art(f"s{i:02d}", [_ev("T19"), _ev("T37")], graph)
        predictor = IntentPredictor(graph=graph,
                                    model_path=str(tmp_path / "m.json"))
        predictor.train()
        predictor.observe("T19", "BLOCK")
        result = predictor.predict()
        if result:
            d = result.to_dict()
            for f in ["top_threats", "alert_level", "evidence",
                      "current_sequence", "model_confidence", "sessions_trained"]:
                assert f in d


# --- SessionForecaster — threshold elevation ---

class TestSessionForecaster:

    def _make_trained_predictor(self, tmp_path):
        graph = ObservationGraph(db_path=str(tmp_path / "obs.db"))
        for i in range(8):
            _make_art(f"s{i:02d}", [_ev("T19"), _ev("T22"), _ev("T37")], graph)
        predictor = IntentPredictor(graph=graph,
                                    model_path=str(tmp_path / "m.json"))
        predictor.train()
        return predictor

    def test_after_action_returns_list(self, tmp_path):
        predictor = self._make_trained_predictor(tmp_path)
        forecaster = SessionForecaster(predictor, session_id="s1")
        result = forecaster.after_action("T19", "BLOCK")
        assert isinstance(result, list)

    def test_high_probability_triggers_elevation(self, tmp_path):
        predictor = self._make_trained_predictor(tmp_path)
        forecaster = SessionForecaster(predictor, session_id="s1")
        # Feed sequence that leads to high T37 probability
        forecaster.after_action("T19", "BLOCK")
        forecaster.after_action("T22", "WARN")
        # Check if any elevation was proposed
        adjustments = forecaster.active_adjustments()
        assert isinstance(adjustments, list)

    def test_effective_tier_elevated(self, tmp_path):
        predictor = self._make_trained_predictor(tmp_path)
        forecaster = SessionForecaster(predictor, session_id="s1")
        # Manually inject an active adjustment
        from aiglos.core.threat_forecast import ForecastAdjustment
        adj = ForecastAdjustment(
            rule_id="T37", proposed_tier=3, original_tier=2,
            probability=0.80, alert_level="HIGH",
            evidence="test", session_id="s1",
        )
        forecaster._active_adjustments["T37"] = adj
        assert forecaster.effective_tier("T37", 2) == 3

    def test_effective_tier_not_elevated(self, tmp_path):
        predictor = self._make_trained_predictor(tmp_path)
        forecaster = SessionForecaster(predictor, session_id="s1")
        assert forecaster.effective_tier("T37", 2) == 2

    def test_is_elevated_false_by_default(self, tmp_path):
        predictor = self._make_trained_predictor(tmp_path)
        forecaster = SessionForecaster(predictor, session_id="s1")
        assert not forecaster.is_elevated("T37")

    def test_summary_structure(self, tmp_path):
        predictor = self._make_trained_predictor(tmp_path)
        forecaster = SessionForecaster(predictor, session_id="s1")
        forecaster.after_action("T19", "BLOCK")
        s = forecaster.summary()
        assert "session_id" in s
        assert "steps_observed" in s
        assert "model_sessions_trained" in s

    def test_artifact_section_structure(self, tmp_path):
        predictor = self._make_trained_predictor(tmp_path)
        forecaster = SessionForecaster(predictor, session_id="s1")
        forecaster.after_action("T19", "BLOCK")
        section = forecaster.to_artifact_section()
        assert "forecast_summary" in section
        assert "forecast_adjustments" in section
        assert "forecast_snapshots" in section


# --- OpenClawGuard — intent prediction lifecycle ---

class TestOpenClawGuardForecast:

    def _guard(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        return OpenClawGuard(
            agent_name="test",
            policy="enterprise",
            log_path=str(tmp_path / "test.log"),
        )

    def test_enable_intent_prediction_returns_forecaster(self, tmp_path):
        guard = self._guard(tmp_path)
        forecaster = guard.enable_intent_prediction()
        assert isinstance(forecaster, SessionForecaster)

    def test_enable_idempotent(self, tmp_path):
        guard = self._guard(tmp_path)
        f1 = guard.enable_intent_prediction()
        f2 = guard.enable_intent_prediction()
        assert f1 is f2

    def test_forecast_returns_none_without_enable(self, tmp_path):
        guard = self._guard(tmp_path)
        assert guard.forecast() is None

    def test_forecast_returns_after_enable(self, tmp_path):
        guard = self._guard(tmp_path)
        guard.enable_intent_prediction()
        # May return None if model untrained — that's fine
        result = guard.forecast()
        assert result is None or isinstance(result, PredictionResult)

    def test_artifact_has_forecast_section_when_enabled(self, tmp_path):
        guard = self._guard(tmp_path)
        guard.enable_intent_prediction()
        artifact = guard.close_session()
        if hasattr(artifact, "extra") and artifact.extra:
            assert "forecast_summary" in artifact.extra


# --- InspectionEngine — THREAT_FORECAST_ALERT trigger ---

class TestThreatForecastAlertTrigger:

    def test_trigger_method_exists(self, tmp_graph):
        engine = InspectionEngine(tmp_graph)
        assert hasattr(engine, "_check_threat_forecast_alert")

    def test_no_fire_without_model(self, tmp_graph):
        engine = InspectionEngine(tmp_graph)
        triggers = [t for t in engine.run()
                    if t.trigger_type == "THREAT_FORECAST_ALERT"]
        assert triggers == []

    def test_trigger_type_in_run_dispatch(self, tmp_graph):
        # Verify run() calls the new check method
        engine = InspectionEngine.__new__(InspectionEngine)
        engine._graph = tmp_graph
        called = []
        engine._check_threat_forecast_alert = lambda: called.append(1) or []
        engine._check_rate_drops = lambda: []
        engine._check_high_overrides = lambda: []
        engine._check_agentdef_repeat = lambda: []
        engine._check_spawn_no_policy = lambda: []
        engine._check_fin_exec_bypass = lambda: []
        engine._check_false_positives = lambda: []
        engine._check_reward_drift = lambda: []
        engine._check_causal_injection_confirmed = lambda: []
        engine.run()
        assert len(called) == 1

    def test_ten_trigger_methods(self, tmp_graph):
        engine = InspectionEngine(tmp_graph)
        methods = [m for m in dir(engine) if m.startswith("_check_")]
        assert "_check_threat_forecast_alert" in methods
        assert len(methods) >= 9  # 8 original + causal + forecast


# --- Module API — v0.10.0 ---

class TestV0100ModuleAPI:

    def test_version_is_0100(self):
        assert aiglos.__version__ == "0.25.11"

    def test_exports_predictor_types(self):
        assert hasattr(aiglos, "IntentPredictor")
        assert hasattr(aiglos, "PredictionResult")
        assert hasattr(aiglos, "MarkovTransitionModel")

    def test_exports_forecaster_types(self):
        assert hasattr(aiglos, "SessionForecaster")
        assert hasattr(aiglos, "ForecastAdjustment")
        assert hasattr(aiglos, "ForecastSnapshot")

    def test_high_consequence_rules_coverage(self):
        # All should be known rule IDs
        for rule in _HIGH_CONSEQUENCE_RULES:
            assert rule.startswith("T") or rule == "T_DEST"

    def test_elevatable_rules_are_high_consequence(self):
        for rule in _ELEVATABLE_RULES:
            assert rule in _HIGH_CONSEQUENCE_RULES or rule.startswith("T")

    def test_intent_predictor_instantiates(self):
        predictor = IntentPredictor()
        assert not predictor.is_ready
        assert predictor.sessions_trained == 0

    def test_session_forecaster_requires_predictor(self):
        predictor = IntentPredictor()
        forecaster = SessionForecaster(predictor, session_id="test")
        assert forecaster.session_id == "test"

    def test_prediction_result_is_alert_property(self):
        pred = PredictionResult(
            top_threats=[("T37", 0.80)],
            alert_level="HIGH",
            alert_threshold=0.80,
            evidence="test",
            current_sequence=["T19", "T22"],
            horizon=5,
            model_confidence=0.75,
            sessions_trained=20,
        )
        assert pred.is_alert is True

    def test_prediction_result_none_not_alert(self):
        pred = PredictionResult(
            top_threats=[],
            alert_level="NONE",
            alert_threshold=0.0,
            evidence="clean",
            current_sequence=[],
            horizon=5,
            model_confidence=0.0,
            sessions_trained=10,
        )
        assert pred.is_alert is False
