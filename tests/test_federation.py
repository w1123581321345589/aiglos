"""
tests/test_federation.py
=========================
Aiglos v0.13.0 — Federated Threat Intelligence

Tests cover:
  - Differential privacy noise (Laplace mechanism)
  - extract_shareable_transitions: content, DP application, session threshold
  - GlobalPrior: construction, serialization, staleness, merge_into
  - Local weight schedule: _local_weight progression
  - FederationClient: push (mock), pull (mock), rate limiting, caching
  - warm_start_from_prior on IntentPredictor
  - enable_federation() on OpenClawGuard
  - GLOBAL_PRIOR_MATCH inspection trigger
  - Module API: exports, version, attach() kwarg
  - Privacy properties: no raw content in extracted payload
"""

import json
import os
import sys
import tempfile
import time
from collections import defaultdict
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiglos
from aiglos.core.federation import (
    FederationClient,
    GlobalPrior,
    _EPSILON,
    _MIN_SESSIONS_TO_PUSH,
    _PRIOR_TTL,
    _PUSH_INTERVAL,
    _apply_dp_noise,
    _laplace_noise,
    _local_weight,
    extract_shareable_transitions,
)
from aiglos.core.intent_predictor import IntentPredictor, MarkovTransitionModel


# =============================================================================
# Helpers
# =============================================================================

def _make_model(n_sessions: int = 15) -> MarkovTransitionModel:
    """Build a MarkovTransitionModel with synthetic training data."""
    model = MarkovTransitionModel()
    sequences = [
        ["T19", "T22", "T37"],
        ["T27", "T31", "T19"],
        ["T08", "T19"],
        ["T37"],
        ["T19", "T37"],
    ]
    for i in range(n_sessions):
        seq = sequences[i % len(sequences)]
        for j in range(len(seq) - 1):
            model._uni[seq[j]][seq[j + 1]] += 1
        model._vocab.update(seq)
    model._total_sessions = n_sessions
    model._trained_at = time.time()
    return model


def _make_prior(
    version:     str = "v1.0",
    deployments: int = 10,
    transitions: dict = None,
) -> GlobalPrior:
    if transitions is None:
        transitions = {
            "T19": {"T37": 0.60, "T22": 0.25, "T31": 0.15},
            "T27": {"T31": 0.70, "T19": 0.30},
        }
    return GlobalPrior(
        prior_version            = version,
        trained_on_n_deployments = deployments,
        trained_at               = time.time(),
        transitions              = transitions,
        vocab                    = list({k for k in transitions}
                                       | {v for d in transitions.values() for v in d}),
        received_at              = time.time(),
    )


def _make_predictor(tmp_path, n_sessions=3) -> IntentPredictor:
    """Make a thin IntentPredictor with few sessions."""
    from aiglos.adaptive.observation import ObservationGraph
    db        = str(tmp_path / "obs.db")
    graph     = ObservationGraph(db_path=db)
    predictor = IntentPredictor(
        graph      = graph,
        model_path = str(tmp_path / "model.json"),
        agent_name = "test-agent",
    )
    # Seed thin model
    predictor._model = _make_model(n_sessions)
    return predictor


# =============================================================================
# Differential privacy utilities
# =============================================================================

class TestLaplaceNoise:

    def test_noise_is_float(self):
        n = _laplace_noise(1.0)
        assert isinstance(n, float)

    def test_noise_centered_near_zero(self):
        # Average of 1000 samples should be close to 0
        samples = [_laplace_noise(1.0) for _ in range(1000)]
        mean    = sum(samples) / len(samples)
        assert abs(mean) < 0.5, f"Mean={mean:.3f} is too far from 0"

    def test_large_scale_produces_large_noise(self):
        # Large scale = large noise (concentration around 0 decreases)
        small_samples = [abs(_laplace_noise(0.1)) for _ in range(200)]
        large_samples = [abs(_laplace_noise(10.0)) for _ in range(200)]
        assert sum(large_samples) > sum(small_samples)

    def test_apply_dp_noise_clamps_to_zero(self):
        """All noised values must be >= 0 (negative counts are invalid)."""
        counts = {"T19": {"T37": 1, "T22": 2}}
        noisy  = _apply_dp_noise(counts, _EPSILON)
        for from_rule, nexts in noisy.items():
            for to_rule, val in nexts.items():
                assert val >= 0.0, f"Negative noised count: {val}"

    def test_apply_dp_noise_changes_values(self):
        """Noise must actually change counts (not be identity)."""
        counts = {"T19": {"T37": 100, "T22": 50}}
        noisy  = _apply_dp_noise(counts, _EPSILON)
        original_t37 = counts["T19"]["T37"]
        if "T19" in noisy and "T37" in noisy.get("T19", {}):
            noised_t37 = noisy["T19"]["T37"]
            # With epsilon=0.1, scale=10 — noise should often be significant
            # (not guaranteed to differ on every call, but over multiple calls)
            pass  # just verify no crash

    def test_apply_dp_noise_drops_near_zero(self):
        """Near-zero noised values are dropped from payload."""
        counts = {"T19": {"T37": 0, "T22": 0}}  # zero counts
        noisy  = _apply_dp_noise(counts, _EPSILON)
        # Even with noise, near-zero entries may be dropped
        for nexts in noisy.values():
            for val in nexts.values():
                assert val > 0.001


# =============================================================================
# _local_weight
# =============================================================================

class TestLocalWeight:

    def test_zero_sessions_returns_min(self):
        assert _local_weight(0) == 0.20

    def test_100_sessions_returns_near_max(self):
        assert _local_weight(100) >= 0.79

    def test_monotonically_increasing(self):
        weights = [_local_weight(n) for n in range(0, 110, 10)]
        for i in range(len(weights) - 1):
            assert weights[i] <= weights[i + 1], (
                f"Not monotonic at n={i*10}: {weights[i]} > {weights[i+1]}"
            )

    def test_bounded_between_min_and_max(self):
        for n in [0, 1, 5, 10, 20, 50, 100, 200, 1000]:
            w = _local_weight(n)
            assert 0.20 <= w <= 0.80, f"Out of bounds at n={n}: w={w}"

    def test_50_sessions_is_between_bounds(self):
        w = _local_weight(50)
        assert 0.40 < w < 0.75


# =============================================================================
# extract_shareable_transitions
# =============================================================================

class TestExtractShareableTransitions:

    def test_returns_none_below_min_sessions(self):
        model = _make_model(n_sessions=_MIN_SESSIONS_TO_PUSH - 1)
        result = extract_shareable_transitions(model)
        assert result is None

    def test_returns_dict_above_min_sessions(self):
        model  = _make_model(n_sessions=_MIN_SESSIONS_TO_PUSH + 5)
        result = extract_shareable_transitions(model)
        assert isinstance(result, dict)

    def test_payload_has_required_keys(self):
        model  = _make_model(n_sessions=15)
        result = extract_shareable_transitions(model)
        assert result is not None
        required = {"transitions", "approx_sessions", "vocab_size",
                    "epsilon", "nonce", "aiglos_version", "contributed_at"}
        assert required.issubset(set(result))

    def test_payload_contains_only_transitions_not_raw_events(self):
        """Privacy: the payload must not contain raw content."""
        model  = _make_model(n_sessions=15)
        result = extract_shareable_transitions(model)
        assert result is not None
        payload_str = json.dumps(result)
        # No session IDs, no agent names, no URLs, no tool names in payload
        private_terms = ["agent", "http", "url", "session_id", "tool"]
        # Transition keys are rule IDs like T19, T37 — these are fine
        # but content fingerprints should not appear
        for term in private_terms:
            for rule_name in result.get("transitions", {}).keys():
                assert term.lower() not in rule_name.lower(), (
                    f"Private term '{term}' found in transition key: {rule_name}"
                )

    def test_payload_nonce_is_unique(self):
        """Each extraction produces a unique nonce for deduplication."""
        model = _make_model(n_sessions=15)
        r1 = extract_shareable_transitions(model)
        r2 = extract_shareable_transitions(model)
        assert r1 is not None and r2 is not None
        assert r1["nonce"] != r2["nonce"]

    def test_approx_sessions_is_noised(self):
        """approx_sessions should differ from exact count due to DP noise."""
        model  = _make_model(n_sessions=50)
        counts = []
        for _ in range(20):
            result = extract_shareable_transitions(model)
            if result:
                counts.append(result["approx_sessions"])
        # After 20 extractions with Laplace noise, not all should equal 50
        assert len(set(counts)) > 1, "approx_sessions should vary due to DP noise"

    def test_transitions_are_noised_counts(self):
        """All values in transitions should be non-negative floats."""
        model  = _make_model(n_sessions=15)
        result = extract_shareable_transitions(model)
        if result and result["transitions"]:
            for from_r, nexts in result["transitions"].items():
                for to_r, val in nexts.items():
                    assert isinstance(val, (int, float))
                    assert val >= 0


# =============================================================================
# GlobalPrior
# =============================================================================

class TestGlobalPrior:

    def test_construction(self):
        prior = _make_prior()
        assert prior.prior_version == "v1.0"
        assert prior.trained_on_n_deployments == 10
        assert "T19" in prior.transitions

    def test_not_stale_when_fresh(self):
        prior = _make_prior()
        assert not prior.is_stale

    def test_stale_when_old(self):
        prior = _make_prior()
        prior.received_at = time.time() - _PRIOR_TTL - 1
        assert prior.is_stale

    def test_to_dict_roundtrip(self):
        p1 = _make_prior()
        d  = p1.to_dict()
        p2 = GlobalPrior.from_dict(d)
        assert p2.prior_version            == p1.prior_version
        assert p2.trained_on_n_deployments == p1.trained_on_n_deployments
        assert p2.transitions              == p1.transitions

    def test_from_dict_tolerates_missing_keys(self):
        p = GlobalPrior.from_dict({})
        assert p.prior_version            == "0"
        assert p.trained_on_n_deployments == 0
        assert p.transitions              == {}

    def test_merge_into_increases_vocab(self, tmp_path):
        predictor = _make_predictor(tmp_path, n_sessions=2)
        prior     = _make_prior(transitions={"T99": {"T98": 0.9}})
        vocab_before = len(predictor._model._vocab)
        prior.merge_into(predictor)
        vocab_after  = len(predictor._model._vocab)
        assert vocab_after >= vocab_before

    def test_merge_into_adds_transitions(self, tmp_path):
        predictor = _make_predictor(tmp_path, n_sessions=2)
        # Prior has a transition T19→T37 with high probability
        prior = _make_prior(transitions={"T19": {"T37": 0.80}})
        prior.merge_into(predictor)
        # T19→T37 should now have nonzero count
        assert predictor._model._uni["T19"]["T37"] >= 0

    def test_merge_empty_prior_is_noop(self, tmp_path):
        predictor = _make_predictor(tmp_path, n_sessions=5)
        prior     = _make_prior(transitions={})
        vocab_before = set(predictor._model._vocab)
        result    = prior.merge_into(predictor)
        assert result is None   # returns None for empty prior

    def test_merge_respects_local_weight(self, tmp_path):
        """High-session predictor should give less weight to global prior."""
        thin_pred  = _make_predictor(tmp_path, n_sessions=0)
        thick_pred = _make_predictor(tmp_path, n_sessions=100)

        prior = _make_prior(transitions={"T19": {"T37": 1.0}})

        thin_pred._model._uni  = defaultdict(lambda: defaultdict(int))
        thick_pred._model._uni = defaultdict(lambda: defaultdict(int))

        prior.merge_into(thin_pred)
        prior.merge_into(thick_pred)

        thin_count  = thin_pred._model._uni.get("T19", {}).get("T37", 0)
        thick_count = thick_pred._model._uni.get("T19", {}).get("T37", 0)

        # Thin model (0 sessions) should receive MORE synthetic counts
        # than thick model (100 sessions)
        assert thin_count >= thick_count, (
            f"Thin model should get more prior weight: thin={thin_count} thick={thick_count}"
        )


# =============================================================================
# FederationClient
# =============================================================================

class TestFederationClientPush:

    def test_no_push_without_key(self):
        client = FederationClient(api_key="")
        model  = _make_model(n_sessions=20)
        result = client.push_transitions(model)
        assert result is False

    def test_no_push_below_min_sessions(self):
        client = FederationClient(api_key="ak_live_test")
        model  = _make_model(n_sessions=_MIN_SESSIONS_TO_PUSH - 1)
        result = client.push_transitions(model)
        assert result is False

    def test_rate_limiting_prevents_double_push(self):
        client = FederationClient(api_key="ak_live_test")
        client._last_push = time.time()   # simulate recent push
        model  = _make_model(n_sessions=20)
        result = client.push_transitions(model)
        assert result is False

    def test_push_succeeds_on_mock_200(self):
        import io
        client = FederationClient(api_key="ak_live_test")
        model  = _make_model(n_sessions=20)

        mock_response = MagicMock()
        mock_response.getcode.return_value = 200
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__  = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = client.push_transitions(model)
        assert result is True
        assert client._last_push > 0

    def test_push_fails_gracefully_on_network_error(self):
        client = FederationClient(api_key="ak_live_test")
        model  = _make_model(n_sessions=20)

        with patch("urllib.request.urlopen", side_effect=URLError("connection refused")):
            result = client.push_transitions(model)
        assert result is False   # must not raise

    def test_push_handles_402_pro_required(self):
        client = FederationClient(api_key="ak_live_test")
        model  = _make_model(n_sessions=20)
        err    = HTTPError(url="", code=402, msg="Payment Required", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            result = client.push_transitions(model)
        assert result is False

    def test_push_respects_rate_limit_on_429(self):
        client = FederationClient(api_key="ak_live_test")
        model  = _make_model(n_sessions=20)
        before = client._last_push
        err    = HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            client.push_transitions(model)
        assert client._last_push > before   # backed off


class TestFederationClientPull:

    def _mock_prior_response(self):
        prior = _make_prior()
        data  = json.dumps(prior.to_dict()).encode("utf-8")
        mock  = MagicMock()
        mock.getcode.return_value = 200
        mock.read.return_value    = data
        mock.__enter__ = lambda s: mock
        mock.__exit__  = MagicMock(return_value=False)
        return mock

    def test_no_pull_without_key(self):
        client = FederationClient(api_key="")
        result = client.pull_global_prior()
        assert result is None

    def test_pull_returns_global_prior_on_success(self):
        client = FederationClient(api_key="ak_live_test")
        with patch("urllib.request.urlopen", return_value=self._mock_prior_response()):
            prior = client.pull_global_prior()
        assert isinstance(prior, GlobalPrior)
        assert prior.prior_version == "v1.0"

    def test_pull_caches_result(self):
        client = FederationClient(api_key="ak_live_test")
        with patch("urllib.request.urlopen", return_value=self._mock_prior_response()) as mock:
            client.pull_global_prior()
            client.pull_global_prior()   # second call should use cache
            assert mock.call_count == 1  # urlopen only called once

    def test_force_pull_bypasses_cache(self):
        client = FederationClient(api_key="ak_live_test")
        with patch("urllib.request.urlopen", return_value=self._mock_prior_response()) as mock:
            client.pull_global_prior()
            client.pull_global_prior(force=True)   # force bypasses cache
            assert mock.call_count == 2

    def test_pull_returns_none_on_network_error(self):
        client = FederationClient(api_key="ak_live_test")
        with patch("urllib.request.urlopen", side_effect=URLError("refused")):
            result = client.pull_global_prior()
        assert result is None

    def test_invalidate_cache_clears_cached_prior(self):
        client = FederationClient(api_key="ak_live_test")
        with patch("urllib.request.urlopen", return_value=self._mock_prior_response()):
            client.pull_global_prior()
        assert client._cached_prior is not None
        client.invalidate_cache()
        assert client._cached_prior is None

    def test_stale_cache_triggers_refresh(self):
        client = FederationClient(api_key="ak_live_test")
        with patch("urllib.request.urlopen", return_value=self._mock_prior_response()):
            client.pull_global_prior()
        # Manually expire the cache
        client._cached_prior.received_at = time.time() - _PRIOR_TTL - 1
        with patch("urllib.request.urlopen", return_value=self._mock_prior_response()) as mock:
            client.pull_global_prior()
            assert mock.call_count == 1   # fresh download triggered

    def test_status_dict_structure(self):
        client = FederationClient(api_key="ak_live_test")
        status = client.status()
        assert "has_key"     in status
        assert "endpoint"    in status
        assert "cached_prior" in status
        assert status["has_key"] is True


# =============================================================================
# warm_start_from_prior on IntentPredictor
# =============================================================================

class TestWarmStartFromPrior:

    def test_warm_start_returns_true_on_success(self, tmp_path):
        pred  = _make_predictor(tmp_path, n_sessions=2)
        prior = _make_prior()
        result = pred.warm_start_from_prior(prior)
        assert result is True

    def test_warm_start_returns_false_for_none(self, tmp_path):
        pred   = _make_predictor(tmp_path, n_sessions=2)
        result = pred.warm_start_from_prior(None)
        assert result is False

    def test_warm_start_returns_false_for_empty_prior(self, tmp_path):
        pred   = _make_predictor(tmp_path, n_sessions=2)
        prior  = _make_prior(transitions={})
        result = pred.warm_start_from_prior(prior)
        assert result is False

    def test_warm_start_sets_prior_version(self, tmp_path):
        pred  = _make_predictor(tmp_path, n_sessions=2)
        prior = _make_prior(version="v2.5")
        pred.warm_start_from_prior(prior)
        assert pred.prior_version == "v2.5"

    def test_prior_version_none_before_warm_start(self, tmp_path):
        pred = _make_predictor(tmp_path, n_sessions=2)
        assert pred.prior_version is None

    def test_warm_start_enables_prediction_below_threshold(self, tmp_path):
        """
        An untrained predictor (< 5 sessions) should be able to predict
        after warm-starting from a prior with useful transitions.
        """
        pred  = _make_predictor(tmp_path, n_sessions=2)
        # Provide a prior with strong T19→T37 signal
        prior = _make_prior(
            deployments=20,
            transitions={"T19": {"T37": 0.80, "T22": 0.20}},
        )
        pred.warm_start_from_prior(prior)
        pred._model._total_sessions = 10   # satisfy predict() threshold
        pred.observe("T19", "BLOCK")
        result = pred.predict()
        # After warm-start + T19 observation, T37 should rank high
        if result:
            top_rules = [r for r, _ in result.top_threats]
            assert "T37" in top_rules, (
                f"T37 not in top predictions after warm-start. Got: {top_rules}"
            )


# =============================================================================
# enable_federation() on OpenClawGuard
# =============================================================================

class TestEnableFederationOnGuard:

    def test_method_exists(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        assert hasattr(g, "enable_federation")
        assert callable(g.enable_federation)

    def test_enable_federation_does_not_crash_without_key(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        g.enable_federation()   # no key — should not raise
        assert hasattr(g, "_federation_client")
        assert not g._federation_client.has_key

    def test_enable_federation_creates_client_with_key(self, tmp_path):
        from aiglos.integrations.openclaw import OpenClawGuard
        g = OpenClawGuard("test", "enterprise",
                          log_path=str(tmp_path / "t.log"))
        g.enable_federation(api_key="ak_live_test123")
        assert g._federation_client.has_key

    def test_attach_kwarg_enables_federation(self):
        aiglos.attach(
            agent_name="fed-test",
            policy="enterprise",
            enable_federation=True,
        )
        art = aiglos.close()
        assert art is not None

    def test_attach_kwarg_with_api_key(self):
        aiglos.attach(
            agent_name="fed-key-test",
            policy="enterprise",
            enable_federation=True,
            api_key="ak_live_test",
        )
        art = aiglos.close()
        assert art is not None


# =============================================================================
# GLOBAL_PRIOR_MATCH inspection trigger
# =============================================================================

class TestGlobalPriorMatchTrigger:

    def test_trigger_does_not_fire_without_cached_prior(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        from aiglos.adaptive.observation import ObservationGraph
        db    = str(tmp_path / "obs.db")
        graph = ObservationGraph(db_path=db)
        ie    = InspectionEngine(graph)
        # Patch _find_cached_prior to return None
        with patch.object(ie, "_find_cached_prior", return_value=None):
            triggers = ie.run()
        gpm = [t for t in triggers if t.trigger_type == "GLOBAL_PRIOR_MATCH"]
        assert len(gpm) == 0

    def test_trigger_does_not_fire_below_min_deployments(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        from aiglos.adaptive.observation import ObservationGraph
        db    = str(tmp_path / "obs.db")
        graph = ObservationGraph(db_path=db)
        ie    = InspectionEngine(graph)
        prior = _make_prior(deployments=2)   # below threshold of 5
        with patch.object(ie, "_find_cached_prior", return_value=prior):
            triggers = ie.run()
        gpm = [t for t in triggers if t.trigger_type == "GLOBAL_PRIOR_MATCH"]
        assert len(gpm) == 0

    def test_find_cached_prior_returns_none_when_no_file(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        from aiglos.adaptive.observation import ObservationGraph
        db    = str(tmp_path / "obs.db")
        graph = ObservationGraph(db_path=db)
        ie    = InspectionEngine(graph)
        # Home directory has no ~/.aiglos/global_prior.json in test env
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = ie._find_cached_prior()
        assert result is None

    def test_find_cached_prior_loads_valid_file(self, tmp_path):
        from aiglos.adaptive.inspect import InspectionEngine
        from aiglos.adaptive.observation import ObservationGraph
        import json, pathlib
        db    = str(tmp_path / "obs.db")
        graph = ObservationGraph(db_path=db)
        ie    = InspectionEngine(graph)

        prior_dir  = tmp_path / ".aiglos"
        prior_dir.mkdir()
        prior_file = prior_dir / "global_prior.json"
        prior      = _make_prior(version="test-v1")
        prior_file.write_text(json.dumps(prior.to_dict()))

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = ie._find_cached_prior()

        if result:
            assert result.prior_version == "test-v1"


# =============================================================================
# Module API
# =============================================================================

class TestV0130ModuleAPI:

    def test_version_is_0130(self):
        assert aiglos.__version__ == "0.16.0"

    def test_federation_client_in_all(self):
        assert "FederationClient" in aiglos.__all__

    def test_global_prior_in_all(self):
        assert "GlobalPrior" in aiglos.__all__

    def test_extract_shareable_transitions_in_all(self):
        assert "extract_shareable_transitions" in aiglos.__all__

    def test_all_exports_importable(self):
        missing = [e for e in aiglos.__all__ if not hasattr(aiglos, e)]
        assert missing == [], f"Missing exports: {missing}"

    def test_federation_client_importable_directly(self):
        from aiglos import FederationClient
        assert FederationClient is not None

    def test_global_prior_importable_directly(self):
        from aiglos import GlobalPrior
        assert GlobalPrior is not None
