"""
aiglos.core.behavioral_baseline
================================
Per-agent behavioral fingerprinting.

The rule engine knows what generic attacks look like (T01-T39 corpus).
The intent predictor knows what your deployment's attack sequences look like.
Neither knows what *your specific agent* normally does.

This module closes that gap.

After 20+ sessions, Aiglos has enough data in the observation graph to build
a baseline: what tools does this agent call, in what rule-firing frequencies,
at what session event rates, across which surfaces?

Deviation from the baseline is an anomaly signal that is:
  - Orthogonal to per-call rule scoring (catches what rules miss)
  - Orthogonal to campaign-mode (which needs a known attack sequence)
  - Agent-specific (a credential read is normal for a DevOps agent, anomalous
    for a code review agent — the baseline knows which is which)

Three feature spaces, each independently scored:

  1. Rule frequency distribution
     How often does this agent trigger each rule family? Expressed as a
     probability vector over T01-T39 (plus a "none/ALLOW" bucket). Anomaly
     measured as KL-divergence from historical mean distribution.

  2. Session event rate
     Typical: events-per-session, blocked-per-session, warn rate, block rate.
     Anomaly: z-score against rolling statistics from last N sessions.

  3. Surface mix
     Ratio of MCP:HTTP:subprocess events. A coding agent with a sudden shift
     toward HTTP-heavy traffic is anomalous even if no individual call triggers
     a rule. Anomaly: chi-squared against historical surface proportions.

Scoring:
  Each feature space produces a score in [0.0, 1.0]:
    0.0 = perfectly normal
    1.0 = maximum anomaly

  Composite anomaly score: weighted average (rate 40%, surface 30%, rules 30%).
  Threshold: LOW < 0.25, MEDIUM 0.25-0.55, HIGH > 0.55

  The thresholds are intentionally conservative. Behavioral baselines produce
  false positives when agent behavior legitimately changes (new task type,
  new environment). The inspection trigger requires HIGH composite AND
  sustained deviation (not a single anomalous session) before firing.

Minimum data requirements:
  _MIN_SESSIONS_TO_TRAIN = 20   sessions needed before baseline is reliable
  _ROLLING_WINDOW       = 30   sessions used in rolling statistics

Usage:
    from aiglos.core.behavioral_baseline import BaselineEngine

    engine = BaselineEngine(graph, agent_name="my-agent")
    engine.train()            # builds baseline from observation graph history

    # At session close
    result = engine.score_session(session_events, session_stats)
    # BaselineScore(composite=0.72, risk="HIGH", feature_scores={...})
"""


import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("aiglos.behavioral_baseline")

# ── Configuration ─────────────────────────────────────────────────────────────

_MIN_SESSIONS_TO_TRAIN = 20   # need this many sessions before baseline is reliable
_ROLLING_WINDOW        = 30   # sessions used in rolling statistics
_ANOMALY_EPSILON       = 1e-9  # prevent log(0) in KL-divergence

# Weight of each feature space in the composite score
_WEIGHT_RATE    = 0.40
_WEIGHT_SURFACE = 0.30
_WEIGHT_RULES   = 0.30

# Known surfaces
_SURFACES = ("mcp", "http", "subprocess")

# Known rule families (T01-T39 plus sentinel buckets)
_RULE_BUCKETS = [
    "ALLOW",           # clean calls (no rule fired)
    "T19", "T22",      # credential access, privilege
    "T07", "T08",      # shell inject, priv esc
    "T37",             # financial exec
    "T31",             # memory poison
    "T27",             # prompt inject
    "T36_AGENTDEF",    # agent def
    "T38",             # agent spawn
    "T39",             # reward poison
    "OTHER_BLOCK",     # any other block/warn
]


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class SessionStats:
    """Summary statistics for one session, used for baseline comparison."""
    agent_name:     str
    session_id:     str
    total_events:   int
    blocked_events: int
    warned_events:  int
    surface_counts: Dict[str, int]   # mcp/http/subprocess → count
    rule_counts:    Dict[str, int]   # rule_id → count of fires

    @property
    def block_rate(self) -> float:
        if self.total_events == 0:
            return 0.0
        return self.blocked_events / self.total_events

    @property
    def warn_rate(self) -> float:
        if self.total_events == 0:
            return 0.0
        return self.warned_events / self.total_events


@dataclass
class AgentBaseline:
    """
    The statistical fingerprint of a specific agent's normal behavior.
    Built from the last _ROLLING_WINDOW sessions in the observation graph.
    """
    agent_name:          str
    sessions_trained:    int
    trained_at:          float

    # Feature space 1: session event rates
    mean_total_events:   float
    std_total_events:    float
    mean_block_rate:     float
    std_block_rate:      float
    mean_warn_rate:      float
    std_warn_rate:       float

    # Feature space 2: surface mix (normalized to proportions)
    surface_proportions: Dict[str, float]   # mcp/http/subprocess → proportion

    # Feature space 3: rule frequency distribution (normalized)
    rule_distribution:   Dict[str, float]   # rule_bucket → proportion

    # Metadata
    is_ready:            bool = False   # True when sessions_trained >= _MIN_SESSIONS_TO_TRAIN

    def to_dict(self) -> dict:
        return {
            "agent_name":          self.agent_name,
            "sessions_trained":    self.sessions_trained,
            "trained_at":          self.trained_at,
            "mean_total_events":   round(self.mean_total_events, 2),
            "std_total_events":    round(self.std_total_events, 2),
            "mean_block_rate":     round(self.mean_block_rate, 4),
            "std_block_rate":      round(self.std_block_rate, 4),
            "mean_warn_rate":      round(self.mean_warn_rate, 4),
            "std_warn_rate":       round(self.std_warn_rate, 4),
            "surface_proportions": {k: round(v, 4) for k, v in self.surface_proportions.items()},
            "rule_distribution":   {k: round(v, 4) for k, v in self.rule_distribution.items()},
            "is_ready":            self.is_ready,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AgentBaseline":
        return cls(
            agent_name          = d["agent_name"],
            sessions_trained    = d.get("sessions_trained", 0),
            trained_at          = d.get("trained_at", 0.0),
            mean_total_events   = d.get("mean_total_events", 0.0),
            std_total_events    = d.get("std_total_events", 1.0),
            mean_block_rate     = d.get("mean_block_rate", 0.0),
            std_block_rate      = d.get("std_block_rate", 0.1),
            mean_warn_rate      = d.get("mean_warn_rate", 0.0),
            std_warn_rate       = d.get("std_warn_rate", 0.1),
            surface_proportions = d.get("surface_proportions", {}),
            rule_distribution   = d.get("rule_distribution", {}),
            is_ready            = d.get("is_ready", False),
        )


@dataclass
class FeatureScore:
    """Score for one feature space."""
    name:     str
    score:    float     # 0.0-1.0, higher = more anomalous
    detail:   str       # human-readable explanation
    metric:   float     # the raw metric (z-score, KL-divergence, etc.)


@dataclass
class BaselineScore:
    """
    Result of scoring a session against the agent's behavioral baseline.
    Produced at session close.
    """
    agent_name:      str
    session_id:      str
    composite:       float             # 0.0-1.0 weighted composite
    risk:            str               # LOW | MEDIUM | HIGH
    feature_scores:  List[FeatureScore]
    anomalous_features: List[str]      # names of features above threshold
    narrative:       str
    baseline_ready:  bool              # False if not enough training data
    timestamp:       float = field(default_factory=time.time)

    @property
    def is_anomalous(self) -> bool:
        return self.risk in ("MEDIUM", "HIGH")

    def to_dict(self) -> dict:
        return {
            "agent_name":      self.agent_name,
            "session_id":      self.session_id,
            "composite":       round(self.composite, 4),
            "risk":            self.risk,
            "feature_scores":  [
                {"name": f.name, "score": round(f.score, 4),
                 "detail": f.detail, "metric": round(f.metric, 4)}
                for f in self.feature_scores
            ],
            "anomalous_features": self.anomalous_features,
            "narrative":       self.narrative,
            "baseline_ready":  self.baseline_ready,
            "timestamp":       self.timestamp,
        }


# ── Math helpers ──────────────────────────────────────────────────────────────

def _mean_std(values: List[float]) -> Tuple[float, float]:
    """Sample mean and std, returns (0.0, 1.0) if fewer than 2 values."""
    if not values:
        return 0.0, 1.0
    n    = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 1.0
    var  = sum((x - mean) ** 2 for x in values) / (n - 1)
    return mean, max(math.sqrt(var), _ANOMALY_EPSILON)


def _z_score(value: float, mean: float, std: float) -> float:
    """Absolute z-score, capped at 5.0 to prevent extreme values dominating."""
    return min(abs(value - mean) / max(std, _ANOMALY_EPSILON), 5.0)


def _z_to_score(z: float) -> float:
    """Map z-score to [0,1] anomaly score. z=0 → 0.0, z≥3 → 1.0."""
    return min(z / 3.0, 1.0)


def _kl_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
    """
    Symmetric KL-divergence between two probability distributions.
    Both dicts map bucket → probability. Missing keys treated as epsilon.
    Returns value in [0, ∞), capped at 5.0.
    """
    all_keys = set(p) | set(q)
    kl = 0.0
    for k in all_keys:
        pk = max(p.get(k, 0.0), _ANOMALY_EPSILON)
        qk = max(q.get(k, 0.0), _ANOMALY_EPSILON)
        kl += pk * math.log(pk / qk) + qk * math.log(qk / pk)
    return min(kl, 5.0)


def _kl_to_score(kl: float) -> float:
    """Map KL-divergence to [0,1] anomaly score. kl=0 → 0.0, kl≥2 → 1.0."""
    return min(kl / 2.0, 1.0)


def _normalize(counts: Dict[str, float]) -> Dict[str, float]:
    """Normalize a count dict to probability distribution."""
    total = sum(counts.values()) or 1.0
    return {k: v / total for k, v in counts.items()}


def _chi_squared_score(observed: Dict[str, float],
                       expected: Dict[str, float]) -> float:
    """
    Chi-squared test statistic normalized to [0,1].
    Measures divergence of surface mix from historical proportions.
    """
    all_keys = set(observed) | set(expected)
    chi2     = 0.0
    for k in all_keys:
        exp = max(expected.get(k, 0.0), _ANOMALY_EPSILON)
        obs = observed.get(k, 0.0)
        chi2 += (obs - exp) ** 2 / exp
    # Normalize: chi2 with 2 df, 95th percentile ≈ 5.99
    return min(chi2 / 6.0, 1.0)


# ── BaselineEngine ────────────────────────────────────────────────────────────

class BaselineEngine:
    """
    Builds and maintains the behavioral baseline for a specific agent.

    Reads historical session data from the observation graph, computes
    rolling statistics across three feature spaces, and scores new sessions
    against those statistics.

    One BaselineEngine instance per agent. The baseline is re-trained
    automatically when enough new sessions have been ingested since last
    training.
    """

    _RETRAIN_AFTER = 10   # retrain when N new sessions since last train

    def __init__(
        self,
        graph,
        agent_name: str,
        min_sessions: int = _MIN_SESSIONS_TO_TRAIN,
        window:       int = _ROLLING_WINDOW,
    ):
        self._graph       = graph
        self.agent_name   = agent_name
        self.min_sessions = min_sessions
        self.window       = window
        self._baseline:   Optional[AgentBaseline] = None
        self._last_trained_session_count = 0

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, force: bool = False) -> bool:
        """
        Build the baseline from observation graph history.
        Returns True if baseline is ready (min_sessions met).
        """
        # Check if we have a recent enough baseline already
        if not force and self._baseline and self._baseline.is_ready:
            current = self._graph.agent_session_count(self.agent_name)
            if current - self._last_trained_session_count < self._RETRAIN_AFTER:
                return True

        session_stats = self._load_session_stats()

        if len(session_stats) < self.min_sessions:
            log.debug(
                "[BaselineEngine] Insufficient data for %s: %d sessions (need %d)",
                self.agent_name, len(session_stats), self.min_sessions,
            )
            self._baseline = self._empty_baseline(len(session_stats))
            return False

        self._baseline = self._compute_baseline(session_stats[-self.window:])
        self._last_trained_session_count = len(session_stats)
        log.info(
            "[BaselineEngine] Baseline trained for %s: %d sessions",
            self.agent_name, self._baseline.sessions_trained,
        )
        return True

    def _load_session_stats(self) -> List[SessionStats]:
        """Load historical session statistics from the observation graph."""
        try:
            return self._graph.get_agent_session_stats(
                self.agent_name, limit=self.window * 3
            )
        except Exception as e:
            log.debug("[BaselineEngine] Load error: %s", e)
            return []

    def _compute_baseline(self, sessions: List[SessionStats]) -> AgentBaseline:
        """Compute the baseline from a list of SessionStats."""
        n = len(sessions)

        # Feature space 1: event rates
        totals      = [s.total_events for s in sessions]
        block_rates = [s.block_rate for s in sessions]
        warn_rates  = [s.warn_rate for s in sessions]

        mean_tot, std_tot     = _mean_std(totals)
        mean_blk, std_blk     = _mean_std(block_rates)
        mean_wrn, std_wrn     = _mean_std(warn_rates)

        # Feature space 2: surface mix
        surface_totals: Dict[str, float] = {s: 0.0 for s in _SURFACES}
        for sess in sessions:
            for surf, count in sess.surface_counts.items():
                if surf in surface_totals:
                    surface_totals[surf] += count
        surface_props = _normalize(surface_totals)

        # Feature space 3: rule frequency distribution
        rule_totals: Dict[str, float] = {b: 0.0 for b in _RULE_BUCKETS}
        for sess in sessions:
            for rule_id, count in sess.rule_counts.items():
                bucket = rule_id if rule_id in rule_totals else "OTHER_BLOCK"
                rule_totals[bucket] += count
            # Add ALLOW count: total events minus blocked/warned
            allow = max(0, sess.total_events - sess.blocked_events - sess.warned_events)
            rule_totals["ALLOW"] = rule_totals.get("ALLOW", 0.0) + allow
        rule_dist = _normalize(rule_totals)

        return AgentBaseline(
            agent_name          = self.agent_name,
            sessions_trained    = n,
            trained_at          = time.time(),
            mean_total_events   = mean_tot,
            std_total_events    = std_tot,
            mean_block_rate     = mean_blk,
            std_block_rate      = std_blk,
            mean_warn_rate      = mean_wrn,
            std_warn_rate       = std_wrn,
            surface_proportions = surface_props,
            rule_distribution   = rule_dist,
            is_ready            = n >= self.min_sessions,
        )

    def _empty_baseline(self, n: int) -> AgentBaseline:
        return AgentBaseline(
            agent_name          = self.agent_name,
            sessions_trained    = n,
            trained_at          = time.time(),
            mean_total_events   = 0.0,
            std_total_events    = 1.0,
            mean_block_rate     = 0.0,
            std_block_rate      = 0.1,
            mean_warn_rate      = 0.0,
            std_warn_rate       = 0.1,
            surface_proportions = {s: 1/3 for s in _SURFACES},
            rule_distribution   = {b: 1/len(_RULE_BUCKETS) for b in _RULE_BUCKETS},
            is_ready            = False,
        )

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score_session(
        self,
        session_stats: SessionStats,
    ) -> BaselineScore:
        """
        Score a completed session against the agent's behavioral baseline.
        Call this at session close.

        Returns BaselineScore with composite anomaly score and per-feature
        breakdown. If baseline not ready, returns a LOW-risk result with
        baseline_ready=False.
        """
        if not self._baseline or not self._baseline.is_ready:
            return BaselineScore(
                agent_name         = self.agent_name,
                session_id         = session_stats.session_id,
                composite          = 0.0,
                risk               = "LOW",
                feature_scores     = [],
                anomalous_features = [],
                narrative          = (
                    f"Baseline not ready for {self.agent_name} "
                    f"({self._baseline.sessions_trained if self._baseline else 0}"
                    f"/{self.min_sessions} sessions). No anomaly scoring yet."
                ),
                baseline_ready     = False,
            )

        b = self._baseline
        feature_scores: List[FeatureScore] = []

        # ── Feature 1: event rate anomaly ─────────────────────────────────────
        z_total = _z_score(session_stats.total_events, b.mean_total_events, b.std_total_events)
        z_blk   = _z_score(session_stats.block_rate,   b.mean_block_rate,   b.std_block_rate)
        z_wrn   = _z_score(session_stats.warn_rate,    b.mean_warn_rate,    b.std_warn_rate)
        rate_z  = max(z_total, z_blk, z_wrn)
        rate_sc = _z_to_score(rate_z)

        dominant = "total_events" if z_total == rate_z else (
            "block_rate" if z_blk == rate_z else "warn_rate"
        )
        feature_scores.append(FeatureScore(
            name   = "event_rate",
            score  = rate_sc,
            detail = (
                f"{dominant} z-score={rate_z:.2f} "
                f"(total={session_stats.total_events} vs baseline "
                f"μ={b.mean_total_events:.1f}±{b.std_total_events:.1f}, "
                f"block_rate={session_stats.block_rate:.3f} vs μ={b.mean_block_rate:.3f})"
            ),
            metric = rate_z,
        ))

        # ── Feature 2: surface mix anomaly ────────────────────────────────────
        session_surf_props = _normalize(dict(session_stats.surface_counts))
        surf_chi2_sc = _chi_squared_score(session_surf_props, b.surface_proportions)
        feature_scores.append(FeatureScore(
            name   = "surface_mix",
            score  = surf_chi2_sc,
            detail = (
                f"Surface chi²={surf_chi2_sc*6:.2f} "
                f"(session={session_surf_props} vs baseline={b.surface_proportions})"
            ),
            metric = surf_chi2_sc * 6.0,
        ))

        # ── Feature 3: rule distribution anomaly ──────────────────────────────
        session_rule_counts: Dict[str, float] = {b_name: 0.0 for b_name in _RULE_BUCKETS}
        for rule_id, count in session_stats.rule_counts.items():
            bucket = rule_id if rule_id in session_rule_counts else "OTHER_BLOCK"
            session_rule_counts[bucket] += count
        allow_count = max(0, session_stats.total_events
                         - session_stats.blocked_events - session_stats.warned_events)
        session_rule_counts["ALLOW"] = allow_count
        session_rule_dist = _normalize(session_rule_counts)

        kl  = _kl_divergence(session_rule_dist, b.rule_distribution)
        kl_sc = _kl_to_score(kl)
        feature_scores.append(FeatureScore(
            name   = "rule_distribution",
            score  = kl_sc,
            detail = f"KL-divergence={kl:.3f} (session rule mix vs historical baseline)",
            metric = kl,
        ))

        # ── Composite score ────────────────────────────────────────────────────
        composite = (
            _WEIGHT_RATE    * rate_sc +
            _WEIGHT_SURFACE * surf_chi2_sc +
            _WEIGHT_RULES   * kl_sc
        )
        composite = round(min(composite, 1.0), 4)

        if composite >= 0.55:
            risk = "HIGH"
        elif composite >= 0.25:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        anomalous = [
            f.name for f in feature_scores if f.score >= 0.40
        ]

        # Build narrative
        if not anomalous:
            narrative = (
                f"Session behavior for {self.agent_name} is within normal range "
                f"across all three feature spaces (composite={composite:.2f})."
            )
        else:
            parts = []
            for f in feature_scores:
                if f.score >= 0.40:
                    parts.append(f"{f.name} ({f.detail})")
            narrative = (
                f"{risk} behavioral anomaly for {self.agent_name}: "
                f"composite score {composite:.2f} across {len(anomalous)} feature(s). "
                f"Anomalous: {'; '.join(parts)}"
            )

        return BaselineScore(
            agent_name         = self.agent_name,
            session_id         = session_stats.session_id,
            composite          = composite,
            risk               = risk,
            feature_scores     = feature_scores,
            anomalous_features = anomalous,
            narrative          = narrative,
            baseline_ready     = True,
        )

    @property
    def baseline(self) -> Optional[AgentBaseline]:
        return self._baseline

    @property
    def is_ready(self) -> bool:
        return self._baseline is not None and self._baseline.is_ready

    def to_artifact_section(self, score: BaselineScore) -> dict:
        return {
            "behavioral_baseline": {
                "score":    score.to_dict(),
                "baseline": self._baseline.to_dict() if self._baseline else None,
            }
        }
