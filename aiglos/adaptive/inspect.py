"""
aiglos.adaptive.inspect
========================
Phase 2: Inspection triggers — automated conditions that surface rules,
agent definitions, and deployment patterns that need attention.

An inspection trigger fires when the observation graph contains enough
evidence that something is wrong, degrading, or needs calibration.
Triggers are non-blocking: they surface findings, they do not change anything.
The amendment engine (Phase 4) acts on trigger findings.

Trigger types:
  RATE_DROP        — rule firing rate dropped >40% from 30-session baseline
  ZERO_FIRE        — rule has gone silent after being active
  HIGH_OVERRIDE    — T3 operations being consistently webhook-approved
  AGENTDEF_REPEAT  — same agent def path modified across multiple sessions
  SPAWN_NO_POLICY  — child agents spawning with no inherited policy
  FIN_EXEC_BYPASS  — T37 overrides accumulating on specific hosts
  FALSE_POSITIVE   — rule firing but consistently not blocking (high warn rate)

Usage:
    from aiglos.adaptive.inspect import InspectionEngine

    engine = InspectionEngine(graph)
    triggers = engine.run()
    for t in triggers:
        print(t.trigger_type, t.rule_id, t.evidence_summary)
"""


import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("aiglos.adaptive.inspect")


@dataclass
class InspectionTrigger:
    trigger_type:     str
    rule_id:          Optional[str]
    severity:         str             # HIGH | MEDIUM | LOW
    evidence_summary: str
    evidence_data:    dict = field(default_factory=dict)
    fired_at:         float = field(default_factory=time.time)
    amendment_candidate: bool = False  # True if Phase 4 should act on this

    def to_dict(self) -> dict:
        return {
            "trigger_type":      self.trigger_type,
            "rule_id":           self.rule_id,
            "severity":          self.severity,
            "evidence_summary":  self.evidence_summary,
            "evidence_data":     self.evidence_data,
            "fired_at":          self.fired_at,
            "amendment_candidate": self.amendment_candidate,
        }


class InspectionEngine:
    """
    Runs all inspection trigger checks against an ObservationGraph.

    Designed to run at session close or on a periodic schedule.
    Each check is independent and safe to run in any order.
    """

    # Thresholds — tunable via constructor kwargs
    RATE_DROP_THRESHOLD    = 0.40   # 40% drop triggers RATE_DROP
    HIGH_OVERRIDE_MIN      = 3      # N consecutive approvals triggers HIGH_OVERRIDE
    AGENTDEF_REPEAT_MIN    = 2      # N cross-session violations triggers AGENTDEF_REPEAT
    SPAWN_NO_POLICY_MIN    = 3      # N policy-gap spawns triggers SPAWN_NO_POLICY
    FIN_BYPASS_MIN         = 3      # N T37 overrides triggers FIN_EXEC_BYPASS
    FALSE_POSITIVE_WARN_RATE = 0.60 # >60% warns (not blocks) triggers FALSE_POSITIVE
    MIN_SESSIONS_FOR_BASELINE = 5   # don't trigger RATE_DROP until N sessions seen

    def __init__(self, graph, **kwargs):
        self._graph = graph
        for k, v in kwargs.items():
            setattr(self, k.upper(), v)

    def run(self) -> List[InspectionTrigger]:
        """Run all inspection checks. Returns list of fired triggers."""
        triggers: List[InspectionTrigger] = []
        triggers.extend(self._check_rate_drops())
        triggers.extend(self._check_high_overrides())
        triggers.extend(self._check_agentdef_repeat())
        triggers.extend(self._check_spawn_no_policy())
        triggers.extend(self._check_fin_exec_bypass())
        triggers.extend(self._check_false_positives())
        triggers.extend(self._check_reward_drift())
        triggers.extend(self._check_causal_injection_confirmed())
        triggers.extend(self._check_threat_forecast_alert())
        triggers.extend(self._check_behavioral_anomaly())
        triggers.extend(self._check_repeated_tier3())
        triggers.extend(self._check_global_prior_match())
        triggers.extend(self._check_unverified_rules())
        triggers.extend(self._check_shared_context_anomaly())
        log.info("[InspectionEngine] %d trigger(s) fired.", len(triggers))
        return triggers

    # ── Rate drop ──────────────────────────────────────────────────────────────

    def _check_rate_drops(self) -> List[InspectionTrigger]:
        """Detect rules whose firing rate has dropped significantly."""
        triggers = []
        all_stats = self._graph.all_rule_stats()
        total_sessions = self._graph.session_count()

        for stats in all_stats:
            if stats.sessions_seen < self.MIN_SESSIONS_FOR_BASELINE:
                continue
            avg_per_session = stats.fires_total / stats.sessions_seen
            if avg_per_session < 0.01:
                continue  # essentially never fired, skip

            # Get recent firing rate (last 5 sessions vs historical)
            recent = self._recent_rule_rate(stats.rule_id, window=5)
            if recent is None:
                continue
            if stats.fires_total == 0:
                continue

            drop = 1.0 - (recent / avg_per_session)
            if drop >= self.RATE_DROP_THRESHOLD:
                if recent == 0:
                    triggers.append(InspectionTrigger(
                        trigger_type="ZERO_FIRE",
                        rule_id=stats.rule_id,
                        severity="HIGH",
                        evidence_summary=(
                            f"{stats.rule_id} has gone silent. Historical avg "
                            f"{avg_per_session:.2f} fires/session, zero in last 5 sessions. "
                            "Environment may have changed, or attack pattern shifted."
                        ),
                        evidence_data={
                            "historical_avg": round(avg_per_session, 4),
                            "recent_avg":     0,
                            "sessions_seen":  stats.sessions_seen,
                        },
                        amendment_candidate=False,
                    ))
                else:
                    triggers.append(InspectionTrigger(
                        trigger_type="RATE_DROP",
                        rule_id=stats.rule_id,
                        severity="MEDIUM",
                        evidence_summary=(
                            f"{stats.rule_id} firing rate dropped {drop*100:.0f}% from baseline. "
                            f"Historical avg {avg_per_session:.2f}/session, "
                            f"recent {recent:.2f}/session."
                        ),
                        evidence_data={
                            "historical_avg": round(avg_per_session, 4),
                            "recent_avg":     round(recent, 4),
                            "drop_pct":       round(drop * 100, 1),
                        },
                        amendment_candidate=False,
                    ))
        return triggers

    def _recent_rule_rate(self, rule_id: str, window: int = 5) -> Optional[float]:
        """Average firing rate in the most recent N sessions."""
        try:
            events = self._graph.events_for_rule(rule_id, limit=window * 10)
            recent_sessions = {e["session_id"] for e in events[:window * 5]}
            total_sessions = self._graph.session_count()
            if total_sessions < window:
                return None
            count = sum(1 for e in events if e["session_id"] in recent_sessions)
            return count / max(len(recent_sessions), 1)
        except Exception:
            return None

    # ── High override rate ─────────────────────────────────────────────────────

    def _check_high_overrides(self) -> List[InspectionTrigger]:
        """
        Detect Tier 3 operations that are consistently being approved via webhook.
        Candidate for Tier 2 reclassification in this deployment.
        """
        triggers = []
        try:
            warn_rules = [
                s for s in self._graph.all_rule_stats()
                if s.warns_total >= self.HIGH_OVERRIDE_MIN
                and s.fires_total > 0
                and (s.warns_total / s.fires_total) > 0.5
            ]
            for stats in warn_rules:
                triggers.append(InspectionTrigger(
                    trigger_type="HIGH_OVERRIDE",
                    rule_id=stats.rule_id,
                    severity="MEDIUM",
                    evidence_summary=(
                        f"{stats.rule_id} has been overridden (WARN/approved) "
                        f"{stats.warns_total} times out of {stats.fires_total} fires. "
                        "Candidate for allow-list amendment or tier reclassification."
                    ),
                    evidence_data={
                        "warns_total":  stats.warns_total,
                        "fires_total":  stats.fires_total,
                        "override_rate": round(stats.override_rate, 4),
                    },
                    amendment_candidate=True,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] high_override check error: %s", e)
        return triggers

    # ── Agent def repeat violations ────────────────────────────────────────────

    def _check_agentdef_repeat(self) -> List[InspectionTrigger]:
        """
        Detect agent definition paths that have been modified across multiple sessions.
        Repeated cross-session violations on the same path indicate a persistent
        adversarial modification pattern or an unreviewed supply chain change.
        """
        triggers = []
        try:
            violations = self._graph.agentdef_violations_for_path.__func__ if False else None
            # Query all agentdef observations with violations, group by path_hash
            import sqlite3
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT path_hash, path_preview, COUNT(DISTINCT session_id) as sessions,
                           COUNT(*) as total, MAX(semantic_risk) as max_risk
                    FROM agentdef_observations
                    WHERE violation_type IS NOT NULL
                    GROUP BY path_hash
                    HAVING sessions >= ?
                """, (self.AGENTDEF_REPEAT_MIN,)).fetchall()

            for row in rows:
                triggers.append(InspectionTrigger(
                    trigger_type="AGENTDEF_REPEAT",
                    rule_id="T36_AGENTDEF",
                    severity="HIGH" if row["max_risk"] == "HIGH" else "MEDIUM",
                    evidence_summary=(
                        f"Agent definition path '...{row['path_preview']}' "
                        f"modified in {row['sessions']} sessions "
                        f"({row['total']} total violations). "
                        f"Highest semantic risk: {row['max_risk'] or 'unscored'}."
                    ),
                    evidence_data={
                        "path_hash":    row["path_hash"],
                        "path_preview": row["path_preview"],
                        "sessions":     row["sessions"],
                        "total":        row["total"],
                        "max_risk":     row["max_risk"],
                    },
                    amendment_candidate=False,  # requires human review
                ))
        except Exception as e:
            log.debug("[InspectionEngine] agentdef_repeat check error: %s", e)
        return triggers

    # ── Spawn without policy propagation ──────────────────────────────────────

    def _check_spawn_no_policy(self) -> List[InspectionTrigger]:
        """
        Detect child agents that have spawned without inheriting the parent's policy.
        These children start from global defaults and may permit operations the
        parent fleet has learned to restrict.
        """
        triggers = []
        try:
            with self._graph._conn() as conn:
                row = conn.execute("""
                    SELECT COUNT(*) as c, COUNT(DISTINCT agent_name) as agents
                    FROM spawn_events WHERE policy_propagated=0
                """).fetchone()
            if row and row["c"] >= self.SPAWN_NO_POLICY_MIN:
                triggers.append(InspectionTrigger(
                    trigger_type="SPAWN_NO_POLICY",
                    rule_id="T38",
                    severity="MEDIUM",
                    evidence_summary=(
                        f"{row['c']} child agent spawns detected with no inherited policy "
                        f"across {row['agents']} agent type(s). "
                        "These children start from global defaults. "
                        "Enable policy inheritance in aiglos.attach()."
                    ),
                    evidence_data={
                        "spawn_count_no_policy": row["c"],
                        "agent_types":           row["agents"],
                    },
                    amendment_candidate=True,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] spawn_no_policy check error: %s", e)
        return triggers

    # ── T37 FIN_EXEC bypass accumulation ──────────────────────────────────────

    def _check_fin_exec_bypass(self) -> List[InspectionTrigger]:
        """
        Detect T37 financial execution blocks that are being repeatedly allowed
        via the allow_http list. Indicates the deployment legitimately needs
        certain financial endpoints and should have a targeted amendment.
        """
        triggers = []
        try:
            stats = self._graph.rule_stats("T37")
            if stats.warns_total >= self.FIN_BYPASS_MIN:
                triggers.append(InspectionTrigger(
                    trigger_type="FIN_EXEC_BYPASS",
                    rule_id="T37",
                    severity="MEDIUM",
                    evidence_summary=(
                        f"T37 FIN_EXEC has been bypassed {stats.warns_total} times. "
                        "Review which financial endpoints this deployment legitimately calls "
                        "and add them explicitly to allow_http."
                    ),
                    evidence_data={
                        "warns_total":  stats.warns_total,
                        "blocks_total": stats.blocks_total,
                        "fires_total":  stats.fires_total,
                    },
                    amendment_candidate=True,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] fin_exec_bypass check error: %s", e)
        return triggers

    # ── False positive detection ───────────────────────────────────────────────

    def _check_false_positives(self) -> List[InspectionTrigger]:
        """
        Detect rules with high warn rates relative to block rates.
        High warn rate = the rule fires but rarely results in a hard block,
        suggesting it may be over-triggering on legitimate operations.
        """
        triggers = []
        all_stats = self._graph.all_rule_stats()
        for stats in all_stats:
            if stats.fires_total < 10:
                continue
            warn_rate = stats.warns_total / stats.fires_total
            if warn_rate >= self.FALSE_POSITIVE_WARN_RATE:
                triggers.append(InspectionTrigger(
                    trigger_type="FALSE_POSITIVE",
                    rule_id=stats.rule_id,
                    severity="LOW",
                    evidence_summary=(
                        f"{stats.rule_id} fires {stats.fires_total} times but "
                        f"{warn_rate*100:.0f}% result in WARNs rather than BLOCKs. "
                        "Rule may be over-triggering. Consider tightening the pattern."
                    ),
                    evidence_data={
                        "fires_total":  stats.fires_total,
                        "warns_total":  stats.warns_total,
                        "blocks_total": stats.blocks_total,
                        "warn_rate":    round(warn_rate, 4),
                    },
                    amendment_candidate=True,
                ))
        return triggers

    # ── Reward drift ───────────────────────────────────────────────────────────

    REWARD_DRIFT_MIN_SIGNALS = 5    # need at least N signals to check drift
    REWARD_DRIFT_THRESHOLD   = 0.40 # positive reward for blocked ops above this rate

    def _check_reward_drift(self) -> List[InspectionTrigger]:
        """
        Detect when reward signals for security-relevant operations shift
        toward positive — indicating possible reward poisoning in an RL loop.

        Fires REWARD_DRIFT when:
        - Claimed rewards for operations Aiglos blocked are trending positive
        - T39 fires are accumulating (OPD injection in feedback text)
        - Reward signal quarantine rate exceeds threshold
        """
        triggers = []
        try:
            stats = self._graph.reward_signal_stats()
            total = stats.get("total_signals", 0)
            if total < self.REWARD_DRIFT_MIN_SIGNALS:
                return []

            quarantine_rate = stats.get("quarantined", 0) / total
            if quarantine_rate >= self.REWARD_DRIFT_THRESHOLD:
                triggers.append(InspectionTrigger(
                    trigger_type="REWARD_DRIFT",
                    rule_id="T39",
                    severity="HIGH",
                    evidence_summary=(
                        f"RL reward signals: {quarantine_rate*100:.0f}% of signals "
                        f"({stats.get('quarantined',0)}/{total}) were quarantined as "
                        "T39 REWARD_POISON or OPD_INJECTION. The RL training loop "
                        "is receiving systematically manipulated feedback."
                    ),
                    evidence_data={
                        "total_signals":    total,
                        "quarantined":      stats.get("quarantined", 0),
                        "quarantine_rate":  round(quarantine_rate, 4),
                        "t39_fires":        stats.get("t39_fires", 0),
                        "high_risk_opd":    stats.get("high_risk_opd", 0),
                    },
                    amendment_candidate=False,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] reward_drift check error: %s", e)
        return triggers

    # ── Causal injection confirmed ─────────────────────────────────────────────

    CAUSAL_MIN_SESSIONS = 2    # need at least N sessions with tracing data
    CAUSAL_CONF_THRESHOLD = 1  # fire if ANY session has a confirmed high-conf attribution

    def _check_causal_injection_confirmed(self) -> List[InspectionTrigger]:
        """
        Fire when causal attribution has confirmed a HIGH-confidence
        injection-to-action chain in one or more sessions.

        This is the highest-severity trigger — it means the observation graph
        contains evidence that a specific blocked action was caused by a
        specific injection source. This is not a suspicion; it is a traced
        attack chain.
        """
        triggers = []
        try:
            stats = self._graph.causal_stats()
            if stats.get("sessions_with_tracing", 0) < self.CAUSAL_MIN_SESSIONS:
                return []

            attacks = stats.get("attacks_confirmed", 0)
            high_conf = stats.get("high_conf_attributions", 0)

            if attacks >= 1 or high_conf >= self.CAUSAL_CONF_THRESHOLD:
                triggers.append(InspectionTrigger(
                    trigger_type="CAUSAL_INJECTION_CONFIRMED",
                    rule_id="T27",
                    severity="HIGH",
                    evidence_summary=(
                        f"Causal attribution has confirmed {high_conf} HIGH-confidence "
                        f"injection-to-action chain(s) across {stats.get('sessions_with_tracing',0)} "
                        f"traced sessions. {attacks} session(s) classified as ATTACK_CONFIRMED. "
                        "A specific blocked action has been traced to a specific injection source. "
                        "Run `python -m aiglos trace <session-id>` for the full investigation report."
                    ),
                    evidence_data={
                        "sessions_with_tracing": stats.get("sessions_with_tracing", 0),
                        "high_conf_attributions": high_conf,
                        "attacks_confirmed":      attacks,
                        "suspicious_sessions":    stats.get("suspicious_sessions", 0),
                        "total_attributed":       stats.get("total_attributed", 0),
                    },
                    amendment_candidate=False,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] causal_injection check error: %s", e)
        return triggers

    # ── Threat forecast alert ──────────────────────────────────────────────────

    FORECAST_MIN_SESSIONS_TRAINED = 5

    def _check_threat_forecast_alert(self) -> List[InspectionTrigger]:
        """
        Fire when the intent predictor has accumulated enough data to make
        reliable predictions AND is currently forecasting HIGH or CRITICAL
        probability of a high-consequence action in recent sessions.

        This trigger bridges the predictive layer into the inspection engine,
        surfacing when deployment-specific patterns suggest an imminent attack
        even before any rule has fired in the current session.
        """
        triggers = []
        try:
            from aiglos.core.intent_predictor import IntentPredictor, DEFAULT_MODEL_PATH
            import json as _json
            from pathlib import Path

            model_path = Path(DEFAULT_MODEL_PATH)
            if not model_path.exists():
                return []

            with open(model_path) as f:
                model_data = _json.load(f)

            sessions_trained = model_data.get("total_sessions", 0)
            if sessions_trained < self.FORECAST_MIN_SESSIONS_TRAINED:
                return []

            # Load predictor and check recent session patterns
            predictor = IntentPredictor(self._graph)
            predictor.train()

            if not predictor.is_ready:
                return []

            # Check observation graph for recent high-risk sequences
            with self._graph._conn() as conn:
                recent_events = conn.execute("""
                    SELECT session_id, rule_id FROM events
                    WHERE verdict != 'ALLOW'
                    AND timestamp > (SELECT MAX(timestamp) - 86400 FROM events)
                    ORDER BY session_id, timestamp ASC
                """).fetchall()

            if not recent_events:
                return []

            # Group by session and run prediction on each
            from collections import defaultdict
            session_seqs: dict = defaultdict(list)
            for row in recent_events:
                if row["rule_id"] not in ("none", ""):
                    session_seqs[row["session_id"]].append(row["rule_id"])

            high_forecast_sessions = []
            for sid, seq in session_seqs.items():
                if len(seq) < 2:
                    continue
                predictor.reset_session()
                for rule in seq[:-1]:  # feed all but last as context
                    predictor.observe(rule, "BLOCK")
                pred = predictor.predict()
                if pred and pred.alert_level in ("HIGH", "CRITICAL"):
                    high_forecast_sessions.append({
                        "session_id": sid,
                        "alert_level": pred.alert_level,
                        "top_threat": pred.top_threats[0] if pred.top_threats else None,
                        "evidence": pred.evidence,
                    })

            if high_forecast_sessions:
                top = high_forecast_sessions[0]
                top_threat_str = (
                    f"{top['top_threat'][0]} ({top['top_threat'][1]:.0%})"
                    if top["top_threat"] else "unknown"
                )
                triggers.append(InspectionTrigger(
                    trigger_type="THREAT_FORECAST_ALERT",
                    rule_id="T06",
                    severity="HIGH",
                    evidence_summary=(
                        f"Intent predictor (trained on {sessions_trained} sessions) "
                        f"forecasts {top['alert_level']} probability of "
                        f"{top_threat_str} in {len(high_forecast_sessions)} recent "
                        f"session(s). Deployment-specific sequence patterns indicate "
                        f"likely imminent high-consequence action. "
                        f"Run `python -m aiglos forecast` for probability breakdown."
                    ),
                    evidence_data={
                        "sessions_trained":        sessions_trained,
                        "high_forecast_sessions":  len(high_forecast_sessions),
                        "sessions":                high_forecast_sessions[:3],
                    },
                    amendment_candidate=False,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] threat_forecast check error: %s", e)
        return triggers
    # ── Behavioral anomaly ────────────────────────────────────────────────────

    BEHAVIORAL_MIN_SESSIONS    = 20   # baseline must be ready before trigger fires
    BEHAVIORAL_HIGH_THRESHOLD  = 0.55  # composite score for HIGH anomaly
    BEHAVIORAL_SUSTAINED_COUNT = 2    # need N anomalous sessions before trigger fires

    def _check_behavioral_anomaly(self) -> List[InspectionTrigger]:
        """
        Fire when recent sessions show sustained behavioral deviation from
        the agent's historical baseline.

        Sustained = _BEHAVIORAL_SUSTAINED_COUNT consecutive HIGH-anomaly
        sessions, or 3+ MEDIUM sessions in the last 10 sessions.

        Amendment candidate: True — deviation may reflect legitimate new
        behavior (new task type, new environment) that should update the baseline.
        """
        triggers = []
        try:
            baseline_stats = self._graph.baseline_anomaly_stats()
            if baseline_stats.get("agents_ready", 0) == 0:
                return []

            # Check each agent with a ready baseline
            for agent_info in baseline_stats.get("agents", []):
                if agent_info.get("sessions_trained", 0) < self.BEHAVIORAL_MIN_SESSIONS:
                    continue

                agent_name = agent_info["agent_name"]

                # Load recent session stats and score against baseline
                from aiglos.core.behavioral_baseline import BaselineEngine
                engine = BaselineEngine(self._graph, agent_name)
                if not engine.train():
                    continue

                recent_stats = self._graph.get_agent_session_stats(agent_name, limit=10)
                if not recent_stats:
                    continue

                high_count   = 0
                medium_count = 0
                top_score    = None

                for sess_stat in recent_stats[-10:]:
                    score = engine.score_session(sess_stat)
                    if score.risk == "HIGH":
                        high_count += 1
                        if top_score is None or score.composite > top_score.composite:
                            top_score = score
                    elif score.risk == "MEDIUM":
                        medium_count += 1
                        if top_score is None or score.composite > top_score.composite:
                            top_score = score

                # Fire if sustained anomaly
                is_sustained = (
                    high_count >= self.BEHAVIORAL_SUSTAINED_COUNT or
                    medium_count >= 3
                )

                if is_sustained and top_score is not None:
                    triggers.append(InspectionTrigger(
                        trigger_type = "BEHAVIORAL_ANOMALY",
                        rule_id      = "BASELINE",
                        severity     = "HIGH" if high_count >= self.BEHAVIORAL_SUSTAINED_COUNT else "MEDIUM",
                        evidence_summary = (
                            f"Agent '{agent_name}' shows sustained behavioral deviation: "
                            f"{high_count} HIGH + {medium_count} MEDIUM anomaly sessions "
                            f"in the last 10 sessions. "
                            f"Peak composite score: {top_score.composite:.2f}. "
                            f"Anomalous features: {top_score.anomalous_features}. "
                            f"{top_score.narrative} "
                            f"This may indicate a novel attack pattern, environment change, "
                            f"or legitimate behavior shift requiring baseline update."
                        ),
                        evidence_data = {
                            "agent_name":    agent_name,
                            "high_sessions":  high_count,
                            "medium_sessions": medium_count,
                            "peak_composite": top_score.composite,
                            "anomalous_features": top_score.anomalous_features,
                            "baseline_sessions": agent_info["sessions_trained"],
                        },
                        amendment_candidate = True,
                    ))
        except Exception as e:
            log.debug("[InspectionEngine] behavioral_anomaly check error: %s", e)
        return triggers

    # ── Repeated Tier 3 block pattern ─────────────────────────────────────────

    TIER3_REPEAT_THRESHOLD  = 5    # blocks in window before trigger fires
    TIER3_WINDOW_DAYS       = 7
    TIER3_TOP_N             = 3    # top patterns to surface

    def _check_repeated_tier3(self) -> List[InspectionTrigger]:
        """
        Fire when the same agent+rule+tool pattern has been blocked at Tier 3
        repeatedly within the rolling window, without a policy proposal having
        been generated.

        This is the observation-graph-level version of the in-session tracking.
        It catches patterns that span multiple sessions and agents that don't
        have enable_policy_proposals() active.

        Amendment candidate: False — generates a PolicyProposal directly
        rather than going through the amendment queue.
        """
        triggers = []
        try:
            from aiglos.adaptive.observation import ObservationGraph
            from aiglos.core.policy_proposal import PolicyProposalEngine
            import time

            cutoff = time.time() - self.TIER3_WINDOW_DAYS * 86400
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT pattern_id, agent_name, rule_id, tool_name,
                           COUNT(*) as cnt
                    FROM block_patterns
                    WHERE tier >= 3 AND occurred_at >= ?
                    GROUP BY pattern_id
                    HAVING cnt >= ?
                    ORDER BY cnt DESC
                    LIMIT ?
                """, (cutoff, self.TIER3_REPEAT_THRESHOLD,
                      self.TIER3_TOP_N)).fetchall()

            for row in rows:
                pattern_id = row["pattern_id"]
                # Skip if a pending proposal already exists
                existing = self._graph.get_proposal_by_pattern(pattern_id)
                if existing:
                    continue

                triggers.append(InspectionTrigger(
                    trigger_type = "REPEATED_TIER3_BLOCK",
                    rule_id      = row["rule_id"],
                    severity     = "MEDIUM",
                    evidence_summary = (
                        f"Tier 3 block pattern repeated {row['cnt']} times in "
                        f"{self.TIER3_WINDOW_DAYS} days — agent='{row['agent_name']}' "
                        f"rule={row['rule_id']} tool='{row['tool_name']}'. "
                        f"Consider enabling policy proposals: "
                        f"`aiglos.attach(enable_policy_proposals=True)`. "
                        f"Run `aiglos policy list` to review pending proposals."
                    ),
                    evidence_data = {
                        "pattern_id":        pattern_id,
                        "agent_name":        row["agent_name"],
                        "rule_id":           row["rule_id"],
                        "tool_name":         row["tool_name"],
                        "repetition_count":  row["cnt"],
                        "window_days":       self.TIER3_WINDOW_DAYS,
                    },
                    amendment_candidate = False,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] repeated_tier3 check error: %s", e)
        return triggers

    # ── Global prior match ────────────────────────────────────────────────────

    _GLOBAL_PRIOR_MIN_DEPLOYMENTS = 5     # prior must cover enough deployments
    _GLOBAL_PRIOR_MIN_PROBABILITY = 0.55  # threat probability to trigger
    _GLOBAL_PRIOR_LOCAL_SESSIONS  = 5     # only fires when local data is thin

    def _check_global_prior_match(self) -> List[InspectionTrigger]:
        """
        Fire when the current deployment's recent sequence matches a HIGH-
        probability attack pattern from the global prior, AND the local
        model has insufficient data to have caught it independently.

        This is the early-warning trigger for novel attack classes that
        haven't yet appeared in this deployment but are spreading across
        the network.

        Fires only when:
          1. The local model has fewer than _GLOBAL_PRIOR_LOCAL_SESSIONS
             sessions (otherwise the local model would have caught it)
          2. The global prior has data from >= _GLOBAL_PRIOR_MIN_DEPLOYMENTS
          3. The global prior predicts a HIGH-probability threat

        Amendment candidate: False — this is a network signal, not a
        local pattern, so policy changes are not appropriate.
        """
        triggers = []
        try:
            from aiglos.core.federation import FederationClient, GlobalPrior
            from aiglos.core.intent_predictor import IntentPredictor

            # Load the cached prior from any available local file
            # (set by a running guard that has federation enabled)
            prior_path = self._find_cached_prior()
            if prior_path is None:
                return []

            prior = prior_path
            if prior.trained_on_n_deployments < self._GLOBAL_PRIOR_MIN_DEPLOYMENTS:
                return []

            # Find agents with thin local models that could benefit from prior
            with self._graph._conn() as conn:
                thin_agents = conn.execute("""
                    SELECT agent_name, COUNT(*) as session_count
                    FROM sessions
                    GROUP BY agent_name
                    HAVING session_count < ?
                """, (self._GLOBAL_PRIOR_LOCAL_SESSIONS,)).fetchall()

            for row in thin_agents:
                agent_name    = row["agent_name"]
                session_count = row["session_count"]

                # Build a temporary predictor with the global prior
                predictor = IntentPredictor(
                    graph      = self._graph,
                    agent_name = agent_name,
                )
                predictor.warm_start_from_prior(prior)

                # Get prediction from the prior-seeded model
                prediction = predictor.predict()
                if prediction is None:
                    continue

                top_threats = prediction.top_threats
                if not top_threats:
                    continue

                top_rule, top_prob = top_threats[0]
                if top_prob < self._GLOBAL_PRIOR_MIN_PROBABILITY:
                    continue

                triggers.append(InspectionTrigger(
                    trigger_type = "GLOBAL_PRIOR_MATCH",
                    rule_id      = top_rule,
                    severity     = "HIGH" if top_prob >= 0.75 else "MEDIUM",
                    evidence_summary = (
                        f"Global prior match for agent '{agent_name}': "
                        f"rule {top_rule} predicted with {top_prob:.0%} probability "
                        f"based on data from {prior.trained_on_n_deployments} deployments. "
                        f"Local model has only {session_count} sessions — insufficient "
                        f"to catch this pattern independently. "
                        f"Enable federation: aiglos.attach(enable_federation=True)"
                    ),
                    evidence_data = {
                        "agent_name":         agent_name,
                        "predicted_rule":     top_rule,
                        "probability":        round(top_prob, 4),
                        "local_sessions":     session_count,
                        "prior_version":      prior.prior_version,
                        "prior_deployments":  prior.trained_on_n_deployments,
                        "all_threats":        [(r, round(p, 4)) for r, p in top_threats[:5]],
                    },
                    amendment_candidate = False,
                ))

        except Exception as e:
            log.debug("[InspectionEngine] global_prior_match check error: %s", e)
        return triggers

    def _find_cached_prior(self):
        """Find a cached GlobalPrior from the filesystem. Returns None if not found."""
        try:
            from aiglos.core.federation import GlobalPrior
            import json as _json
            from pathlib import Path
            cache_path = Path.home() / ".aiglos" / "global_prior.json"
            if not cache_path.exists():
                return None
            with open(cache_path) as f:
                data = _json.load(f)
            prior = GlobalPrior.from_dict(data)
            if prior.is_stale:
                return None
            return prior
        except Exception:
            return None

    # ── Unverified rule detection ─────────────────────────────────────────────

    _UNVERIFIED_MIN_BLOCKS = 10   # rule must have fired this many times to trigger

    def _check_unverified_rules(self) -> List[InspectionTrigger]:
        """
        Fire when active rules have no verified citation but have been
        blocking in production. These rules work — but they can't be
        explained to an auditor, a regulator, or a compliance review.

        Fires for rules that have:
          - Fired _UNVERIFIED_MIN_BLOCKS+ times in production
          - No citation record in the graph, or citation status UNVERIFIED/PENDING

        Amendment candidate: False — this doesn't change the rule, it flags
        that the rule needs a citation attached. Run `aiglos research verify`
        to fix it.
        """
        triggers = []
        try:
            # Get all rules with significant block history but no citation
            with self._graph._conn() as conn:
                # Rules that have fired but have no verified citation
                rows = conn.execute("""
                    SELECT bp.rule_id, COUNT(*) as block_count
                    FROM block_patterns bp
                    LEFT JOIN rule_citations rc ON bp.rule_id = rc.rule_id
                    WHERE (rc.rule_id IS NULL
                           OR rc.status IN ('UNVERIFIED', 'PENDING'))
                    GROUP BY bp.rule_id
                    HAVING block_count >= ?
                    ORDER BY block_count DESC
                    LIMIT 10
                """, (self._UNVERIFIED_MIN_BLOCKS,)).fetchall()

            for row in rows:
                rule_id     = row["rule_id"]
                block_count = row["block_count"]

                triggers.append(InspectionTrigger(
                    trigger_type = "UNVERIFIED_RULE_ACTIVE",
                    rule_id      = rule_id,
                    severity     = "LOW",
                    evidence_summary = (
                        f"Rule {rule_id} has fired {block_count} times in production "
                        f"but has no verified citation from OWASP, MITRE ATLAS, or NVD. "
                        f"This rule cannot be explained to a compliance auditor. "
                        f"Run `aiglos research verify --rule {rule_id}` to attach a citation. "
                        f"Run `aiglos research report` to generate the full compliance report."
                    ),
                    evidence_data = {
                        "rule_id":     rule_id,
                        "block_count": block_count,
                        "action":      "aiglos research verify --rule " + rule_id,
                    },
                    amendment_candidate = False,
                ))

        except Exception as e:
            log.debug("[InspectionEngine] unverified_rules check error: %s", e)
        return triggers

    # ── Shared context anomaly ────────────────────────────────────────────────

    _SHARED_CONTEXT_MIN_EVENTS = 2

    def _check_shared_context_anomaly(self) -> List[InspectionTrigger]:
        triggers = []
        try:
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT COUNT(*) as cnt, session_id
                    FROM events
                    WHERE rule_id = 'T40'
                    GROUP BY session_id
                    HAVING cnt >= ?
                    ORDER BY cnt DESC
                    LIMIT 10
                """, (self._SHARED_CONTEXT_MIN_EVENTS,)).fetchall()

            for row in rows:
                triggers.append(InspectionTrigger(
                    trigger_type="SHARED_CONTEXT_ANOMALY",
                    rule_id="T40",
                    severity="HIGH" if row["cnt"] >= 5 else "MEDIUM",
                    evidence_summary=(
                        f"Session {row['session_id']} has {row['cnt']} shared context "
                        f"write events (T40). Multiple poisoned writes to fleet "
                        f"coordination paths detected — inspect shared directories "
                        f"for coordinated injection attempts."
                    ),
                    evidence_data={
                        "session_id": row["session_id"],
                        "t40_event_count": row["cnt"],
                    },
                    amendment_candidate=False,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] shared_context_anomaly check error: %s", e)
        return triggers
