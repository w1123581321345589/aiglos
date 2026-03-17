"""
aiglos.adaptive.observation
============================
Phase 1: Observation graph -- SQLite-backed storage of session artifacts,
rule firing history, and agent definition snapshots.

Everything the adaptive layer needs as input is already in the v0.3.0 session
artifact. This module structures that output into a queryable graph keyed by
rule, agent, command pattern, and outcome.

Schema:
  rules         -- one row per rule family (T01-T38)
  sessions      -- one row per session
  events        -- one row per inspected action (MCP, HTTP, subprocess)
  agentdef_obs  -- one row per agent definition observation
  spawn_events  -- one row per T38 spawn
  amendments    -- one row per proposed/applied rule amendment (Phase 4)

Usage:
    from aiglos.adaptive.observation import ObservationGraph

    graph = ObservationGraph()            # defaults to ~/.aiglos/observations.db
    graph.ingest(artifact)                # call after aiglos.close()

    stats = graph.rule_stats("T37")
    # { "fires": 12, "blocks": 9, "warns": 2, "allows": 1,
    #   "override_rate": 0.08, "trend": "STABLE" }
"""



import hashlib
import json
import logging
import threading
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("aiglos.adaptive.observation")

DEFAULT_DB_PATH = Path.home() / ".aiglos" / "observations.db"

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    agent_name      TEXT NOT NULL DEFAULT '',
    aiglos_version  TEXT NOT NULL DEFAULT '',
    started_at      REAL NOT NULL DEFAULT 0,
    closed_at       REAL NOT NULL DEFAULT 0,
    total_events    INTEGER NOT NULL DEFAULT 0,
    blocked_events  INTEGER NOT NULL DEFAULT 0,
    raw_artifact    TEXT,          -- JSON blob of full artifact
    ingested_at     REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    surface         TEXT NOT NULL,  -- 'mcp' | 'http' | 'subprocess'
    rule_id         TEXT NOT NULL DEFAULT 'none',
    rule_name       TEXT NOT NULL DEFAULT '',
    verdict         TEXT NOT NULL,  -- ALLOW | WARN | BLOCK | PAUSE
    tier            INTEGER,        -- 1 | 2 | 3 (subprocess only)
    cmd_hash        TEXT,           -- sha256[:16] of cmd/url (no raw data stored)
    cmd_preview     TEXT,           -- first 80 chars of cmd/url (for debugging)
    latency_ms      REAL,
    timestamp       REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rule_stats_cache (
    rule_id         TEXT PRIMARY KEY,
    fires_total     INTEGER NOT NULL DEFAULT 0,
    blocks_total    INTEGER NOT NULL DEFAULT 0,
    warns_total     INTEGER NOT NULL DEFAULT 0,
    allows_total    INTEGER NOT NULL DEFAULT 0,
    sessions_seen   INTEGER NOT NULL DEFAULT 0,
    last_seen       REAL NOT NULL DEFAULT 0,
    last_updated    REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agentdef_observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    path_hash       TEXT NOT NULL,   -- sha256[:16] of path
    path_preview    TEXT NOT NULL,   -- last 60 chars of path
    violation_type  TEXT,            -- MODIFIED | ADDED | DELETED | NULL (clean)
    semantic_risk   TEXT,            -- HIGH | MEDIUM | LOW | NULL
    semantic_score  REAL,            -- 0.0-1.0 divergence score
    original_hash   TEXT,
    current_hash    TEXT,
    observed_at     REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS spawn_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    parent_id       TEXT NOT NULL,
    child_id        TEXT NOT NULL,
    agent_name      TEXT NOT NULL DEFAULT '',
    cmd_preview     TEXT,
    policy_propagated INTEGER NOT NULL DEFAULT 0,
    spawned_at      REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reward_signals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    rule_id         TEXT NOT NULL DEFAULT 'T39',
    verdict         TEXT NOT NULL,           -- ALLOW | WARN | QUARANTINE | BLOCK
    aiglos_verdict  TEXT NOT NULL DEFAULT '', -- original Aiglos verdict for the op
    aiglos_rule_id  TEXT NOT NULL DEFAULT '', -- rule that fired for the op
    claimed_reward  REAL NOT NULL DEFAULT 0,
    adjusted_reward REAL NOT NULL DEFAULT 0,
    override_applied INTEGER NOT NULL DEFAULT 0,
    semantic_risk   TEXT NOT NULL DEFAULT 'LOW',
    semantic_score  REAL NOT NULL DEFAULT 0,
    signal_type     TEXT NOT NULL DEFAULT 'binary', -- binary | opd | prm
    feedback_preview TEXT NOT NULL DEFAULT '',
    timestamp       REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS causal_chains (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         TEXT NOT NULL,
    agent_name         TEXT NOT NULL DEFAULT '',
    session_verdict    TEXT NOT NULL DEFAULT 'CLEAN',
    flagged_actions    INTEGER NOT NULL DEFAULT 0,
    attributed_actions INTEGER NOT NULL DEFAULT 0,
    high_conf_chains   INTEGER NOT NULL DEFAULT 0,
    chains_json        TEXT NOT NULL DEFAULT '[]',
    timestamp          REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS honeypot_hits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    honeypot_name   TEXT NOT NULL DEFAULT '',
    honeypot_path   TEXT NOT NULL DEFAULT '',
    tool_name       TEXT NOT NULL DEFAULT '',
    agent_name      TEXT NOT NULL DEFAULT '',
    session_id      TEXT NOT NULL DEFAULT '',
    detection_mode  TEXT NOT NULL DEFAULT 'TOOL_CALL',
    timestamp       REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_honeypot_agent ON honeypot_hits(agent_name);
CREATE INDEX IF NOT EXISTS idx_honeypot_ts    ON honeypot_hits(timestamp);

CREATE TABLE IF NOT EXISTS override_challenges (
    challenge_id   TEXT PRIMARY KEY,
    rule_id        TEXT NOT NULL DEFAULT '',
    tool_name      TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT '',
    agent_name     TEXT NOT NULL DEFAULT '',
    session_id     TEXT NOT NULL DEFAULT '',
    issued_at      REAL NOT NULL DEFAULT 0,
    expires_at     REAL NOT NULL DEFAULT 0,
    resolved       INTEGER NOT NULL DEFAULT 0,
    approved       INTEGER NOT NULL DEFAULT 0,
    resolved_at    REAL,
    attempts       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_override_agent   ON override_challenges(agent_name);
CREATE INDEX IF NOT EXISTS idx_override_session ON override_challenges(session_id);

CREATE TABLE IF NOT EXISTS rule_citations (
    rule_id         TEXT PRIMARY KEY,
    source          TEXT NOT NULL DEFAULT '',
    reference_id    TEXT NOT NULL DEFAULT '',
    reference_name  TEXT NOT NULL DEFAULT '',
    reference_url   TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0.0,
    status          TEXT NOT NULL DEFAULT 'UNVERIFIED',
    verified_at     REAL NOT NULL DEFAULT 0,
    evidence_summary TEXT NOT NULL DEFAULT '',
    internal_block_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS threat_signals (
    signal_id       TEXT PRIMARY KEY,
    source          TEXT NOT NULL DEFAULT '',
    reference_id    TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    published_at    TEXT NOT NULL DEFAULT '',
    relevance_score REAL NOT NULL DEFAULT 0.0,
    suggested_rule  TEXT,
    is_new          INTEGER NOT NULL DEFAULT 1,
    detected_at     REAL NOT NULL DEFAULT 0,
    keywords_json   TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_signals_rule ON threat_signals(suggested_rule);
CREATE INDEX IF NOT EXISTS idx_signals_det  ON threat_signals(detected_at);

CREATE TABLE IF NOT EXISTS block_patterns (
    pattern_id      TEXT NOT NULL,
    agent_name      TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    tool_name       TEXT NOT NULL DEFAULT '',
    args_fingerprint TEXT NOT NULL DEFAULT '',
    tier            INTEGER NOT NULL DEFAULT 3,
    occurred_at     REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_block_pat_id    ON block_patterns(pattern_id);
CREATE INDEX IF NOT EXISTS idx_block_pat_agent ON block_patterns(agent_name);
CREATE INDEX IF NOT EXISTS idx_block_pat_ts    ON block_patterns(occurred_at);

CREATE TABLE IF NOT EXISTS policy_proposals (
    proposal_id       TEXT PRIMARY KEY,
    pattern_id        TEXT NOT NULL,
    proposal_type     TEXT NOT NULL,
    agent_name        TEXT NOT NULL,
    rule_id           TEXT NOT NULL,
    tool_name         TEXT NOT NULL DEFAULT '',
    args_fingerprint  TEXT NOT NULL DEFAULT '',
    proposed_change   TEXT NOT NULL DEFAULT '{}',
    confidence        REAL NOT NULL DEFAULT 0.0,
    status            TEXT NOT NULL DEFAULT 'pending',
    evidence_json     TEXT NOT NULL DEFAULT '{}',
    created_at        REAL NOT NULL DEFAULT 0,
    expires_at        REAL NOT NULL DEFAULT 0,
    reviewed_at       REAL,
    reviewed_by       TEXT,
    applied_at        REAL,
    rollback_reason   TEXT
);
CREATE INDEX IF NOT EXISTS idx_proposals_status  ON policy_proposals(status);
CREATE INDEX IF NOT EXISTS idx_proposals_agent   ON policy_proposals(agent_name);
CREATE INDEX IF NOT EXISTS idx_proposals_pattern ON policy_proposals(pattern_id);

CREATE TABLE IF NOT EXISTS agent_baselines (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name   TEXT NOT NULL UNIQUE,
    baseline_json TEXT NOT NULL DEFAULT '{}',
    sessions_trained INTEGER NOT NULL DEFAULT 0,
    trained_at   REAL NOT NULL DEFAULT 0,
    updated_at   REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_rule    ON events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp);
"""


# ── RuleStats dataclass ───────────────────────────────────────────────────────

@dataclass
class RuleStats:
    rule_id:      str
    fires_total:  int   = 0
    blocks_total: int   = 0
    warns_total:  int   = 0
    allows_total: int   = 0
    sessions_seen: int  = 0
    last_seen:    float = 0.0

    @property
    def block_rate(self) -> float:
        return self.blocks_total / self.fires_total if self.fires_total else 0.0

    @property
    def override_rate(self) -> float:
        """Rate at which blocks are followed by manual allow-list addition."""
        # Approximated as warns_total / fires_total for now;
        # Phase 4 amendment engine tracks true override rate.
        return self.warns_total / self.fires_total if self.fires_total else 0.0

    @property
    def trend(self) -> str:
        """Coarse trend based on sessions_seen vs fires_total."""
        if self.fires_total == 0:
            return "SILENT"
        avg = self.fires_total / max(self.sessions_seen, 1)
        if avg < 0.1:
            return "RARE"
        if avg < 1.0:
            return "OCCASIONAL"
        if avg < 5.0:
            return "ACTIVE"
        return "HIGH_VOLUME"

    def to_dict(self) -> dict:
        return {
            "rule_id":      self.rule_id,
            "fires_total":  self.fires_total,
            "blocks_total": self.blocks_total,
            "warns_total":  self.warns_total,
            "allows_total": self.allows_total,
            "sessions_seen": self.sessions_seen,
            "last_seen":    self.last_seen,
            "block_rate":   round(self.block_rate, 4),
            "override_rate": round(self.override_rate, 4),
            "trend":        self.trend,
        }


# ── ObservationGraph ──────────────────────────────────────────────────────────

class ObservationGraph:
    """
    SQLite-backed observation graph for Aiglos session artifacts.

    Thread-safe. Uses WAL mode for concurrent reads.
    The database is created automatically on first use.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path    = Path(db_path or os.environ.get("AIGLOS_OBS_DB", str(DEFAULT_DB_PATH)))
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()   # serialise concurrent writes
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self._db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    # ── Ingestion ──────────────────────────────────────────────────────────────

    def ingest(self, artifact: Any) -> str:
        """
        Ingest a SessionArtifact into the observation graph.

        Returns the session_id stored.
        Idempotent: ingesting the same artifact twice is a no-op.
        """
        session_id = self._extract_session_id(artifact)
        if self._session_exists(session_id):
            log.debug("[ObsGraph] Session %s already ingested, skipping.", session_id[:12])
            return session_id

        extra      = getattr(artifact, "extra", {}) or {}
        agent_name = getattr(artifact, "agent_name", "")
        version    = extra.get("aiglos_version", "")
        now        = time.time()

        http_events    = extra.get("http_events", [])
        subproc_events = extra.get("subproc_events", [])
        all_events     = self._normalise_events(http_events, "http") + \
                         self._normalise_events(subproc_events, "subprocess")

        # Fallback: real SessionArtifact stores events in .threats list
        # when http_events/subproc_events are not populated via extra
        if not all_events:
            threats_raw = getattr(artifact, "threats", None) or []
            if threats_raw:
                all_events = self._normalise_events(threats_raw, "mcp")
        blocked        = sum(1 for e in all_events if e["verdict"] == "BLOCK")

        agentdef_violations = extra.get("agentdef_violations", [])
        multi_agent         = extra.get("multi_agent", {})
        identity            = extra.get("session_identity", {})
        started_at          = identity.get("created_at", now)

        try:
            raw = json.dumps({
                "session_id": session_id,
                "agent_name": agent_name,
                "version":    version,
            })
        except Exception:
            raw = "{}"

        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO sessions
                    (session_id, agent_name, aiglos_version, started_at,
                     closed_at, total_events, blocked_events, raw_artifact, ingested_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (session_id, agent_name, version, started_at,
                  now, len(all_events), blocked, raw, now))

            for ev in all_events:
                conn.execute("""
                    INSERT INTO events
                        (session_id, surface, rule_id, rule_name, verdict,
                         tier, cmd_hash, cmd_preview, latency_ms, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (session_id, ev["surface"], ev["rule_id"], ev["rule_name"],
                      ev["verdict"], ev.get("tier"), ev["cmd_hash"],
                      ev["cmd_preview"], ev.get("latency_ms"), ev.get("timestamp", now)))

            for v in agentdef_violations:
                path = v.get("path", "")
                conn.execute("""
                    INSERT INTO agentdef_observations
                        (session_id, path_hash, path_preview, violation_type,
                         semantic_risk, semantic_score, original_hash, current_hash, observed_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (session_id,
                      hashlib.sha256(path.encode()).hexdigest()[:16],
                      path[-60:],
                      v.get("violation"),
                      v.get("semantic_risk"),
                      v.get("semantic_score"),
                      v.get("original_hash", ""),
                      v.get("current_hash", ""),
                      v.get("detected_at", now)))

            for spawn in multi_agent.get("spawns", []):
                conn.execute("""
                    INSERT INTO spawn_events
                        (session_id, parent_id, child_id, agent_name,
                         cmd_preview, policy_propagated, spawned_at)
                    VALUES (?,?,?,?,?,?,?)
                """, (session_id,
                      spawn.get("parent_session_id", ""),
                      spawn.get("child_session_id", ""),
                      spawn.get("agent_name", ""),
                      (spawn.get("cmd", "") or "")[:80],
                      1 if spawn.get("policy_propagated") else 0,
                      spawn.get("spawned_at", now)))

        self._update_rule_stats_cache(session_id)
        log.info("[ObsGraph] Ingested session %s: %d events, %d blocked.",
                 session_id[:12], len(all_events), blocked)
        return session_id

    def _normalise_events(self, events: list, surface: str) -> list:
        out = []
        for ev in events:
            cmd = ev.get("cmd") or ev.get("url") or ev.get("tool_name", "")
            # Support both mock format (rule_id/rule_name) and real artifact
            # format (threat_class/threat_name) from SessionArtifact.threats
            rule_id   = ev.get("rule_id") or ev.get("threat_class") or "none"
            rule_name = ev.get("rule_name") or ev.get("threat_name") or ""
            # Verdict may be Verdict enum string like "Verdict.BLOCK"
            raw_verdict = str(ev.get("verdict", "ALLOW"))
            if "." in raw_verdict:
                raw_verdict = raw_verdict.split(".")[-1]
            out.append({
                "surface":     surface,
                "rule_id":     rule_id,
                "rule_name":   rule_name,
                "verdict":     raw_verdict,
                "tier":        ev.get("tier"),
                "cmd_hash":    hashlib.sha256(cmd.encode()).hexdigest()[:16],
                "cmd_preview": cmd[:80],
                "latency_ms":  ev.get("latency_ms"),
                "timestamp":   ev.get("timestamp", time.time()),
            })
        return out

    def _extract_session_id(self, artifact: Any) -> str:
        # First try: real SessionArtifact has a plain string .session_id attribute
        sid = getattr(artifact, "session_id", None)
        if sid and isinstance(sid, str):
            return sid
        # Second: mock artifacts and dicts store it in extra.session_identity
        extra = getattr(artifact, "extra", {}) or {}
        identity = extra.get("session_identity", {})
        sid = identity.get("session_id")
        if sid and isinstance(sid, str):
            return sid
        # Last resort: hash object id + timestamp
        return hashlib.sha256(f"{id(artifact)}{time.time()}".encode()).hexdigest()[:32]

    def _session_exists(self, session_id: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM sessions WHERE session_id=?", (session_id,)
            ).fetchone()
        return row is not None

    def _update_rule_stats_cache(self, session_id: str) -> None:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT rule_id,
                       COUNT(*) as fires,
                       SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) as blocks,
                       SUM(CASE WHEN verdict='WARN'  THEN 1 ELSE 0 END) as warns,
                       SUM(CASE WHEN verdict='ALLOW' THEN 1 ELSE 0 END) as allows,
                       MAX(timestamp) as last_seen
                FROM events WHERE session_id=? AND rule_id != 'none'
                GROUP BY rule_id
            """, (session_id,)).fetchall()

            for row in rows:
                conn.execute("""
                    INSERT INTO rule_stats_cache
                        (rule_id, fires_total, blocks_total, warns_total,
                         allows_total, sessions_seen, last_seen, last_updated)
                    VALUES (?,?,?,?,?,1,?,?)
                    ON CONFLICT(rule_id) DO UPDATE SET
                        fires_total  = fires_total  + excluded.fires_total,
                        blocks_total = blocks_total + excluded.blocks_total,
                        warns_total  = warns_total  + excluded.warns_total,
                        allows_total = allows_total + excluded.allows_total,
                        sessions_seen = sessions_seen + 1,
                        last_seen    = MAX(last_seen, excluded.last_seen),
                        last_updated = excluded.last_updated
                """, (row["rule_id"], row["fires"], row["blocks"],
                      row["warns"], row["allows"], row["last_seen"], time.time()))

    # ── Query API ──────────────────────────────────────────────────────────────

    def rule_stats(self, rule_id: str) -> RuleStats:
        """Return firing statistics for a specific rule."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rule_stats_cache WHERE rule_id=?", (rule_id,)
            ).fetchone()
        if row is None:
            return RuleStats(rule_id=rule_id)
        return RuleStats(
            rule_id=rule_id,
            fires_total=row["fires_total"],
            blocks_total=row["blocks_total"],
            warns_total=row["warns_total"],
            allows_total=row["allows_total"],
            sessions_seen=row["sessions_seen"],
            last_seen=row["last_seen"],
        )

    def all_rule_stats(self) -> List[RuleStats]:
        """Return stats for all rules that have fired."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM rule_stats_cache ORDER BY fires_total DESC"
            ).fetchall()
        return [RuleStats(
            rule_id=r["rule_id"],
            fires_total=r["fires_total"],
            blocks_total=r["blocks_total"],
            warns_total=r["warns_total"],
            allows_total=r["allows_total"],
            sessions_seen=r["sessions_seen"],
            last_seen=r["last_seen"],
        ) for r in rows]

    def session_count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    def recent_sessions(self, n: int = 10) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT session_id, agent_name, total_events, blocked_events, closed_at "
                "FROM sessions ORDER BY closed_at DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(r) for r in rows]

    def events_for_rule(self, rule_id: str, limit: int = 100) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT e.*, s.agent_name FROM events e
                JOIN sessions s ON e.session_id = s.session_id
                WHERE e.rule_id=? ORDER BY e.timestamp DESC LIMIT ?
            """, (rule_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def agentdef_violations_for_path(self, path_hash: str) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM agentdef_observations WHERE path_hash=? "
                "ORDER BY observed_at DESC", (path_hash,)
            ).fetchall()
        return [dict(r) for r in rows]

    def spawn_history(self, agent_name: Optional[str] = None) -> List[dict]:
        with self._conn() as conn:
            if agent_name:
                rows = conn.execute(
                    "SELECT * FROM spawn_events WHERE agent_name=? "
                    "ORDER BY spawned_at DESC", (agent_name,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM spawn_events ORDER BY spawned_at DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def ingest_reward_signal(self, rl_result, session_id: str) -> None:
        """
        Ingest a reward signal result from RLFeedbackGuard or SecurityAwareReward.
        Accepts the dict form or any object with .to_dict().
        """
        if hasattr(rl_result, "to_dict"):
            d = rl_result.to_dict()
        else:
            d = rl_result

        with self._conn() as conn:
            conn.execute("""
                INSERT INTO reward_signals
                    (session_id, rule_id, verdict, aiglos_verdict, aiglos_rule_id,
                     claimed_reward, adjusted_reward, override_applied,
                     semantic_risk, semantic_score, signal_type,
                     feedback_preview, timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                session_id,
                d.get("rule_id", "T39"),
                d.get("verdict", "ALLOW"),
                d.get("aiglos_verdict", ""),
                d.get("aiglos_rule_id", ""),
                d.get("claimed_reward", 0.0),
                d.get("adjusted_reward", 0.0),
                1 if d.get("override_applied") else 0,
                d.get("semantic_risk", "LOW"),
                d.get("semantic_score", 0.0),
                d.get("signal_type", "binary"),
                d.get("feedback_preview", "")[:200],
                d.get("timestamp", time.time()),
            ))

    def reward_signal_stats(self, session_id: Optional[str] = None) -> dict:
        """Return reward signal statistics, optionally scoped to a session."""
        with self._conn() as conn:
            if session_id:
                where, args = "WHERE session_id=?", (session_id,)
            else:
                where, args = "", ()
            row = conn.execute(f"""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN verdict IN ('QUARANTINE','BLOCK') THEN 1 ELSE 0 END) as quarantined,
                    SUM(CASE WHEN rule_id='T39' THEN 1 ELSE 0 END) as t39_fires,
                    AVG(claimed_reward) as avg_claimed,
                    AVG(adjusted_reward) as avg_adjusted,
                    SUM(CASE WHEN semantic_risk='HIGH' THEN 1 ELSE 0 END) as high_risk_opd
                FROM reward_signals {where}
            """, args).fetchone()
        return {
            "total_signals":    row["total"] or 0,
            "quarantined":      row["quarantined"] or 0,
            "t39_fires":        row["t39_fires"] or 0,
            "avg_claimed":      round(row["avg_claimed"] or 0, 4),
            "avg_adjusted":     round(row["avg_adjusted"] or 0, 4),
            "high_risk_opd":    row["high_risk_opd"] or 0,
        }


    def ingest_causal_result(self, attribution_result, session_id: str) -> None:
        """Ingest a CausalTracer AttributionResult into the observation graph.
        Thread-safe -- write lock acquired for the INSERT.
        """
        if hasattr(attribution_result, "to_dict"):
            d = attribution_result.to_dict()
        else:
            d = attribution_result
        import json as _json
        chains_json = _json.dumps(d.get("chains", []))
        high_conf = sum(
            1 for c in d.get("chains", [])
            if c.get("confidence") == "HIGH"
        )
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO causal_chains
                    (session_id, agent_name, session_verdict, flagged_actions,
                     attributed_actions, high_conf_chains, chains_json, timestamp)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                session_id,
                d.get("agent_name", ""),
                d.get("session_verdict", "CLEAN"),
                d.get("flagged_actions", 0),
                d.get("attributed_actions", 0),
                high_conf,
                chains_json,
                d.get("timestamp", time.time()),
            ))

    def causal_stats(self) -> dict:
        """Return causal attribution statistics across all sessions."""
        with self._conn() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*) as total_sessions,
                    SUM(flagged_actions) as total_flagged,
                    SUM(attributed_actions) as total_attributed,
                    SUM(high_conf_chains) as total_high_conf,
                    SUM(CASE WHEN session_verdict='ATTACK_CONFIRMED' THEN 1 ELSE 0 END) as attacks_confirmed,
                    SUM(CASE WHEN session_verdict='SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious_sessions
                FROM causal_chains
            """).fetchone()
        return {
            "sessions_with_tracing":  row["total_sessions"] or 0,
            "total_flagged_actions":  row["total_flagged"] or 0,
            "total_attributed":       row["total_attributed"] or 0,
            "high_conf_attributions": row["total_high_conf"] or 0,
            "attacks_confirmed":      row["attacks_confirmed"] or 0,
            "suspicious_sessions":    row["suspicious_sessions"] or 0,
        }

    def get_causal_chain(self, session_id: str) -> Optional[dict]:
        """Retrieve the causal attribution result for a specific session."""
        import json as _json
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM causal_chains WHERE session_id=? ORDER BY id DESC LIMIT 1",
                (session_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["chains"] = _json.loads(d.get("chains_json", "[]"))
        except Exception:
            d["chains"] = []
        return d

    # ── Honeypot and override support ────────────────────────────────────────────

    def record_honeypot_hit(self, result) -> None:
        """Persist a honeypot access event."""
        d = result.to_dict() if hasattr(result, "to_dict") else result
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO honeypot_hits
                    (honeypot_name, honeypot_path, tool_name, agent_name,
                     session_id, detection_mode, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                d.get("honeypot_name", ""),
                d.get("honeypot_path", ""),
                d.get("tool_name", ""),
                d.get("agent_name", ""),
                d.get("session_id", ""),
                d.get("detection_mode", "TOOL_CALL"),
                d.get("timestamp", time.time()),
            ))

    def get_honeypot_hits(self, agent_name: str = None, limit: int = 50) -> list:
        """Retrieve honeypot hit records."""
        with self._conn() as conn:
            if agent_name:
                rows = conn.execute("""
                    SELECT * FROM honeypot_hits WHERE agent_name=?
                    ORDER BY timestamp DESC LIMIT ?
                """, (agent_name, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM honeypot_hits
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def upsert_override_challenge(self, challenge) -> None:
        """Persist or update an OverrideChallenge."""
        d = challenge.to_dict() if hasattr(challenge, "to_dict") else challenge
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO override_challenges
                    (challenge_id, rule_id, tool_name, reason, agent_name,
                     session_id, issued_at, expires_at, resolved, approved,
                     resolved_at, attempts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(challenge_id) DO UPDATE SET
                    resolved   = excluded.resolved,
                    approved   = excluded.approved,
                    resolved_at = excluded.resolved_at,
                    attempts   = excluded.attempts
            """, (
                d.get("challenge_id", ""),
                d.get("rule_id", ""),
                d.get("tool_name", ""),
                d.get("reason", ""),
                d.get("agent_name", ""),
                d.get("session_id", ""),
                d.get("issued_at", time.time()),
                d.get("expires_at", time.time() + 120),
                1 if d.get("resolved") else 0,
                1 if d.get("approved") else 0,
                d.get("resolved_at"),
                d.get("attempts", 0),
            ))

    def list_override_challenges(
        self,
        agent_name: str = None,
        pending_only: bool = False,
        limit: int = 50,
    ) -> list:
        """List override challenges."""
        with self._conn() as conn:
            if pending_only:
                q = "SELECT * FROM override_challenges WHERE resolved=0 ORDER BY issued_at DESC LIMIT ?"
                args = (limit,)
            elif agent_name:
                q = "SELECT * FROM override_challenges WHERE agent_name=? ORDER BY issued_at DESC LIMIT ?"
                args = (agent_name, limit)
            else:
                q = "SELECT * FROM override_challenges ORDER BY issued_at DESC LIMIT ?"
                args = (limit,)
            rows = conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    # ── Citation and threat signal support ──────────────────────────────────────

    def upsert_citation(self, citation) -> None:
        """Persist or update a VerifiedCitation."""
        d = citation.to_dict() if hasattr(citation, "to_dict") else citation
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO rule_citations
                    (rule_id, source, reference_id, reference_name,
                     reference_url, confidence, status, verified_at,
                     evidence_summary, internal_block_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    source         = excluded.source,
                    reference_id   = excluded.reference_id,
                    reference_name = excluded.reference_name,
                    reference_url  = excluded.reference_url,
                    confidence     = excluded.confidence,
                    status         = excluded.status,
                    verified_at    = excluded.verified_at,
                    evidence_summary = excluded.evidence_summary,
                    internal_block_count = excluded.internal_block_count
            """, (
                d["rule_id"], d["source"], d["reference_id"],
                d["reference_name"], d["reference_url"],
                d["confidence"], d["status"], d["verified_at"],
                d["evidence_summary"], d["internal_block_count"],
            ))

    def get_citation(self, rule_id: str):
        """Load a VerifiedCitation by rule_id. Returns None if not found."""
        from aiglos.autoresearch.citation_verifier import VerifiedCitation
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rule_citations WHERE rule_id=?",
                (rule_id,)
            ).fetchone()
        if not row:
            return None
        return VerifiedCitation.from_dict(dict(row))

    def get_rule_block_count(self, rule_id: str, window_days: int = 90) -> int:
        """Count total blocks for a rule in the rolling window."""
        cutoff = time.time() - window_days * 86400
        with self._conn() as conn:
            # Check block_patterns table
            row = conn.execute("""
                SELECT COUNT(*) as c FROM block_patterns
                WHERE rule_id=? AND occurred_at >= ?
            """, (rule_id, cutoff)).fetchone()
        return row["c"] if row else 0

    def upsert_threat_signal(self, signal) -> None:
        """Persist or update a ThreatSignal."""
        import json as _json
        d = signal.to_dict() if hasattr(signal, "to_dict") else signal
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO threat_signals
                    (signal_id, source, reference_id, title, description,
                     published_at, relevance_score, suggested_rule, is_new,
                     detected_at, keywords_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(signal_id) DO UPDATE SET
                    is_new = excluded.is_new,
                    detected_at = excluded.detected_at
            """, (
                d["signal_id"], d["source"], d["reference_id"],
                d["title"], d["description"][:500],
                d["published_at"], d["relevance_score"],
                d.get("suggested_rule"), 1 if d.get("is_new", True) else 0,
                d["detected_at"],
                _json.dumps(d.get("keywords_matched", [])),
            ))

    def get_threat_signals(
        self, rule_id: str = None, limit: int = 20
    ) -> list:
        """Load threat signals optionally filtered by suggested_rule."""
        from aiglos.autoresearch.threat_literature import ThreatSignal
        import json as _json
        with self._conn() as conn:
            if rule_id:
                rows = conn.execute("""
                    SELECT * FROM threat_signals WHERE suggested_rule=?
                    ORDER BY detected_at DESC LIMIT ?
                """, (rule_id, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM threat_signals
                    ORDER BY detected_at DESC LIMIT ?
                """, (limit,)).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            results.append(ThreatSignal(
                signal_id        = d["signal_id"],
                source           = d["source"],
                reference_id     = d["reference_id"],
                title            = d["title"],
                description      = d["description"],
                published_at     = d["published_at"],
                relevance_score  = d["relevance_score"],
                suggested_rule   = d.get("suggested_rule"),
                is_new           = bool(d.get("is_new", 1)),
                detected_at      = d["detected_at"],
                keywords_matched = _json.loads(d.get("keywords_json", "[]")),
            ))
        return results

    def list_threat_signals(self, limit: int = 20) -> list:
        """List most recent threat signals."""
        return self.get_threat_signals(limit=limit)

    # ── Policy proposal support ──────────────────────────────────────────────────

    def record_block_pattern_event(
        self, pattern_id: str, agent_name: str, rule_id: str,
        tool_name: str, args_fingerprint: str, tier: int = 3
    ) -> None:
        """Record a single block event for pattern tracking."""
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO block_patterns
                    (pattern_id, agent_name, rule_id, tool_name,
                     args_fingerprint, tier, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (pattern_id, agent_name, rule_id, tool_name,
                  args_fingerprint, tier, time.time()))

    def get_block_pattern_count(
        self, pattern_id: str, window_days: int = 7
    ) -> int:
        """Count occurrences of a block pattern within the rolling window."""
        cutoff = time.time() - window_days * 86400
        with self._conn() as conn:
            row = conn.execute("""
                SELECT COUNT(*) as c FROM block_patterns
                WHERE pattern_id=? AND occurred_at >= ?
            """, (pattern_id, cutoff)).fetchone()
        return row["c"] if row else 0

    def upsert_proposal(self, proposal) -> None:
        """Persist or update a PolicyProposal."""
        import json as _json
        d = proposal.to_dict() if hasattr(proposal, "to_dict") else proposal
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO policy_proposals
                    (proposal_id, pattern_id, proposal_type, agent_name,
                     rule_id, tool_name, args_fingerprint, proposed_change,
                     confidence, status, evidence_json, created_at, expires_at,
                     reviewed_at, reviewed_by, applied_at, rollback_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(proposal_id) DO UPDATE SET
                    status          = excluded.status,
                    reviewed_at     = excluded.reviewed_at,
                    reviewed_by     = excluded.reviewed_by,
                    applied_at      = excluded.applied_at,
                    rollback_reason = excluded.rollback_reason
            """, (
                d["proposal_id"], d["pattern_id"], d["proposal_type"],
                d["agent_name"], d["rule_id"], d["tool_name"],
                d["args_fingerprint"],
                _json.dumps(d.get("proposed_change", {})),
                d["confidence"], d["status"],
                _json.dumps(d.get("evidence", {})),
                d["created_at"], d["expires_at"],
                d.get("reviewed_at"), d.get("reviewed_by"),
                d.get("applied_at"), d.get("rollback_reason"),
            ))

    def get_proposal(self, proposal_id: str):
        """Load a PolicyProposal by ID. Returns None if not found."""
        from aiglos.core.policy_proposal import PolicyProposal
        import json as _json
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM policy_proposals WHERE proposal_id=?",
                (proposal_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_proposal(dict(row))

    def get_proposal_by_pattern(self, pattern_id: str, status: str = "pending"):
        """Find an existing proposal for a given pattern_id."""
        with self._conn() as conn:
            row = conn.execute("""
                SELECT * FROM policy_proposals
                WHERE pattern_id=? AND status=?
                ORDER BY created_at DESC LIMIT 1
            """, (pattern_id, status)).fetchone()
        if not row:
            return None
        return self._row_to_proposal(dict(row))

    def list_proposals(
        self,
        status: str = "pending",
        agent_name: str = None,
        limit: int = 50,
    ) -> list:
        """List proposals filtered by status and optionally agent."""
        query = "SELECT * FROM policy_proposals WHERE status=?"
        args  = [status]
        if agent_name:
            query += " AND agent_name=?"
            args.append(agent_name)
        query += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        with self._conn() as conn:
            rows = conn.execute(query, args).fetchall()
        return [self._row_to_proposal(dict(r)) for r in rows]

    def expire_proposals(self) -> int:
        """Mark all expired pending proposals as expired. Returns count updated."""
        now = time.time()
        with self._write_lock, self._conn() as conn:
            result = conn.execute("""
                UPDATE policy_proposals SET status='expired'
                WHERE status='pending' AND expires_at < ?
            """, (now,))
            return result.rowcount

    def proposal_stats(self) -> dict:
        """Summary counts by status for CLI display."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT status, COUNT(*) as c FROM policy_proposals GROUP BY status
            """).fetchall()
        stats = {r["status"]: r["c"] for r in rows}
        return {
            "pending":     stats.get("pending", 0),
            "approved":    stats.get("approved", 0),
            "rejected":    stats.get("rejected", 0),
            "expired":     stats.get("expired", 0),
            "rolled_back": stats.get("rolled_back", 0),
            "total":       sum(stats.values()),
        }

    def _row_to_proposal(self, row: dict):
        """Convert a DB row dict to a PolicyProposal."""
        from aiglos.core.policy_proposal import PolicyProposal, BlockPattern, ProposalType, ProposalStatus
        import json as _json
        ev = _json.loads(row.get("evidence_json", "{}"))
        evidence = BlockPattern(
            agent_name       = row.get("agent_name", ""),
            rule_id          = row.get("rule_id", ""),
            tool_name        = row.get("tool_name", ""),
            args_fingerprint = row.get("args_fingerprint", ""),
            repetition_count = ev.get("repetition_count", 0),
            window_days      = ev.get("window_days", 7),
            first_seen       = ev.get("first_seen", 0.0),
            last_seen        = ev.get("last_seen", 0.0),
            consistency_score  = ev.get("consistency_score", 0.0),
            incident_count     = ev.get("incident_count", 0),
            baseline_confirmed = ev.get("baseline_confirmed", False),
        )
        return PolicyProposal(
            proposal_id      = row["proposal_id"],
            pattern_id       = row["pattern_id"],
            proposal_type    = ProposalType(row["proposal_type"]),
            agent_name       = row["agent_name"],
            rule_id          = row["rule_id"],
            tool_name        = row.get("tool_name", ""),
            args_fingerprint = row.get("args_fingerprint", ""),
            proposed_change  = _json.loads(row.get("proposed_change", "{}")),
            evidence         = evidence,
            confidence       = row.get("confidence", 0.0),
            status           = ProposalStatus(row.get("status", "pending")),
            created_at       = row.get("created_at", 0.0),
            expires_at       = row.get("expires_at", 0.0),
            reviewed_at      = row.get("reviewed_at"),
            reviewed_by      = row.get("reviewed_by"),
            applied_at       = row.get("applied_at"),
            rollback_reason  = row.get("rollback_reason"),
        )

    # ── Behavioral baseline support ───────────────────────────────────────────

    def agent_session_count(self, agent_name: str) -> int:
        """Return total sessions ingested for this agent."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as c FROM sessions WHERE agent_name=?",
                (agent_name,)
            ).fetchone()
        return row["c"] if row else 0

    def get_agent_session_stats(
        self, agent_name: str, limit: int = 90
    ) -> list:
        """
        Load per-session statistics for an agent, most recent first.
        Returns list of SessionStats-compatible objects.

        Reads individual event records for surface/rule breakdown.
        Falls back to sessions-table totals (total_events, blocked_events)
        when the events table has no records for a session -- this handles
        sessions ingested via the threats list rather than subproc/http events.
        """
        from aiglos.core.behavioral_baseline import SessionStats
        with self._conn() as conn:
            sessions = conn.execute("""
                SELECT session_id, total_events, blocked_events
                FROM sessions
                WHERE agent_name=?
                ORDER BY closed_at DESC
                LIMIT ?
            """, (agent_name, limit)).fetchall()

        result = []
        for sess in sessions:
            sid           = sess["session_id"]
            total_fallback  = sess["total_events"]  or 0
            blocked_fallback = sess["blocked_events"] or 0

            with self._conn() as conn:
                events = conn.execute("""
                    SELECT surface, rule_id, verdict, tier
                    FROM events WHERE session_id=?
                """, (sid,)).fetchall()

            surface_counts: dict = {}
            rule_counts:    dict = {}
            warned = 0
            blocked_from_events = 0

            for ev in events:
                surf = ev["surface"] or "mcp"
                surface_counts[surf] = surface_counts.get(surf, 0) + 1
                if ev["verdict"] in ("BLOCK",):
                    blocked_from_events += 1
                    rule_id = ev["rule_id"] or "none"
                    if rule_id != "none":
                        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
                if ev["verdict"] == "WARN":
                    warned += 1

            # If no individual events recorded, synthesise from sessions table
            if not events and total_fallback > 0:
                surface_counts = {"mcp": total_fallback}
                blocked_from_events = blocked_fallback
            elif events and total_fallback > 0:
                # MCP events are not individually recorded in the events table
                # (only http and subprocess events are stored there).
                # Reconstruct MCP count from: total - sum(recorded surfaces)
                recorded_surface_total = sum(surface_counts.values())
                mcp_count = max(0, total_fallback - recorded_surface_total)
                if mcp_count > 0:
                    surface_counts["mcp"] = surface_counts.get("mcp", 0) + mcp_count

            result.append(SessionStats(
                agent_name     = agent_name,
                session_id     = sid,
                total_events   = max(total_fallback, len(events)),
                blocked_events = blocked_from_events,
                warned_events  = warned,
                surface_counts = surface_counts,
                rule_counts    = rule_counts,
            ))

        return list(reversed(result))  # chronological order

    def upsert_baseline(self, agent_name: str, baseline) -> None:
        """Persist a computed AgentBaseline to the agent_baselines table."""
        import json as _json
        d = baseline.to_dict() if hasattr(baseline, "to_dict") else baseline
        now = time.time()
        with self._write_lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO agent_baselines
                    (agent_name, baseline_json, sessions_trained, trained_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(agent_name) DO UPDATE SET
                    baseline_json    = excluded.baseline_json,
                    sessions_trained = excluded.sessions_trained,
                    trained_at       = excluded.trained_at,
                    updated_at       = excluded.updated_at
            """, (
                agent_name,
                _json.dumps(d),
                d.get("sessions_trained", 0),
                d.get("trained_at", now),
                now,
            ))

    def get_baseline(self, agent_name: str):
        """Load a persisted AgentBaseline from the database. Returns None if not found."""
        import json as _json
        from aiglos.core.behavioral_baseline import AgentBaseline
        with self._conn() as conn:
            row = conn.execute(
                "SELECT baseline_json FROM agent_baselines WHERE agent_name=?",
                (agent_name,)
            ).fetchone()
        if not row:
            return None
        try:
            d = _json.loads(row["baseline_json"])
            return AgentBaseline.from_dict(d)
        except Exception as e:
            log.debug("[ObsGraph] Baseline load error for %s: %s", agent_name, e)
            return None

    def baseline_anomaly_stats(self) -> dict:
        """Summary stats about behavioral anomalies across all agents."""
        with self._conn() as conn:
            agents = conn.execute(
                "SELECT agent_name, sessions_trained FROM agent_baselines"
            ).fetchall()
        return {
            "agents_with_baselines": len(agents),
            "agents_ready": sum(1 for a in agents
                                if a["sessions_trained"] >= 20),
            "agents": [dict(a) for a in agents],
        }

    def reward_drift_data(self, window: int = 20) -> dict:
        """
        Return reward signal data for the REWARD_DRIFT inspection trigger.
        Compares recent vs baseline reward patterns for security-relevant ops.
        """
        with self._conn() as conn:
            # Recent signals for security-sensitive operations
            recent = conn.execute("""
                SELECT aiglos_rule_id, AVG(claimed_reward) as avg_claimed,
                       AVG(adjusted_reward) as avg_adjusted,
                       COUNT(*) as count
                FROM reward_signals
                WHERE aiglos_rule_id NOT IN ('none', '')
                AND aiglos_rule_id != 'none'
                ORDER BY timestamp DESC
                LIMIT ?
            """, (window,)).fetchall()

            # Historical baseline
            baseline = conn.execute("""
                SELECT aiglos_rule_id, AVG(claimed_reward) as avg_claimed,
                       COUNT(*) as count
                FROM reward_signals
                WHERE aiglos_rule_id NOT IN ('none', '')
            """).fetchall()

        return {
            "recent":   [dict(r) for r in recent],
            "baseline": [dict(r) for r in baseline],
        }

    def summary(self) -> dict:
        """High-level summary across all ingested data."""
        with self._conn() as conn:
            sess = conn.execute(
                "SELECT COUNT(*) as c, SUM(blocked_events) as b FROM sessions"
            ).fetchone()
            top_rules = conn.execute(
                "SELECT rule_id, fires_total FROM rule_stats_cache "
                "ORDER BY fires_total DESC LIMIT 5"
            ).fetchall()
            recent_agentdef = conn.execute(
                "SELECT COUNT(*) FROM agentdef_observations WHERE violation_type IS NOT NULL"
            ).fetchone()[0]
            spawn_count = conn.execute("SELECT COUNT(*) FROM spawn_events").fetchone()[0]
        return {
            "sessions":          sess["c"] or 0,
            "total_blocked":     sess["b"] or 0,
            "top_rules":         [{"rule_id": r["rule_id"], "fires": r["fires_total"]}
                                  for r in top_rules],
            "agentdef_violations": recent_agentdef,
            "spawn_events":      spawn_count,
        }
