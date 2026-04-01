"""
aiglos.forensics -- Tamper-evident forensic persistence store.

Automatically captures every signed session artifact into a local SQLite
database at ~/.aiglos/forensics.db when close_session() is called.
No operator action required. Artifacts outlive the agent process.

This is the direct answer to a publicly documented "specific Tuesday" question:
"Do you know what your system did last Tuesday -- not what it was
configured to do, not what it was supposed to do, but what it actually did?"
(a field report (March 31, 2026), "dark code" post, March 31, 2026)

The cryptographic signatures from the session artifact chain are preserved
intact, meaning any forensic record can be verified against tampering after
the fact. The agent is gone; the signed audit trail is not.

Usage:
    # Auto-populated by OpenClawGuard.close_session()
    # No manual calls needed.

    # CLI query:
    # aiglos forensics query --date 2026-03-12
    # aiglos forensics query --agent reporting-pipeline
    # aiglos forensics query --threat T86
    # aiglos forensics query --session abc123

    # Programmatic:
    from aiglos.forensics import ForensicStore
    store = ForensicStore()
    records = store.query(date="2026-03-12", agent="reporting-pipeline")
    for r in records:
        print(r.summary())
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


# ── Default store location ────────────────────────────────────────────────────

def _default_db_path() -> Path:
    """Return the default forensic store path: ~/.aiglos/forensics.db"""
    base = Path(os.environ.get("AIGLOS_FORENSICS_DIR", Path.home() / ".aiglos"))
    base.mkdir(parents=True, exist_ok=True)
    return base / "forensics.db"


# ── Schema version ────────────────────────────────────────────────────────────
_SCHEMA_VERSION = 1

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS forensic_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    session_id      TEXT NOT NULL UNIQUE,
    agent_name      TEXT NOT NULL,
    policy          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    closed_at       TEXT NOT NULL,
    total_calls     INTEGER NOT NULL DEFAULT 0,
    blocked_calls   INTEGER NOT NULL DEFAULT 0,
    warned_calls    INTEGER NOT NULL DEFAULT 0,
    threats_json    TEXT,       -- JSON array of {threat_class, count} objects
    campaigns_json  TEXT,       -- JSON array of detected campaign names
    govbench_score  REAL,
    attestation_ready INTEGER NOT NULL DEFAULT 0,
    artifact_hash   TEXT,       -- SHA-256 of the full artifact JSON
    signature       TEXT,       -- HMAC-SHA256 or RSA-2048 signature hex
    artifact_json   TEXT,       -- full artifact blob for replay/verification
    inserted_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_name  ON forensic_sessions(agent_name);
CREATE INDEX IF NOT EXISTS idx_closed_at   ON forensic_sessions(closed_at);
CREATE INDEX IF NOT EXISTS idx_session_id  ON forensic_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_policy      ON forensic_sessions(policy);

CREATE TABLE IF NOT EXISTS forensic_denials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    agent_name      TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    threat_class    TEXT,
    threat_name     TEXT,
    score           REAL,
    verdict         TEXT,
    timestamp       TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES forensic_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_denial_session  ON forensic_denials(session_id);
CREATE INDEX IF NOT EXISTS idx_denial_threat   ON forensic_denials(threat_class);
CREATE INDEX IF NOT EXISTS idx_denial_agent    ON forensic_denials(agent_name);
CREATE INDEX IF NOT EXISTS idx_denial_ts       ON forensic_denials(timestamp);
"""


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ForensicRecord:
    """
    A single forensic session record pulled from the store.
    """
    session_id:       str
    agent_name:       str
    policy:           str
    started_at:       str
    closed_at:        str
    total_calls:      int
    blocked_calls:    int
    warned_calls:     int
    threats:          List[dict]
    campaigns:        List[str]
    govbench_score:   Optional[float]
    attestation_ready: bool
    artifact_hash:    Optional[str]
    signature:        Optional[str]
    artifact_json:    Optional[str]
    inserted_at:      str
    denials:          List[dict] = field(default_factory=list)

    def summary(self) -> str:
        """One-line human-readable summary for CLI output."""
        threat_str = ", ".join(
            f"{t['threat_class']}(x{t['count']})"
            for t in self.threats[:5]
        ) if self.threats else "none"
        campaign_str = ", ".join(self.campaigns[:3]) if self.campaigns else "none"
        sig_status = "SIGNED" if self.signature else "unsigned"
        return (
            f"[{self.closed_at[:19]}] agent={self.agent_name}  "
            f"policy={self.policy}  calls={self.total_calls}  "
            f"blocked={self.blocked_calls}  threats={threat_str}  "
            f"campaigns={campaign_str}  {sig_status}"
        )

    def verify_integrity(self) -> bool:
        """
        Verify that the stored artifact_hash matches the artifact_json.
        Does NOT verify the cryptographic signature (requires the signing key).
        Returns True if the stored hash matches the content hash.
        """
        if not self.artifact_json or not self.artifact_hash:
            return False
        computed = hashlib.sha256(self.artifact_json.encode()).hexdigest()
        return computed == self.artifact_hash

    def as_dict(self) -> dict:
        return {
            "session_id":       self.session_id,
            "agent_name":       self.agent_name,
            "policy":           self.policy,
            "started_at":       self.started_at,
            "closed_at":        self.closed_at,
            "total_calls":      self.total_calls,
            "blocked_calls":    self.blocked_calls,
            "warned_calls":     self.warned_calls,
            "threats":          self.threats,
            "campaigns":        self.campaigns,
            "govbench_score":   self.govbench_score,
            "attestation_ready": self.attestation_ready,
            "artifact_hash":    self.artifact_hash,
            "signature":        self.signature,
            "inserted_at":      self.inserted_at,
            "integrity_ok":     self.verify_integrity(),
            "denials":          self.denials,
        }


# ── ForensicStore ─────────────────────────────────────────────────────────────

class ForensicStore:
    """
    Tamper-evident forensic persistence store for Aiglos session artifacts.

    Backed by SQLite at ~/.aiglos/forensics.db (configurable via
    AIGLOS_FORENSICS_DIR environment variable).

    Automatically populated by OpenClawGuard.close_session().
    No manual calls required to persist sessions.

    The "specific Tuesday" answer:
        store = ForensicStore()
        records = store.query(date="2026-03-12", agent="reporting-pipeline")
        for r in records:
            print(r.summary())
            if r.verify_integrity():
                print("  Integrity: OK")
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else _default_db_path()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            conn.executescript(_CREATE_TABLE_SQL)

    def persist(self, artifact: dict, denials: Optional[List[dict]] = None) -> bool:
        """
        Persist a session artifact to the forensic store.

        Called automatically by OpenClawGuard.close_session().
        artifact: the signed session artifact dict from close_session()
        denials: optional list of PermissionDenialEvent.to_dict() records

        Returns True on success, False on duplicate (session already stored).
        """
        now = datetime.now(timezone.utc).isoformat()
        artifact_json = json.dumps(artifact, sort_keys=True)
        artifact_hash = hashlib.sha256(artifact_json.encode()).hexdigest()

        # Extract threat summary
        threats_raw = artifact.get("threats", [])
        if isinstance(threats_raw, list):
            # Count by threat class
            from collections import Counter
            counts = Counter(
                t.get("threat_class", t) if isinstance(t, dict) else t
                for t in threats_raw
            )
            threats_json = json.dumps([
                {"threat_class": k, "count": v}
                for k, v in counts.most_common()
            ])
        else:
            threats_json = json.dumps([])

        campaigns_raw = artifact.get("campaign_detections", [])
        campaigns_json = json.dumps(campaigns_raw if isinstance(campaigns_raw, list) else [])

        try:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT INTO forensic_sessions (
                        session_id, agent_name, policy, started_at, closed_at,
                        total_calls, blocked_calls, warned_calls,
                        threats_json, campaigns_json,
                        govbench_score, attestation_ready,
                        artifact_hash, signature, artifact_json, inserted_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    artifact.get("artifact_id", artifact.get("session_id", "")),
                    artifact.get("agent_name", "unknown"),
                    artifact.get("policy", "unknown"),
                    artifact.get("started_at", now),
                    artifact.get("closed_at", now),
                    artifact.get("total_calls", 0),
                    artifact.get("blocked_calls", 0),
                    artifact.get("warned_calls", 0),
                    threats_json,
                    campaigns_json,
                    artifact.get("govbench_score"),
                    1 if artifact.get("attestation_ready") else 0,
                    artifact_hash,
                    artifact.get("signature"),
                    artifact_json,
                    now,
                ))

                # Persist individual denial events
                if denials:
                    session_id = artifact.get("artifact_id", artifact.get("session_id", ""))
                    agent_name = artifact.get("agent_name", "unknown")
                    for d in denials:
                        conn.execute("""
                            INSERT INTO forensic_denials (
                                session_id, agent_name, tool_name,
                                threat_class, threat_name, score, verdict, timestamp
                            ) VALUES (?,?,?,?,?,?,?,?)
                        """, (
                            session_id, agent_name,
                            d.get("tool_name", ""),
                            d.get("threat_class", ""),
                            d.get("threat_name", ""),
                            d.get("score", 0.0),
                            d.get("verdict", ""),
                            d.get("timestamp", now),
                        ))
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate session_id

    def query(
        self,
        date: Optional[str] = None,
        agent: Optional[str] = None,
        threat: Optional[str] = None,
        policy: Optional[str] = None,
        session: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 50,
        include_denials: bool = True,
    ) -> List[ForensicRecord]:
        """
        Query the forensic store.

        date:    filter by closed_at date prefix (e.g. "2026-03-12")
        agent:   filter by agent_name (substring match)
        threat:  filter by threat class in threats_json (e.g. "T86")
        policy:  filter by policy tier (e.g. "federal")
        session: filter by exact session_id (or prefix)
        since:   ISO datetime -- only sessions closed after this time
        limit:   max records to return (default 50)

        Returns list of ForensicRecord, newest first.

        The "specific Tuesday" query:
            store.query(date="2026-03-12", agent="reporting-pipeline")
        """
        conditions = []
        params = []

        if date:
            conditions.append("closed_at LIKE ?")
            params.append(f"{date}%")
        if agent:
            conditions.append("agent_name LIKE ?")
            params.append(f"%{agent}%")
        if threat:
            conditions.append("threats_json LIKE ?")
            params.append(f"%{threat}%")
        if policy:
            conditions.append("policy = ?")
            params.append(policy)
        if session:
            conditions.append("session_id LIKE ?")
            params.append(f"{session}%")
        if since:
            conditions.append("closed_at >= ?")
            params.append(since)

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"""
            SELECT * FROM forensic_sessions
            {where_clause}
            ORDER BY closed_at DESC
            LIMIT ?
        """
        params.append(limit)

        records = []
        with self._get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            for row in rows:
                denials = []
                if include_denials:
                    denial_rows = conn.execute(
                        "SELECT * FROM forensic_denials WHERE session_id = ? ORDER BY timestamp ASC",
                        (row["session_id"],)
                    ).fetchall()
                    denials = [dict(d) for d in denial_rows]

                records.append(ForensicRecord(
                    session_id       = row["session_id"],
                    agent_name       = row["agent_name"],
                    policy           = row["policy"],
                    started_at       = row["started_at"],
                    closed_at        = row["closed_at"],
                    total_calls      = row["total_calls"],
                    blocked_calls    = row["blocked_calls"],
                    warned_calls     = row["warned_calls"],
                    threats          = json.loads(row["threats_json"] or "[]"),
                    campaigns        = json.loads(row["campaigns_json"] or "[]"),
                    govbench_score   = row["govbench_score"],
                    attestation_ready= bool(row["attestation_ready"]),
                    artifact_hash    = row["artifact_hash"],
                    signature        = row["signature"],
                    artifact_json    = row["artifact_json"],
                    inserted_at      = row["inserted_at"],
                    denials          = denials,
                ))
        return records

    def stats(self) -> dict:
        """Return summary stats about the forensic store."""
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM forensic_sessions").fetchone()[0]
            agents = conn.execute(
                "SELECT COUNT(DISTINCT agent_name) FROM forensic_sessions"
            ).fetchone()[0]
            threats = conn.execute(
                "SELECT COUNT(*) FROM forensic_denials"
            ).fetchone()[0]
            oldest = conn.execute(
                "SELECT MIN(closed_at) FROM forensic_sessions"
            ).fetchone()[0]
            newest = conn.execute(
                "SELECT MAX(closed_at) FROM forensic_sessions"
            ).fetchone()[0]
            signed = conn.execute(
                "SELECT COUNT(*) FROM forensic_sessions WHERE signature IS NOT NULL"
            ).fetchone()[0]
        return {
            "total_sessions":   total,
            "unique_agents":    agents,
            "total_denials":    threats,
            "signed_sessions":  signed,
            "oldest_session":   oldest,
            "newest_session":   newest,
            "db_path":          str(self.db_path),
        }

    def get_session(self, session_id: str) -> Optional[ForensicRecord]:
        """Retrieve a single session by exact session_id."""
        results = self.query(session=session_id, limit=1)
        return results[0] if results else None

    def verify_chain(self, session_id: str) -> dict:
        """
        Verify the integrity of a stored session artifact.

        Returns a dict with:
          hash_ok: bool -- stored hash matches artifact content
          has_signature: bool -- session was cryptographically signed
          session_id: str
        """
        record = self.get_session(session_id)
        if not record:
            return {"error": f"session {session_id} not found"}
        return {
            "session_id":    record.session_id,
            "hash_ok":       record.verify_integrity(),
            "has_signature": bool(record.signature),
            "agent_name":    record.agent_name,
            "closed_at":     record.closed_at,
        }

    def wipe(self, confirm: bool = False) -> bool:
        """
        Delete all forensic records. Requires confirm=True.
        Intended for testing/development only.
        """
        if not confirm:
            return False
        with self._get_conn() as conn:
            conn.execute("DELETE FROM forensic_denials")
            conn.execute("DELETE FROM forensic_sessions")
        return True
