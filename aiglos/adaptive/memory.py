import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class CrossSessionRisk:
    content_hash: str
    sessions_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    semantic_risk: str = "LOW"
    age_hours: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "content_hash": self.content_hash,
            "sessions_count": self.sessions_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "semantic_risk": self.semantic_risk,
            "age_hours": self.age_hours,
        }


@dataclass
class BeliefDriftReport:
    rule_id: str = "T31"
    early_avg_score: float = 0.0
    recent_avg_score: float = 0.0
    drift_ratio: float = 0.0
    severity: str = "LOW"

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "early_avg_score": self.early_avg_score,
            "recent_avg_score": self.recent_avg_score,
            "drift_ratio": self.drift_ratio,
            "severity": self.severity,
        }


class MemoryProvenanceGraph:

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._ensure_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS memory_writes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    content_hash TEXT,
                    verdict TEXT,
                    semantic_risk TEXT DEFAULT 'LOW',
                    semantic_score REAL DEFAULT 0.0,
                    signals TEXT DEFAULT '[]',
                    tool_name TEXT DEFAULT '',
                    content_preview TEXT DEFAULT '',
                    compression_warning INTEGER DEFAULT 0,
                    stored_at REAL,
                    UNIQUE(session_id, content_hash)
                );
            """)

    def ingest_write(self, result: Dict, session_id: str):
        d = result if isinstance(result, dict) else result.to_dict()
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO memory_writes (session_id, content_hash, verdict, semantic_risk, semantic_score, signals, tool_name, content_preview, compression_warning, stored_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (session_id, d.get("content_hash", ""),
                     d.get("verdict", "ALLOW"), d.get("semantic_risk", "LOW"),
                     d.get("semantic_score", 0.0), str(d.get("signals_found", [])),
                     d.get("tool_name", ""), d.get("content_preview", ""),
                     1 if d.get("compression_warning") else 0,
                     d.get("stored_at", d.get("timestamp", time.time()))),
                )
            except Exception:
                pass

    def summary(self) -> Dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM memory_writes").fetchone()[0]
            high = conn.execute("SELECT COUNT(*) FROM memory_writes WHERE semantic_risk='HIGH'").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM memory_writes WHERE verdict='BLOCK'").fetchone()[0]
            sessions = conn.execute("SELECT COUNT(DISTINCT session_id) FROM memory_writes").fetchone()[0]
        risks = self.cross_session_risks()
        return {
            "total_writes": total,
            "high_risk_writes": high,
            "blocked_writes": blocked,
            "sessions_with_writes": sessions,
            "cross_session_risks": len(risks),
        }

    def high_risk_writes(self, last_n_sessions: int = 10) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM memory_writes WHERE semantic_risk='HIGH' OR verdict='BLOCK' ORDER BY stored_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def cross_session_risks(self, min_sessions: int = 2) -> List[CrossSessionRisk]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT content_hash, COUNT(DISTINCT session_id) as cnt, "
                "MIN(stored_at) as first_seen, MAX(stored_at) as last_seen, "
                "MAX(semantic_risk) as max_risk "
                "FROM memory_writes WHERE semantic_risk IN ('HIGH','MEDIUM') OR verdict='BLOCK' "
                "GROUP BY content_hash HAVING cnt >= ?",
                (min_sessions,),
            ).fetchall()
        results = []
        now = time.time()
        for r in rows:
            age = (now - r["first_seen"]) / 3600 if r["first_seen"] else 0
            results.append(CrossSessionRisk(
                content_hash=r["content_hash"],
                sessions_count=r["cnt"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                semantic_risk=r["max_risk"],
                age_hours=age,
            ))
        return results

    def compression_warnings(self, last_n_sessions: int = 10) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM memory_writes WHERE compression_warning=1 ORDER BY stored_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def detect_belief_drift(self) -> Optional[BeliefDriftReport]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT semantic_score FROM memory_writes ORDER BY stored_at"
            ).fetchall()
        if len(rows) < 4:
            return None
        scores = [r["semantic_score"] for r in rows]
        mid = len(scores) // 2
        early = scores[:mid]
        recent = scores[mid:]
        early_avg = sum(early) / len(early) if early else 0
        recent_avg = sum(recent) / len(recent) if recent else 0
        if early_avg < 0.01 and recent_avg > 0.3:
            drift = recent_avg - early_avg
            return BeliefDriftReport(
                rule_id="T31",
                early_avg_score=early_avg,
                recent_avg_score=recent_avg,
                drift_ratio=drift,
                severity="HIGH" if drift > 0.4 else "MEDIUM",
            )
        return None

    def ingest_session_artifact(self, artifact) -> int:
        extra = artifact.extra
        provenance = extra.get("memory_guard_provenance", [])
        sid = extra.get("session_identity", {}).get("session_id", "unknown")
        count = 0
        for wr in provenance:
            self.ingest_write(wr, sid)
            count += 1
        return count
