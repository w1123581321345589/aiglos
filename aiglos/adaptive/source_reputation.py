"""
aiglos.adaptive.source_reputation
====================================
Source-level threat intelligence -- URL and document reputation tracking.

The injection scanner catches threats after they arrive in the agent's context.
Source reputation catches them before.

After session 1: The injection scanner flagged content from
https://attacker.com/docs at score 0.81 (T27 INBOUND_INJECTION).
This gets recorded against the source URL.

Session 2: Before the agent fetches from that URL again, source reputation
is checked. The URL is HIGH_RISK. The injection threshold is pre-elevated.
The agent gets a WARN before the content even loads.

Session 10: The URL has been flagged 8 times across the network.
BLOCK on fetch -- the agent never sees the content.

This is the Context Hub mechanism applied to threat intelligence:
  Session 1: Agent encounters injection, annotates the source.
  Session 2: That annotation auto-loads. Elevated scrutiny.
  Session 10: Pattern confirmed. Source blocked.

Three reputation levels:
  CLEAN       -- no injection history, normal trust
  SUSPICIOUS  -- 1–2 injection events, score-weighted scrutiny
  HIGH_RISK   -- 3+ events or single HIGH severity, elevated threshold
  BLOCKED     -- network consensus or local pattern: do not fetch

Scope:
  - Per-URL (exact and domain-level)
  - Per-document (hashed content fingerprint)
  - Per-tool (which tool returned bad content)

Federation extension:
  Source reputation scores can be shared via the federation layer.
  A URL that 12 deployments have flagged is globally HIGH_RISK.
  New deployments start with network-validated source reputation
  rather than learning it from scratch.

Usage:
    from aiglos.adaptive.source_reputation import SourceReputationGraph

    graph = SourceReputationGraph()

    # After injection scanner flags a source:
    graph.record_event(
        source_url  = "https://attacker.com/docs",
        tool_name   = "web_search",
        score       = 0.81,
        verdict     = "BLOCK",
        rule_id     = "T27",
        session_id  = "sess-abc",
    )

    # Before fetching:
    risk = graph.get_risk("https://attacker.com/docs")
    # SourceRisk(level="HIGH_RISK", score=0.81, event_count=1,
    #            recommendation="ELEVATE_THRESHOLD")
"""



import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger("aiglos.source_reputation")

# ── Configuration ─────────────────────────────────────────────────────────────

_SUSPICIOUS_THRESHOLD  = 1     # events to reach SUSPICIOUS
_HIGH_RISK_THRESHOLD   = 3     # events to reach HIGH_RISK
_BLOCKED_THRESHOLD     = 8     # events to reach BLOCKED (local)
_NETWORK_BLOCK_COUNT   = 5     # deployments flagging same source = BLOCKED
_SCORE_DECAY_DAYS      = 30    # reputation decays after inactivity
_DOMAIN_PROPAGATION    = True  # flag on exact URL propagates to domain

# Reputation levels
CLEAN      = "CLEAN"
SUSPICIOUS = "SUSPICIOUS"
HIGH_RISK  = "HIGH_RISK"
BLOCKED    = "BLOCKED"


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class SourceRecord:
    """Reputation record for a single source (URL, domain, or content hash)."""
    source_key:     str          # normalized URL, domain, or content hash
    source_type:    str          # "url" | "domain" | "document"
    event_count:    int = 0
    max_score:      float = 0.0
    avg_score:      float = 0.0
    last_seen:      float = field(default_factory=time.time)
    first_seen:     float = field(default_factory=time.time)
    verdicts:       List[str] = field(default_factory=list)   # BLOCK/WARN/ALLOW
    rule_ids:       List[str] = field(default_factory=list)   # T27, T01, etc.
    tool_names:     List[str] = field(default_factory=list)
    network_flags:  int = 0      # how many deployments have flagged this

    @property
    def reputation_level(self) -> str:
        """Current reputation level based on accumulated evidence."""
        if self.network_flags >= _NETWORK_BLOCK_COUNT:
            return BLOCKED
        if self.event_count >= _BLOCKED_THRESHOLD:
            return BLOCKED
        if self.event_count >= _HIGH_RISK_THRESHOLD or self.max_score >= 0.75:
            return HIGH_RISK
        if self.event_count >= _SUSPICIOUS_THRESHOLD or self.max_score >= 0.40:
            return SUSPICIOUS
        return CLEAN

    @property
    def is_stale(self) -> bool:
        """Return True if the record hasn't been updated in _SCORE_DECAY_DAYS."""
        return (time.time() - self.last_seen) > (_SCORE_DECAY_DAYS * 86400)

    def to_dict(self) -> dict:
        return {
            "source_key":    self.source_key,
            "source_type":   self.source_type,
            "event_count":   self.event_count,
            "max_score":     round(self.max_score, 4),
            "avg_score":     round(self.avg_score, 4),
            "last_seen":     self.last_seen,
            "first_seen":    self.first_seen,
            "verdicts":      self.verdicts[-10:],  # keep last 10
            "rule_ids":      list(set(self.rule_ids)),
            "tool_names":    list(set(self.tool_names)),
            "network_flags": self.network_flags,
            "reputation_level": self.reputation_level,
        }


@dataclass
class SourceRisk:
    """
    Risk assessment for a source before content is fetched.
    Used by before_tool_call() to pre-elevate scrutiny.
    """
    source_key:      str
    level:           str       # CLEAN | SUSPICIOUS | HIGH_RISK | BLOCKED
    score:           float
    event_count:     int
    last_seen:       Optional[float]
    recommendation:  str       # NORMAL | ELEVATE_THRESHOLD | BLOCK
    evidence_summary: str = ""

    @property
    def should_block(self) -> bool:
        return self.level == BLOCKED

    @property
    def should_elevate(self) -> bool:
        return self.level in (SUSPICIOUS, HIGH_RISK)

    @property
    def threshold_multiplier(self) -> float:
        """
        Score threshold multiplier to apply when scanning content from this source.
        HIGH_RISK: 0.5x threshold (more sensitive)
        SUSPICIOUS: 0.75x threshold
        CLEAN: 1.0x (normal)
        """
        if self.level in (BLOCKED, HIGH_RISK):
            return 0.5
        if self.level == SUSPICIOUS:
            return 0.75
        return 1.0


# ── Normalization helpers ─────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """Normalize a URL for consistent keying."""
    try:
        parsed = urlparse(url.strip().lower())
        # Drop query string and fragment for domain-level matching
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    except Exception:
        return url.lower().strip()


def _extract_domain(url: str) -> str:
    """Extract domain from URL for domain-level reputation."""
    try:
        parsed = urlparse(url.strip().lower())
        return parsed.netloc or url
    except Exception:
        return url.lower().strip()


def _content_fingerprint(content: str) -> str:
    """SHA-256 fingerprint of document content for document-level reputation."""
    return "doc_" + hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:24]


# ── SourceReputationGraph ─────────────────────────────────────────────────────

class SourceReputationGraph:
    """
    Persistent reputation tracking for URLs, domains, and documents.

    Records injection events against their source. Provides pre-fetch
    risk assessment so the scanning threshold can be elevated before
    content even enters the agent's context.

    Context Hub integration: the same annotation persistence mechanism
    that Context Hub uses for API docs -- but for threat intelligence.
    An injection detected in session 1 auto-loads as elevated scrutiny
    in session 2, without any manual configuration.
    """

    def __init__(self, graph=None):
        self._graph = graph
        # In-memory cache for current session
        self._cache: Dict[str, SourceRecord] = {}

    # ── Event recording ───────────────────────────────────────────────────────

    def record_event(
        self,
        source_url:  Optional[str],
        tool_name:   str,
        score:       float,
        verdict:     str,
        rule_id:     str   = "",
        session_id:  str   = "",
        content:     Optional[str] = None,
    ) -> None:
        """
        Record an injection event against a source.
        Called by the injection scanner after_tool_call() via OpenClawGuard.

        Persists:
          1. URL-level record (exact URL)
          2. Domain-level record (if DOMAIN_PROPAGATION is enabled)
          3. Document-level record (if content provided)
        """
        if score < 0.25:
            return  # below signal threshold -- don't pollute reputation

        now = time.time()

        if source_url:
            norm_url = _normalize_url(source_url)
            self._update_record(
                source_key  = norm_url,
                source_type = "url",
                score       = score,
                verdict     = verdict,
                rule_id     = rule_id,
                tool_name   = tool_name,
                now         = now,
            )

            if _DOMAIN_PROPAGATION:
                domain = _extract_domain(source_url)
                if domain and domain != norm_url:
                    self._update_record(
                        source_key  = domain,
                        source_type = "domain",
                        score       = score * 0.7,   # domain gets dampened score
                        verdict     = verdict,
                        rule_id     = rule_id,
                        tool_name   = tool_name,
                        now         = now,
                    )

        if content:
            fp = _content_fingerprint(content)
            self._update_record(
                source_key  = fp,
                source_type = "document",
                score       = score,
                verdict     = verdict,
                rule_id     = rule_id,
                tool_name   = tool_name,
                now         = now,
            )

        log.debug(
            "[SourceReputationGraph] Recorded: url=%s score=%.2f verdict=%s",
            source_url or "none", score, verdict,
        )

    def _update_record(
        self,
        source_key: str,
        source_type: str,
        score: float,
        verdict: str,
        rule_id: str,
        tool_name: str,
        now: float,
    ) -> None:
        """Update or create a SourceRecord."""
        rec = self._cache.get(source_key)
        if not rec and self._graph:
            rec = self._load_from_graph(source_key)

        if rec:
            rec.event_count += 1
            rec.max_score    = max(rec.max_score, score)
            rec.avg_score    = (rec.avg_score * (rec.event_count - 1) + score) / rec.event_count
            rec.last_seen    = now
            if verdict:
                rec.verdicts.append(verdict)
            if rule_id:
                rec.rule_ids.append(rule_id)
            if tool_name:
                rec.tool_names.append(tool_name)
        else:
            rec = SourceRecord(
                source_key  = source_key,
                source_type = source_type,
                event_count = 1,
                max_score   = score,
                avg_score   = score,
                last_seen   = now,
                first_seen  = now,
                verdicts    = [verdict] if verdict else [],
                rule_ids    = [rule_id] if rule_id else [],
                tool_names  = [tool_name] if tool_name else [],
            )

        self._cache[source_key] = rec
        if self._graph:
            self._persist_record(rec)

    # ── Risk assessment ───────────────────────────────────────────────────────

    def get_risk(
        self,
        source_url: Optional[str] = None,
        content:    Optional[str] = None,
    ) -> SourceRisk:
        """
        Get reputation risk for a source before content is fetched.

        Returns SourceRisk with level, recommendation, and threshold_multiplier.
        Called by before_tool_call() before any fetch operation.
        """
        records = []

        if source_url:
            norm_url = _normalize_url(source_url)
            rec = self._get_record(norm_url)
            if rec and not rec.is_stale:
                records.append(rec)

            domain = _extract_domain(source_url)
            if domain and domain != norm_url:
                dom_rec = self._get_record(domain)
                if dom_rec and not dom_rec.is_stale:
                    records.append(dom_rec)

        if content:
            fp = _content_fingerprint(content)
            rec = self._get_record(fp)
            if rec and not rec.is_stale:
                records.append(rec)

        if not records:
            return SourceRisk(
                source_key       = source_url or "",
                level            = CLEAN,
                score            = 0.0,
                event_count      = 0,
                last_seen        = None,
                recommendation   = "NORMAL",
                evidence_summary = "No reputation history.",
            )

        # Use the worst record
        worst = max(records, key=lambda r: r.max_score)
        level = worst.reputation_level

        recommendation = "NORMAL"
        if level == BLOCKED:
            recommendation = "BLOCK"
        elif level == HIGH_RISK:
            recommendation = "ELEVATE_THRESHOLD"
        elif level == SUSPICIOUS:
            recommendation = "ELEVATE_THRESHOLD"

        age_days = (time.time() - worst.last_seen) / 86400
        summary  = (
            f"{level}: {worst.event_count} injection event(s), "
            f"max score {worst.max_score:.2f}, "
            f"last seen {age_days:.1f} days ago. "
            f"Rules: {', '.join(set(worst.rule_ids[:3]))}."
        )

        return SourceRisk(
            source_key       = worst.source_key,
            level            = level,
            score            = worst.max_score,
            event_count      = worst.event_count,
            last_seen        = worst.last_seen,
            recommendation   = recommendation,
            evidence_summary = summary,
        )

    def _get_record(self, key: str) -> Optional[SourceRecord]:
        """Fetch from cache, then graph."""
        if key in self._cache:
            return self._cache[key]
        if self._graph:
            rec = self._load_from_graph(key)
            if rec:
                self._cache[key] = rec
            return rec
        return None

    # ── Queries ───────────────────────────────────────────────────────────────

    def top_risky_sources(self, limit: int = 10) -> List[SourceRecord]:
        """Return the most dangerous sources sorted by max_score."""
        all_records = list(self._cache.values())
        if self._graph:
            try:
                db_records = self._graph.list_source_records(limit=100)
                seen = {r.source_key for r in all_records}
                for r in db_records:
                    if r.source_key not in seen:
                        all_records.append(r)
            except Exception:
                pass

        dangerous = [r for r in all_records if r.reputation_level != CLEAN]
        return sorted(dangerous, key=lambda r: r.max_score, reverse=True)[:limit]

    def domain_summary(self) -> Dict[str, int]:
        """Return count of flagged sources per domain."""
        summary = {}
        for rec in self._cache.values():
            if rec.source_type == "domain" and rec.reputation_level != CLEAN:
                summary[rec.source_key] = rec.event_count
        return dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))

    def get_shareable_reputation(self) -> List[dict]:
        """
        Return anonymized reputation data for federation sharing.
        Only includes domains (not exact URLs) above SUSPICIOUS level.
        No session IDs, no content, no agent names.
        """
        shareable = []
        for rec in self._cache.values():
            if rec.source_type == "domain" and rec.reputation_level != CLEAN:
                shareable.append({
                    "domain":       rec.source_key,
                    "event_count":  rec.event_count,
                    "max_score":    round(rec.max_score, 2),
                    "rule_ids":     list(set(rec.rule_ids)),
                    "level":        rec.reputation_level,
                })
        return shareable

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist_record(self, rec: SourceRecord) -> None:
        try:
            self._graph.upsert_source_record(rec)
        except Exception as e:
            log.debug("[SourceReputationGraph] Persist error: %s", e)

    def _load_from_graph(self, source_key: str) -> Optional[SourceRecord]:
        try:
            return self._graph.get_source_record(source_key)
        except Exception:
            return None
