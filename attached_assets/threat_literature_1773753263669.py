"""
aiglos.autoresearch.threat_literature
=======================================
Continuous threat intelligence surveillance for AI agent security.

The arXiv/Semantic Scholar equivalent for the security domain.

Polls three live sources for new threat patterns relevant to AI agents:
  1. NVD CVE feed — new CVEs tagged with AI agent keywords
  2. OWASP references — updates to the agentic AI taxonomy
  3. GitHub Security Advisories — new package vulnerabilities

When a new relevant threat is found, it creates a ThreatSignal — a
structured alert that the autoresearch loop can use to generate new
detection rules or update existing ones.

The surveillance loop runs continuously in the background and stores
signals in the observation graph. The THREAT_LITERATURE_MATCH inspection
trigger (14th) fires when new signals appear that map to coverage gaps.

This is the mechanism that makes Aiglos's rules compound with the network
effect. New CVEs become new rules. New OWASP updates become rule improvements.
The detection engine is never static.

Usage:
    from aiglos.autoresearch.threat_literature import ThreatLiteratureSearch

    searcher = ThreatLiteratureSearch()
    signals  = searcher.scan_new_threats(since_days=7)
    for signal in signals:
        print(signal.summary())
    # ThreatSignal(source=NVD, cve=CVE-2026-25253, relevance=0.91,
    #              suggested_rule=T36_AGENTDEF)
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("aiglos.threat_literature")

# ── Configuration ─────────────────────────────────────────────────────────────

_NVD_BASE        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_GHSA_API_BASE   = "https://api.github.com/advisories"
_REQUEST_TIMEOUT = 8.0
_NVD_RATE_LIMIT  = 0.7

# Keywords that indicate AI agent security relevance
_AI_AGENT_KEYWORDS = [
    "claude code", "openclaw", "clawdbot", "cursor", "copilot",
    "mcp", "model context protocol", "ai agent", "llm agent",
    "autonomous agent", "agentic", "tool call", "function call",
    "prompt injection", "ai coding assistant",
    "language model", "large language model",
]

# Keyword-to-rule mapping for auto-suggestion
_KEYWORD_RULE_MAP = {
    "prompt injection":         "T01",
    "indirect injection":       "T27",
    "ssrf":                     "T03",
    "shell injection":          "T07",
    "command injection":        "T07",
    "privilege escalation":     "T08",
    "credential":               "T19",
    "exfiltration":             "T22",
    "supply chain":             "T30",
    "memory poisoning":         "T31",
    "agent definition":         "T36_AGENTDEF",
    "financial":                "T37",
    "agent spawn":              "T38",
    "reward poison":            "T39",
    "rce":                      "T10",
    "remote code execution":    "T10",
    "persistent":               "T11",
    "lateral movement":         "T12",
    "data exfil":               "T22",
    "authorization bypass":     "T08",
}


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class ThreatSignal:
    """
    A new threat pattern detected from external surveillance.
    May trigger a new rule proposal or an update to an existing rule.
    """
    signal_id:       str
    source:          str          # "NVD" | "GHSA" | "OWASP"
    reference_id:    str          # CVE ID, GHSA ID, or OWASP reference
    title:           str
    description:     str
    published_at:    str
    relevance_score: float        # 0.0-1.0 AI agent relevance
    suggested_rule:  Optional[str]  # Aiglos rule ID this maps to
    is_new:          bool = True
    detected_at:     float = field(default_factory=time.time)
    keywords_matched: List[str] = field(default_factory=list)

    def summary(self) -> str:
        rule_str = f" → {self.suggested_rule}" if self.suggested_rule else ""
        return (
            f"[{self.source}] {self.reference_id}: {self.title[:60]} "
            f"(relevance={self.relevance_score:.0%}{rule_str})"
        )

    def to_dict(self) -> dict:
        return {
            "signal_id":        self.signal_id,
            "rule_id":          self.suggested_rule or "",
            "source":           self.source,
            "reference_id":     self.reference_id,
            "title":            self.title,
            "description":      self.description[:500],
            "published_at":     self.published_at,
            "relevance_score":  round(self.relevance_score, 4),
            "suggested_rule":   self.suggested_rule,
            "is_new":           self.is_new,
            "detected_at":      self.detected_at,
            "keywords_matched": self.keywords_matched,
        }


# ── ThreatLiteratureSearch ────────────────────────────────────────────────────

class ThreatLiteratureSearch:
    """
    Continuous surveillance of external threat intelligence sources.

    Scans for new CVEs, advisories, and taxonomy updates relevant to
    AI agent security. Produces ThreatSignals that feed the autoresearch loop.

    All network calls are best-effort with hard timeouts. Network failures
    are logged and ignored — the surveillance loop never blocks the agent path.
    """

    def __init__(self, graph=None, timeout: float = _REQUEST_TIMEOUT):
        self._graph   = graph
        self._timeout = timeout
        self._last_nvd_call: float = 0.0

    def scan_new_threats(self, since_days: int = 7) -> List[ThreatSignal]:
        """
        Scan all sources for new threat signals in the past N days.
        Returns list of ThreatSignals sorted by relevance descending.
        """
        signals: List[ThreatSignal] = []

        nvd_signals  = self._scan_nvd(since_days)
        ghsa_signals = self._scan_ghsa(since_days)

        signals.extend(nvd_signals)
        signals.extend(ghsa_signals)

        # Deduplicate by reference_id
        seen = set()
        deduped = []
        for s in signals:
            if s.reference_id not in seen:
                seen.add(s.reference_id)
                deduped.append(s)

        # Sort by relevance
        deduped.sort(key=lambda s: s.relevance_score, reverse=True)

        # Persist to graph
        for signal in deduped:
            self._persist_signal(signal)

        log.info(
            "[ThreatLiteratureSearch] Scan complete: %d signals "
            "(NVD=%d GHSA=%d) since_days=%d",
            len(deduped), len(nvd_signals), len(ghsa_signals), since_days,
        )
        return deduped

    def get_signals_for_rule(
        self, rule_id: str, limit: int = 10
    ) -> List[ThreatSignal]:
        """Fetch stored threat signals that map to a specific rule."""
        if not self._graph:
            return []
        try:
            return self._graph.get_threat_signals(rule_id=rule_id, limit=limit)
        except Exception as e:
            log.debug("[ThreatLiteratureSearch] Get signals error: %s", e)
            return []

    def coverage_gaps(self) -> List[str]:
        """
        Return list of rule IDs that have no recent threat signals.
        These are coverage gaps — rules that may be drifting from current threats.
        """
        if not self._graph:
            return []
        try:
            all_rules = [f"T{i:02d}" for i in range(1, 40)] + ["T36_AGENTDEF"]
            gaps = []
            for rule_id in all_rules:
                signals = self.get_signals_for_rule(rule_id, limit=1)
                if not signals:
                    gaps.append(rule_id)
            return gaps
        except Exception:
            return []

    # ── NVD scan ──────────────────────────────────────────────────────────

    def _scan_nvd(self, since_days: int) -> List[ThreatSignal]:
        """Scan NVD for new AI agent CVEs."""
        signals = []

        # Query each AI agent keyword cluster
        keyword_clusters = [
            "AI agent prompt injection",
            "AI coding agent vulnerability",
            "MCP model context protocol",
            "LLM agent security",
        ]

        for keyword in keyword_clusters:
            try:
                self._nvd_rate_limit()
                cluster_signals = self._nvd_search(keyword, since_days)
                signals.extend(cluster_signals)
            except Exception as e:
                log.debug("[ThreatLiteratureSearch] NVD cluster error: %s", e)

        return signals

    def _nvd_search(self, keyword: str, since_days: int) -> List[ThreatSignal]:
        """Single NVD keyword search."""
        try:
            # Build date range
            import datetime as _dt
            end   = _dt.datetime.utcnow()
            start = end - _dt.timedelta(days=since_days)
            fmt   = "%Y-%m-%dT%H:%M:%S.000"

            params = urllib.parse.urlencode({
                "keywordSearch":  keyword,
                "pubStartDate":   start.strftime(fmt),
                "pubEndDate":     end.strftime(fmt),
                "resultsPerPage": 10,
            })
            url = f"{_NVD_BASE}?{params}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "aiglos/0.14.0"}
            )
            self._last_nvd_call = time.time()
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.getcode() != 200:
                    return []
                data = json.loads(resp.read().decode("utf-8"))

            signals = []
            for vuln in data.get("vulnerabilities", []):
                cve  = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                descs = cve.get("descriptions", [])
                desc  = next(
                    (d.get("value", "") for d in descs if d.get("lang") == "en"),
                    ""
                )
                published = cve.get("published", "")

                relevance, keywords_matched = self._score_relevance(
                    f"{cve_id} {desc}"
                )
                if relevance < 0.30:
                    continue

                suggested = self._suggest_rule(desc)

                import hashlib as _hs
                sig_id = "sig_" + _hs.sha256(cve_id.encode()).hexdigest()[:12]

                signals.append(ThreatSignal(
                    signal_id        = sig_id,
                    source           = "NVD",
                    reference_id     = cve_id,
                    title            = cve_id,
                    description      = desc,
                    published_at     = published,
                    relevance_score  = relevance,
                    suggested_rule   = suggested,
                    keywords_matched = keywords_matched,
                ))

            return signals

        except (OSError, urllib.error.URLError, TimeoutError) as e:
            log.debug("[ThreatLiteratureSearch] NVD network error: %s", e)
            return []

    def _nvd_rate_limit(self) -> None:
        elapsed = time.time() - self._last_nvd_call
        if elapsed < _NVD_RATE_LIMIT:
            time.sleep(_NVD_RATE_LIMIT - elapsed)

    # ── GitHub Security Advisory scan ─────────────────────────────────────

    def _scan_ghsa(self, since_days: int) -> List[ThreatSignal]:
        """Scan GitHub Security Advisories for AI agent package vulnerabilities."""
        try:
            import datetime as _dt
            cutoff = (_dt.datetime.utcnow() -
                      _dt.timedelta(days=since_days)).isoformat() + "Z"

            params = urllib.parse.urlencode({
                "type":       "reviewed",
                "per_page":   20,
                "sort":       "published",
                "direction":  "desc",
            })
            url = f"{_GHSA_API_BASE}?{params}"
            req = urllib.request.Request(
                url,
                headers={
                    "Accept":     "application/vnd.github+json",
                    "User-Agent": "aiglos/0.14.0",
                }
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.getcode() != 200:
                    return []
                advisories = json.loads(resp.read().decode("utf-8"))

            signals = []
            for adv in advisories:
                ghsa_id   = adv.get("ghsa_id", "")
                summary   = adv.get("summary", "")
                desc      = adv.get("description", "")
                published = adv.get("published_at", "")

                if published < cutoff:
                    continue

                relevance, keywords_matched = self._score_relevance(
                    f"{summary} {desc}"
                )
                if relevance < 0.25:
                    continue

                suggested = self._suggest_rule(f"{summary} {desc}")

                import hashlib as _hs
                sig_id = "sig_" + _hs.sha256(ghsa_id.encode()).hexdigest()[:12]

                signals.append(ThreatSignal(
                    signal_id        = sig_id,
                    source           = "GHSA",
                    reference_id     = ghsa_id,
                    title            = summary[:100],
                    description      = desc,
                    published_at     = published,
                    relevance_score  = relevance,
                    suggested_rule   = suggested,
                    keywords_matched = keywords_matched,
                ))

            return signals

        except (OSError, urllib.error.URLError, TimeoutError) as e:
            log.debug("[ThreatLiteratureSearch] GHSA network error: %s", e)
            return []
        except Exception as e:
            log.debug("[ThreatLiteratureSearch] GHSA error: %s", e)
            return []

    # ── Scoring ───────────────────────────────────────────────────────────

    def _score_relevance(self, text: str) -> tuple[float, list]:
        """Score how relevant a piece of text is to AI agent security."""
        text_lower = text.lower()
        matched    = []

        for kw in _AI_AGENT_KEYWORDS:
            if kw in text_lower:
                matched.append(kw)

        if not matched:
            return 0.0, []

        # Base score from match count, saturates at 5 matches
        base = min(len(matched) / 5.0, 1.0)

        # Bonus for high-signal keywords
        high_signal = ["prompt injection", "agent", "mcp", "openclaw",
                       "clawdbot", "claude code", "cursor", "autonomous"]
        bonus = sum(0.10 for kw in high_signal if kw in text_lower)

        return min(round(base * 0.70 + bonus, 4), 1.0), matched

    def _suggest_rule(self, text: str) -> Optional[str]:
        """Suggest the most relevant Aiglos rule for a threat description."""
        text_lower = text.lower()
        best_rule  = None
        best_count = 0

        for keyword, rule_id in _KEYWORD_RULE_MAP.items():
            if keyword in text_lower:
                count = text_lower.count(keyword)
                if count > best_count:
                    best_count = count
                    best_rule  = rule_id

        return best_rule

    # ── Persistence ───────────────────────────────────────────────────────

    def _persist_signal(self, signal: ThreatSignal) -> None:
        if not self._graph:
            return
        try:
            self._graph.upsert_threat_signal(signal)
        except Exception as e:
            log.debug("[ThreatLiteratureSearch] Persist error: %s", e)
