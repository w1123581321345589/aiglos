"""
aiglos/adaptive/skill_reputation.py
=====================================
ClawKeeper Skill Marketplace badge ingestion.

ClawKeeper scans 13,000+ ClawHub skills and assigns each a security badge:
  Clean      -- no suspicious signals
  Suspicious -- one or more warning signals
  Blocked    -- active threat, do not install

This module ingests that badge data into Aiglos's SourceReputationGraph,
giving every Aiglos deployment pre-populated threat intelligence before
any agent encounters a skill.

Three ingestion paths:

  1. ClawKeeper Security Feed (live polling)
     GET https://clawkeeper.dev/security-feed
     Returns JSON list of recently flagged skills.

  2. ClawKeeper API (Pro tier)
     GET https://api.clawkeeper.dev/v1/skills/reputation
     Returns full badge dataset for Pro subscribers.

  3. Local ClawKeeper audit JSON (file path)
     `aiglos skill import --clawkeeper ./audit.json`
     Ingests badges from a local ClawKeeper audit output file.

The skill reputation is a source-type extension of SourceReputationGraph.
Skill package names are stored as source_key with source_type="skill".
T30 SUPPLY_CHAIN fires when an agent tries to install a Suspicious or Blocked skill.

Network effect extension:
  Skill reputation scores are included in federation sharing.
  A skill that 5+ deployments have blocked is globally BLOCKED.

Usage:
    from aiglos.adaptive.skill_reputation import SkillReputationGraph

    srg = SkillReputationGraph()
    srg.sync_security_feed()   # poll ClawKeeper feed

    risk = srg.get_skill_risk("solana-wallet-tracker")
    # SkillRisk(level="BLOCKED", badge="Blocked", source="clawkeeper")
"""



import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aiglos.adaptive.source_reputation import (
    SourceReputationGraph,
    SourceRecord,
    SourceRisk,
    CLEAN, SUSPICIOUS, HIGH_RISK, BLOCKED,
)

log = logging.getLogger("aiglos.skill_reputation")

# ── Configuration ─────────────────────────────────────────────────────────────

_SECURITY_FEED_URL = "https://clawkeeper.dev/security-feed.json"
_API_BASE          = "https://api.clawkeeper.dev/v1"
_REQUEST_TIMEOUT   = 8.0
_FEED_CACHE_TTL    = 3600   # re-fetch feed every hour

# Badge → score mapping
_BADGE_SCORES = {
    "Blocked":    1.00,
    "blocked":    1.00,
    "BLOCKED":    1.00,
    "Suspicious": 0.65,
    "suspicious": 0.65,
    "SUSPICIOUS": 0.65,
    "Clean":      0.00,
    "clean":      0.00,
    "CLEAN":      0.00,
}

# Score → verdict for T30
_SCORE_VERDICT = {
    1.00: "BLOCK",
    0.65: "WARN",
    0.00: "ALLOW",
}


@dataclass
class SkillRisk:
    """Risk assessment for a specific skill package."""
    skill_name:  str
    badge:       str    # ClawKeeper badge: Clean | Suspicious | Blocked
    level:       str    # Aiglos reputation level
    score:       float
    source:      str    # "clawkeeper" | "federation" | "internal"
    last_updated: Optional[float] = None
    detail:      str    = ""

    @property
    def should_block(self) -> bool:
        return self.level == BLOCKED

    @property
    def should_warn(self) -> bool:
        return self.level in (SUSPICIOUS, HIGH_RISK)


class SkillReputationGraph(SourceReputationGraph):
    """
    Extends SourceReputationGraph with ClawKeeper Skill Marketplace badge data.

    Skills are stored with source_type="skill" and source_key = package name.
    The standard get_risk() method works for URL-based lookups.
    get_skill_risk() provides the skill-specific interface.
    """

    def __init__(self, graph=None, clawkeeper_api_key: str = ""):
        super().__init__(graph=graph)
        self._ck_api_key   = clawkeeper_api_key
        self._last_feed_fetch: float = 0.0

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def sync_security_feed(self) -> int:
        """
        Poll the ClawKeeper security feed and ingest new badges.
        Returns number of skills ingested.
        Fails gracefully on network errors -- never blocks the agent path.
        """
        if time.time() - self._last_feed_fetch < _FEED_CACHE_TTL:
            log.debug("[SkillReputationGraph] Feed cache fresh, skipping sync")
            return 0

        try:
            req  = urllib.request.Request(
                _SECURITY_FEED_URL,
                headers={"User-Agent": "aiglos/0.17.0"},
            )
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                if resp.getcode() != 200:
                    return 0
                data = json.loads(resp.read().decode("utf-8"))

            count = self._ingest_feed_data(data)
            self._last_feed_fetch = time.time()
            log.info("[SkillReputationGraph] Feed sync: %d skills ingested", count)
            return count

        except (OSError, urllib.error.URLError, TimeoutError) as e:
            log.debug("[SkillReputationGraph] Feed sync network error: %s", e)
            return 0
        except Exception as e:
            log.debug("[SkillReputationGraph] Feed sync error: %s", e)
            return 0

    def ingest_clawkeeper_audit(self, audit_data: dict) -> int:
        """
        Ingest badge data from a local ClawKeeper audit JSON file.

        The ClawKeeper audit output includes a "skills" section with
        per-skill badge assessments. Pass the parsed JSON directly.

        Returns number of skills ingested.
        """
        skills = (
            audit_data.get("skills") or
            audit_data.get("skill_scan") or
            audit_data.get("supply_chain", {}).get("skills", [])
        )
        if not skills:
            log.debug("[SkillReputationGraph] No skills section in audit data")
            return 0

        return self._ingest_skill_list(skills, source="clawkeeper_audit")

    def ingest_badge_list(self, badges: List[Dict[str, Any]], source: str = "clawkeeper") -> int:
        """
        Ingest a list of skill badge records.
        Expected format: [{"name": "skill-name", "badge": "Blocked", ...}, ...]
        """
        return self._ingest_skill_list(badges, source=source)

    # ── Risk queries ──────────────────────────────────────────────────────────

    def get_skill_risk(self, skill_name: str) -> SkillRisk:
        """
        Get reputation risk for a skill by package name.
        Returns SkillRisk -- always returns something, never raises.
        """
        key = self._skill_key(skill_name)
        rec = self._get_record(key)

        if not rec:
            return SkillRisk(
                skill_name   = skill_name,
                badge        = "Unknown",
                level        = CLEAN,
                score        = 0.0,
                source       = "none",
                detail       = "No reputation data. Scan with: aiglos skill scan " + skill_name,
            )

        badge = self._score_to_badge(rec.max_score)
        return SkillRisk(
            skill_name   = skill_name,
            badge        = badge,
            level        = rec.reputation_level,
            score        = rec.max_score,
            source       = rec.tool_names[0] if rec.tool_names else "unknown",
            last_updated = rec.last_seen,
            detail       = f"{rec.event_count} ingestion event(s). Rules: {', '.join(set(rec.rule_ids[:3]))}.",
        )

    def blocked_skills(self) -> List[str]:
        """Return list of all skill names with BLOCKED reputation."""
        blocked = []
        for key, rec in self._cache.items():
            if key.startswith("skill::") and rec.reputation_level == BLOCKED:
                blocked.append(key.replace("skill::", ""))
        return blocked

    def suspicious_skills(self) -> List[str]:
        """Return list of skill names with SUSPICIOUS or HIGH_RISK reputation."""
        risky = []
        for key, rec in self._cache.items():
            if key.startswith("skill::") and rec.reputation_level in (SUSPICIOUS, HIGH_RISK):
                risky.append(key.replace("skill::", ""))
        return risky

    # ── Internal ─────────────────────────────────────────────────────────────

    def _ingest_feed_data(self, data: Any) -> int:
        """Normalize and ingest feed data in various formats."""
        if isinstance(data, list):
            return self._ingest_skill_list(data, source="clawkeeper_feed")
        if isinstance(data, dict):
            skills = (data.get("skills") or data.get("blocked") or
                      data.get("flagged") or [])
            if isinstance(skills, list):
                return self._ingest_skill_list(skills, source="clawkeeper_feed")
        return 0

    def _ingest_skill_list(self, skills: List[Any], source: str) -> int:
        count = 0
        for item in skills:
            if not isinstance(item, dict):
                continue

            name  = (item.get("name") or item.get("skill") or
                     item.get("package") or "")
            badge = (item.get("badge") or item.get("status") or
                     item.get("security_badge") or "Unknown")
            if not name:
                continue

            score = _BADGE_SCORES.get(badge, 0.0)
            if score < 0.01:
                continue   # skip Clean skills -- no threat record needed

            key = self._skill_key(name)
            self._update_record(
                source_key  = key,
                source_type = "skill",
                score       = score,
                verdict     = _SCORE_VERDICT.get(score, "WARN"),
                rule_id     = "T30",
                tool_name   = source,
                now         = time.time(),
            )
            # Force BLOCKED level when badge is explicitly Blocked
            if score >= 0.99:
                rec = self._cache.get(key)
                if rec:
                    rec.network_flags = 5   # triggers BLOCKED level
            count += 1

        return count

    def _skill_key(self, name: str) -> str:
        """Normalize skill name to a consistent cache key."""
        return f"skill::{name.lower().strip()}"

    def _score_to_badge(self, score: float) -> str:
        if score >= 0.80: return "Blocked"
        if score >= 0.40: return "Suspicious"
        return "Clean"

    # ── Federation sharing ────────────────────────────────────────────────────

    def get_shareable_skill_reputation(self) -> List[dict]:
        """
        Return anonymized skill reputation data for federation sharing.
        Only includes Suspicious/Blocked skills -- no Clean skills, no session data.
        """
        shareable = []
        for key, rec in self._cache.items():
            if not key.startswith("skill::"):
                continue
            if rec.reputation_level == CLEAN:
                continue
            name = key.replace("skill::", "")
            shareable.append({
                "skill":       name,
                "badge":       self._score_to_badge(rec.max_score),
                "max_score":   round(rec.max_score, 2),
                "event_count": rec.event_count,
                "level":       rec.reputation_level,
            })
        return shareable
