"""
aiglos/adaptive/permission_recommender.py
==========================================
Minimum viable permission recommender.

After hardening ("your agents might feel dumb, don't panic"), the instinct
is to re-open every permission the agent had before. That's the wrong move.
The right move is to open only what the agent actually needs.

PermissionRecommender answers that question empirically:
  - Queries the observation graph across all sessions for a specific agent
  - Builds a complete picture of which tools were called, how often,
    with what verdicts (ALLOW/WARN/BLOCK), and across which sessions
  - Returns a minimum viable allowlist: tools the agent actually uses
  - Flags tools that were only ever called with BLOCK verdicts
    (the agent tried to use them, but shouldn't be allowed to)
  - Formats output as ready-to-paste OpenClaw config JSON

The output closes the loop between what Aiglos observes and what
OpenClaw enforces. You don't have to guess what your agent needs.
The observation graph already knows.

Usage:
    from aiglos.adaptive.permission_recommender import PermissionRecommender

    rec = PermissionRecommender(graph=graph)
    recommendation = rec.recommend(agent_name="my-agent")
    print(recommendation.openclaw_config())
    # {
    #   "tools": {
    #     "allowed": ["filesystem.read_file", "web_search", "http.get"],
    #     "blocked":  ["shell.execute", "filesystem.write_file"]
    #   }
    # }

CLI:
    aiglos policy recommend --agent my-agent
    aiglos policy recommend --agent my-agent --format json
    aiglos policy recommend --agent my-agent --format openclaw
"""



import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("aiglos.permission_recommender")


@dataclass
class ToolUsageStats:
    """Usage statistics for a single tool across all sessions."""
    tool_name:      str
    total_calls:    int = 0
    allow_calls:    int = 0
    warn_calls:     int = 0
    block_calls:    int = 0
    session_count:  int = 0    # distinct sessions that called this tool
    last_called:    float = 0.0

    @property
    def allow_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.allow_calls / self.total_calls

    @property
    def block_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.block_calls / self.total_calls

    @property
    def recommendation(self) -> str:
        """ALLOW | WARN | BLOCK | REVIEW"""
        if self.total_calls == 0:
            return "UNUSED"
        if self.block_rate >= 0.8:
            return "BLOCK"     # mostly blocked -- agent probably shouldn't have this
        if self.allow_rate >= 0.7:
            return "ALLOW"     # mostly clean -- add to allowlist
        if self.allow_rate >= 0.3:
            return "REVIEW"    # mixed -- human should decide
        return "WARN"          # mostly warned -- allow with monitoring


@dataclass
class PermissionRecommendation:
    """
    Minimum viable permission recommendation for an agent.
    Consumable as OpenClaw config JSON.
    """
    agent_name:          str
    total_sessions:      int
    total_tool_calls:    int
    recommended_allow:   List[str] = field(default_factory=list)
    recommended_block:   List[str] = field(default_factory=list)
    recommended_review:  List[str] = field(default_factory=list)
    never_used:          List[str] = field(default_factory=list)
    tool_stats:          Dict[str, ToolUsageStats] = field(default_factory=dict)
    generated_at:        float = field(default_factory=time.time)

    def openclaw_config(self) -> str:
        """Ready-to-paste OpenClaw config JSON fragment."""
        return json.dumps({
            "tools": {
                "allowed":        self.recommended_allow,
                "blocked":        self.recommended_block,
                "review_required": self.recommended_review,
            },
            "_aiglos_generated": True,
            "_agent":            self.agent_name,
            "_based_on_sessions": self.total_sessions,
        }, indent=2)

    def summary(self) -> str:
        """Human-readable summary for CLI display."""
        lines = [
            f"\n  Permission Recommendation -- {self.agent_name}",
            f"  {'─' * 56}",
            f"  Based on {self.total_sessions} sessions, "
            f"{self.total_tool_calls:,} tool calls",
            "",
        ]
        if self.recommended_allow:
            lines.append(f"  ALLOW ({len(self.recommended_allow)} tools):")
            for t in sorted(self.recommended_allow):
                s = self.tool_stats.get(t)
                if s:
                    lines.append(f"    ✓ {t:<40} "
                                 f"calls={s.total_calls:>4}  "
                                 f"allow={s.allow_rate:.0%}")
            lines.append("")
        if self.recommended_block:
            lines.append(f"  BLOCK ({len(self.recommended_block)} tools):")
            for t in sorted(self.recommended_block):
                s = self.tool_stats.get(t)
                if s:
                    lines.append(f"    ✗ {t:<40} "
                                 f"calls={s.total_calls:>4}  "
                                 f"block={s.block_rate:.0%}")
            lines.append("")
        if self.recommended_review:
            lines.append(f"  REVIEW ({len(self.recommended_review)} tools -- decide manually):")
            for t in sorted(self.recommended_review):
                lines.append(f"    ? {t}")
            lines.append("")
        lines.append(
            "  Copy the OpenClaw config with: "
            f"aiglos policy recommend --agent {self.agent_name} --format openclaw"
        )
        return "\n".join(lines)


class PermissionRecommender:
    """
    Analyzes observation graph history to recommend minimum viable permissions.

    The principle: lock every door first, then open only what the agent
    actually needs. This class answers the "what does it actually need?"
    question with data rather than guesswork.
    """

    def __init__(self, graph=None):
        self._graph = graph

    def recommend(
        self,
        agent_name: str,
        lookback_days: int = 90,
    ) -> PermissionRecommendation:
        """
        Generate a permission recommendation for an agent.
        Analyzes all tool calls in the lookback window.
        """
        if not self._graph:
            return PermissionRecommendation(
                agent_name=agent_name,
                total_sessions=0,
                total_tool_calls=0,
            )

        since = time.time() - lookback_days * 86400

        try:
            # Query all tool calls for this agent
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT
                        bp.rule_id,
                        COUNT(*) as call_count,
                        COUNT(DISTINCT bp.args_fingerprint) as session_count,
                        MAX(bp.occurred_at) as last_called
                    FROM block_patterns bp
                    WHERE bp.agent_name = ?
                    AND bp.occurred_at >= ?
                    GROUP BY bp.rule_id
                """, (agent_name, since)).fetchall()

                # Also get distinct session count
                sess_row = conn.execute("""
                    SELECT COUNT(DISTINCT args_fingerprint) as c
                    FROM block_patterns
                    WHERE agent_name = ? AND occurred_at >= ?
                """, (agent_name, since)).fetchone()

            total_sessions = sess_row["c"] if sess_row else 0

            # For tool-level analysis, we need the actual tool names
            # block_patterns stores rule_id + agent_name, tool_name is in
            # the pattern payload -- query directly
            with self._graph._conn() as conn:
                tool_rows = conn.execute("""
                    SELECT
                        tool_name,
                        COUNT(*) as total_calls,
                        COUNT(DISTINCT args_fingerprint) as session_count,
                        MAX(occurred_at) as last_called
                    FROM block_patterns
                    WHERE agent_name = ?
                    AND occurred_at >= ?
                    AND tool_name != ''
                    GROUP BY tool_name
                    ORDER BY total_calls DESC
                """, (agent_name, since)).fetchall()

        except Exception as e:
            log.debug("[PermissionRecommender] Query error: %s", e)
            return PermissionRecommendation(
                agent_name=agent_name,
                total_sessions=0,
                total_tool_calls=0,
            )

        tool_stats: Dict[str, ToolUsageStats] = {}
        total_calls = 0

        for row in tool_rows:
            d = dict(row)
            tn = d.get("tool_name", "")
            if not tn:
                continue
            calls = d.get("total_calls", 0)
            total_calls += calls

            # Estimate allow/block/warn from rule_id distribution for this tool
            with self._graph._conn() as conn:
                verdict_rows = conn.execute("""
                    SELECT rule_id, COUNT(*) as c
                    FROM block_patterns
                    WHERE agent_name = ? AND tool_name = ? AND occurred_at >= ?
                    GROUP BY rule_id
                """, (agent_name, tn, since)).fetchall()

            allow_cnt = 0
            block_cnt = 0
            warn_cnt  = 0
            for vr in verdict_rows:
                vd = dict(vr)
                rid = vd.get("rule_id", "")
                cnt = vd.get("c", 0)
                # Rules with high scores = block, T01-T09 style = likely block
                # No rule fired (empty rule_id) = likely allow
                if not rid or rid == "ALLOW":
                    allow_cnt += cnt
                elif rid in ("WARN",):
                    warn_cnt += cnt
                else:
                    block_cnt += cnt

            # If no verdict breakdown available, assume mostly allow
            if allow_cnt + block_cnt + warn_cnt == 0:
                allow_cnt = calls

            stats = ToolUsageStats(
                tool_name     = tn,
                total_calls   = calls,
                allow_calls   = allow_cnt,
                warn_calls    = warn_cnt,
                block_calls   = block_cnt,
                session_count = d.get("session_count", 0),
                last_called   = d.get("last_called", 0.0),
            )
            tool_stats[tn] = stats

        # Classify into recommendation buckets
        allow   = [t for t, s in tool_stats.items() if s.recommendation == "ALLOW"]
        block   = [t for t, s in tool_stats.items() if s.recommendation == "BLOCK"]
        review  = [t for t, s in tool_stats.items() if s.recommendation in ("REVIEW", "WARN")]

        return PermissionRecommendation(
            agent_name         = agent_name,
            total_sessions     = total_sessions,
            total_tool_calls   = total_calls,
            recommended_allow  = sorted(allow),
            recommended_block  = sorted(block),
            recommended_review = sorted(review),
            tool_stats         = tool_stats,
        )

    def all_agents(self, lookback_days: int = 90) -> List[str]:
        """Return all agent names with activity in the lookback window."""
        if not self._graph:
            return []
        since = time.time() - lookback_days * 86400
        try:
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT DISTINCT agent_name FROM block_patterns
                    WHERE occurred_at >= ? AND agent_name != ''
                    ORDER BY agent_name
                """, (since,)).fetchall()
            return [r["agent_name"] for r in rows]
        except Exception:
            return []
