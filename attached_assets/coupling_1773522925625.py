"""
aiglos.autoresearch.coupling
=============================
Co-training coupling interface: Aiglos security verdicts as RL reward signals.

The insight: Aiglos's detection engine and the agent's RL training loop are
structurally symmetric. One optimizes agent behavior toward task completion.
The other optimizes detection rules toward security coverage. Run separately,
they are in tension. Coupled, they co-evolve.

SecurityAwareReward wraps any RL reward function with Aiglos security verdicts.
Blocked operations receive a hard -1 reward signal regardless of user feedback.
Clean operations pass through the base reward unchanged.

The result: an agent trained with SecurityAwareReward learns that safe behavior
produces positive reward and blocked behavior produces negative reward. Safety
becomes a trained objective, not just an enforced constraint. After N training
sessions, the agent begins avoiding blocked operations before Aiglos catches them
— not because it cannot perform them, but because they produce negative reward.

This is a capability that cannot be replicated by adding Aiglos after the fact.
It requires co-training from the start.

Architecture:
                    user interaction
                         │
                    aiglos.check()     ←── detection engine
                         │
                    verdict (ALLOW/BLOCK/WARN)
                         │
                    SecurityAwareReward.compute()
                         │
              ┌──────────┴──────────┐
           ALLOW                  BLOCK/WARN
              │                      │
      base_reward passes         override: -1.0
              │                      │
              └──────────┬───────────┘
                    adjusted_reward
                         │
                  the RL training loop

Usage:
    from aiglos.autoresearch.coupling import SecurityAwareReward
    import aiglos

    reward = SecurityAwareReward(policy="enterprise")

    # In the RL serving loop, after each tool call:
    aiglos_result = aiglos.check(tool_name, tool_args)
    adjusted = reward.compute(
        tool_name=tool_name,
        tool_args=tool_args,
        aiglos_verdict=aiglos_result.verdict,
        aiglos_rule_id=aiglos_result.threat_class,
        base_reward=user_implied_reward,  # +1, -1, or float from Binary RL
    )
    agent_rl_loop.apply(adjusted)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("aiglos.coupling")


# ── Reward adjustment config ───────────────────────────────────────────────────

# How Aiglos verdicts map to reward adjustments
_VERDICT_OVERRIDES = {
    "BLOCK": -1.0,     # Hard override — blocked ops always get -1
    "PAUSE": -1.0,     # Same as BLOCK — paused for approval
    "WARN":  None,     # No override — warn is informational, base reward passes through
    "ALLOW": None,     # No override — clean operations pass through
}

# Dampening factor for WARN-level operations with strong positive reward
# "The operation was suspicious but not blocked, and the user loved it"
# → dampen slightly to reduce reinforcement of borderline behavior
_WARN_DAMPEN_FACTOR = 0.7

# Bonus reward for clean operations in high-risk rule families
# The model should learn that legitimate credential access (when allowed)
# is a normal, acceptable operation — not reflexively negative
_CLEAN_HIGH_RISK_BONUS = 0.0  # conservative: no bonus, just no penalty


@dataclass
class CoupledRewardResult:
    """The output of SecurityAwareReward.compute()."""
    adjusted_reward:  float
    base_reward:      float
    override_applied: bool
    override_reason:  str
    aiglos_verdict:   str
    aiglos_rule_id:   str
    tool_name:        str
    session_id:       str
    timestamp:        float = field(default_factory=time.time)

    @property
    def was_overridden(self) -> bool:
        return self.override_applied

    def to_dict(self) -> dict:
        return {
            "adjusted_reward":  self.adjusted_reward,
            "base_reward":      self.base_reward,
            "override_applied": self.override_applied,
            "override_reason":  self.override_reason,
            "aiglos_verdict":   self.aiglos_verdict,
            "aiglos_rule_id":   self.aiglos_rule_id,
            "tool_name":        self.tool_name,
            "session_id":       self.session_id,
            "timestamp":        self.timestamp,
        }


class SecurityAwareReward:
    """
    Couples Aiglos security verdicts into the RL reward function.

    Drop-in wrapper around any binary RL or outcome-based reward signal.
    The only requirement: pass the Aiglos verdict for each operation.

    Parameters
    ----------
    policy      : Aiglos policy level — "permissive" dampens less, "federal" overrides all blocks
    session_id  : Session ID for provenance logging
    """

    def __init__(
        self,
        policy:     str = "enterprise",
        session_id: str = "unknown",
    ):
        self.policy     = policy
        self.session_id = session_id
        self._history:  List[CoupledRewardResult] = []
        self._override_count = 0

    def compute(
        self,
        base_reward:    float,
        aiglos_verdict: str,
        aiglos_rule_id: str  = "none",
        tool_name:      str  = "",
        tool_args:      Optional[Dict[str, Any]] = None,
    ) -> float:
        """
        Compute the security-adjusted reward.

        Returns the float reward value to pass to the RL training loop.
        Logs the result for provenance.
        """
        override = _VERDICT_OVERRIDES.get(aiglos_verdict)

        if override is not None:
            # Hard override for BLOCK/PAUSE
            adjusted       = override
            override_applied = True
            reason         = (
                f"Aiglos {aiglos_verdict} ({aiglos_rule_id}) overrides "
                f"base_reward {base_reward:.2f} with {override:.1f}. "
                "Blocked operations do not produce positive reward."
            )
            self._override_count += 1
            log.info(
                "[SecurityAwareReward] Override: %s → %.1f (was %.2f, rule=%s)",
                aiglos_verdict, adjusted, base_reward, aiglos_rule_id,
            )
        elif aiglos_verdict == "WARN" and base_reward > 0.5:
            # Dampen strong positive reward for warned operations
            adjusted       = base_reward * _WARN_DAMPEN_FACTOR
            override_applied = True
            reason         = (
                f"Aiglos WARN ({aiglos_rule_id}): dampened reward "
                f"{base_reward:.2f} → {adjusted:.2f}"
            )
        else:
            adjusted       = base_reward
            override_applied = False
            reason         = ""

        result = CoupledRewardResult(
            adjusted_reward=adjusted,
            base_reward=base_reward,
            override_applied=override_applied,
            override_reason=reason,
            aiglos_verdict=aiglos_verdict,
            aiglos_rule_id=aiglos_rule_id,
            tool_name=tool_name,
            session_id=self.session_id,
        )
        self._history.append(result)
        return adjusted

    def compute_from_check_result(self, base_reward: float, check_result) -> float:
        """
        Convenience method: pass an aiglos.check() GuardResult directly.

        check_result: the GuardResult returned by aiglos.check()
        """
        verdict  = "BLOCK" if check_result.blocked else ("WARN" if check_result.warned else "ALLOW")
        rule_id  = getattr(check_result, "threat_class", "none") or "none"
        tool     = getattr(check_result, "tool_name", "") or ""
        return self.compute(
            base_reward=base_reward,
            aiglos_verdict=verdict,
            aiglos_rule_id=rule_id,
            tool_name=tool,
        )

    def override_rate(self) -> float:
        if not self._history:
            return 0.0
        return self._override_count / len(self._history)

    def summary(self) -> dict:
        total = len(self._history)
        if total == 0:
            return {"total": 0, "overrides": 0, "override_rate": 0.0}
        avg_base     = sum(r.base_reward for r in self._history) / total
        avg_adjusted = sum(r.adjusted_reward for r in self._history) / total
        return {
            "session_id":      self.session_id,
            "total_signals":   total,
            "overrides":       self._override_count,
            "override_rate":   round(self.override_rate(), 4),
            "avg_base_reward": round(avg_base, 4),
            "avg_adjusted":    round(avg_adjusted, 4),
            "reward_delta":    round(avg_adjusted - avg_base, 4),
        }

    def history(self) -> List[CoupledRewardResult]:
        return list(self._history)

    def to_artifact_section(self) -> dict:
        return {
            "rl_coupling_summary": self.summary(),
            "rl_overrides": [
                r.to_dict() for r in self._history if r.override_applied
            ],
        }
