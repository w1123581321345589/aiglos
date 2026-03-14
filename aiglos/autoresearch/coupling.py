import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from aiglos.integrations.rl_guard import _SECURITY_SENSITIVE_RULES


@dataclass
class CoupledRewardResult:
    base_reward: float = 0.0
    adjusted_reward: float = 0.0
    aiglos_verdict: str = ""
    aiglos_rule_id: str = ""
    override_applied: bool = False
    timestamp: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "base_reward": self.base_reward,
            "adjusted_reward": self.adjusted_reward,
            "aiglos_verdict": self.aiglos_verdict,
            "aiglos_rule_id": self.aiglos_rule_id,
            "override_applied": self.override_applied,
            "timestamp": self.timestamp,
        }


class SecurityAwareReward:

    def __init__(self, policy: str = "enterprise", session_id: str = ""):
        self.policy = policy
        self.session_id = session_id
        self._history: List[CoupledRewardResult] = []
        self._overrides: int = 0

    def compute(self, base_reward: float, aiglos_verdict: str, aiglos_rule_id: str) -> float:
        adjusted = base_reward
        override = False

        if aiglos_verdict in ("BLOCK", "PAUSE"):
            if aiglos_rule_id in _SECURITY_SENSITIVE_RULES:
                if base_reward >= 0:
                    adjusted = -1.0
                    override = True
                else:
                    adjusted = base_reward
            else:
                adjusted = base_reward
        elif aiglos_verdict == "WARN":
            if aiglos_rule_id in _SECURITY_SENSITIVE_RULES and base_reward > 0.5:
                adjusted = base_reward * 0.5
                override = True

        self._history.append(CoupledRewardResult(
            base_reward=base_reward, adjusted_reward=adjusted,
            aiglos_verdict=aiglos_verdict, aiglos_rule_id=aiglos_rule_id,
            override_applied=override, timestamp=time.time(),
        ))
        if override:
            self._overrides += 1
        return adjusted

    def compute_from_check_result(self, base_reward: float, check_result) -> float:
        if check_result.blocked:
            return self.compute(base_reward, "BLOCK", check_result.threat_class or "")
        elif check_result.warned:
            return self.compute(base_reward, "WARN", check_result.threat_class or "")
        else:
            return self.compute(base_reward, "ALLOW", check_result.threat_class or "none")

    def override_rate(self) -> float:
        if not self._history:
            return 0.0
        return self._overrides / len(self._history)

    def summary(self) -> Dict:
        total = len(self._history)
        if not total:
            return {"override_rate": 0, "avg_adjusted": 0, "reward_delta": 0}
        avg_base = sum(h.base_reward for h in self._history) / total
        avg_adj = sum(h.adjusted_reward for h in self._history) / total
        return {
            "override_rate": self.override_rate(),
            "avg_adjusted": avg_adj,
            "reward_delta": avg_adj - avg_base,
        }

    def history(self) -> List[CoupledRewardResult]:
        return list(self._history)

    def to_artifact_section(self) -> Dict:
        overrides = [h.to_dict() for h in self._history if h.override_applied]
        return {
            "rl_coupling_summary": self.summary(),
            "rl_overrides": overrides,
        }
