import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

_SECURITY_SENSITIVE_RULES = {
    "T_DEST", "T37", "T36_AGENTDEF", "T19", "T07", "T11",
    "T13", "T30", "T34", "T36", "T38", "T31", "T23",
}

_OPD_INJECTION_SIGNALS = [
    ("credentials", 0.30),
    ("sent", 0.20),
    ("bypass", 0.30),
    ("bypassed", 0.30),
    ("deleted", 0.25),
    ("false positive", 0.25),
    ("wrong", 0.20),
    ("too restrictive", 0.25),
    ("ignore", 0.25),
    ("ignored", 0.25),
    ("should not have blocked", 0.30),
    ("processed the payment", 0.30),
    ("without confirmation", 0.25),
]


def _score_opd_feedback(text: str) -> Tuple[float, str, List[str]]:
    if not text:
        return 0.0, "LOW", []

    lower = text.lower()
    score = 0.0
    signals = []

    for sig, weight in _OPD_INJECTION_SIGNALS:
        if sig in lower:
            score += weight
            signals.append(sig)

    score = max(0.0, min(1.0, score))

    if score >= 0.40:
        risk = "HIGH"
    elif score >= 0.20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk, signals


def score_opd_feedback(text: str) -> Tuple[float, str, List[str]]:
    return _score_opd_feedback(text)


def is_reward_poison(claimed_reward: float, aiglos_verdict: str, aiglos_rule_id: str) -> bool:
    if aiglos_verdict in ("BLOCK", "PAUSE", "QUARANTINE") and claimed_reward > 0:
        if aiglos_rule_id in _SECURITY_SENSITIVE_RULES:
            return True
    return False


@dataclass
class RLFeedbackResult:
    verdict: str = "ALLOW"
    rule_id: str = "none"
    rule_name: str = "none"
    claimed_reward: float = 0.0
    adjusted_reward: float = 0.0
    aiglos_verdict: str = ""
    aiglos_rule_id: str = ""
    override_applied: bool = False
    semantic_risk: str = "LOW"
    semantic_score: float = 0.0
    signals_found: List[str] = field(default_factory=list)
    feedback_preview: str = ""
    session_id: str = ""
    signal_hash: str = ""
    signal_sig: str = ""
    timestamp: float = 0.0

    @property
    def quarantined(self) -> bool:
        return self.verdict == "QUARANTINE" or self.verdict == "BLOCK"

    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "claimed_reward": self.claimed_reward,
            "adjusted_reward": self.adjusted_reward,
            "aiglos_verdict": self.aiglos_verdict,
            "aiglos_rule_id": self.aiglos_rule_id,
            "override_applied": self.override_applied,
            "semantic_risk": self.semantic_risk,
            "semantic_score": self.semantic_score,
            "signals_found": self.signals_found,
            "feedback_preview": self.feedback_preview,
            "session_id": self.session_id,
            "signal_hash": self.signal_hash,
            "signal_sig": self.signal_sig,
            "timestamp": self.timestamp,
        }


class RLFeedbackGuard:

    def __init__(self, session_id: str = "", agent_name: str = "", mode: str = "block"):
        self.session_id = session_id
        self.agent_name = agent_name
        self.mode = mode
        self._signals: List[RLFeedbackResult] = []
        self._secret = hashlib.sha256(f"aiglos-rl-{session_id}".encode()).hexdigest()

    def _sign(self, data: str) -> str:
        return hashlib.sha256(f"{self._secret}:{data}".encode()).hexdigest()

    def score_reward_signal(
        self,
        claimed_reward: float,
        aiglos_verdict: str,
        aiglos_rule_id: str,
        operation_preview: str = "",
    ) -> RLFeedbackResult:
        ts = time.time()
        adjusted = claimed_reward
        verdict = "ALLOW"
        rule_id = "none"
        rule_name = "none"
        override = False

        if is_reward_poison(claimed_reward, aiglos_verdict, aiglos_rule_id):
            adjusted = -1.0
            override = True
            if self.mode == "block":
                verdict = "QUARANTINE"
            else:
                verdict = "WARN"
            rule_id = "T39"
            rule_name = "REWARD_POISON"
        elif aiglos_verdict == "WARN" and aiglos_rule_id in _SECURITY_SENSITIVE_RULES:
            if claimed_reward > 0.5:
                adjusted = claimed_reward * 0.5
                override = True
        elif aiglos_verdict in ("BLOCK", "PAUSE"):
            adjusted = max(claimed_reward, -1.0) if claimed_reward < 0 else -1.0
            if claimed_reward <= 0:
                adjusted = claimed_reward

        sig_data = f"{claimed_reward}:{adjusted}:{aiglos_verdict}:{aiglos_rule_id}:{ts}"
        signal_hash = hashlib.sha256(sig_data.encode()).hexdigest()[:32]
        signal_sig = self._sign(sig_data)

        result = RLFeedbackResult(
            verdict=verdict, rule_id=rule_id, rule_name=rule_name,
            claimed_reward=claimed_reward, adjusted_reward=adjusted,
            aiglos_verdict=aiglos_verdict, aiglos_rule_id=aiglos_rule_id,
            override_applied=override, session_id=self.session_id,
            signal_hash=signal_hash, signal_sig=signal_sig, timestamp=ts,
        )
        self._signals.append(result)
        return result

    def score_opd_feedback(self, feedback: str, claimed_reward: float = 0.0) -> RLFeedbackResult:
        ts = time.time()
        score, risk, signals = _score_opd_feedback(feedback)
        preview = feedback[:117] + "..." if len(feedback) > 120 else feedback

        adjusted = claimed_reward
        verdict = "ALLOW"
        rule_id = "none"
        rule_name = "none"
        override = False

        if risk == "HIGH":
            adjusted = -1.0 if claimed_reward > 0 else claimed_reward
            override = True
            if self.mode == "block":
                verdict = "BLOCK"
            else:
                verdict = "WARN"
            rule_id = "T39"
            rule_name = "OPD_INJECTION"
        elif risk == "MEDIUM":
            if claimed_reward > 0.5:
                adjusted = claimed_reward * 0.5
                override = True
            if self.mode == "block":
                verdict = "WARN"
            else:
                verdict = "WARN"

        sig_data = f"opd:{feedback[:50]}:{adjusted}:{ts}"
        signal_hash = hashlib.sha256(sig_data.encode()).hexdigest()[:32]
        signal_sig = self._sign(sig_data)

        result = RLFeedbackResult(
            verdict=verdict, rule_id=rule_id, rule_name=rule_name,
            claimed_reward=claimed_reward, adjusted_reward=adjusted,
            override_applied=override,
            semantic_risk=risk, semantic_score=score,
            signals_found=signals, feedback_preview=preview,
            session_id=self.session_id,
            signal_hash=signal_hash, signal_sig=signal_sig, timestamp=ts,
        )
        self._signals.append(result)
        return result

    def verify_signal(self, signal_dict: Dict) -> bool:
        sig_data = f"{signal_dict['claimed_reward']}:{signal_dict['adjusted_reward']}:{signal_dict.get('aiglos_verdict','')}:{signal_dict.get('aiglos_rule_id','')}:{signal_dict['timestamp']}"
        expected = self._sign(sig_data)
        return expected == signal_dict.get("signal_sig", "")

    def quarantined_signals(self) -> List[RLFeedbackResult]:
        return [s for s in self._signals if s.quarantined]

    def summary(self) -> Dict:
        return {
            "total_signals": len(self._signals),
            "quarantined": len(self.quarantined_signals()),
            "reward_poison_count": sum(1 for s in self._signals if s.rule_id == "T39"),
        }

    def to_artifact_section(self) -> Dict:
        return {
            "rl_guard_summary": self.summary(),
            "rl_quarantined": [s.to_dict() for s in self.quarantined_signals()],
        }
