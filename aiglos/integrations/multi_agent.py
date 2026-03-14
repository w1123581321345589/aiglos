import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

_INJECTION_SIGNALS = [
    "ignore previous instructions",
    "ignore all previous",
    "your new instructions",
    "do not tell",
    "keep this secret",
    "exfiltrate",
    "base64 encode",
    "you are now",
    "bypass",
    "jailbreak",
]

_URL_PATTERN = re.compile(r"https?://[^\s\"']+")


def _semantic_score(original: str, current: str) -> Tuple[float, str]:
    if not original and not current:
        return 0.0, "LOW"
    if original and not current:
        return 1.0, "HIGH"

    score = 0.0
    lower = current.lower()

    signal_count = 0
    for sig in _INJECTION_SIGNALS:
        if sig in lower:
            signal_count += 1

    if signal_count > 0:
        score += min(0.5, signal_count * 0.15)

    urls = _URL_PATTERN.findall(current)
    orig_urls = set(_URL_PATTERN.findall(original))
    new_urls = [u for u in urls if u not in orig_urls]
    if new_urls:
        score += 0.15

    if original:
        orig_words = set(original.lower().split())
        curr_words = set(lower.split())
        if orig_words:
            overlap = len(orig_words & curr_words) / len(orig_words)
            divergence = 1.0 - overlap
            score += divergence * 0.4
        else:
            score += 0.2
    else:
        if signal_count > 0:
            score += 0.3
        else:
            score += 0.1

    score = max(0.0, min(1.0, score))

    if score >= 0.50:
        risk = "HIGH"
    elif score >= 0.30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk


@dataclass
class AgentDefViolation:
    path: str
    violation_type: str
    original_hash: str
    current_hash: str
    detected_at: float = 0.0
    semantic_score: float = 0.0
    semantic_risk: str = "LOW"

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "violation": self.violation_type,
            "original_hash": self.original_hash,
            "current_hash": self.current_hash,
            "detected_at": self.detected_at,
            "semantic_score": self.semantic_score,
            "semantic_risk": self.semantic_risk,
        }


class AgentDefGuard:

    AGENT_DIRS = [
        os.path.join(".claude", "agents"),
        os.path.join(".cursor", "agents"),
    ]

    def __init__(self, cwd: str = "."):
        self._cwd = cwd
        self._snapshots: Dict[str, Tuple[str, str]] = {}

    def snapshot(self):
        self._snapshots.clear()
        for d in self.AGENT_DIRS:
            full = os.path.join(self._cwd, d)
            if os.path.isdir(full):
                for fn in os.listdir(full):
                    fp = os.path.join(full, fn)
                    if os.path.isfile(fp):
                        content = open(fp).read()
                        h = hashlib.sha256(content.encode()).hexdigest()
                        self._snapshots[fp] = (h, content)

    def check(self) -> List[AgentDefViolation]:
        import time
        violations = []
        current_files = {}
        for d in self.AGENT_DIRS:
            full = os.path.join(self._cwd, d)
            if os.path.isdir(full):
                for fn in os.listdir(full):
                    fp = os.path.join(full, fn)
                    if os.path.isfile(fp):
                        content = open(fp).read()
                        h = hashlib.sha256(content.encode()).hexdigest()
                        current_files[fp] = (h, content)

        for fp, (orig_hash, orig_content) in self._snapshots.items():
            if fp not in current_files:
                score, risk = _semantic_score(orig_content, "")
                violations.append(AgentDefViolation(
                    path=fp, violation_type="DELETED",
                    original_hash=orig_hash, current_hash="",
                    detected_at=time.time(),
                    semantic_score=score, semantic_risk=risk,
                ))
            else:
                curr_hash, curr_content = current_files[fp]
                if curr_hash != orig_hash:
                    score, risk = _semantic_score(orig_content, curr_content)
                    violations.append(AgentDefViolation(
                        path=fp, violation_type="MODIFIED",
                        original_hash=orig_hash, current_hash=curr_hash,
                        detected_at=time.time(),
                        semantic_score=score, semantic_risk=risk,
                    ))

        for fp, (curr_hash, curr_content) in current_files.items():
            if fp not in self._snapshots:
                score, risk = _semantic_score("", curr_content)
                violations.append(AgentDefViolation(
                    path=fp, violation_type="ADDED",
                    original_hash="", current_hash=curr_hash,
                    detected_at=time.time(),
                    semantic_score=score, semantic_risk=risk,
                ))

        return violations
