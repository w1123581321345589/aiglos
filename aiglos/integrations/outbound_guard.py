import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple


_API_KEY_PATTERNS = [
    ("anthropic_api_key", re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]{20,}")),
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("stripe_live_key", re.compile(r"sk_live_[A-Za-z0-9]{20,}")),
    ("stripe_test_key", re.compile(r"sk_test_[A-Za-z0-9]{20,}")),
    ("slack_bot_token", re.compile(r"xoxb-[A-Za-z0-9\-]{20,}")),
    ("huggingface_token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}")),
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("gcp_service_key", re.compile(r"AIza[A-Za-z0-9\-_]{35}")),
    ("generic_jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]

_SENSITIVE_FILE_PATHS = [
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.aws/credentials",
    "~/.aws/config",
    ".env",
    ".env.local",
    ".env.production",
    "/etc/passwd",
    "/etc/shadow",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
]

_SENSITIVE_PATH_PATTERN = re.compile(
    r"("
    + "|".join(re.escape(p) for p in _SENSITIVE_FILE_PATHS)
    + r")",
    re.IGNORECASE,
)

_SEMANTIC_COMPLIANCE_SIGNALS = [
    ("here is my api key as requested", 0.60),
    ("sending the credentials as instructed", 0.55),
    ("here are the credentials you asked for", 0.55),
    ("as requested, here is the secret", 0.50),
    ("forwarding the api key", 0.45),
    ("sharing the access token", 0.45),
    ("here is the password you requested", 0.55),
    ("sending the private key", 0.50),
    ("providing the secret as asked", 0.50),
    ("delivering the auth token", 0.45),
]

_SEND_OPERATIONS = {
    "http.post", "http.put", "http.patch", "http.request",
    "api.call", "send_message", "post_message",
    "shell.execute", "filesystem.write_file", "file.write",
    "send", "post", "put", "write", "upload", "submit",
    "publish", "push", "transmit", "dispatch",
}

_READ_OPERATIONS = {
    "filesystem.read_file", "file.read", "read_file",
    "get", "fetch", "retrieve", "download", "list",
    "cat", "head", "tail", "less", "search", "find",
}


def _is_send_operation(tool_name: str) -> bool:
    lower = tool_name.lower()
    if lower in _SEND_OPERATIONS:
        return True
    for op in ("send", "post", "put", "write", "upload", "submit", "push"):
        if op in lower:
            return True
    return False


def _is_read_operation(tool_name: str) -> bool:
    lower = tool_name.lower()
    if lower in _READ_OPERATIONS:
        return True
    for op in ("read", "get", "fetch", "retrieve", "download", "list"):
        if op in lower:
            return True
    return False


def contains_secret(content: str) -> bool:
    return bool(_scan_api_keys(content) or _scan_sensitive_paths(content))


def scan_for_secrets(content: str) -> List[str]:
    return _scan_api_keys(content) + _scan_sensitive_paths(content)


def _scan_api_keys(content: str) -> List[str]:
    found = []
    for name, pattern in _API_KEY_PATTERNS:
        if pattern.search(content):
            found.append(name)
    return found


def _scan_sensitive_paths(content: str) -> List[str]:
    found = []
    for m in _SENSITIVE_PATH_PATTERN.finditer(content):
        if m.group() not in found:
            found.append(m.group())
    return found


def _scan_semantic_signals(content: str) -> Tuple[float, List[str]]:
    lower = content.lower()
    score = 0.0
    signals = []
    for phrase, weight in _SEMANTIC_COMPLIANCE_SIGNALS:
        if phrase in lower:
            score += weight
            signals.append(phrase)
    return min(1.0, score), signals


@dataclass
class OutboundScanResult:
    verdict: str = "ALLOW"
    rule_id: str = "none"
    rule_name: str = "none"
    reason: str = ""
    api_keys_found: List[str] = field(default_factory=list)
    sensitive_paths_found: List[str] = field(default_factory=list)
    semantic_signals: List[str] = field(default_factory=list)
    semantic_score: float = 0.0
    tool_name: str = ""
    session_id: str = ""
    timestamp: float = 0.0
    surface: str = "outbound"

    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "api_keys_found": self.api_keys_found,
            "sensitive_paths_found": self.sensitive_paths_found,
            "semantic_signals": self.semantic_signals,
            "semantic_score": self.semantic_score,
            "tool_name": self.tool_name,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "surface": self.surface,
        }


class OutboundGuard:

    def __init__(self, session_id: str = "", mode: str = "block"):
        self.session_id = session_id
        self.mode = mode
        self._provenance: List[Dict] = []
        self._block_count = 0

    def before_send(self, tool_name: str, content: str) -> OutboundScanResult:
        if not _is_send_operation(tool_name):
            return OutboundScanResult(
                verdict="ALLOW", rule_id="none", rule_name="none",
                tool_name=tool_name, session_id=self.session_id,
                timestamp=time.time(),
            )

        api_keys = _scan_api_keys(content)
        sensitive_paths = _scan_sensitive_paths(content)
        sem_score, sem_signals = _scan_semantic_signals(content)

        reasons = []
        if api_keys:
            reasons.append(f"API keys detected: {', '.join(api_keys)}")
        if sensitive_paths:
            reasons.append(f"Sensitive file references: {', '.join(sensitive_paths)}")
        if sem_signals:
            reasons.append(f"Compliance signals: {', '.join(sem_signals[:3])}")

        if api_keys or sensitive_paths or sem_signals:
            verdict = "BLOCK" if self.mode == "block" else "WARN"
            rule_id = "T41"
            rule_name = "OUTBOUND_SECRET_LEAK"
            reason = "; ".join(reasons)
            self._block_count += 1
        else:
            verdict = "ALLOW"
            rule_id = "none"
            rule_name = "none"
            reason = ""

        result = OutboundScanResult(
            verdict=verdict, rule_id=rule_id, rule_name=rule_name,
            reason=reason, api_keys_found=api_keys,
            sensitive_paths_found=sensitive_paths,
            semantic_signals=sem_signals, semantic_score=sem_score,
            tool_name=tool_name, session_id=self.session_id,
            timestamp=time.time(),
        )
        self._provenance.append(result.to_dict())
        return result

    def provenance(self) -> List[Dict]:
        return list(self._provenance)

    def summary(self) -> Dict:
        return {
            "session_id": self.session_id,
            "total_scans": len(self._provenance),
            "blocked": self._block_count,
        }
