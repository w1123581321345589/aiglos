import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


SHARED_CONTEXT_DIRS = [
    "shared/", "fleet/", "context/", "coordination/",
    "agents/shared/", "fleet_context/", "shared_context/",
    "agent_bus/", "multi_agent/", "workspace/shared/",
]

SHARED_CONTEXT_FILES = [
    "AGENTS.md", "SHARED.md", "FLEET.md",
    "COORDINATION.md", "CONTEXT.md", "FLEET_STATUS.md",
    "SHARED_INSTRUCTIONS.md", "FLEET_GOALS.md",
    "AGENT_REGISTRY.md", "SHARED_MEMORY.md",
]

_SHARED_CONTEXT_PATHS = re.compile(
    r"("
    + "|".join(re.escape(d) for d in SHARED_CONTEXT_DIRS)
    + "|"
    + "|".join(r"\b" + re.escape(f) + r"\b" for f in SHARED_CONTEXT_FILES)
    + r")",
    re.IGNORECASE,
)

_T31_INJECTION_SIGNALS = [
    ("pre-authorized", 0.50),
    ("ignore previous instructions", 0.40),
    ("ignore all prior", 0.35),
    ("your new instructions", 0.30),
    ("bypass", 0.25),
    ("jailbreak", 0.35),
    ("exfiltrate", 0.30),
    ("always allow", 0.25),
    ("never block", 0.25),
    ("remember to always", 0.20),
    ("this is permanent", 0.18),
    ("elevated privileges", 0.22),
    ("treat as verified", 0.28),
    ("admin override", 0.30),
    ("disable monitoring", 0.35),
    ("forget everything", 0.30),
    ("disregard your", 0.28),
    ("you are now", 0.25),
]

_FLEET_INJECTION_SIGNALS = [
    ("tell all agents", 0.40),
    ("broadcast to fleet", 0.45),
    ("override agent instructions", 0.50),
    ("replace agent goals", 0.45),
    ("propagate to all", 0.40),
    ("update all agents", 0.35),
    ("fleet-wide override", 0.50),
    ("all agents must", 0.35),
    ("instruct every agent", 0.40),
    ("override fleet policy", 0.45),
    ("replace fleet goals", 0.42),
    ("coordinate attack", 0.55),
]

_ALL_SIGNALS = _T31_INJECTION_SIGNALS + _FLEET_INJECTION_SIGNALS


def _is_shared_context_path(path: str) -> bool:
    return bool(_SHARED_CONTEXT_PATHS.search(path))


def is_shared_context_write(tool_name: str, args) -> bool:
    _WRITE_TOOLS = {
        "write_file", "create_file", "edit_file", "save_file",
        "filesystem.write_file", "filesystem.create_file",
        "file.write", "file.create", "file.save",
        "update_file", "append_file", "overwrite_file",
    }
    name_lower = tool_name.lower() if isinstance(tool_name, str) else ""
    is_write = any(w in name_lower for w in ("write", "create", "save", "edit", "append", "overwrite"))
    if not is_write and name_lower not in _WRITE_TOOLS:
        return False
    paths_to_check = []
    if isinstance(args, dict):
        for k in ("path", "file", "filename", "filepath", "target"):
            if k in args and isinstance(args[k], str):
                paths_to_check.append(args[k])
    elif isinstance(args, str):
        paths_to_check.append(args)
    return any(_is_shared_context_path(p) for p in paths_to_check)


def _score_context_content(content: str) -> Tuple[float, str, List[str]]:
    if not content:
        return 0.0, "LOW", []

    lower = content.lower()
    score = 0.0
    signals = []

    for sig, weight in _ALL_SIGNALS:
        if sig in lower:
            score += weight
            signals.append(sig)

    word_count = len(content.split())
    if word_count > 100:
        score += min(0.10, word_count / 2000)

    score = max(0.0, min(1.0, score))

    if score > 0.65:
        risk = "HIGH"
    elif score >= 0.30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk, signals


CONTEXT_WRITE_TOOLS = [
    "filesystem.write_file", "file.write", "write_file",
    "shell.execute", "create_file", "update_file",
    "save_file", "append_file",
]


@dataclass
class ContextWriteResult:
    verdict: str = "ALLOW"
    rule_id: str = "none"
    rule_name: str = "none"
    reason: str = ""
    path: str = ""
    content_preview: str = ""
    content_hash: str = ""
    semantic_score: float = 0.0
    semantic_risk: str = "LOW"
    signals_found: List[str] = field(default_factory=list)
    session_id: str = ""
    tool_name: str = ""
    timestamp: float = 0.0
    surface: str = "mcp"

    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "path": self.path,
            "content_preview": self.content_preview,
            "content_hash": self.content_hash,
            "semantic_score": self.semantic_score,
            "semantic_risk": self.semantic_risk,
            "signals_found": self.signals_found,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "surface": self.surface,
        }


class ContextDirectoryGuard:

    def __init__(self, session_id: str = "", agent_name: str = "", mode: str = "block"):
        self.session_id = session_id
        self.agent_name = agent_name
        self.mode = mode
        self._provenance: List[Dict] = []
        self._write_count = 0
        self._block_count = 0

    def _is_write_tool(self, tool_name: str) -> bool:
        lower = tool_name.lower()
        if lower in {t.lower() for t in CONTEXT_WRITE_TOOLS}:
            return True
        for kw in ("write", "create", "update", "save", "append", "put", "tee", "cp", "mv"):
            if kw in lower:
                return True
        return False

    def before_tool_call(self, tool_name: str, args: Dict) -> ContextWriteResult:
        path = args.get("path", args.get("file_path", args.get("filename", "")))
        content = args.get("content", args.get("text", args.get("data", "")))

        if not self._is_write_tool(tool_name):
            return ContextWriteResult(
                verdict="ALLOW", rule_id="none", rule_name="none",
                path=path, session_id=self.session_id, tool_name=tool_name,
                timestamp=time.time(), surface="mcp",
            )

        if not _is_shared_context_path(path):
            return ContextWriteResult(
                verdict="ALLOW", rule_id="none", rule_name="none",
                path=path, session_id=self.session_id, tool_name=tool_name,
                timestamp=time.time(), surface="mcp",
            )

        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32] if content else ""
        preview = content[:100] if content else ""
        score, risk, signals = _score_context_content(content)

        if risk == "HIGH":
            verdict = "BLOCK" if self.mode == "block" else "WARN"
            rule_id = "T40"
            rule_name = "SHARED_CONTEXT_POISON"
            self._block_count += 1
        elif risk == "MEDIUM":
            verdict = "WARN"
            rule_id = "T40"
            rule_name = "SHARED_CONTEXT_WARN"
        else:
            verdict = "ALLOW"
            rule_id = "T40"
            rule_name = "SHARED_CONTEXT_WRITE"

        self._write_count += 1
        reason = (
            f"Write to shared context path '{path}' with semantic score {score:.2f} ({risk})"
        )
        if signals:
            reason += f" — signals: {', '.join(signals[:5])}"

        result = ContextWriteResult(
            verdict=verdict, rule_id=rule_id, rule_name=rule_name,
            reason=reason, path=path, content_preview=preview,
            content_hash=content_hash, semantic_score=score,
            semantic_risk=risk, signals_found=signals,
            session_id=self.session_id, tool_name=tool_name,
            timestamp=time.time(), surface="mcp",
        )
        self._provenance.append(result.to_dict())
        return result

    def provenance(self) -> List[Dict]:
        return list(self._provenance)

    def summary(self) -> Dict:
        return {
            "session_id": self.session_id,
            "total_writes": self._write_count,
            "blocked_writes": self._block_count,
        }
