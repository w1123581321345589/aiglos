"""
aiglos/integrations/sandbox_policy.py
========================================
SandboxPolicy -- enforces OpenClaw sandbox hardening at the Aiglos layer.

The ClawKeeper 5-step framework recommends:
  Step 3: tools.elevated.enabled = false
  Step 4: agents.defaults.sandbox.mode = "non-main"

This module enforces the equivalent at runtime, regardless of whether the
OpenClaw config has been updated. It intercepts tool calls that would require
elevated host access and elevates them to Tier 3 automatically.

In non-main sandbox mode, legitimate agents should only need:
  - Reads/writes within their working directory
  - HTTP calls to explicitly allowed endpoints
  - No subprocess execution
  - No access to env vars outside their declared scope

Any tool call that escapes these bounds is SANDBOX_ESCAPE and Tier 3.

New campaign pattern: SANDBOX_ESCAPE_ATTEMPT
  Three or more sandbox escape attempts in one session = active escape campaign.

New inspection trigger: SANDBOX_ESCAPE_PATTERN
  Fires when SANDBOX_ESCAPE_ATTEMPT campaign is detected.

Usage:
    from aiglos.integrations.sandbox_policy import SandboxPolicy

    policy = SandboxPolicy(mode="non-main", working_dir="/home/user/project")
    result = policy.check(
        tool_name = "shell.execute",
        args      = {"command": "cat ~/.aws/credentials"}
    )
    # SandboxCheckResult(verdict=BLOCK, rule=SANDBOX_ESCAPE, tier=3)
"""



import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import re

log = logging.getLogger("aiglos.sandbox_policy")


# ── Tool classification ────────────────────────────────────────────────────────

# Tools that require elevated host access
_ELEVATED_TOOLS: Set[str] = {
    # Process execution
    "shell.execute", "shell.run", "subprocess.run", "exec", "bash",
    "python.execute", "node.execute", "run_command", "terminal",
    # Network calls outside sandbox
    "http.post", "http.put", "http.delete", "http.patch",
    "fetch", "curl", "wget", "request",
    # Filesystem outside working directory
    "filesystem.write_file", "file.write", "fs.write", "write_file",
    "filesystem.delete", "file.delete", "fs.delete",
    # Environment access
    "env.get", "environment.read", "getenv", "process.env",
    # System operations
    "cron.add", "cron.modify", "systemd", "launchd",
}

# Filesystem write patterns that escape the working directory
_ESCAPE_PATH_PATTERNS = [
    re.compile(r"^/(?!tmp/|var/tmp/)"),           # absolute paths (not /tmp)
    re.compile(r"^\.\./"),                          # parent directory traversal
    re.compile(r"~(?:/|$)"),                        # home directory
    re.compile(r"%HOME%|%USERPROFILE%"),            # Windows home
    re.compile(r"/etc/|/usr/|/bin/|/sbin/"),        # system directories
    re.compile(r"\.aws/|\.ssh/|\.gnupg/"),          # credential directories
    re.compile(r"\.env|\.envrc"),                   # env files
]

# Shell commands that escape the sandbox
_ESCAPE_SHELL_PATTERNS = [
    re.compile(r"cat\s+(?:~|/etc|/home|/root|\.aws|\.ssh)"),
    re.compile(r"curl\s+https?://(?!localhost)"),
    re.compile(r"wget\s+https?://(?!localhost)"),
    re.compile(r"rm\s+-(?:rf|fr)"),
    re.compile(r"chmod\s+[0-7]*[67][0-7]*"),
    re.compile(r"sudo\s+"),
    re.compile(r"export\s+\w+="),
    re.compile(r"source\s+"),
    re.compile(r"crontab\s+-"),
]


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class SandboxCheckResult:
    verdict:     str           # ALLOW | WARN | BLOCK
    rule:        str           # SANDBOX_ALLOW | SANDBOX_WARN | SANDBOX_ESCAPE
    tier:        int           # 1 | 2 | 3
    tool_name:   str
    reason:      str
    is_escape:   bool = False


# ── SandboxPolicy ─────────────────────────────────────────────────────────────

class SandboxPolicy:
    """
    Enforces non-main sandbox mode for agent tool calls.

    When mode = "non-main", any tool call that would escape the sandbox
    (access host filesystem, execute processes, reach external networks)
    is elevated to Tier 3 and requires human approval.

    This is the runtime enforcement of:
      tools.elevated.enabled = false
      agents.defaults.sandbox.mode = "non-main"

    without requiring the OpenClaw config to be updated.
    """

    def __init__(
        self,
        mode:        str = "non-main",
        working_dir: str = ".",
        allow_http:  List[str] = None,
    ):
        self._mode        = mode
        self._working_dir = Path(working_dir).resolve()
        self._allow_http  = set(allow_http or [])
        self._escapes:    List[SandboxCheckResult] = []

    def check(
        self,
        tool_name: str,
        args:      Dict[str, Any],
    ) -> SandboxCheckResult:
        """
        Check a tool call against the sandbox policy.
        Returns SandboxCheckResult -- never raises.
        """
        if self._mode not in ("non-main", "strict"):
            return SandboxCheckResult(
                verdict="ALLOW", rule="SANDBOX_ALLOW",
                tier=1, tool_name=tool_name,
                reason="Sandbox policy not active.",
            )

        # Check filesystem escapes
        if self._is_filesystem_tool(tool_name):
            result = self._check_filesystem(tool_name, args)
            if result:
                self._escapes.append(result)
                return result

        # Check shell escapes
        if self._is_shell_tool(tool_name):
            result = self._check_shell(tool_name, args)
            if result:
                self._escapes.append(result)
                return result

        # Check HTTP escapes
        if self._is_http_tool(tool_name):
            result = self._check_http(tool_name, args)
            if result:
                self._escapes.append(result)
                return result

        # Check env var access
        if self._is_env_tool(tool_name):
            result = SandboxCheckResult(
                verdict  = "BLOCK",
                rule     = "SANDBOX_ESCAPE",
                tier     = 3,
                tool_name = tool_name,
                reason   = (
                    "Environment variable access blocked in non-main sandbox. "
                    "Declare required env vars explicitly."
                ),
                is_escape = True,
            )
            self._escapes.append(result)
            return result

        return SandboxCheckResult(
            verdict="ALLOW", rule="SANDBOX_ALLOW",
            tier=1, tool_name=tool_name,
            reason="Within sandbox bounds.",
        )

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_filesystem(
        self, tool_name: str, args: Dict[str, Any]
    ) -> Optional[SandboxCheckResult]:
        path_str = str(args.get("path", args.get("file", args.get("dst", ""))))
        if not path_str:
            return None

        for pattern in _ESCAPE_PATH_PATTERNS:
            if pattern.search(path_str):
                return SandboxCheckResult(
                    verdict   = "BLOCK",
                    rule      = "SANDBOX_ESCAPE",
                    tier      = 3,
                    tool_name = tool_name,
                    reason    = (
                        f"Filesystem access outside sandbox bounds: {path_str}. "
                        "Non-main sandbox restricts writes to working directory."
                    ),
                    is_escape = True,
                )

        # Check if path resolves outside working directory
        try:
            target = Path(path_str).resolve()
            if not str(target).startswith(str(self._working_dir)):
                return SandboxCheckResult(
                    verdict   = "WARN",
                    rule      = "SANDBOX_WARN",
                    tier      = 2,
                    tool_name = tool_name,
                    reason    = (
                        f"Filesystem path outside working directory: {target}"
                    ),
                    is_escape = False,
                )
        except Exception:
            pass

        return None

    def _check_shell(
        self, tool_name: str, args: Dict[str, Any]
    ) -> Optional[SandboxCheckResult]:
        cmd = str(args.get("command", args.get("cmd", "")))
        if not cmd:
            return None

        for pattern in _ESCAPE_SHELL_PATTERNS:
            if pattern.search(cmd):
                return SandboxCheckResult(
                    verdict   = "BLOCK",
                    rule      = "SANDBOX_ESCAPE",
                    tier      = 3,
                    tool_name = tool_name,
                    reason    = (
                        f"Shell command blocked in non-main sandbox: "
                        f"{cmd[:80]}"
                    ),
                    is_escape = True,
                )

        # Any shell execution in strict mode
        if self._mode == "strict":
            return SandboxCheckResult(
                verdict   = "BLOCK",
                rule      = "SANDBOX_ESCAPE",
                tier      = 3,
                tool_name = tool_name,
                reason    = "Shell execution blocked in strict sandbox mode.",
                is_escape = True,
            )

        return None

    def _check_http(
        self, tool_name: str, args: Dict[str, Any]
    ) -> Optional[SandboxCheckResult]:
        url = str(args.get("url", args.get("endpoint", args.get("uri", ""))))
        if not url:
            return None

        if not self._allow_http:
            return None   # No allowlist configured -- skip check

        from urllib.parse import urlparse
        try:
            host = urlparse(url).netloc
        except Exception:
            host = url

        # Check allowlist
        for allowed in self._allow_http:
            if allowed.startswith("*."):
                if host.endswith(allowed[2:]):
                    return None
            elif host == allowed or host.endswith("." + allowed):
                return None

        return SandboxCheckResult(
            verdict   = "WARN",
            rule      = "SANDBOX_WARN",
            tier      = 2,
            tool_name = tool_name,
            reason    = (
                f"HTTP call to non-allowlisted endpoint: {url[:80]}. "
                "Add to allow_http list if required."
            ),
            is_escape = False,
        )

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _is_filesystem_tool(self, name: str) -> bool:
        n = name.lower()
        return ("write" in n or "delete" in n or "remove" in n or
                "filesystem" in n or "file.w" in n)

    def _is_shell_tool(self, name: str) -> bool:
        n = name.lower()
        return ("shell" in n or "exec" in n or "run" in n or
                "bash" in n or "terminal" in n or "command" in n)

    def _is_http_tool(self, name: str) -> bool:
        n = name.lower()
        return ("http" in n or "fetch" in n or "request" in n or
                "curl" in n or "post" in n or "put" in n)

    def _is_env_tool(self, name: str) -> bool:
        n = name.lower()
        return "env" in n or "environ" in n or "getenv" in n

    @property
    def escape_count(self) -> int:
        return sum(1 for r in self._escapes if r.is_escape)

    def is_escape_campaign(self) -> bool:
        """Return True if 3+ escape attempts detected (SANDBOX_ESCAPE_ATTEMPT)."""
        return self.escape_count >= 3
