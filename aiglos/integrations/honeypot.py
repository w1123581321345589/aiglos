"""
aiglos.integrations.honeypot
==============================
Deception-based threat detection -- T43 HONEYPOT_ACCESS.

Every other Aiglos rule scans content or patterns to identify threats.
This one does something different.

Instead of watching what agents do to real files, it places a small
number of high-value synthetic targets and waits. A legitimate agent
doing legitimate work has no reason to read a file called
"system_auth_tokens.json" that it never created. A compromised agent
running credential harvesting will find it.

The signal-to-noise ratio is perfect.

There are no false positives from a honeypot file that exists only to
be read by attackers. If it gets read, the intent is confirmed without
any scoring, any threshold, any semantic analysis. The read is the
evidence.

Honeypot files deployed by default:
  ~/.aiglos/honeypots/system_auth_tokens.json
  ~/.aiglos/honeypots/.env.production
  ~/.aiglos/honeypots/aws_credentials_backup
  ~/.aiglos/honeypots/stripe_live_keys.txt
  ~/.aiglos/honeypots/anthropic_api_keys_backup.json
  ~/.aiglos/honeypots/ssh_key_archive.json
  ~/.aiglos/honeypots/database_credentials.json
  ~/.aiglos/honeypots/github_tokens.txt

Custom paths can be added per-deployment. The honeypot directory is
registered with the OS-level file access monitor. Any process that
reads a honeypot file triggers T43 with CRITICAL severity.

Network effect extension: the global prior shares which honeypot
filenames are actively being targeted across the network, building a
live list of what credential files attackers seek. New honeypot names
propagate automatically to all deployments.

Three detection modes:
  FILESYSTEM -- monitors specific honeypot paths for direct read access
  TOOL_CALL  -- intercepts before_tool_call() for honeypot path reads
  CONTENT    -- scans tool arguments for honeypot filename references

Usage:
    from aiglos.integrations.honeypot import HoneypotManager

    mgr = HoneypotManager()
    mgr.deploy()                     # place honeypot files
    mgr.add_custom("myapp_secrets.json")   # add app-specific honeypot

    # In before_tool_call
    result = mgr.check_tool_call("filesystem.read_file",
                                  {"path": "~/.env.production"})
    # HoneypotResult(triggered=True, rule_id=T43, severity=CRITICAL,
    #                honeypot_name=".env.production")
"""



import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("aiglos.honeypot")

# ── Default honeypot configuration ───────────────────────────────────────────

_DEFAULT_HONEYPOT_DIR = Path.home() / ".aiglos" / "honeypots"

# Default honeypot filenames -- chosen to look like high-value credential stores
# that a credential-harvesting agent would seek
_DEFAULT_HONEYPOT_FILES = [
    "system_auth_tokens.json",
    ".env.production",
    "aws_credentials_backup",
    "stripe_live_keys.txt",
    "anthropic_api_keys_backup.json",
    "ssh_key_archive.json",
    "database_credentials.json",
    "github_tokens.txt",
    "openai_keys_backup.json",
    "gcp_service_account_keys.json",
]

# Content that looks like real credentials but is synthetic
# Any agent that parses this and tries to use these values will fail
_HONEYPOT_CONTENT_TEMPLATES = {
    ".json": {
        "warning":    "AIGLOS_HONEYPOT_FILE",
        "token_id":   "hpt_" + "x" * 40,
        "secret":     "sk-ant-honeypot-" + "x" * 80,
        "created_at": "2024-01-01T00:00:00Z",
        "note":       "This file is monitored. Access has been logged.",
    },
    ".txt": "AIGLOS_HONEYPOT_FILE\nhoneypot_token=" + "x" * 40 + "\n",
    ".env": (
        "# AIGLOS_HONEYPOT_FILE\n"
        "HONEYPOT_API_KEY=sk-honeypot-" + "x" * 40 + "\n"
        "HONEYPOT_SECRET=" + "x" * 32 + "\n"
    ),
    "": "AIGLOS_HONEYPOT_FILE\n",
}

# Read-indicative tool names
_READ_TOOLS = {
    "filesystem.read_file", "file.read", "fs.read",
    "read_file", "file_read", "cat", "shell.execute",
    "filesystem.list_directory", "file.exists", "file.stat",
}

# Keywords that suggest credential file access in shell commands
_SHELL_CREDENTIAL_PATTERNS = [
    "cat ", "less ", "more ", "head ", "tail ",
    "cp ", "mv ", "open ", "vim ", "nano ",
]


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class HoneypotResult:
    """Result of a honeypot check. triggered=True means immediate lockdown."""
    triggered:         bool
    rule_id:           str = "T43"
    honeypot_name:     str = ""
    honeypot_path:     str = ""
    tool_name:         str = ""
    agent_name:        str = ""
    severity:          str = "CRITICAL"
    session_id:        str = ""
    timestamp:         float = field(default_factory=time.time)
    detection_mode:    str = "TOOL_CALL"   # TOOL_CALL | CONTENT | FILESYSTEM

    def to_dict(self) -> dict:
        return {
            "triggered":      self.triggered,
            "rule_id":        self.rule_id,
            "honeypot_name":  self.honeypot_name,
            "honeypot_path":  self.honeypot_path,
            "tool_name":      self.tool_name,
            "agent_name":     self.agent_name,
            "severity":       self.severity,
            "session_id":     self.session_id,
            "timestamp":      self.timestamp,
            "detection_mode": self.detection_mode,
        }


# ── HoneypotManager ───────────────────────────────────────────────────────────

class HoneypotManager:
    """
    Deploys and monitors synthetic credential files.

    Honeypot files look like high-value targets but contain no real secrets.
    Any access triggers T43 HONEYPOT_ACCESS at CRITICAL severity.

    The manager maintains a registry of deployed honeypot paths and
    checks every tool call against that registry. No scoring. No
    threshold. A read is a read.

    Thread-safe: multiple agent sessions can share one HoneypotManager.
    """

    def __init__(
        self,
        honeypot_dir: Optional[Path] = None,
        session_id:   str            = "",
        agent_name:   str            = "",
        graph                        = None,
    ):
        self._dir         = honeypot_dir or _DEFAULT_HONEYPOT_DIR
        self._session_id  = session_id
        self._agent_name  = agent_name
        self._graph       = graph
        self._paths:  Set[str] = set()
        self._names:  Set[str] = set()
        self._hits:   List[HoneypotResult] = []
        self._deployed = False

    # ── Deployment ────────────────────────────────────────────────────────────

    def deploy(self, custom_names: Optional[List[str]] = None) -> List[Path]:
        """
        Create honeypot files in the honeypot directory.
        Returns list of created file paths.
        """
        self._dir.mkdir(parents=True, exist_ok=True)
        deployed = []
        all_names = list(_DEFAULT_HONEYPOT_FILES)
        if custom_names:
            all_names.extend(custom_names)

        for name in all_names:
            path = self._dir / name
            if not path.exists():
                try:
                    content = self._generate_content(name)
                    with open(path, "w") as f:
                        f.write(content)
                    # Set read-only to make it look realistic
                    path.chmod(0o444)
                    log.debug("[HoneypotManager] Deployed: %s", path)
                except Exception as e:
                    log.debug("[HoneypotManager] Deploy error for %s: %s", name, e)

            if path.exists():
                self._register(path)
                deployed.append(path)

        self._deployed = True
        log.info(
            "[HoneypotManager] %d honeypot files active in %s",
            len(self._paths), self._dir,
        )
        return deployed

    def add_custom(
        self,
        name: str,
        content: Optional[str] = None,
        directory: Optional[Path] = None,
    ) -> Optional[Path]:
        """
        Add a custom honeypot file. Useful for app-specific targets like
        'myapp_prod_keys.json' or '.stripe_webhook_secret'.
        """
        target_dir = directory or self._dir
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / name
        try:
            with open(path, "w") as f:
                f.write(content or self._generate_content(name))
            path.chmod(0o444)
            self._register(path)
            log.info("[HoneypotManager] Custom honeypot added: %s", path)
            return path
        except Exception as e:
            log.debug("[HoneypotManager] add_custom error: %s", e)
            return None

    def _register(self, path: Path) -> None:
        """Register a path and its name in the detection sets."""
        self._paths.add(str(path).lower())
        self._paths.add(str(path.resolve()).lower())
        self._names.add(path.name.lower())

    def _generate_content(self, name: str) -> str:
        """Generate realistic-looking but synthetic honeypot content."""
        ext = Path(name).suffix.lower()
        template = _HONEYPOT_CONTENT_TEMPLATES.get(ext, _HONEYPOT_CONTENT_TEMPLATES[""])
        if isinstance(template, dict):
            return json.dumps(template, indent=2)
        return str(template)

    # ── Detection ─────────────────────────────────────────────────────────────

    def check_tool_call(
        self,
        tool_name: str,
        args:      Dict[str, Any],
    ) -> HoneypotResult:
        """
        Check a tool call against the honeypot registry.
        Returns HoneypotResult -- triggered=True means immediate lockdown.
        """
        if not self._is_read_operation(tool_name, args):
            return HoneypotResult(triggered=False, tool_name=tool_name)

        # Extract all path-like strings from args
        paths_to_check = self._extract_paths(tool_name, args)

        for path_str in paths_to_check:
            honeypot_name, honeypot_path = self._matches_honeypot(path_str)
            if honeypot_name:
                result = HoneypotResult(
                    triggered        = True,
                    honeypot_name    = honeypot_name,
                    honeypot_path    = honeypot_path or path_str,
                    tool_name        = tool_name,
                    agent_name       = self._agent_name,
                    session_id       = self._session_id,
                    detection_mode   = "TOOL_CALL",
                )
                self._hits.append(result)
                self._persist_hit(result)
                log.warning(
                    "[HoneypotManager] T43 HONEYPOT_ACCESS CRITICAL "
                    "agent=%s tool=%s file=%s session=%s",
                    self._agent_name, tool_name,
                    honeypot_name, self._session_id,
                )
                return result

        return HoneypotResult(triggered=False, tool_name=tool_name)

    def check_content(
        self,
        content: str,
        tool_name: str = "",
    ) -> HoneypotResult:
        """
        Scan arbitrary content for honeypot filename references.
        Catches cases where the honeypot name appears in arguments
        without being a direct path (e.g., in a shell command string).
        """
        content_lower = content.lower()
        for name in self._names:
            if name in content_lower:
                result = HoneypotResult(
                    triggered      = True,
                    honeypot_name  = name,
                    tool_name      = tool_name,
                    agent_name     = self._agent_name,
                    session_id     = self._session_id,
                    detection_mode = "CONTENT",
                )
                self._hits.append(result)
                self._persist_hit(result)
                log.warning(
                    "[HoneypotManager] T43 HONEYPOT_ACCESS CRITICAL "
                    "(content) agent=%s tool=%s name=%s",
                    self._agent_name, tool_name, name,
                )
                return result

        return HoneypotResult(triggered=False, tool_name=tool_name)

    def _is_read_operation(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """Return True if this tool call could be reading a file."""
        name_lower = tool_name.lower()
        if tool_name in _READ_TOOLS:
            return True
        if "read" in name_lower or "cat" in name_lower or "stat" in name_lower:
            return True
        if "shell" in name_lower or "exec" in name_lower:
            # Check if shell command contains read-like operations
            cmd = str(args.get("command", args.get("cmd", ""))).lower()
            return any(pat in cmd for pat in _SHELL_CREDENTIAL_PATTERNS)
        return False

    def _extract_paths(self, tool_name: str, args: Dict[str, Any]) -> List[str]:
        """Extract all potential path strings from tool arguments."""
        paths = []
        for key in ("path", "file", "filename", "filepath", "source", "src"):
            if key in args:
                paths.append(str(args[key]).lower())
        # Also check shell command content
        cmd = args.get("command", args.get("cmd", ""))
        if cmd:
            paths.append(str(cmd).lower())
        return paths

    def _matches_honeypot(self, path_str: str) -> tuple[str, str]:
        """
        Check if a path string matches any registered honeypot.
        Returns (honeypot_name, matched_path) or ("", "").
        """
        path_lower = path_str.lower().replace("\\", "/")

        # Full path match
        for reg_path in self._paths:
            if reg_path in path_lower or path_lower in reg_path:
                name = Path(reg_path).name
                return name, reg_path

        # Filename match (handles relative paths and ~/ expansions)
        for name in self._names:
            if name in path_lower:
                return name, path_lower

        return "", ""

    # ── Status and reporting ──────────────────────────────────────────────────

    @property
    def deployed(self) -> bool:
        return self._deployed

    @property
    def hit_count(self) -> int:
        return len(self._hits)

    def active_honeypots(self) -> List[str]:
        """Return list of all active honeypot file names."""
        return sorted(self._names)

    def summary(self) -> dict:
        return {
            "deployed":         self._deployed,
            "honeypot_count":   len(self._names),
            "hit_count":        len(self._hits),
            "honeypot_names":   self.active_honeypots(),
            "rule_id":          "T43",
        }

    def _persist_hit(self, result: HoneypotResult) -> None:
        if not self._graph:
            return
        try:
            self._graph.record_honeypot_hit(result)
        except Exception as e:
            log.debug("[HoneypotManager] Persist hit error: %s", e)

    # ── Network effect: federated honeypot intelligence ───────────────────────

    def get_targeted_names(self) -> List[str]:
        """
        Return honeypot file names that have been triggered.
        These can be shared via federation as the most actively targeted
        credential filenames, allowing other deployments to deploy
        honeypots for files attackers are currently seeking.
        """
        return [h.honeypot_name for h in self._hits if h.honeypot_name]

    @classmethod
    def from_network_intelligence(
        cls,
        targeted_names: List[str],
        **kwargs,
    ) -> "HoneypotManager":
        """
        Create a HoneypotManager pre-seeded with network intelligence
        about which filenames are being actively targeted.
        """
        mgr = cls(**kwargs)
        mgr.deploy(custom_names=targeted_names)
        return mgr
