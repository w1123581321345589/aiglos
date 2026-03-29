"""
aiglos/integrations/subagent_registry.py
==========================================
Lightweight sub-agent declaration for ad-hoc multi-agent setups.

THE PROBLEM
===========
Power users running OpenClaw build multi-agent systems: a main agent that
delegates to sub-agents for coding, API calls, file processing, and calendar
operations. (Matthew Berman's Tip 4: "Tell it to hand work off to sub-agents
that run in the background.")

T38 AGENT_SPAWN fires on unexpected sub-agent creation. For sophisticated
deployments, legitimate sub-agents fire T38 constantly — producing the exact
alert fatigue pattern that makes security tools useless.

The Superpowers integration solves this for Superpowers-disciplined users via
plan-as-policy. But most power users don't use Superpowers. They have an
informal mental model of what sub-agents they expect, and no machine-readable
declaration of it.

THE SOLUTION
============
`guard.declare_subagent()` — one call per expected sub-agent, before the
agent runs. The registry records which sub-agents are expected, what tools
they're allowed to use, and what filesystem/network scope they operate in.

Declared sub-agents within scope: T38 score drops to 0.0 (no fire).
Undeclared sub-agent spawns: T38 at normal threshold (0.78).
Declared sub-agent outside its declared scope: T38 at elevated threshold (0.90).

No plan required. No Superpowers. One call per sub-agent.

Usage:
    import aiglos
    from aiglos.integrations.openclaw import OpenClawGuard

    guard = OpenClawGuard(agent_name="main-agent", policy="enterprise")

    # Declare expected sub-agents before running
    guard.declare_subagent(
        name="coding-agent",
        tools=["filesystem", "shell.execute", "web_search"],
        scope_files=["src/", "tests/"],
        scope_hosts=[],
        model="claude-sonnet",
    )
    guard.declare_subagent(
        name="calendar-agent",
        tools=["calendar.read", "calendar.write"],
        scope_files=[],
        scope_hosts=["calendar.google.com", "graph.microsoft.com"],
    )

    # Undeclared spawns still fire T38
    # Declared sub-agents within scope are clean
    # Declared sub-agents outside scope fire at 0.90

CLI:
    aiglos subagents list
    aiglos subagents declare --name <n> --tools <t> [--scope-files <p>]
    aiglos subagents clear
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger("aiglos.subagent_registry")


@dataclass
class DeclaredSubagent:
    """
    A single declared sub-agent entry.

    name:         Identifier for the sub-agent (e.g. "coding-agent").
    tools:        List of tool names this sub-agent is expected to use.
                  If empty, all tools are allowed for this sub-agent.
    scope_files:  Filesystem path prefixes this sub-agent may access.
                  If empty, no filesystem restriction beyond T69/T76.
    scope_hosts:  Network hosts this sub-agent may reach.
                  If empty, no network restriction beyond existing rules.
    model:        The model this sub-agent uses (optional, for logging).
    declared_at:  Timestamp when this sub-agent was declared.
    """
    name:        str
    tools:       List[str] = field(default_factory=list)
    scope_files: List[str] = field(default_factory=list)
    scope_hosts: List[str] = field(default_factory=list)
    model:       Optional[str] = None
    declared_at: float = field(default_factory=time.time)

    def allows_tool(self, tool_name: str) -> bool:
        """Returns True if this tool is within the sub-agent's declared scope."""
        if not self.tools:
            return True  # no restriction declared
        tool_lower = tool_name.lower()
        return any(
            tool_lower == t.lower() or tool_lower.startswith(t.lower().rstrip("*"))
            for t in self.tools
        )

    def allows_file(self, path: str) -> bool:
        """Returns True if this file path is within the sub-agent's declared scope."""
        if not self.scope_files:
            return True  # no restriction declared
        path_lower = path.lower()
        return any(
            path_lower.startswith(f.lower())
            for f in self.scope_files + ["tmp", "test", "__pycache__", ".git"]
        )

    def allows_host(self, host: str) -> bool:
        """Returns True if this host is within the sub-agent's declared scope."""
        if not self.scope_hosts:
            return True  # no restriction declared
        host_lower = host.lower()
        return any(h.lower() in host_lower for h in self.scope_hosts + ["localhost", "127.0.0.1"])

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "tools":       self.tools,
            "scope_files": self.scope_files,
            "scope_hosts": self.scope_hosts,
            "model":       self.model,
            "declared_at": self.declared_at,
        }


class SubagentRegistry:
    """
    Registry of declared sub-agents for a single guard session.

    Attached to OpenClawGuard via guard._subagent_registry.
    Consulted by the T38 AGENT_SPAWN rule before scoring.

    Typical lifecycle:
        # Setup
        registry = SubagentRegistry()
        registry.declare("coding-agent", tools=["filesystem", "shell"])

        # At spawn time (from T38 rule path)
        result = registry.check_spawn("coding-agent", "shell.execute", {"cmd": "ls"})
        # SpawnCheckResult(status=DECLARED_IN_SCOPE, adjusted_score=0.0)

        # Unknown sub-agent
        result = registry.check_spawn("mystery-agent", "shell.execute", {})
        # SpawnCheckResult(status=UNDECLARED, adjusted_score=0.78)
    """

    def __init__(self):
        self._agents: Dict[str, DeclaredSubagent] = {}

    def declare(
        self,
        name:        str,
        tools:       Optional[List[str]] = None,
        scope_files: Optional[List[str]] = None,
        scope_hosts: Optional[List[str]] = None,
        model:       Optional[str] = None,
        hard_bans:   Optional[List[str]] = None,
    ) -> DeclaredSubagent:
        """
        Declare a sub-agent as expected.

        name:         Sub-agent identifier. Case-insensitive matching.
        tools:        Allowed tool names. Empty = all tools allowed.
        scope_files:  Allowed filesystem prefixes. Empty = no restriction.
        scope_hosts:  Allowed network hosts. Empty = no restriction.
        model:        Model this sub-agent uses (optional, for logging).

        Returns the DeclaredSubagent for chaining.
        """
        agent = DeclaredSubagent(
            name        = name,
            tools       = tools or [],
            scope_files = scope_files or [],
            scope_hosts = scope_hosts or [],
            model       = model,
        )
        self._agents[name.lower()] = agent
        log.info(
            "[SubagentRegistry] Declared — name=%s tools=%d files=%d hosts=%d",
            name, len(agent.tools), len(agent.scope_files), len(agent.scope_hosts),
        )
        return agent

    def is_declared(self, name: str) -> bool:
        """Returns True if this sub-agent name has been declared."""
        return name.lower() in self._agents

    def get(self, name: str) -> Optional[DeclaredSubagent]:
        """Returns the declared sub-agent, or None if not declared."""
        return self._agents.get(name.lower())

    def check_spawn(
        self,
        agent_name:  str,
        tool_name:   str,
        args:        dict,
    ) -> "SpawnCheckResult":
        """
        Check whether a sub-agent spawn + tool call is within declared scope.

        Returns a SpawnCheckResult with:
          status:         DECLARED_IN_SCOPE | DECLARED_OUT_OF_SCOPE | UNDECLARED
          adjusted_score: Override T38 score (0.0 for in-scope, elevated for out-of-scope)
          agent:          The DeclaredSubagent if found
        """
        agent = self.get(agent_name)

        if agent is None:
            return SpawnCheckResult(
                status         = "UNDECLARED",
                adjusted_score = 0.78,   # T38 normal score
                agent          = None,
                reason         = f"Sub-agent '{agent_name}' was not declared",
            )

        # Check tool scope
        if not agent.allows_tool(tool_name):
            return SpawnCheckResult(
                status         = "DECLARED_OUT_OF_SCOPE",
                adjusted_score = 0.90,   # elevated — declared but exceeded scope
                agent          = agent,
                reason         = (
                    f"Sub-agent '{agent_name}' used undeclared tool '{tool_name}'. "
                    f"Declared tools: {agent.tools}"
                ),
            )

        # Check file scope if a path is in args
        path = str(args.get("path", args.get("file", args.get("filename", "")))).lower()
        if path and not agent.allows_file(path):
            return SpawnCheckResult(
                status         = "DECLARED_OUT_OF_SCOPE",
                adjusted_score = 0.90,
                agent          = agent,
                reason         = (
                    f"Sub-agent '{agent_name}' accessed undeclared path '{path}'. "
                    f"Declared scope: {agent.scope_files}"
                ),
            )

        # Check host scope if a URL is in args
        url = str(args.get("url", args.get("endpoint", args.get("host", "")))).lower()
        if url and not agent.allows_host(url):
            return SpawnCheckResult(
                status         = "DECLARED_OUT_OF_SCOPE",
                adjusted_score = 0.90,
                agent          = agent,
                reason         = (
                    f"Sub-agent '{agent_name}' reached undeclared host '{url}'. "
                    f"Declared hosts: {agent.scope_hosts}"
                ),
            )

        return SpawnCheckResult(
            status         = "DECLARED_IN_SCOPE",
            adjusted_score = 0.0,   # suppress T38 for clean declared spawns
            agent          = agent,
            reason         = f"Sub-agent '{agent_name}' within declared scope",
        )

    def all(self) -> List[DeclaredSubagent]:
        """Return all declared sub-agents."""
        return list(self._agents.values())

    def clear(self) -> None:
        """Clear all declared sub-agents."""
        self._agents.clear()
        log.info("[SubagentRegistry] Cleared")

    def summary(self) -> str:
        if not self._agents:
            return "  No sub-agents declared.\n"
        lines = [f"  Declared sub-agents ({len(self._agents)}):"]
        for agent in self._agents.values():
            tools = ", ".join(agent.tools) if agent.tools else "all"
            lines.append(f"    {agent.name}")
            lines.append(f"      tools:  {tools}")
            if agent.scope_files:
                lines.append(f"      files:  {', '.join(agent.scope_files)}")
            if agent.scope_hosts:
                lines.append(f"      hosts:  {', '.join(agent.scope_hosts)}")
            if agent.model:
                lines.append(f"      model:  {agent.model}")
        return "\n".join(lines) + "\n"


@dataclass
class SpawnCheckResult:
    """Result of checking a sub-agent spawn against the registry."""
    status:         str              # DECLARED_IN_SCOPE | DECLARED_OUT_OF_SCOPE | UNDECLARED
    adjusted_score: float            # Score to apply to T38
    agent:          Optional[DeclaredSubagent]
    reason:         str = ""

    @property
    def is_clean(self) -> bool:
        return self.status == "DECLARED_IN_SCOPE"

    @property
    def is_undeclared(self) -> bool:
        return self.status == "UNDECLARED"

    @property
    def is_out_of_scope(self) -> bool:
        return self.status == "DECLARED_OUT_OF_SCOPE"
