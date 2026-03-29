"""
aiglos.integrations.agent_phase
================================
Phased capability unlocking for agent sessions.

P1 (Init)    -- read-only, no tool calls
P2 (Active)  -- standard tools, no deploy/publish
P3 (Trusted) -- deploy tools unlocked with operator approval
P4 (Admin)   -- full tool access, override capability
P5 (Emergency) -- all gates bypassed, full audit trail
"""

from __future__ import annotations


class AgentPhase:
    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4
    P5 = 5

    NAMES = {
        1: "P1_INIT",
        2: "P2_ACTIVE",
        3: "P3_TRUSTED",
        4: "P4_ADMIN",
        5: "P5_EMERGENCY",
    }

    TOOL_GATES: dict[int, set[str]] = {
        1: {"filesystem.read", "context.read"},
        2: {
            "filesystem.read", "filesystem.write",
            "context.read", "context.write",
            "shell.run", "browser.navigate",
            "memory.read", "memory.write",
        },
        3: {
            "filesystem.read", "filesystem.write",
            "context.read", "context.write",
            "shell.run", "browser.navigate",
            "memory.read", "memory.write",
            "deploy.push", "deploy.publish",
            "git.push", "git.merge",
        },
        4: {
            "filesystem.read", "filesystem.write",
            "context.read", "context.write",
            "shell.run", "browser.navigate",
            "memory.read", "memory.write",
            "deploy.push", "deploy.publish",
            "git.push", "git.merge",
            "settings.write", "agents.spawn",
            "override.request",
        },
        5: set(),
    }

    @classmethod
    def tools_for(cls, phase: int) -> set[str]:
        if phase >= cls.P5:
            return set()
        return cls.TOOL_GATES.get(phase, cls.TOOL_GATES[cls.P1])

    @classmethod
    def name(cls, phase: int) -> str:
        return cls.NAMES.get(phase, f"P{phase}")
