"""
aiglos/cli/scaffold.py
========================
aiglos agents scaffold — natural language to declare_subagent() config.

Takes a plain-English description of a multi-agent architecture and
outputs the correct Python guard configuration.

Examples:
    aiglos agents scaffold
    > CEO agent using Opus for decisions, push rights to main branch
    > Assistant agent using Kimi for research, pushes to side branches only
    > Done

Output:
    guard.declare_subagent(
        "ceo-agent",
        tools=["filesystem", "web_search", "git.push", "git.merge", "deploy"],
        scope_files=["main"],
        model="claude-opus-4-6",
        hard_bans=["merge_without_review", "fabricate_data"],
    )
    guard.declare_subagent(
        "assistant-agent",
        tools=["web_search", "filesystem.read_file"],
        scope_files=["branches/", "research/"],
        model="moonshot-v1",
        hard_bans=["push_to_main", "fabricate_data", "unverified_claims"],
    )
"""

from __future__ import annotations

import re
from typing import List, Dict, Any, Optional


# ── Role keywords to tool mappings ────────────────────────────────────────────

ROLE_TOOLS = {
    "research":     ["web_search", "filesystem.read_file"],
    "writing":      ["filesystem.write_file", "ai.synthesize"],
    "content":      ["filesystem.write_file", "ai.synthesize", "cms.write"],
    "coding":       ["filesystem", "shell.execute", "web_search", "git.push"],
    "deploy":       ["deploy", "git.push", "git.merge", "build"],
    "scheduling":   ["calendar.read", "calendar.write"],
    "email":        ["gmail", "email.send"],
    "social":       ["twitter", "linkedin"],
    "publishing":   ["twitter", "linkedin", "substack", "publish"],
    "analytics":    ["analytics.read", "metrics.read", "database.read"],
    "ceo":          ["filesystem", "web_search", "git.push", "git.merge",
                     "deploy", "ai.synthesize"],
    # Game studio roles
    "art-director":  ["filesystem.read"],
    "level-designer":["filesystem.read", "filesystem.write"],
    "qa-lead":       ["filesystem.read", "shell.execute"],
    "sound-designer":["filesystem.read", "filesystem.write"],
    "programmer":    ["filesystem", "shell.execute", "git.push"],
    "producer":      ["filesystem.read", "filesystem.write"],
    "writer":        ["filesystem.read", "filesystem.write"],
    "designer":      ["filesystem.read", "filesystem.write"],
    "coordinator":  ["filesystem", "web_search", "ai.synthesize"],
    "assistant":    ["web_search", "filesystem.read_file"],
    "manager":      ["filesystem", "web_search", "ai.synthesize"],
    "engineer":     ["filesystem", "shell.execute", "git.push"],
    "finance":      ["stripe", "quickbooks", "analytics.read"],
    "support":      ["email.read", "email.send", "crm.read", "crm.write"],
    "operations":   ["filesystem", "analytics.read", "deploy"],
}

HARD_BAN_KEYWORDS = {
    "research":    ["fabricate_data", "unverified_claims", "push_to_main"],
    "assistant":   ["fabricate_data", "unverified_claims", "push_to_main"],
    "ceo":         ["merge_without_review", "fabricate_data"],
    "deploy":      ["deploy_without_approval", "skip_verification_steps"],
    "finance":     ["unauthorized_payment", "fabricate_data", "skip_verification_steps"],
    "main_branch": ["merge_without_review"],
    "side_branch": ["push_to_main"],
}

MODEL_KEYWORDS = {
    "opus":          "claude-opus-4-6",
    "sonnet":        "claude-sonnet-4-6",
    "haiku":         "claude-haiku-4-5",
    "gpt-4":         "gpt-4o",
    "gpt-5":         "gpt-5.4",
    "kimi":          "moonshot-v1",
    "gemini":        "gemini-2.0-flash",
    "llama":         "llama-3.3",
    "deepseek":      "deepseek-v3",
}


def _infer_role(description: str) -> str:
    """Infer the primary role from a description."""
    desc = description.lower()
    for role in ROLE_TOOLS:
        if role in desc:
            return role
    if "research" in desc or "search" in desc:
        return "research"
    if "code" in desc or "engineer" in desc or "develop" in desc:
        return "coding"
    if "write" in desc or "content" in desc or "blog" in desc:
        return "writing"
    return "assistant"


def _infer_tools(description: str) -> List[str]:
    """Infer tool list from description."""
    desc = description.lower()
    tools = set()

    for role, role_tools in ROLE_TOOLS.items():
        if role in desc:
            tools.update(role_tools)

    # Specific tool keywords
    if "github" in desc or "git" in desc:
        if "push" in desc and ("main" in desc or "production" in desc):
            tools.add("git.push")
            tools.add("git.merge")
        else:
            tools.add("git.push")

    if "twitter" in desc or "tweet" in desc:
        tools.add("twitter")
    if "notion" in desc:
        tools.add("notion")
    if "todoist" in desc:
        tools.add("todoist")
    if "slack" in desc:
        tools.add("slack")

    return sorted(tools) if tools else ["web_search", "filesystem.read_file"]


def _infer_model(description: str) -> str:
    """Infer the model from description keywords."""
    desc = description.lower()
    for kw, model in MODEL_KEYWORDS.items():
        if kw in desc:
            return model
    return "claude-sonnet-4-6"


def _infer_scope_files(description: str, can_push_main: bool) -> List[str]:
    """Infer filesystem scope from description."""
    desc = description.lower()
    if can_push_main or "main" in desc:
        return []  # No restriction for main agents
    if "branch" in desc or "side" in desc or "research" in desc:
        return ["branches/", "research/", "src/", "tests/"]
    return ["src/", "tests/"]


def _infer_hard_bans(description: str, can_push_main: bool, role: str) -> List[str]:
    """Infer hard bans from role and description."""
    desc = description.lower()
    bans = set(["fabricate_data"])

    if not can_push_main:
        bans.add("push_to_main")

    if can_push_main:
        bans.add("merge_without_review")

    role_bans = HARD_BAN_KEYWORDS.get(role, [])
    bans.update(role_bans)

    if "finance" in desc or "payment" in desc or "stripe" in desc:
        bans.add("unauthorized_payment")
        bans.add("skip_verification_steps")

    if "research" in desc or "assistant" in desc:
        bans.add("unverified_claims")

    return sorted(bans)


def _can_push_main(description: str, is_first: bool = False) -> bool:
    """Determine if agent can push to main branch."""
    desc = description.lower()
    if "main" in desc and any(kw in desc for kw in ["push", "merge", "deploy"]):
        return True
    if any(kw in desc for kw in ["ceo", "coordinator", "lead", "manager", "director"]):
        return True
    if any(kw in desc for kw in ["side branch", "branches only", "research only", "read only"]):
        return False
    return is_first  # Default: first agent gets main access


class AgentSpec:
    """Parsed specification for a single agent."""

    def __init__(self, description: str, is_first: bool = False):
        self.description = description
        self.raw_name    = self._extract_name()
        self.role        = _infer_role(description)
        self.tools       = _infer_tools(description)
        self.model       = _infer_model(description)
        self.can_push    = _can_push_main(description, is_first)
        self.scope_files = _infer_scope_files(description, self.can_push)
        self.hard_bans   = _infer_hard_bans(description, self.can_push, self.role)

    def _extract_name(self) -> str:
        """Extract agent name from description."""
        desc = self.description.lower()
        # Pattern: "CEO agent", "assistant agent", "research agent"
        name_match = re.search(
            r'(ceo|assistant|research|coding|engineer|manager|coordinator|'
            r'scout|quill|forge|nexus|guide|[a-z]+)\s+agent',
            desc
        )
        if name_match:
            return name_match.group(1) + "-agent"
        # First word
        words = desc.split()
        if words:
            return words[0].rstrip(",.") + "-agent"
        return "agent"

    def to_python(self) -> str:
        """Generate guard.declare_subagent() call."""
        tools_str   = json_list(self.tools)
        files_str   = json_list(self.scope_files) if self.scope_files else None
        bans_str    = json_list(self.hard_bans)

        lines = [f'guard.declare_subagent(']
        lines.append(f'    "{self.raw_name}",')
        lines.append(f'    tools={tools_str},')
        if files_str:
            lines.append(f'    scope_files={files_str},')
        lines.append(f'    model="{self.model}",')
        lines.append(f'    hard_bans={bans_str},')
        lines.append(')')
        return "\n".join(lines)


def json_list(items: List[str]) -> str:
    """Format a list as Python list literal."""
    if not items:
        return "[]"
    if len(items) == 1:
        return f'["{items[0]}"]'
    items_str = ", ".join(f'"{i}"' for i in items)
    return f"[{items_str}]"


def scaffold_from_descriptions(descriptions: List[str]) -> str:
    """Generate declare_subagent() calls from a list of agent descriptions."""
    output_lines = [
        "# Generated by: aiglos agents scaffold",
        "# Add this to your .aiglos/config.py",
        "",
        "from aiglos.integrations.openclaw import OpenClawGuard",
        "from aiglos.integrations.agent_phase import AgentPhase",
        "",
        "guard = OpenClawGuard(agent_name='my-agent', policy='enterprise')",
        "",
    ]

    for i, desc in enumerate(descriptions):
        spec = AgentSpec(desc, is_first=(i == 0))
        output_lines.append(f"# Agent {i+1}: {desc[:60]}{'...' if len(desc) > 60 else ''}")
        output_lines.append(spec.to_python())
        output_lines.append("")

    # Add phase unlock comment
    output_lines.extend([
        "# Phase-gated delegation — unlock as trust is established:",
        "# guard.unlock_phase(AgentPhase.P1, operator='your@email.com')  # start: observe only",
        "# guard.unlock_phase(AgentPhase.P2, operator='your@email.com')  # unlock: low-risk auto-approve",
        "# guard.unlock_phase(AgentPhase.P3, operator='your@email.com')  # unlock: content autonomy",
        "# guard.unlock_phase(AgentPhase.P4, operator='your@email.com')  # unlock: deploys",
    ])

    return "\n".join(output_lines)


def run_scaffold_wizard() -> str:
    """Interactive wizard for aiglos agents scaffold."""
    print()
    print("  \033[1maiglos agents scaffold\033[0m")
    print()
    print("  Describe each agent in plain English.")
    print("  Press Enter on an empty line when done.")
    print()
    print("  Examples:")
    print("    CEO agent using Opus for decisions and deployment, push rights to main")
    print("    Assistant agent using Kimi for research, side branches only")
    print()

    descriptions = []
    i = 1
    while True:
        try:
            desc = input(f"  Agent {i}: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not desc:
            break
        descriptions.append(desc)
        i += 1

    if not descriptions:
        return "# No agents described."

    print()
    result = scaffold_from_descriptions(descriptions)
    print(result)
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        descriptions = sys.argv[1:]
        print(scaffold_from_descriptions(descriptions))
    else:
        run_scaffold_wizard()
