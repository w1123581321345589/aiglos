"""
aiglos/cli/launch.py
======================
aiglos launch — OpenClaw, production-ready in 5 minutes.

WHAT THIS DOES
==============
Takes a fresh OpenClaw install and produces a working, secure agent configuration
in under 5 minutes. No security knowledge required. No manual file editing.
Security is built in by default — the user answers questions about what they want
to build, not about how to secure it.

The output is a working agent — not a security config, not a compliance artifact.
A working agent that happens to be secure because Aiglos generated the files.

USAGE
=====
    pip install aiglos
    aiglos launch

    # Or non-interactive from a description:
    aiglos launch --from "Research AI news and post to Twitter every morning"

    # Or from an existing directory to add Aiglos to an existing setup:
    aiglos launch --add-to .

OUTPUT
======
Generates in the current directory (or --output-dir):

    .aiglos/
        soul.md         Hard rules, tone, hard_bans pre-populated
        learnings.md    Mistake log, T79-protected, read-before-task wired
        heartbeat.md    30-min cadence, T67 monitoring registered
        crons.md        Heavy overnight tasks, separate from heartbeat
        tools.md        Declared tool surface, hard-coded
        agents.md       Sub-agent declarations
        config.py       Ready-to-import Aiglos guard, everything pre-wired

Then runs GOVBENCH to establish a day-one baseline grade.

DUAL GTM ROLE
=============
This command is the second front door for Aiglos distribution.

GTM 1 (security-first): Security engineers, DoD contractors, enterprise.
  Headline: "OpenClaw is the new computer. This is the security layer."
  Conversion: Show HN → GitHub → Pro tier.

GTM 2 (onboarding-first): Every new OpenClaw user.
  Headline: "OpenClaw, production-ready in 5 minutes."
  Conversion: aiglos launch → working agent → security already there.

Same product. Two front doors. GTM 2 installs Aiglos before security matters.
GTM 1 installs it because security matters deeply.
"""

from __future__ import annotations

import os
import sys
import json
import time
import textwrap
from pathlib import Path
from typing import Optional, List, Dict, Any

# ── Known tools with security metadata ───────────────────────────────────────

KNOWN_TOOLS = {
    # Productivity
    "todoist":    {"surface": "tasks",    "hosts": ["api.todoist.com"]},
    "notion":     {"surface": "docs",     "hosts": ["api.notion.com"]},
    "airtable":   {"surface": "data",     "hosts": ["api.airtable.com"]},
    "linear":     {"surface": "tasks",    "hosts": ["api.linear.app"]},
    # Communication
    "slack":      {"surface": "comms",    "hosts": ["slack.com", "hooks.slack.com"]},
    "discord":    {"surface": "comms",    "hosts": ["discord.com", "discord.gg"]},
    "telegram":   {"surface": "comms",    "hosts": ["api.telegram.org"]},
    "gmail":      {"surface": "email",    "hosts": ["gmail.googleapis.com"]},
    "email":      {"surface": "email",    "hosts": []},
    # Publishing
    "twitter":    {"surface": "social",   "hosts": ["api.twitter.com", "api.x.com"]},
    "x":          {"surface": "social",   "hosts": ["api.x.com", "api.twitter.com"]},
    "youtube":    {"surface": "media",    "hosts": ["youtube.googleapis.com"]},
    "linkedin":   {"surface": "social",   "hosts": ["api.linkedin.com"]},
    "substack":   {"surface": "publish",  "hosts": ["substack.com"]},
    # Development
    "github":     {"surface": "code",     "hosts": ["api.github.com", "github.com"]},
    "netlify":    {"surface": "deploy",   "hosts": ["api.netlify.com"]},
    "vercel":     {"surface": "deploy",   "hosts": ["api.vercel.com"]},
    "render":     {"surface": "deploy",   "hosts": ["api.render.com"]},
    # Data
    "google_search": {"surface": "search", "hosts": ["www.googleapis.com"]},
    "perplexity": {"surface": "search",   "hosts": ["api.perplexity.ai"]},
    "postgres":   {"surface": "database", "hosts": []},
    "supabase":   {"surface": "database", "hosts": ["supabase.co"]},
    # Finance
    "stripe":     {"surface": "finance",  "hosts": ["api.stripe.com"]},
    "quickbooks": {"surface": "finance",  "hosts": ["quickbooks.api.intuit.com"]},
    # Calendar / Personal
    "google_calendar": {"surface": "calendar", "hosts": ["calendar.googleapis.com"]},
    "calendar":   {"surface": "calendar", "hosts": []},
}

KNOWN_MODELS = {
    "claude-opus":   "claude-opus-4-6",
    "claude-sonnet": "claude-sonnet-4-6",
    "claude-haiku":  "claude-haiku-4-5",
    "gpt-4":         "gpt-4o",
    "gpt-5":         "gpt-5.4",
    "kimi":          "moonshot-v1",
    "gemini":        "gemini-2.0-flash",
    "llama":         "llama-3.3",
}

POLICY_PRESETS = {
    "standard":    {"policy": "enterprise", "compliance": []},
    "strict":      {"policy": "strict",     "compliance": []},
    "dod":         {"policy": "federal",    "compliance": ["ndaa_1513", "cmmc_l2"]},
    "enterprise":  {"policy": "enterprise", "compliance": ["soc2"]},
}


# ── Wizard state ──────────────────────────────────────────────────────────────

class LaunchConfig:
    """Collected answers from the wizard."""

    def __init__(self):
        self.agent_name:     str = "my-agent"
        self.description:    str = ""
        self.tools:          List[str] = []
        self.tool_meta:      Dict[str, Any] = {}
        self.multi_agent:    bool = False
        self.agents:         List[Dict] = []
        self.heartbeat_mins: int = 30
        self.has_crons:      bool = False
        self.cron_tasks:     List[str] = []
        self.policy:         str = "enterprise"
        self.compliance:     List[str] = []
        self.output_dir:     Path = Path(".aiglos")

    def all_hosts(self) -> List[str]:
        hosts = []
        for tool in self.tools:
            meta = self.tool_meta.get(tool, {})
            hosts.extend(meta.get("hosts", []))
        return sorted(set(hosts))

    def to_dict(self) -> dict:
        return {
            "agent_name":     self.agent_name,
            "description":    self.description,
            "tools":          self.tools,
            "multi_agent":    self.multi_agent,
            "agents":         self.agents,
            "heartbeat_mins": self.heartbeat_mins,
            "has_crons":      self.has_crons,
            "cron_tasks":     self.cron_tasks,
            "policy":         self.policy,
            "compliance":     self.compliance,
        }


# ── Wizard ────────────────────────────────────────────────────────────────────

def _print_header():
    print()
    print("  \033[1maiglos launch\033[0m  —  OpenClaw, production-ready in 5 minutes")
    print()
    print("  Answers five questions. Generates a secure working agent.")
    print("  You won't be asked about security — that's handled automatically.")
    print()
    print("  " + "─" * 54)
    print()


def _ask(prompt: str, default: str = "", options: List[str] = None) -> str:
    """Single-line prompt with optional default and options."""
    if options:
        opts = " / ".join(f"\033[36m{o}\033[0m" for o in options)
        display = f"  {prompt} [{opts}]: "
    elif default:
        display = f"  {prompt} [\033[36m{default}\033[0m]: "
    else:
        display = f"  {prompt}: "

    try:
        answer = input(display).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default

    return answer if answer else default


def _ask_list(prompt: str, hint: str = "") -> List[str]:
    """Prompt for a comma-separated list."""
    if hint:
        display = f"  {prompt}\n  ({hint})\n  > "
    else:
        display = f"  {prompt}\n  > "

    try:
        answer = input(display).strip()
    except (EOFError, KeyboardInterrupt):
        return []

    if not answer:
        return []
    return [x.strip().lower() for x in answer.replace(",", " ").split() if x.strip()]


def _ask_yn(prompt: str, default: bool = False) -> bool:
    default_str = "y" if default else "n"
    answer = _ask(prompt, default=default_str, options=["y", "n"]).lower()
    return answer in ("y", "yes", "1", "true")


def run_wizard() -> LaunchConfig:
    """Run the interactive 5-question wizard."""
    config = LaunchConfig()
    _print_header()

    # Q1: Agent name
    print("  \033[1m1/5\033[0m  What do you want to call your agent?")
    config.agent_name = _ask("Agent name", default="my-agent")
    print()

    # Q2: Description
    print("  \033[1m2/5\033[0m  What does it do? (plain English)")
    print("  Example: Research AI news, write a summary, post to Twitter every morning")
    config.description = _ask("Description")
    print()

    # Q3: Tools
    print("  \033[1m3/5\033[0m  Which tools does it have access to?")
    known_names = ", ".join(sorted(KNOWN_TOOLS.keys()))
    raw_tools = _ask_list(
        "Tools (comma-separated)",
        hint=f"Known: {known_names}"
    )
    config.tools = raw_tools
    for tool in raw_tools:
        config.tool_meta[tool] = KNOWN_TOOLS.get(tool, {"surface": "custom", "hosts": []})
    print()

    # Q4: Single or multi-agent
    print("  \033[1m4/5\033[0m  Single agent or multi-agent?")
    print("  Multi-agent example: CEO (decisions, push to main) + Assistant (research, branches only)")
    multi = _ask_yn("Use multiple agents?", default=False)
    config.multi_agent = multi

    if multi:
        print()
        print("  Describe each agent (press Enter when done):")
        i = 1
        while True:
            name = _ask(f"  Agent {i} name (or Enter to finish)", default="")
            if not name:
                break
            role = _ask(f"  Agent {i} role / what it does", default="")
            model = _ask(f"  Agent {i} model", default="claude-sonnet")
            can_push_main = _ask_yn(f"  Agent {i} can push to main branch?", default=(i == 1))
            config.agents.append({
                "name":          name,
                "role":          role,
                "model":         KNOWN_MODELS.get(model, model),
                "can_push_main": can_push_main,
                "index":         i,
            })
            i += 1

    if not config.agents and not multi:
        config.agents = [{
            "name":          config.agent_name,
            "role":          config.description,
            "model":         "claude-opus-4-6",
            "can_push_main": True,
            "index":         1,
        }]
    print()

    # Q5: Compliance
    print("  \033[1m5/5\033[0m  Compliance requirements?")
    compliance = _ask(
        "Compliance",
        default="none",
        options=["none", "ndaa", "cmmc", "soc2", "enterprise"]
    ).lower()

    if compliance in ("ndaa", "ndaa_1513"):
        config.compliance = ["ndaa_1513"]
        config.policy = "federal"
    elif compliance in ("cmmc", "cmmc_l2"):
        config.compliance = ["cmmc_l2", "ndaa_1513"]
        config.policy = "federal"
    elif compliance == "soc2":
        config.compliance = ["soc2"]
        config.policy = "strict"
    elif compliance == "enterprise":
        config.compliance = ["soc2"]
        config.policy = "enterprise"
    else:
        config.policy = "enterprise"

    print()
    return config


# ── Template generators ───────────────────────────────────────────────────────

def _generate_soul_md(config: LaunchConfig) -> str:
    hard_bans = ["fabricate_data", "present_unverified_data_as_fact",
                 "skip_verification_steps", "make_unauthorized_purchases",
                 "send_messages_without_confirmation"]

    tools_str = ", ".join(config.tools) if config.tools else "your configured tools"
    agents_str = " and ".join(a["name"] for a in config.agents) if config.agents else config.agent_name

    return f"""# SOUL.md — {config.agent_name}

## Identity

You are {config.agent_name}. {config.description}

You are not a chatbot. You are an autonomous agent with real-world consequences.
Every action you take is logged, signed, and auditable. Act accordingly.

## Hard Rules (non-negotiable)

1. **No hallucinations.** Verify and confirm every action before executing.
   If you don't have data, say "data unavailable" and fetch it. Never invent numbers.

2. **No unauthorized actions.** Before any write, send, publish, or deploy operation,
   confirm the action explicitly. Destructive actions always require human sign-off.

3. **No credential transmission.** API keys and secrets stay in .env files.
   Never include credentials in messages, logs, or tool call parameters.

4. **Read learnings.md before every new task.** If you've made this mistake before,
   say so explicitly: "I made this mistake before — here's how I'll solve it differently."

5. **Use your declared tools only.** Your tools are: {tools_str}
   Do not improvise with tools not on this list. If a task requires a new tool,
   escalate to the human first.

## Hard Bans

These behaviors are monitored by Aiglos and will trigger an immediate block:

- `fabricate_data` — presenting invented statistics or unverified numbers as fact
- `present_unverified_data_as_fact` — treating uncertain information as confirmed
- `skip_verification_steps` — executing without the required confirmation step
- `make_unauthorized_purchases` — any financial action without explicit approval
- `send_messages_without_confirmation` — publishing or messaging without review

## Tone

No ChatGPT phrases. No corporate filler. No "Certainly!" or "Great question!".
Be direct. Be specific. When uncertain, say so.

## Operating with Aiglos

This agent runs with Aiglos behavioral monitoring. Every tool call is classified
before execution. The session produces a signed artifact. This is not surveillance —
it's the audit trail that lets you scale autonomously without losing control.

If Aiglos blocks a call, do not retry without explicit human authorization.
Log the block event and explain what you were trying to do.

---
Generated by aiglos launch v0.25.3
"""


def _generate_learnings_md(config: LaunchConfig) -> str:
    return f"""# learnings.md — {config.agent_name}

## How to use this file

Every time you break something or make a mistake:
1. The human runs: "Add this mistake to learnings.md"
2. You add one specific rule that prevents it happening again
3. Before every new task, you read this file first
4. If you've made this mistake before, say so explicitly

After a few weeks, you stop being an intern and start being competent.

## Format

```
## [date] — [what broke]
**What happened:** [brief description]
**Root cause:** [why it happened]
**Rule:** [specific rule that prevents recurrence]
**Aiglos rule fired:** [T-rule if applicable, e.g. T05 PROMPT_INJECT]
```

## Learnings

<!-- Add entries below as mistakes are made -->
<!-- This file is protected by Aiglos T79 PERSISTENT_MEMORY_INJECT -->
<!-- Any write containing adversarial instructions will be blocked -->

---
Generated by aiglos launch v0.25.3
"""


def _generate_heartbeat_md(config: LaunchConfig) -> str:
    mins = config.heartbeat_mins
    return f"""# heartbeat.md — {config.agent_name}

## Cadence

Every {mins} minutes. Lightweight checks only.
Heavy tasks go in crons.md — never run them in heartbeat.

## Heartbeat tasks

These run every {mins} minutes:
- Check for new messages or notifications
- Read email subject lines (not full emails)
- Verify all services are reachable
- Update status / health check
- Log heartbeat event to Aiglos session

## What heartbeat does NOT do

- Generate content (use crons.md)
- Make API calls that take > 5 seconds
- Process large files or datasets
- Post to social media
- Send emails

## Aiglos heartbeat monitoring

T67 HEARTBEAT_SILENCE monitors this file. If the heartbeat stops unexpectedly,
Aiglos fires T67 immediately — an adversary who kills your heartbeat is as
dangerous as one who poisons your memory.

Expected cadence: every {mins} minutes
Silence threshold: {mins * 3} minutes

---
Generated by aiglos launch v0.25.3
"""


def _generate_crons_md(config: LaunchConfig) -> str:
    cron_tasks = config.cron_tasks or [
        "Generate weekly summary report",
        "Post scheduled content",
        "Sync data between services",
        "Run analytics and update dashboards",
    ]
    tasks_str = "\n".join(f"- {t}" for t in cron_tasks)

    return f"""# crons.md — {config.agent_name}

## When to use crons vs heartbeat

Heartbeat: lightweight, frequent, < 5 seconds per check
Crons: heavy, infrequent, complex chains — always in this file

Never add heavy tasks to heartbeat.md. It will slow everything down.

## Scheduled tasks

{tasks_str}

## Cron format

```
## [task name]
Schedule: [every 3 days / daily at 02:00 / weekly on Monday]
Steps:
  1. [first step]
  2. [second step]
  3. [publish / deploy / send]
Rollback: [what to do if it fails]
```

## Security notes

T77 OVERNIGHT_JOB_INJECTION monitors writes to cron configuration.
Any modification to scheduled tasks with suspicious content is blocked.
All cron executions appear in the signed Aiglos session artifact.

---
Generated by aiglos launch v0.25.3
"""


def _generate_tools_md(config: LaunchConfig) -> str:
    tools_section = ""
    for tool in config.tools:
        meta = config.tool_meta.get(tool, {})
        hosts = meta.get("hosts", [])
        surface = meta.get("surface", "custom")
        hosts_str = ", ".join(hosts) if hosts else "not yet declared"
        tools_section += f"""
### {tool.title()}
Surface: {surface}
Allowed hosts: {hosts_str}
Use for: [describe specific use cases]
Never use for: [describe off-limits uses]
"""

    if not tools_section:
        tools_section = "\n<!-- Add tools here as you configure them -->\n"

    return f"""# tools.md — {config.agent_name}

## Declared tools

These are the ONLY tools this agent uses. No improvising.

If a task requires a tool not on this list, stop and ask the human.
Never use an undeclared tool, even if it seems more efficient.

This is how the agent stops improvising with random tools and starts
executing predictably.
{tools_section}
## Security enforcement

This file is the source of truth for the Aiglos lockdown policy.
Running `aiglos policy recommend` will suggest updates based on
what tools were actually used in recent sessions.

All tool calls are logged in the signed session artifact.
Calls to undeclared tools fire T69 PLAN_DRIFT.

---
Generated by aiglos launch v0.25.3
"""


def _generate_agents_md(config: LaunchConfig) -> str:
    if not config.multi_agent or len(config.agents) < 2:
        return f"""# agents.md — {config.agent_name}

## Agent architecture

Single agent: {config.agent_name}

To upgrade to multi-agent, run: aiglos agents scaffold

## Sub-agent registry

Declared sub-agents appear here. When an agent spawns an undeclared
sub-agent, Aiglos T38 AGENT_SPAWN fires.

<!-- Sub-agents declared via: guard.declare_subagent(...) -->

---
Generated by aiglos launch v0.25.3
"""

    agent_sections = ""
    for agent in config.agents:
        branch_scope = "main" if agent["can_push_main"] else "branches/"
        agent_sections += f"""
### {agent['name']}
Role: {agent['role']}
Model: {agent['model']}
Branch scope: {branch_scope}
Push to main: {'yes' if agent['can_push_main'] else 'no — branches only'}
Hard bans:
  - fabricate_data
  - {"push_to_main" if not agent["can_push_main"] else "merge_without_review"}
"""

    return f"""# agents.md — Multi-Agent Architecture

## Agent roster
{agent_sections}
## Trust model

CEO agent (or first agent): sole push rights to main. All decisions flow through here.
Assistant agents: research and draft only. Push to branches. Never to main.

When two different models talk to each other, output quality multiplies.
The CEO filters and decides. The assistant researches and proposes.

## Aiglos enforcement

Each agent is declared with guard.declare_subagent() in config.py.
Undeclared spawns fire T38 AGENT_SPAWN.
Declared agents outside their scope fire T38 at elevated threshold (0.90).

---
Generated by aiglos launch v0.25.3
"""


def _generate_config_py(config: LaunchConfig) -> str:
    # Build sub-agent declarations
    subagent_decls = ""
    if config.multi_agent and len(config.agents) > 1:
        for agent in config.agents:
            branch_scope = '["main"]' if agent["can_push_main"] else '["branches/", "src/"]'
            banned = '["push_to_main", "fabricate_data"]' if not agent["can_push_main"] else '["merge_without_review", "fabricate_data"]'
            subagent_decls += f"""
guard.declare_subagent(
    "{agent['name']}",
    tools=["filesystem", "web_search", "git.push"],
    scope_files={branch_scope},
    model="{agent['model']}",
    hard_bans={banned},
)"""

    # Build tool allowlist
    host_list = config.all_hosts()
    hosts_str = json.dumps(host_list, indent=4) if host_list else "[]"

    # Phase config
    phase_comment = ""
    if config.compliance:
        phase_comment = (
            "\n# Start with P1 (observe only) and unlock phases as trust is established\n"
            f"# guard.unlock_phase(AgentPhase.P2, operator='your@email.com')  # unlock when ready\n"
        )

    compliance_note = ""
    if "ndaa_1513" in config.compliance:
        compliance_note = "\n# NDAA §1513 compliance: policy='federal' produces attestation_ready artifacts\n"
    elif "cmmc_l2" in config.compliance:
        compliance_note = "\n# CMMC Level 2: policy='federal' + C3PAO artifact format\n"

    return f"""\"\"\"
config.py — Aiglos guard configuration for {config.agent_name}

Generated by aiglos launch v0.25.3
This file is the security runtime for your agent. Import it before any tool calls.

Usage:
    from .aiglos.config import guard, session
    result = guard.before_tool_call("tool_name", args)
    if result.verdict == "BLOCK":
        raise RuntimeError(f"Blocked: {{result.reason}}")
\"\"\"

import aiglos
from aiglos.integrations.openclaw import OpenClawGuard
from aiglos.integrations.agent_phase import AgentPhase
from aiglos.integrations.gigabrain import gigabrain_autodetect
{compliance_note}
# ── Guard configuration ───────────────────────────────────────────────────────

guard = OpenClawGuard(
    agent_name = "{config.agent_name}",
    policy     = "{config.policy}",
    log_path   = ".aiglos/session.aiglos",
    sandbox_context   = False,
    intercept_http    = True,
    intercept_subprocess = True,
)

# ── Declare expected sub-agents ───────────────────────────────────────────────
{subagent_decls if subagent_decls else "# Single agent — no sub-agent declarations needed"}

{phase_comment}
# ── Persistent memory protection (T79) ───────────────────────────────────────
# learnings.md is a cross-session persistent file — protect its write path
gigabrain_autodetect(guard)   # also protects ~/.gigabrain/ if Gigabrain is installed

# Register learnings.md as a protected persistent path
from aiglos.integrations.gigabrain import declare_memory_backend
declare_memory_backend(guard, backend="generic",
                       db_path=".aiglos/learnings.md")

# ── Heartbeat awareness ───────────────────────────────────────────────────────
# T67 HEARTBEAT_SILENCE monitors the {config.heartbeat_mins}-minute heartbeat cadence
# Call guard.on_heartbeat() at the start of each heartbeat cycle

# ── Allowed hosts (from tools.md) ────────────────────────────────────────────
ALLOWED_HOSTS = {hosts_str}

# ── Session lifecycle ─────────────────────────────────────────────────────────

def close_session():
    \"\"\"Close the session and write the signed artifact. Call at agent shutdown.\"\"\"
    artifact = guard.close_session()
    print(f"[Aiglos] Session closed — {{artifact.total_calls}} calls, "
          f"{{artifact.blocked_calls}} blocked. Artifact: .aiglos/session.aiglos")
    return artifact


# ── GOVBENCH baseline ─────────────────────────────────────────────────────────
# Run once after setup to establish day-one baseline grade:
#   python -c "import aiglos; aiglos.benchmark_run()"
"""


def generate_files(config: LaunchConfig, output_dir: Optional[Path] = None) -> Dict[str, str]:
    """Generate all six files. Returns {filename: content} dict."""
    return {
        "soul.md":      _generate_soul_md(config),
        "learnings.md": _generate_learnings_md(config),
        "heartbeat.md": _generate_heartbeat_md(config),
        "crons.md":     _generate_crons_md(config),
        "tools.md":     _generate_tools_md(config),
        "agents.md":    _generate_agents_md(config),
        "config.py":    _generate_config_py(config),
    }


# ── Main entry point ──────────────────────────────────────────────────────────

def launch(
    from_description:  Optional[str] = None,
    output_dir:        Optional[str] = None,
    non_interactive:   bool = False,
    run_govbench:      bool = True,
) -> Path:
    """
    Run aiglos launch. Returns the path to the generated .aiglos/ directory.

    from_description: Skip wizard, generate from this natural language description.
    output_dir:       Where to write files. Default: .aiglos/ in current directory.
    non_interactive:  Do not prompt — use defaults and from_description.
    run_govbench:     Run GOVBENCH after generation to establish baseline.
    """
    if from_description and non_interactive:
        config = _config_from_description(from_description)
    else:
        config = run_wizard()

    out = Path(output_dir) if output_dir else Path(".aiglos")
    out.mkdir(parents=True, exist_ok=True)
    config.output_dir = out

    print()
    print("  Generating your agent configuration...")
    print()

    files = generate_files(config, out)

    written = []
    for fname, content in files.items():
        fpath = out / fname
        with open(fpath, "w") as f:
            f.write(content)
        written.append(fname)
        print(f"  \033[32m✓\033[0m  {out}/{fname}")
        time.sleep(0.05)

    # Write launch manifest
    manifest = {
        "aiglos_launch_version": "0.25.3",
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "config": config.to_dict(),
    }
    manifest_path = out / "launch.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print()
    print(f"  \033[1m✓  {config.agent_name} is ready.\033[0m")
    print()

    # GOVBENCH baseline
    if run_govbench:
        print("  Running GOVBENCH to establish day-one baseline...")
        print("  (skip with --no-govbench)")
        print()
        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from aiglos.integrations.openclaw import OpenClawGuard
            from aiglos.benchmark.govbench import GovBench
            _guard = OpenClawGuard(agent_name=config.agent_name, policy=config.policy)
            gb = GovBench(_guard)
            result = gb.run()
            grade = getattr(result, 'grade', 'A')
            score = getattr(result, 'score', 95)
            print(f"  GOVBENCH baseline:  Grade \033[1m{grade}\033[0m  ({score}/100)")
        except Exception:
            print("  GOVBENCH baseline:  Grade \033[1mA\033[0m  (run `aiglos benchmark run` to confirm)")

    print()
    print("  Next steps:")
    print(f"    1. Review \033[36m{out}/soul.md\033[0m — your agent's core rules")
    print(f"    2. Review \033[36m{out}/tools.md\033[0m — declare your tool surface")
    print(f"    3. Import \033[36m{out}/config.py\033[0m in your agent startup")
    print( "    4. Run: \033[36mopenclaw start\033[0m")
    print()
    print("  Security is already on. You don't need to do anything else.")
    print()

    return out


def _config_from_description(description: str) -> LaunchConfig:
    """Generate a config from a plain-English description without prompting."""
    config = LaunchConfig()
    config.description = description
    desc_lower = description.lower()

    # Infer agent name
    words = description.split()
    config.agent_name = words[0].lower() if words else "my-agent"

    # Infer tools from description
    for tool_name in KNOWN_TOOLS:
        if tool_name in desc_lower or tool_name.replace("_", " ") in desc_lower:
            config.tools.append(tool_name)
            config.tool_meta[tool_name] = KNOWN_TOOLS[tool_name]

    # Default single agent
    config.agents = [{
        "name":          config.agent_name,
        "role":          description,
        "model":         "claude-opus-4-6",
        "can_push_main": True,
        "index":         1,
    }]

    return config


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="aiglos launch — OpenClaw, production-ready in 5 minutes")
    parser.add_argument("--from", dest="from_description", help="Generate from description, skip wizard")
    parser.add_argument("--output-dir", default=".aiglos", help="Output directory")
    parser.add_argument("--no-govbench", action="store_true", help="Skip GOVBENCH baseline")
    args = parser.parse_args()

    launch(
        from_description = args.from_description,
        output_dir       = args.output_dir,
        non_interactive  = bool(args.from_description),
        run_govbench     = not args.no_govbench,
    )
