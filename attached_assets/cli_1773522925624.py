"""
aiglos.cli
===========
Command-line interface for the Aiglos adaptive security layer.

Commands:
    stats              — rule firing stats across all ingested sessions
    amend list         — list pending amendment proposals
    amend approve <id> — approve a pending amendment
    amend reject <id>  — reject a pending amendment
    amend history      — all amendments (all statuses)
    inspect            — run inspection triggers and show findings
    policy <session>   — show the derived policy for a session ID
    run                — full adaptive cycle: inspect + propose
    sessions           — recent session history
    version            — print version
    demo               — run the OpenClaw demo
    check <tool>       — check a tool call interactively
    scan-skill <name>  — scan a ClawHub/SkillsMP skill

Usage:
    python -m aiglos stats
    python -m aiglos amend list
    python -m aiglos amend approve a3f8c1
    python -m aiglos inspect
    python -m aiglos run
    python -m aiglos sessions --n 20
"""

from __future__ import annotations

import json
import sys
import os
import textwrap
from typing import List, Optional


# ── ANSI colors (disabled on non-TTY) ────────────────────────────────────────

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_USE_COLOR = _supports_color()

def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def red(t):    return _c(t, "31")
def yellow(t): return _c(t, "33")
def green(t):  return _c(t, "32")
def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")
def cyan(t):   return _c(t, "36")


# ── Shared graph loader ───────────────────────────────────────────────────────

def _load_graph(db_path: Optional[str] = None):
    from aiglos.adaptive.observation import ObservationGraph
    return ObservationGraph(db_path=db_path)


def _load_adaptive(db_path: Optional[str] = None):
    from aiglos.adaptive import AdaptiveEngine
    return AdaptiveEngine(db_path=db_path)


# ── Formatters ────────────────────────────────────────────────────────────────

def _severity_color(s: str) -> str:
    if s == "HIGH":   return red(s)
    if s == "MEDIUM": return yellow(s)
    return dim(s)


def _verdict_color(v: str) -> str:
    if v == "BLOCK": return red(v)
    if v == "WARN":  return yellow(v)
    if v == "ALLOW": return green(v)
    return v


def _trend_color(t: str) -> str:
    if t == "SILENT":     return red(t)
    if t == "HIGH_VOLUME": return yellow(t)
    if t == "ACTIVE":     return cyan(t)
    return dim(t)


def _status_color(s: str) -> str:
    if s == "pending":     return yellow(s)
    if s == "approved":    return green(s)
    if s == "rejected":    return dim(s)
    if s == "rolled_back": return red(s)
    return s


def _bar(value: float, width: int = 20) -> str:
    filled = int(value * width)
    return green("█" * filled) + dim("░" * (width - filled))


# ── Command: stats ────────────────────────────────────────────────────────────

def cmd_stats(args: List[str]) -> None:
    db = os.environ.get("AIGLOS_OBS_DB")
    graph = _load_graph(db)

    summary = graph.summary()
    print()
    print(bold("  Aiglos Observation Graph"))
    print(dim(f"  {'─' * 50}"))
    print(f"  Sessions ingested : {bold(str(summary['sessions']))}")
    print(f"  Total blocked     : {red(str(summary['total_blocked']))}")
    print(f"  AgentDef violations: {yellow(str(summary['agentdef_violations']))}")
    print(f"  Spawn events      : {cyan(str(summary['spawn_events']))}")
    print()

    all_stats = graph.all_rule_stats()
    if not all_stats:
        print(dim("  No rule events recorded yet. Run agents and call aiglos.close() to populate."))
        print()
        return

    print(bold(f"  {'Rule':<18} {'Fires':>6} {'Blocks':>7} {'Warns':>6} {'Block%':>7} {'Trend':<14} {'Sessions':>8}"))
    print(dim(f"  {'─'*18} {'─'*6} {'─'*7} {'─'*6} {'─'*7} {'─'*14} {'─'*8}"))

    for s in all_stats:
        bp = f"{s.block_rate*100:.0f}%"
        print(
            f"  {cyan(s.rule_id):<27} "
            f"{s.fires_total:>6} "
            f"{red(str(s.blocks_total)):>15} "
            f"{yellow(str(s.warns_total)):>14} "
            f"{bp:>7} "
            f"{_trend_color(s.trend):<22} "
            f"{s.sessions_seen:>8}"
        )
    print()

    if summary["top_rules"]:
        print(bold("  Top rules by fire volume"))
        for r in summary["top_rules"]:
            pct = r["fires"] / max(all_stats[0].fires_total, 1)
            print(f"  {r['rule_id']:<16} {_bar(pct, 24)} {r['fires']}")
    print()


# ── Command: sessions ─────────────────────────────────────────────────────────

def cmd_sessions(args: List[str]) -> None:
    n = 10
    for i, a in enumerate(args):
        if a in ("--n", "-n") and i + 1 < len(args):
            n = int(args[i + 1])
    db = os.environ.get("AIGLOS_OBS_DB")
    graph = _load_graph(db)
    sessions = graph.recent_sessions(n=n)
    if not sessions:
        print(dim("\n  No sessions recorded yet.\n"))
        return
    print()
    print(bold(f"  {'Session ID':<32} {'Agent':<20} {'Events':>7} {'Blocked':>8}"))
    print(dim(f"  {'─'*32} {'─'*20} {'─'*7} {'─'*8}"))
    for s in sessions:
        blocked = s.get("blocked_events", 0) or 0
        b_str = red(str(blocked)) if blocked else dim("0")
        print(
            f"  {dim(s['session_id'][:32]):<40} "
            f"{s.get('agent_name','')[:20]:<20} "
            f"{s.get('total_events',0):>7} "
            f"{b_str:>16}"
        )
    print()


# ── Command: inspect ──────────────────────────────────────────────────────────

def cmd_inspect(args: List[str]) -> None:
    db = os.environ.get("AIGLOS_OBS_DB")
    engine = _load_adaptive(db)
    triggers = engine.inspector.run()

    print()
    if not triggers:
        print(green("  ✓ No inspection triggers fired. System looks healthy."))
        print()
        return

    print(bold(f"  {len(triggers)} inspection trigger(s) fired"))
    print()
    for i, t in enumerate(triggers, 1):
        cand = cyan(" [amendment candidate]") if t.amendment_candidate else ""
        print(f"  {bold(str(i))}. [{_severity_color(t.severity)}] {bold(t.trigger_type)}{cand}")
        print(f"     Rule: {cyan(t.rule_id or 'n/a')}")
        print(f"     {textwrap.fill(t.evidence_summary, width=72, subsequent_indent='     ')}")
        print()


# ── Command: run ──────────────────────────────────────────────────────────────

def cmd_run(args: List[str]) -> None:
    db = os.environ.get("AIGLOS_OBS_DB")
    engine = _load_adaptive(db)
    report = engine.run()

    print()
    print(bold("  Aiglos Adaptive Run"))
    print(dim(f"  {'─' * 50}"))
    print(f"  Triggers fired   : {yellow(str(report['triggers_fired']))}")
    print(f"  Proposals made   : {cyan(str(report['proposals_made']))}")
    print(f"  Pending amendments: {yellow(str(report['pending_amendments']))}")
    print()

    if report["triggers"]:
        print(bold("  Triggers"))
        for t in report["triggers"]:
            cand = " *" if t.get("amendment_candidate") else ""
            print(f"  [{_severity_color(t['severity'])}] {t['trigger_type']}{cand}  —  {t['rule_id'] or 'n/a'}")
            print(dim(f"    {t['evidence_summary'][:100]}"))
        print()

    if report["proposals"]:
        print(bold("  New Proposals"))
        for p in report["proposals"]:
            print(f"  {dim(p['amendment_id'][:8])}  {cyan(p['target'])}  [{p['rule_id'] or 'n/a'}]")
            print(dim(f"    {p['rationale'][:100]}"))
        print()
        print(dim("  Run `python -m aiglos amend list` to review and approve."))
        print()


# ── Command: amend ────────────────────────────────────────────────────────────

def cmd_amend(args: List[str]) -> None:
    sub = args[0] if args else "list"
    db = os.environ.get("AIGLOS_OBS_DB")
    engine = _load_adaptive(db)
    amender = engine.amender

    if sub == "list":
        pending = amender.pending()
        print()
        if not pending:
            print(dim("  No pending amendments."))
            print()
            return
        print(bold(f"  {len(pending)} pending amendment(s)"))
        print()
        for a in pending:
            print(f"  {bold(a.amendment_id[:8])}  [{cyan(a.target)}]  rule={a.rule_id or 'n/a'}")
            print(f"    {textwrap.fill(a.rationale, width=72, subsequent_indent='    ')}")
            proposal_str = json.dumps(a.proposal, indent=6)
            print(dim(f"    Proposal:\n{textwrap.indent(proposal_str, '      ')}"))
            print()
        print(dim("  Approve: python -m aiglos amend approve <id>"))
        print(dim("  Reject:  python -m aiglos amend reject <id>"))
        print()

    elif sub in ("approve", "reject", "rollback"):
        if len(args) < 2:
            print(red(f"  Usage: python -m aiglos amend {sub} <amendment-id-prefix>"))
            sys.exit(1)
        prefix = args[1].lower()
        # Find matching amendment by prefix
        all_a = amender.all_amendments()
        matches = [a for a in all_a if a.amendment_id.lower().startswith(prefix)]
        if not matches:
            print(red(f"  No amendment found matching prefix '{prefix}'."))
            sys.exit(1)
        if len(matches) > 1:
            print(yellow(f"  Ambiguous prefix — {len(matches)} matches. Use more characters."))
            sys.exit(1)
        a = matches[0]
        if sub == "approve":
            amender.approve(a.amendment_id)
            print(green(f"  ✓ Approved: {a.amendment_id[:8]}  [{a.rule_id or 'n/a'}]"))
        elif sub == "reject":
            amender.reject(a.amendment_id)
            print(dim(f"  Rejected: {a.amendment_id[:8]}  [{a.rule_id or 'n/a'}]"))
        elif sub == "rollback":
            amender.rollback(a.amendment_id)
            print(yellow(f"  Rolled back: {a.amendment_id[:8]}  [{a.rule_id or 'n/a'}]"))

    elif sub == "history":
        all_a = amender.all_amendments()
        print()
        if not all_a:
            print(dim("  No amendments on record."))
            print()
            return
        print(bold(f"  {'ID':<10} {'Status':<14} {'Target':<22} {'Rule':<16} {'Eval'}"))
        print(dim(f"  {'─'*10} {'─'*14} {'─'*22} {'─'*16} {'─'*10}"))
        for a in all_a:
            status_str = _status_color(a.status)
            print(
                f"  {dim(a.amendment_id[:8]):<10} "
                f"{status_str:<22} "
                f"{a.target[:22]:<22} "
                f"{(a.rule_id or '')[:16]:<16} "
                f"{a.eval_outcome or dim('—')}"
            )
        print()

    else:
        print(red(f"  Unknown amend subcommand: {sub}"))
        print(dim("  Usage: python -m aiglos amend [list|approve|reject|rollback|history]"))
        sys.exit(1)


# ── Command: policy ───────────────────────────────────────────────────────────

def cmd_policy(args: List[str]) -> None:
    parent_id = args[0] if args else ""
    db = os.environ.get("AIGLOS_OBS_DB")
    engine = _load_adaptive(db)
    policy = engine.derive_child_policy(parent_id or "current")
    print()
    print(bold(f"  Derived policy for session: {dim(parent_id or 'current')}"))
    print(dim(f"  Based on {policy.evidence_sessions} session(s) of evidence"))
    print()
    if policy.is_empty():
        print(dim("  Policy is empty — insufficient session history to derive context."))
        print()
        return
    if policy.inherited_allow_http:
        print(bold("  Inherited allow_http"))
        for h in policy.inherited_allow_http:
            print(f"    {green('+')} {h}")
        print()
    if policy.tier_overrides:
        print(bold("  Tier reclassifications"))
        for rule, tier in policy.tier_overrides.items():
            print(f"    {cyan(rule)} → {tier}")
        print()
    if policy.suppressed_rules:
        print(bold("  Suppressed rules (never block in this deployment)"))
        for r in policy.suppressed_rules:
            print(f"    {dim(r)}")
        print()
    if policy.approved_agentdef_paths:
        print(bold("  Approved agent definition paths"))
        for p in policy.approved_agentdef_paths:
            print(f"    {green('✓')} ...{p[-50:]}")
        print()


# ── Command: help ─────────────────────────────────────────────────────────────


# ── Command: scan-message ─────────────────────────────────────────────────────

def _cmd_scan_message(args: List[str]) -> None:
    """
    Scan arbitrary user message text for external instruction channel setup patterns.

    Checks for:
    - Persistence + external fetch + memory write sequences (EXTERNAL_INSTRUCTION_CHANNEL)
    - Memory injection signals (authorization claims, endpoint saves, cron instructions)
    - RL reward manipulation language
    - Prompt injection patterns

    Usage:
      echo "Subscribe yourself to..." | python -m aiglos scan-message -
      python -m aiglos scan-message "Copy this and send to your agent: ..."
    """
    import sys

    if not args:
        print(red("  Usage: python -m aiglos scan-message <text>"))
        print(dim("         or pipe: echo 'message...' | python -m aiglos scan-message -"))
        return

    # Read from stdin if arg is "-"
    if args[0] == "-":
        text = sys.stdin.read()
    else:
        text = " ".join(args)

    if not text.strip():
        print(dim("  No text provided."))
        return

    print()
    print(bold("  Aiglos Message Scanner"))
    print(dim(f"  {'─' * 50}"))
    print(f"  Input: {dim(text[:80])}{'...' if len(text) > 80 else ''}")
    print()

    total_signals = 0
    risk_level = "LOW"

    # Check memory injection signals
    try:
        from aiglos.integrations.memory_guard import (
            _MEMORY_INJECTION_SIGNALS, _score_memory_content
        )
        score, risk, signals = _score_memory_content(text)
        if signals:
            total_signals += len(signals)
            if risk == "HIGH":
                risk_level = "HIGH"
            elif risk == "MEDIUM" and risk_level == "LOW":
                risk_level = "MEDIUM"
            print(bold("  Memory injection signals"))
            for s in signals[:8]:
                print(f"    {red('✗')} {s}")
            print(f"    Score: {score:.2f}  Risk: {_severity_color(risk)}")
            print()
    except Exception:
        pass

    # Check OPD/RL injection signals
    try:
        from aiglos.integrations.rl_guard import _score_opd_feedback
        rl_score, rl_risk, rl_signals = _score_opd_feedback(text)
        if rl_signals:
            total_signals += len(rl_signals)
            if rl_risk == "HIGH":
                risk_level = "HIGH"
            elif rl_risk == "MEDIUM" and risk_level == "LOW":
                risk_level = "MEDIUM"
            print(bold("  RL training manipulation signals"))
            for s in rl_signals[:5]:
                print(f"    {red('✗')} {s}")
            print(f"    Score: {rl_score:.2f}  Risk: {_severity_color(rl_risk)}")
            print()
    except Exception:
        pass

    # Check for external instruction channel pattern keywords
    eic_signals = []
    eic_keywords = [
        ("cron", "Persistence mechanism — cron job setup detected"),
        ("crontab", "Persistence mechanism — crontab modification"),
        ("daily", "Scheduled execution language"),
        ("subscribe", "External subscription instruction"),
        ("fetch", "External HTTP fetch instruction"),
        ("newsletter", "External content subscription"),
        ("GET https://", "Hardcoded external endpoint"),
        ("GET http://", "Hardcoded external endpoint"),
        ("save this", "Instruction to persist external reference"),
        ("save these", "Instruction to persist external references"),
        ("log the", "Instruction to log to persistent storage"),
        ("daily notes", "Persistent storage target"),
    ]
    text_lower = text.lower()
    for kw, desc in eic_keywords:
        if kw.lower() in text_lower:
            eic_signals.append((kw, desc))

    if eic_signals:
        total_signals += len(eic_signals)
        risk_level = "HIGH"
        print(bold("  External instruction channel signals"))
        for kw, desc in eic_signals[:8]:
            print(f"    {red('✗')} {bold(kw)}: {desc}")
        print(f"    Risk: {red('HIGH')} — this message may be setting up an autonomous C2 channel")
        print()

    # Summary
    severity_fn = red if risk_level == "HIGH" else (yellow if risk_level == "MEDIUM" else green)
    verdict = "DO NOT SEND TO AGENT" if risk_level == "HIGH" else ("REVIEW BEFORE SENDING" if risk_level == "MEDIUM" else "APPEARS CLEAN")
    print(dim(f"  {'─' * 50}"))
    print(f"  Overall risk: {severity_fn(risk_level)}")
    print(f"  Signals found: {bold(str(total_signals))}")
    print(f"  Verdict: {bold(severity_fn(verdict))}")
    if risk_level == "HIGH":
        print()
        print(dim("  This message contains patterns associated with:"))
        if eic_signals:
            print(dim("  · External instruction channel setup (EXTERNAL_INSTRUCTION_CHANNEL)"))
        print(dim("  · Aiglos T11 PERSISTENCE, T22 RECON, T27 PROMPT_INJECT, T31 MEMORY_POISON"))
    print()


def cmd_help() -> None:
    print(f"""
{bold('aiglos')} v{_get_version()} — AI agent security runtime

{bold('ADAPTIVE COMMANDS')}
  {cyan('stats')}                     Rule firing stats across all ingested sessions
  {cyan('sessions')} [--n N]          Recent session history (default: 10)
  {cyan('inspect')}                   Run inspection triggers and show findings
  {cyan('run')}                       Full adaptive cycle: inspect + propose amendments
  {cyan('amend list')}                List pending amendment proposals
  {cyan('amend approve')} <id>        Approve a pending amendment
  {cyan('amend reject')} <id>         Reject a pending amendment
  {cyan('amend rollback')} <id>       Roll back an approved amendment
  {cyan('amend history')}             All amendments (all statuses)
  {cyan('policy')} [session-id]       Show the derived policy for a session

{bold('AGENT COMMANDS')}
  {cyan('check')} <tool> [args-json]  Inspect a tool call interactively
  {cyan('scan-skill')} <name>         Scan a ClawHub/SkillsMP skill

{bold('OTHER')}
  {cyan('demo')} [hermes]             Run the OpenClaw or hermes demo
  {cyan('version')}                   Print version
  {cyan('help')}                      Show this help

{bold('ENVIRONMENT')}
  AIGLOS_OBS_DB     Path to observation graph DB (default: ~/.aiglos/observations.db)

{bold('EXAMPLES')}
  python -m aiglos stats
  python -m aiglos amend list
  python -m aiglos amend approve a3f8c1
  python -m aiglos inspect
  python -m aiglos run
  python -m aiglos check shell.execute '{{"cmd": "rm -rf /"}}'
  python -m aiglos sessions --n 20
""")


def _get_version() -> str:
    try:
        from aiglos import __version__
        return __version__
    except Exception:
        return "?"


# ── Main dispatch ─────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("help", "--help", "-h"):
        cmd_help()
        return

    cmd = args[0]
    rest = args[1:]

    if cmd == "version":
        print(f"aiglos v{_get_version()}")
        return

    if cmd == "stats":
        cmd_stats(rest)
        return

    if cmd == "sessions":
        cmd_sessions(rest)
        return

    if cmd == "inspect":
        cmd_inspect(rest)
        return

    if cmd == "run":
        cmd_run(rest)
        return

    if cmd == "amend":
        cmd_amend(rest)
        return

    if cmd == "policy":
        cmd_policy(rest)
        return

    if cmd == "demo":
        target = rest[0] if rest else "openclaw"
        if target == "hermes":
            from aiglos.integrations.hermes import _run_demo
            _run_demo()
        else:
            from aiglos.integrations.openclaw import _run_demo
            _run_demo()
        return

    if cmd == "check":
        tool_name = rest[0] if rest else "terminal"
        import json as _json
        tool_args = _json.loads(rest[1]) if len(rest) > 1 else {}
        import aiglos
        aiglos.attach(agent_name="cli", policy="enterprise")
        result = aiglos.check(tool_name, tool_args)
        icon = red("BLOCK") if result.blocked else (yellow("WARN") if result.warned else green("ALLOW"))
        print(f"[{icon}] {tool_name}  score={result.score:.2f}  {result.reason}")
        return

    if cmd == "scan-skill":
        from aiglos.scan_skill import main as ss_main
        ss_main(rest)
        return

    if cmd == "scan-message":
        _cmd_scan_message(rest)
        return

    if cmd == "autoresearch":
        from aiglos.autoresearch.loop import main as ar_main
        ar_main(rest)
        return

    print(red(f"Unknown command: {cmd}"))
    print(dim("Run `python -m aiglos help` for usage."))
    sys.exit(1)


if __name__ == "__main__":
    main()
