"""
aiglos.cli
===========
Command-line interface for the Aiglos adaptive security layer.

Commands:
    stats              -- rule firing stats across all ingested sessions
    amend list         -- list pending amendment proposals
    amend approve <id> -- approve a pending amendment
    amend reject <id>  -- reject a pending amendment
    amend history      -- all amendments (all statuses)
    inspect            -- run inspection triggers and show findings
    policy <session>   -- show the derived policy for a session ID
    run                -- full adaptive cycle: inspect + propose
    sessions           -- recent session history
    version            -- print version
    demo               -- run the OpenClaw demo
    check <tool>       -- check a tool call interactively
    scan-skill <name>  -- scan a ClawHub/SkillsMP skill

Usage:
    python -m aiglos stats
    python -m aiglos amend list
    python -m aiglos amend approve a3f8c1
    python -m aiglos inspect
    python -m aiglos run
    python -m aiglos sessions --n 20
"""



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
            print(f"  [{_severity_color(t['severity'])}] {t['trigger_type']}{cand}  --  {t['rule_id'] or 'n/a'}")
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
            print(yellow(f"  Ambiguous prefix -- {len(matches)} matches. Use more characters."))
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
                f"{a.eval_outcome or dim('--')}"
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
        print(dim("  Policy is empty -- insufficient session history to derive context."))
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
        ("cron", "Persistence mechanism -- cron job setup detected"),
        ("crontab", "Persistence mechanism -- crontab modification"),
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
        print(f"    Risk: {red('HIGH')} -- this message may be setting up an autonomous C2 channel")
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


# ── Command: trace ────────────────────────────────────────────────────────────

def _cmd_trace(args: List[str]) -> None:
    """
    Run causal attribution investigation for a session.

    Usage:
      python -m aiglos trace <session-id>
      python -m aiglos trace --latest
      python -m aiglos trace --all
    """
    import json as _json

    if not args:
        print(red("  Usage: python -m aiglos trace <session-id>"))
        print(dim("         python -m aiglos trace --latest"))
        print(dim("         python -m aiglos trace --all"))
        return

    graph = _get_graph()
    print()
    print(bold("  Aiglos Causal Attribution"))
    print(dim(f"  {chr(8212) * 52}"))

    if args[0] == "--all":
        stats = graph.causal_stats()
        print(f"  Sessions with tracing : {bold(str(stats.get('sessions_with_tracing',0)))}")
        print(f"  Attacks confirmed     : {bold(red(str(stats.get('attacks_confirmed',0)))) if stats.get('attacks_confirmed') else bold('0')}")
        print(f"  Suspicious sessions   : {bold(str(stats.get('suspicious_sessions',0)))}")
        print(f"  High-conf attributions: {bold(str(stats.get('high_conf_attributions',0)))}")
        print(f"  Total attributed      : {bold(str(stats.get('total_attributed',0)))}")
        print()
        return

    if args[0] == "--latest":
        sessions = graph.recent_sessions(n=20)
        session_id = None
        for s in sessions:
            chain = graph.get_causal_chain(s.get("session_id", ""))
            if chain:
                session_id = s.get("session_id", "")
                break
        if not session_id:
            print(dim("  No traced sessions found. Enable causal tracing with enable_causal_tracing=True."))
            print()
            return
    else:
        session_id = args[0]

    chain = graph.get_causal_chain(session_id)
    if not chain:
        print(dim(f"  No causal attribution data for session: {session_id}"))
        print(dim("  Enable tracing with: aiglos.attach(enable_causal_tracing=True)"))
        print()
        return

    verdict = chain.get("session_verdict", "CLEAN")
    flagged = chain.get("flagged_actions", 0)
    attributed = chain.get("attributed_actions", 0)
    high_conf = chain.get("high_conf_chains", 0)

    verdict_str = (
        red(bold(verdict)) if verdict == "ATTACK_CONFIRMED"
        else yellow(bold(verdict)) if verdict == "SUSPICIOUS"
        else green(verdict)
    )

    print(f"  Session   : {bold(session_id)}")
    print(f"  Agent     : {chain.get('agent_name', 'unknown')}")
    print(f"  Verdict   : {verdict_str}")
    print(f"  Actions   : {flagged} flagged · {attributed} attributed · {high_conf} HIGH confidence")
    print()

    chains = chain.get("chains", [])
    if not chains:
        print(dim("  No flagged actions in this session."))
        print()
        return

    for c in chains:
        action = c.get("action", {})
        conf   = c.get("confidence", "NONE")
        conf_score = c.get("confidence_score", 0)

        conf_color = (
            red(bold(conf)) if conf == "HIGH"
            else yellow(conf) if conf == "MEDIUM"
            else dim(conf)
        )

        step_num = action.get("step", "?")
        print(f"  {bold(f'Step {step_num:>3}')}  "
              f"{_severity_color(action.get('verdict','ALLOW')):<7}  "
              f"{action.get('tool_name','?')}  "
              f"[{dim(action.get('rule_id','?'))}]")
        print(f"    Attribution: {conf_color}  ({conf_score:.0%})")

        sources = c.get("attributed_sources", [])
        if sources:
            top = sources[0]
            print(f"    Source  :  step {top.get('step','?')}  "
                  f"{top.get('tool_name','?')}  "
                  f"[score {top.get('injection_score',0):.2f} · {_severity_color(top.get('risk','LOW'))}]")
            if top.get("source_url"):
                print(f"    URL     :  {dim(top['source_url'])}")
            if top.get("phrase_hits"):
                print(f"    Phrases :  {dim(str(top['phrase_hits'][:3]))}")
            gap = c.get("steps_since_injection")
            if gap is not None:
                print(f"    Gap     :  {gap} steps between injection and action")

        narrative = c.get("narrative", "")
        if narrative:
            # Word-wrap at 64 chars
            words = narrative.split()
            line, wrapped = [], []
            for w in words:
                if sum(len(x)+1 for x in line) + len(w) > 64:
                    wrapped.append(" ".join(line))
                    line = [w]
                else:
                    line.append(w)
            if line:
                wrapped.append(" ".join(line))
            print(f"    {dim('Narrative')}: {dim(wrapped[0])}")
            for extra_line in wrapped[1:]:
                print(f"              {dim(extra_line)}")
        print()

    print(dim(f"  {chr(8212) * 52}"))
    narrative = chain.get("session_narrative", "")
    if verdict == "ATTACK_CONFIRMED":
        print(f"  {red(bold(narrative))}")
    elif verdict == "SUSPICIOUS":
        print(f"  {yellow(narrative)}")
    else:
        print(f"  {dim(narrative)}")
    print()



# ── Command: forecast ────────────────────────────────────────────────────────

def _cmd_forecast(args: List[str]) -> None:
    """
    Show the threat forecast for the current deployment.

    Usage:
      python -m aiglos forecast              # current model state + recent prediction
      python -m aiglos forecast --train      # retrain model from observation graph
      python -m aiglos forecast --sequence T19 T22 T08   # predict from custom sequence
    """
    from aiglos.core.intent_predictor import IntentPredictor, _HIGH_CONSEQUENCE_RULES, _MIN_TRAINING_SESSIONS

    graph = _get_graph()

    print()
    print(bold("  Aiglos Threat Forecast"))
    print(dim(f"  {chr(8212) * 52}"))

    predictor = IntentPredictor(graph)

    if "--train" in args:
        print(dim("  Training model from observation graph..."))
        trained = predictor.train(force=True)
        if not trained:
            print(red("  Insufficient training data."))
            print(dim(f"  Need at least {_MIN_TRAINING_SESSIONS} sessions with flagged events."))
            print(dim("  Run more agent sessions to build the model."))
            print()
            return
        print(green(f"  Model trained on {predictor.sessions_trained} sessions."))
        print()
    else:
        predictor.train()

    if not predictor.is_ready:
        print(yellow(f"  Model not ready: {predictor.sessions_trained}/{_MIN_TRAINING_SESSIONS} sessions trained."))
        print(dim("  Run `python -m aiglos forecast --train` after more sessions."))
        print()
        return

    print(f"  Model: {bold(str(predictor.sessions_trained))} sessions trained")
    print()

    # Build sequence to predict from
    if "--sequence" in args:
        idx = args.index("--sequence")
        sequence = args[idx+1:]
        if not sequence:
            print(red("  --sequence requires rule IDs: python -m aiglos forecast --sequence T19 T22 T08"))
            print()
            return
    else:
        # Use most recent session's sequence from graph
        sequence = []
        try:
            with graph._conn() as conn:
                rows = conn.execute("""
                    SELECT rule_id FROM events
                    WHERE verdict != 'ALLOW' AND rule_id NOT IN ('none','')
                    AND session_id = (
                        SELECT session_id FROM sessions ORDER BY closed_at DESC LIMIT 1
                    )
                    ORDER BY timestamp ASC
                """).fetchall()
                sequence = [r["rule_id"] for r in rows]
        except Exception:
            pass

    if not sequence:
        print(dim("  No recent session data. Use --sequence T19 T22 to predict from a custom sequence."))
        print()
        return

    # Feed sequence into predictor
    for rule in sequence:
        predictor.observe(rule, "BLOCK")

    prediction = predictor.predict()
    if not prediction:
        print(dim("  No prediction available."))
        print()
        return

    # Render sequence
    seq_display = " → ".join(sequence[-6:])
    if len(sequence) > 6:
        seq_display = f"...({len(sequence)-6} earlier) → " + seq_display
    print(f"  Observed sequence:  {dim(seq_display)}")
    print()

    # Alert level
    alert_color = (
        red(bold(prediction.alert_level)) if prediction.alert_level in ("HIGH","CRITICAL")
        else yellow(prediction.alert_level) if prediction.alert_level == "MEDIUM"
        else green(prediction.alert_level) if prediction.alert_level == "NONE"
        else dim(prediction.alert_level)
    )
    print(f"  Alert level:        {alert_color}")
    print(f"  Model confidence:   {dim(f'{prediction.model_confidence:.0%}')}")
    print()

    # Probability bars
    print(bold("  Next-step threat probabilities:"))
    print()
    bar_width = 28
    for rule_id, prob in prediction.top_threats[:8]:
        filled   = int(prob * bar_width)
        bar      = "█" * filled + "░" * (bar_width - filled)
        is_hc    = rule_id in _HIGH_CONSEQUENCE_RULES
        rule_col = red(bold(f"{rule_id:<16}")) if is_hc else f"{rule_id:<16}"
        prob_col = red(f"{prob:.0%}") if prob >= 0.60 else (
                   yellow(f"{prob:.0%}") if prob >= 0.35 else dim(f"{prob:.0%}")
        )
        print(f"    {rule_col}  {bar}  {prob_col}")

    print()
    print(dim(f"  {chr(8212) * 52}"))

    # Threshold elevation suggestions
    from aiglos.core.threat_forecast import _ELEVATABLE_RULES, _ELEVATION_THRESHOLDS
    elevations = []
    threshold = _ELEVATION_THRESHOLDS.get(prediction.alert_level, 1.0)
    for rule_id, prob in prediction.top_threats:
        if rule_id in _ELEVATABLE_RULES and prob >= threshold:
            elevations.append((rule_id, prob, _ELEVATABLE_RULES[rule_id]))

    if elevations:
        print()
        print(bold("  Recommended session-scoped elevations:"))
        for rule_id, prob, tier in elevations:
            print(f"    {red(rule_id):<20}  →  Tier {tier} GATED  "
                  f"({yellow(f'{prob:.0%}')} probability)")
        print()
        print(dim("  These elevations are applied automatically when"))
        print(dim("  enable_intent_prediction=True is set in aiglos.attach()."))
    print()


def cmd_help() -> None:
    print(f"""
{bold('aiglos')} v{_get_version()} -- AI agent security runtime

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
  {cyan('audit')}      [--deep] [--format summary|full|json|briefing] [--schedule nightly]
                                   Security posture audit -- host, skills, runtime, network
  {cyan('skill')}      scan|import|blocked        Skill reputation -- ClawKeeper badge ingestion
  {cyan('reputation')} top|show|clear           Source reputation -- URL and document threat history
  {cyan('override')} list|confirm|reject       Challenge-response Tier 3 override management
  {cyan('honeypot')} status|list|deploy         Honeypot file management and hit log
  {cyan('research')} verify|report|scan        Citation verification and compliance reports
  {cyan('policy')}  list|show|approve|reject  Policy proposals from repeated block patterns
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


def _cmd_policy(args: list) -> None:
    """
    aiglos policy <subcommand> [args]

    Subcommands:
      list [--status pending|approved|rejected|expired] [--agent NAME]
           List policy proposals. Defaults to pending.

      show <proposal-id>
           Show full detail for a specific proposal.

      approve <proposal-id>
           Approve a pending proposal (marks as approved in graph).

      reject <proposal-id>
           Reject a pending proposal.

      stats
           Show summary counts by status.
    """
    from aiglos.adaptive.observation import ObservationGraph
    from aiglos.core.policy_proposal import PolicyProposalEngine

    graph  = ObservationGraph()
    engine = PolicyProposalEngine(graph=graph)
    engine.expire_stale_proposals()

    subcmd = args[0] if args else "list"
    rest   = args[1:]

    if subcmd == "list":
        status     = "pending"
        agent_name = None
        i = 0
        while i < len(rest):
            if rest[i] == "--status" and i + 1 < len(rest):
                status = rest[i + 1]; i += 2
            elif rest[i] == "--agent" and i + 1 < len(rest):
                agent_name = rest[i + 1]; i += 2
            else:
                i += 1

        proposals = engine.list_proposals(status=status, agent_name=agent_name)
        if not proposals:
            print(f"No {status} proposals" + (f" for agent '{agent_name}'" if agent_name else "") + ".")
            return

        print(f"\n  {bold('Policy Proposals')} [{status}] ({len(proposals)} found)")
        print("  " + "─" * 70)
        for p in proposals:
            conf_bar = "█" * int(p.confidence * 10) + "░" * (10 - int(p.confidence * 10))
            expiry   = f"{p.days_until_expiry:.0f}d left" if p.status.value == "pending" else ""
            print(f"  {cyan(p.proposal_id)}  {p.proposal_type.value:<18} {p.agent_name}/{p.rule_id}")
            print(f"    {conf_bar} {p.confidence:.0%} confidence  "
                  f"{p.evidence.repetition_count} blocks  {expiry}")
            print(f"    {p.proposed_change.get('rationale', '')[:72]}")
            print()

        print(f"  Use {cyan('aiglos policy show <id>')} for full detail.")
        print(f"  Use {cyan('aiglos policy approve <id>')} or {cyan('reject <id>')} to review.")

    elif subcmd == "show":
        if not rest:
            print("Usage: aiglos policy show <proposal-id>")
            return
        pid = rest[0]
        p   = engine.get_proposal(pid)
        if not p:
            print(f"Proposal '{pid}' not found.")
            return

        print(f"\n  {bold('Policy Proposal')} {cyan(p.proposal_id)}")
        print("  " + "─" * 60)
        print(f"  Type:       {p.proposal_type.value}")
        print(f"  Status:     {p.status.value}")
        print(f"  Agent:      {p.agent_name}")
        print(f"  Rule:       {p.rule_id}")
        print(f"  Tool:       {p.tool_name}")
        print(f"  Confidence: {p.confidence:.0%}")
        print()
        print(f"  {bold('Evidence')}")
        print(f"  Repetitions: {p.evidence.repetition_count} blocks in {p.evidence.window_days} days")
        print(f"  Consistency: {p.evidence.consistency_score:.0%}")
        print(f"  Incidents:   {p.evidence.incident_count}")
        print(f"  Baseline:    {'confirmed' if p.evidence.baseline_confirmed else 'not ready'}")
        print()
        print(f"  {bold('Proposed change')}")
        for k, v in p.proposed_change.items():
            if k != "rationale":
                print(f"  {k}: {v}")
        print()
        if p.proposed_change.get("rationale"):
            print(f"  {bold('Rationale')}")
            rationale = p.proposed_change["rationale"]
            for chunk in [rationale[i:i+70] for i in range(0, len(rationale), 70)]:
                print(f"  {chunk}")
        print()
        print(f"  Expires: {p.days_until_expiry:.0f} days from now")
        if p.reviewed_by:
            print(f"  Reviewed by: {p.reviewed_by}")

    elif subcmd == "approve":
        if not rest:
            print("Usage: aiglos policy approve <proposal-id>")
            return
        pid      = rest[0]
        reviewer = rest[1] if len(rest) > 1 else "cli"
        result   = engine.approve_proposal(pid, approved_by=reviewer)
        if result:
            print(f"  Approved: {pid} ({result.proposal_type.value} for {result.agent_name}/{result.rule_id})")
            print(f"  Apply the change in your aiglos configuration to take effect.")
        else:
            print(f"  Could not approve '{pid}'. Check status with: aiglos policy show {pid}")

    elif subcmd == "reject":
        if not rest:
            print("Usage: aiglos policy reject <proposal-id>")
            return
        pid      = rest[0]
        reviewer = rest[1] if len(rest) > 1 else "cli"
        result   = engine.reject_proposal(pid, rejected_by=reviewer)
        if result:
            print(f"  Rejected: {pid}. Pattern will continue to block normally.")
        else:
            print(f"  Could not reject '{pid}'.")

    elif subcmd == "stats":
        stats = engine.summary_stats()
        print(f"\n  {bold('Policy Proposal Summary')}")
        print("  " + "─" * 40)
        for status, count in stats.items():
            if status != "total":
                bar = "█" * min(count, 20)
                print(f"  {status:<12} {count:>4}  {bar}")
        print(f"  {'total':<12} {stats.get('total', 0):>4}")

    else:
        print(f"Unknown policy subcommand: {subcmd}")
        print("Usage: aiglos policy list|show|approve|reject|stats")


def _cmd_audit(args: list) -> None:
    """
    aiglos audit [--deep] [--format summary|full|json|briefing|clawkeeper]
                 [--schedule nightly] [--clawkeeper path/to/audit.json]
                 [--save]

    Security posture audit for AI agent deployments.

    --deep       Runs additional phases: injection scan, reputation check,
                 citation coverage analysis
    --format     Output format (default: summary)
    --schedule   Set up a nightly cron job to run the audit automatically
    --clawkeeper Merge with a ClawKeeper host audit JSON file
    --save       Save the report to ~/.aiglos/reports/
    """
    from aiglos.audit.scanner import AuditScanner
    from aiglos.audit.report  import AuditReporter

    deep             = "--deep" in args
    fmt              = "summary"
    schedule         = False
    clawkeeper_path  = None
    save             = "--save" in args

    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2
        elif args[i] == "--schedule" and i + 1 < len(args):
            schedule = args[i + 1] == "nightly"; i += 2
        elif args[i] == "--clawkeeper" and i + 1 < len(args):
            clawkeeper_path = args[i + 1]; i += 2
        else:
            i += 1

    if "--ghsa" in args:
        _cmd_audit_ghsa(args)
        return

    if "--atlas" in args:
        _cmd_audit_atlas(args)
        return

    if schedule:
        _schedule_nightly_audit()
        return

    print(f"\n  {cyan('Aiglos Security Audit')} {'[deep]' if deep else ''}  running...")
    scanner = AuditScanner(deep=deep)
    result  = scanner.run()
    reporter = AuditReporter(result)

    if fmt == "full":
        print(reporter.full())
    elif fmt == "json":
        print(reporter.to_json())
    elif fmt == "briefing":
        print(reporter.briefing())
    elif fmt == "clawkeeper":
        ck_data = None
        if clawkeeper_path:
            import json as _json
            try:
                with open(clawkeeper_path) as f:
                    ck_data = _json.load(f)
            except Exception as e:
                print(f"  Could not load ClawKeeper audit: {e}")
        print(reporter.to_clawkeeper_json(ck_data))
    else:
        print(reporter.summary())

    if save:
        path = reporter.save()
        print(f"  Report saved: {cyan(str(path))}")


def _cmd_audit_ghsa(args: list) -> None:
    """
    aiglos audit --ghsa [--format markdown|json|summary]

    GHSA coverage report -- maps published OpenClaw advisories to Aiglos rules.
    """
    from aiglos.autoresearch.ghsa_coverage import generate_coverage_artifact

    fmt = "summary"
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2
        else:
            i += 1

    artifact = generate_coverage_artifact()

    if fmt == "markdown":
        print(artifact.to_markdown())
    elif fmt == "json":
        print(artifact.to_json())
    else:
        print(f"\n  {cyan('Aiglos GHSA Coverage Report')}  v{artifact.version}")
        print(f"  {'=' * 50}")
        print(f"  Published advisories:  {artifact.total_ghsa}")
        print(f"  Covered by rules:      {artifact.total_covered}")
        print(f"  Coverage:              {green(f'{artifact.coverage_pct:.0f}%')}")
        print()
        for e in artifact.entries:
            cvss_str = f"CVSS {e.cvss}" if e.cvss else "CVSS N/A"
            rules_str = ", ".join(e.rules)
            print(f"  {green('+')} {e.ghsa_id}  [{e.severity}]  {cvss_str}")
            print(f"    {e.title[:65]}")
            print(f"    Rules: {cyan(rules_str)}")
            if e.disclosed_by:
                print(f"    Disclosed by: {e.disclosed_by}")
            print()
        print(f"  {bold(f'{artifact.total_covered}/{artifact.total_ghsa}. {artifact.coverage_pct:.0f}%.')}")
        print(f"  Every published OpenClaw GHSA caught by existing Aiglos rules.")
        print()


def _cmd_audit_atlas(args: list) -> None:
    """
    aiglos audit --atlas [--format json|gaps-only]

    ATLAS coverage report -- maps OpenClaw ATLAS threat model to Aiglos rules.
    """
    from aiglos.autoresearch.atlas_coverage import ATLASCoverage

    fmt = "summary"
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2
        else:
            i += 1

    cov = ATLASCoverage()

    if fmt == "json":
        print(cov.to_json())
    elif fmt == "gaps-only":
        print(cov.report(gaps_only=True))
    else:
        print(cov.report())


def _schedule_nightly_audit() -> None:
    """Write a nightly cron job for the audit."""
    import subprocess
    try:
        cron_line = "0 6 * * * aiglos audit --deep --format briefing --save >> ~/.aiglos/audit.log 2>&1"
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True
        )
        existing = result.stdout
        if "aiglos audit" in existing:
            print("  Nightly audit already scheduled.")
            return
        new_cron = existing.rstrip() + "\n" + cron_line + "\n"
        proc = subprocess.run(
            ["crontab", "-"], input=new_cron, text=True, capture_output=True
        )
        if proc.returncode == 0:
            print(f"  Nightly audit scheduled at 6:00 AM.")
            print(f"  Output: ~/.aiglos/audit.log")
            print(f"  To view: cat ~/.aiglos/audit.log")
            print(f"  {bold('Important:')} Do not set --auto-fix. Review each finding manually.")
        else:
            print(f"  Failed to schedule cron: {proc.stderr[:100]}")
    except Exception as e:
        print(f"  Cron scheduling error: {e}")


def _cmd_scan_exposed(args: list) -> None:
    """
    aiglos scan-exposed <ip-or-hostname> [--port PORT]

    Probe an exposed OpenClaw instance for security misconfigurations.
    Returns a security grade and the specific findings that make it
    vulnerable. Designed for the 40,000+ instances found by SecurityScorecard.

    Examples:
        aiglos scan-exposed 192.168.1.100
        aiglos scan-exposed myclaw.example.com --port 3000
        aiglos scan-exposed 10.0.0.1 --port 8080
    """
    import socket, urllib.request, urllib.error, json as _json, time as _time

    if not args:
        print("  Usage: aiglos scan-exposed <ip-or-hostname> [--port PORT]")
        print("  Probes an exposed OpenClaw gateway for security misconfigurations.")
        return

    target = args[0]
    port   = 3000
    for i, t in enumerate(args):
        if t == "--port" and i + 1 < len(args):
            port = int(args[i + 1])

    print("")
    print(f"  {cyan('Aiglos Exposure Scanner')} -- probing {bold(target)}:{port}")
    print(f"  {'---' * 19}")

    findings = []
    score    = 100
    start    = _time.time()

    def _check(label, fn, on_fail_sev="FAIL", on_fail_detail="", remediation=""):
        nonlocal score
        try:
            result = fn()
            if result is True:
                print(f"  {_c('92', 'OK')} {label}")
            elif result is False:
                deduct = {"CRITICAL": 30, "FAIL": 15, "WARN": 5}.get(on_fail_sev, 15)
                score -= deduct
                findings.append((on_fail_sev, label, on_fail_detail, remediation))
                print(f"  {_c('91' if on_fail_sev == 'CRITICAL' else '33', 'X')} [{on_fail_sev}] {label}")
                if on_fail_detail:
                    print(f"      {on_fail_detail[:80]}")
        except Exception as e:
            print(f"  {_c('2', '?')} {label} -- {str(e)[:60]}")

    gateway_url = f"http://{target}:{port}"
    is_open = False
    try:
        req = urllib.request.Request(
            f"{gateway_url}/api/status",
            headers={"User-Agent": "aiglos-scanner/0.22.0"},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        is_open = True
        print(f"  {_c('91', '!')} [CRITICAL] Gateway reachable on {target}:{port}")
        findings.append((
            "CRITICAL",
            f"OpenClaw gateway exposed on {target}:{port}",
            "Gateway responded to unauthenticated status probe.",
            "Set allow_remote=false or add authentication.",
        ))
        score -= 30
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            print(f"  {_c('92', 'OK')} Gateway requires authentication (HTTP {e.code})")
            is_open = True
        else:
            print(f"  {_c('91', '?')} Gateway returned HTTP {e.code}")
            is_open = True
    except Exception:
        print(f"  {_c('92', 'OK')} Port {port} not reachable from this network")

    if is_open:
        for endpoint in ["/api/config", "/api/agents", "/api/cron"]:
            try:
                req = urllib.request.Request(
                    f"{gateway_url}{endpoint}",
                    headers={"User-Agent": "aiglos-scanner/0.22.0"},
                )
                resp = urllib.request.urlopen(req, timeout=3)
                if resp.status == 200:
                    findings.append((
                        "CRITICAL",
                        f"Unauthenticated access to {endpoint}",
                        f"Endpoint returned 200 with no credentials.",
                        "Add API key authentication to all endpoints.",
                    ))
                    print(f"  {_c('91', 'X')} [CRITICAL] {endpoint} accessible without credentials")
                    score -= 30
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    print(f"  {_c('92', 'OK')} {endpoint} requires authentication")
            except Exception:
                pass

        try:
            req = urllib.request.Request(
                f"{gateway_url}/socket.io/",
                headers={"User-Agent": "aiglos-scanner/0.22.0"},
            )
            resp = urllib.request.urlopen(req, timeout=3)
            findings.append((
                "CRITICAL",
                "WebSocket endpoint exposed (CVE-2026-25253 surface)",
                "Gateway WebSocket accessible without authentication. "
                "Attack vector for token theft and remote code execution.",
                "Require authentication on all WebSocket connections.",
            ))
            print(f"  {_c('91', 'X')} [CRITICAL] WebSocket endpoint exposed (CVE-2026-25253)")
            score -= 30
        except Exception:
            print(f"  {_c('92', 'OK')} WebSocket endpoint requires authentication or not exposed")

    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"
    grade_color = "92" if grade == "A" else "93" if grade in "BC" else "91"

    print("")
    print(f"  Security Grade: {_c(grade_color, bold(grade))}  Score: {score}/100")
    print(f"  Scan duration: {(_time.time()-start)*1000:.0f}ms")
    print("")

    if not findings:
        print(f"  {_c('92', 'OK')} No critical exposures found from this network.")
    else:
        print(f"  {bold('Findings:')}")
        for sev, label, detail, rem in findings[:6]:
            sev_icon = "X" if sev == "CRITICAL" else "!"
            print(f"  {sev_icon} [{sev}] {label}")
        print("")
        print(f"  This instance appears in the 40,000+ exposed OpenClaw deployments")
        print(f"  documented by SecurityScorecard (February 2026).")
        print("")
        print(f"  Fix with Aiglos: {cyan('pip install aiglos && aiglos audit --deep')}")
        print(f"  Detailed report: {cyan('aiglos.dev/intel')}")
    print("")


def _cmd_baseline(args: list) -> None:
    """aiglos baseline reset|history|status [--agent name] [--reason str]"""
    from aiglos.adaptive.observation import ObservationGraph
    import time as _time

    graph  = ObservationGraph()
    subcmd = args[0] if args else "status"
    rest   = args[1:]

    agent = None
    reason = ""
    for i, t in enumerate(rest):
        if t == "--agent" and i + 1 < len(rest):
            agent = rest[i + 1]
        if t == "--reason" and i + 1 < len(rest):
            reason = rest[i + 1]

    if subcmd == "reset":
        if not agent:
            print("  Usage: aiglos baseline reset --agent <name> [--reason <str>]")
            return
        sessions_before = graph.get_agent_session_count_since(agent, 0)
        suppress_until  = sessions_before + 20
        graph.record_baseline_event(
            agent_name               = agent,
            event_type               = "reset",
            reason                   = reason or "manual reset",
            sessions_before          = sessions_before,
            suppressed_until_session = suppress_until,
        )
        print("")
        print(f"  Baseline reset -- agent: {cyan(agent)}")
        print(f"  Sessions before reset:  {sessions_before}")
        print(f"  Anomaly suppression:    next 20 sessions (until #{suppress_until})")
        print(f"  Reason:                 {reason or 'manual reset'}")
        print("")
        print("  Note: Agents may feel dumber after hardening. That is normal.")
        print("  The baseline rebuilds against the new permission profile.")
        print("")

    elif subcmd == "history":
        if not agent:
            print("  Usage: aiglos baseline history --agent <name>")
            return
        events = graph.get_baseline_events(agent)
        if not events:
            print(f"  No baseline events for agent: {agent}")
            return
        print("")
        print(f"  Baseline History -- {bold(agent)}")
        print(f"  {'─' * 56}")
        import datetime as _dt
        for e in events:
            dt = _dt.datetime.fromtimestamp(e['occurred_at']).strftime("%Y-%m-%d %H:%M")
            print(f"  {dt}  {e['event_type']:<10}  {e['reason']}")
        print("")

    elif subcmd == "status":
        if not agent:
            print("  Usage: aiglos baseline status --agent <name>")
            return
        latest = graph.get_latest_baseline_reset(agent)
        if not latest:
            print(f"  Agent {cyan(agent)}: baseline active, no reset events.")
            return
        current       = graph.get_agent_session_count_since(agent, 0)
        suppress_until = latest.get("suppressed_until_session", 0)
        if current < suppress_until:
            remaining = suppress_until - current
            print("")
            print(f"  Agent {cyan(agent)}: hardening mode active")
            print(f"  BEHAVIORAL_ANOMALY suppressed for {remaining} more session(s)")
            print(f"  Reset reason: {latest.get('reason', '')}")
            print("")
        else:
            print(f"  Agent {cyan(agent)}: baseline active, no suppression in effect.")

    else:
        print(f"  Unknown baseline subcommand: {subcmd}. Use reset|history|status.")


def _cmd_benchmark(args: list) -> None:
    """
    aiglos benchmark <subcommand>

    run  [--dimension D1|D2|D3|D4|D5] [--format summary|json] [--agent name]
         Run GOVBENCH -- the governance benchmark for AI agents.
         Measures what SWE-CI didn't: campaign detection, agent definition
         file resistance, memory belief layer, RL feedback exploitation,
         multi-agent cascading failure.
    """
    from aiglos.benchmark.govbench import GovBench
    from aiglos.integrations.openclaw import OpenClawGuard
    import tempfile, os

    subcmd = args[0] if args else "run"
    rest   = args[1:]

    if subcmd != "run":
        print(f"Unknown benchmark subcommand: {subcmd}. Use 'run'.")
        return

    dimension  = None
    fmt        = "summary"
    agent_name = "govbench-agent"

    i = 0
    while i < len(rest):
        if rest[i] == "--dimension" and i + 1 < len(rest):
            dimension = [rest[i + 1].upper()]; i += 2
        elif rest[i] == "--format" and i + 1 < len(rest):
            fmt = rest[i + 1]; i += 2
        elif rest[i] == "--agent" and i + 1 < len(rest):
            agent_name = rest[i + 1]; i += 2
        else:
            i += 1

    dim_str = f" [dimension={dimension[0]}]" if dimension else " [all dimensions]"
    print("")
    print(f"  {cyan('GOVBENCH')} running{dim_str}...")

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = tf.name

    try:
        guard = OpenClawGuard(
            agent_name  = agent_name,
            policy      = "enterprise",
            log_path    = log_path,
        )
        bench  = GovBench(guard=guard)
        result = bench.run(dimensions=dimension)
    finally:
        try: os.unlink(log_path)
        except: pass

    if fmt == "json":
        print(result.to_json())
    else:
        print(result.summary())


def _cmd_skill_reputation(args: list) -> None:
    """
    aiglos skill <subcommand> [args]

    Subcommands:
      scan <skill-name>
           Scan a single skill against ClawKeeper badge data and Aiglos rules.

      import [--clawkeeper path/to/audit.json] [--feed]
           Ingest ClawKeeper badge data into source reputation graph.
           --clawkeeper: import from local ClawKeeper audit JSON
           --feed: poll live ClawKeeper security feed

      blocked
           List all skills with BLOCKED reputation.

      suspicious
           List all skills with SUSPICIOUS reputation.
    """
    from aiglos.adaptive.skill_reputation import SkillReputationGraph
    from aiglos.adaptive.observation import ObservationGraph

    graph = ObservationGraph()
    srg   = SkillReputationGraph(graph=graph)
    subcmd = args[0] if args else "blocked"
    rest   = args[1:]

    if subcmd == "scan":
        if not rest:
            print("Usage: aiglos skill scan <skill-name>")
            return
        skill = rest[0]
        risk  = srg.get_skill_risk(skill)
        badge_colors = {"Blocked": "\033[91m", "Suspicious": "\033[33m", "Clean": "\033[92m"}
        color = badge_colors.get(risk.badge, "")
        reset = "\033[0m"
        print(f"\n  Skill: {bold(skill)}")
        print(f"  Badge: {color}{risk.badge}{reset}")
        print(f"  Level: {risk.level}")
        print(f"  Score: {risk.score:.2f}")
        if risk.detail:
            print(f"  {risk.detail}")
        if risk.should_block:
            print(f"  {cyan('→')} {bold('DO NOT INSTALL')} -- T30 SUPPLY_CHAIN will block at runtime.")
        elif risk.should_warn:
            print(f"  {cyan('→')} Install with caution. T30 SUPPLY_CHAIN will WARN at runtime.")

    elif subcmd == "import":
        count  = 0
        source = ""
        if "--feed" in rest:
            print("  Polling ClawKeeper security feed...")
            count  = srg.sync_security_feed()
            source = "security feed"
        else:
            ck_path = None
            for i, token in enumerate(rest):
                if token == "--clawkeeper" and i + 1 < len(rest):
                    ck_path = rest[i + 1]
            if ck_path:
                import json as _json
                try:
                    with open(ck_path) as f:
                        data = _json.load(f)
                    count  = srg.ingest_clawkeeper_audit(data)
                    source = ck_path
                except Exception as e:
                    print(f"  Import error: {e}")
                    return
            else:
                print("Usage: aiglos skill import [--clawkeeper path] [--feed]")
                return
        print(f"  Imported {count} skill reputation record(s) from {source}.")

    elif subcmd in ("blocked", "list-blocked"):
        blocked = srg.blocked_skills()
        if not blocked:
            print("  No blocked skills in reputation graph.")
            print("  Run: aiglos skill import --feed")
        else:
            print(f"\n  {bold('Blocked Skills')} ({len(blocked)})")
            for s in blocked[:20]:
                print(f"  ⛔ {s}")

    elif subcmd == "suspicious":
        suspicious = srg.suspicious_skills()
        if not suspicious:
            print("  No suspicious skills in reputation graph.")
        else:
            print(f"\n  {bold('Suspicious Skills')} ({len(suspicious)})")
            for s in suspicious[:20]:
                print(f"  ⚠ {s}")
    else:
        print(f"Unknown skill subcommand: {subcmd}")


def _cmd_reputation(args: list) -> None:
    """
    aiglos reputation <subcommand> [args]

    Subcommands:
      top [--limit 10]
           Show most dangerous sources for this deployment.

      show <url-or-domain>
           Show reputation details for a specific source.

      domains
           Show domain-level reputation summary.

      shareable
           Show anonymized reputation data that can be shared via federation.
    """
    from aiglos.adaptive.observation import ObservationGraph
    from aiglos.adaptive.source_reputation import SourceReputationGraph, CLEAN

    graph   = ObservationGraph()
    srg     = SourceReputationGraph(graph=graph)
    subcmd  = args[0] if args else "top"
    rest    = args[1:]

    if subcmd == "top":
        limit = 10
        for i, token in enumerate(rest):
            if token == "--limit" and i + 1 < len(rest):
                try:
                    limit = int(rest[i + 1])
                except ValueError:
                    pass

        records = srg.top_risky_sources(limit=limit)
        if not records:
            print("  No reputation history yet.")
            print("  Enable with: aiglos.attach(enable_source_reputation=True)")
            return

        print(f"\n  {bold('Top Risky Sources')} ({len(records)} found)")
        print("  " + "─" * 70)
        for r in records:
            level_colors = {
                "BLOCKED":   "\033[91m",
                "HIGH_RISK": "\033[33m",
                "SUSPICIOUS": "\033[93m",
            }
            color = level_colors.get(r.reputation_level, "")
            reset = "\033[0m"
            print(f"  {color}{r.reputation_level:<12}{reset} "
                  f"{r.source_key[:50]:<50} "
                  f"events={r.event_count} "
                  f"max={r.max_score:.2f}")
            if r.rule_ids:
                rules = ', '.join(set(r.rule_ids[:3]))
                print(f"    rules: {rules}")

    elif subcmd == "show":
        if not rest:
            print("Usage: aiglos reputation show <url-or-domain>")
            return
        url   = rest[0]
        risk  = srg.get_risk(source_url=url)
        print(f"\n  {bold('Source Reputation')}: {url}")
        print(f"  Level:      {risk.level}")
        print(f"  Score:      {risk.score:.2f}")
        print(f"  Events:     {risk.event_count}")
        print(f"  Action:     {risk.recommendation}")
        if risk.evidence_summary:
            print(f"  Evidence:   {risk.evidence_summary[:100]}")

    elif subcmd == "domains":
        summary = srg.domain_summary()
        if not summary:
            print("  No domain reputation history.")
            return
        print(f"\n  {bold('Domain Reputation Summary')}")
        print("  " + "─" * 50)
        for domain, count in list(summary.items())[:20]:
            print(f"  {domain:<40} events={count}")

    elif subcmd == "shareable":
        data = srg.get_shareable_reputation()
        if not data:
            print("  No shareable reputation data.")
            return
        print(f"\n  {bold('Shareable Reputation')} ({len(data)} domains)")
        print("  (anonymized domain-level data for federation)")
        print("  " + "─" * 50)
        for item in data[:10]:
            print(f"  {item['level']:<12} {item['domain']:<40} "
                  f"score={item['max_score']:.2f}")
    else:
        print(f"Unknown reputation subcommand: {subcmd}")


def _cmd_override(args: list) -> None:
    """
    aiglos override <subcommand> [args]

    Subcommands:
      list [--agent NAME]
           List pending override challenges.

      confirm <challenge-id> <code>
           Confirm an override with the provided code.

      reject <challenge-id>
           Explicitly reject a pending override challenge.

      summary
           Show override statistics.
    """
    from aiglos.adaptive.observation import ObservationGraph
    graph  = ObservationGraph()
    subcmd = args[0] if args else "list"
    rest   = args[1:]

    if subcmd == "list":
        agent_name   = None
        pending_only = True
        i = 0
        while i < len(rest):
            if rest[i] == "--agent" and i + 1 < len(rest):
                agent_name = rest[i + 1]; i += 2
            elif rest[i] == "--all":
                pending_only = False; i += 1
            else:
                i += 1

        rows = graph.list_override_challenges(
            agent_name=agent_name, pending_only=pending_only, limit=20
        )
        if not rows:
            print("  No pending override challenges." if pending_only else "  No override challenges.")
            return
        print(f"\n  {bold('Override Challenges')} ({'pending' if pending_only else 'all'}) -- {len(rows)} found")
        print("  " + "─" * 60)
        for r in rows:
            status = "✓ approved" if r["approved"] else ("✗ rejected" if r["resolved"] else "⏳ pending")
            exp    = f"{max(0, r['expires_at'] - __import__('time').time()):.0f}s left" if not r["resolved"] else ""
            print(f"  {cyan(r['challenge_id'][:12])}  {r['rule_id']:<8} {r['tool_name'][:30]:<30}  {status}  {exp}")
            if r.get("reason"):
                print(f"    Reason: {r['reason'][:70]}")
            print()

    elif subcmd == "confirm":
        if len(rest) < 2:
            print("Usage: aiglos override confirm <challenge-id> <code>")
            return
        from aiglos.integrations.override import OverrideManager
        mgr    = OverrideManager(graph=graph)
        # Reload challenges from graph
        rows   = graph.list_override_challenges(pending_only=False, limit=100)
        result = mgr.confirm_override(rest[0], rest[1])
        if result.approved:
            print(f"  Override approved: {rest[0][:12]}")
            print(f"  Reason: {result.reason}")
        else:
            print(f"  Override rejected: {result.error}")

    elif subcmd == "reject":
        if not rest:
            print("Usage: aiglos override reject <challenge-id>")
            return
        from aiglos.integrations.override import OverrideManager
        mgr    = OverrideManager(graph=graph)
        result = mgr.reject_override(rest[0])
        print(f"  Override {rest[0][:12]} rejected.")

    elif subcmd == "summary":
        rows    = graph.list_override_challenges(limit=500)
        total   = len(rows)
        approved = sum(1 for r in rows if r["approved"])
        rejected = sum(1 for r in rows if r["resolved"] and not r["approved"])
        pending  = sum(1 for r in rows if not r["resolved"])
        print(f"\n  {bold('Override Summary')}")
        print(f"  Total:    {total}")
        print(f"  Approved: {approved}")
        print(f"  Rejected: {rejected}")
        print(f"  Pending:  {pending}")
    else:
        print(f"Unknown override subcommand: {subcmd}")


def _cmd_honeypot(args: list) -> None:
    """
    aiglos honeypot <subcommand> [args]

    Subcommands:
      deploy [--dir PATH] [--names name1,name2]
           Deploy honeypot files to the default directory.

      status
           Show active honeypots and hit count.

      list
           List all honeypot hit events.

      add <name>
           Add a custom honeypot filename.
    """
    from aiglos.adaptive.observation import ObservationGraph
    from aiglos.integrations.honeypot import HoneypotManager
    graph  = ObservationGraph()
    subcmd = args[0] if args else "status"
    rest   = args[1:]

    if subcmd == "deploy":
        hp_dir    = None
        names     = None
        i = 0
        while i < len(rest):
            if rest[i] == "--dir" and i + 1 < len(rest):
                from pathlib import Path
                hp_dir = Path(rest[i + 1]); i += 2
            elif rest[i] == "--names" and i + 1 < len(rest):
                names = rest[i + 1].split(","); i += 2
            else:
                i += 1
        mgr      = HoneypotManager(honeypot_dir=hp_dir, graph=graph)
        deployed = mgr.deploy(custom_names=names)
        print(f"\n  Deployed {len(deployed)} honeypot file(s):")
        for p in deployed:
            print(f"  {cyan(str(p))}")
        print(f"\n  Any agent read of these files fires T43 HONEYPOT_ACCESS CRITICAL.")

    elif subcmd == "status":
        mgr  = HoneypotManager(graph=graph)
        mgr.deploy()
        hits = graph.get_honeypot_hits(limit=5)
        print(f"\n  {bold('Honeypot Status')}")
        print(f"  Active files: {len(mgr.active_honeypots())}")
        print(f"  Recent hits:  {len(hits)}")
        if hits:
            print(f"\n  Recent hits:")
            for h in hits[:5]:
                print(f"    {h['honeypot_name']:<30} agent={h['agent_name']} mode={h['detection_mode']}")

    elif subcmd == "list":
        hits = graph.get_honeypot_hits(limit=50)
        if not hits:
            print("  No honeypot hits recorded.")
            return
        print(f"\n  {bold('Honeypot Hit Log')} ({len(hits)} events)")
        print("  " + "─" * 60)
        for h in hits:
            import datetime as _dt
            ts = _dt.datetime.fromtimestamp(h["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            print(f"  {ts}  {cyan(h['honeypot_name']):<35} agent={h['agent_name']}")

    elif subcmd == "add":
        if not rest:
            print("Usage: aiglos honeypot add <filename>")
            return
        mgr  = HoneypotManager(graph=graph)
        mgr.deploy()
        path = mgr.add_custom(rest[0])
        if path:
            print(f"  Custom honeypot added: {cyan(str(path))}")
        else:
            print(f"  Failed to add honeypot: {rest[0]}")
    else:
        print(f"Unknown honeypot subcommand: {subcmd}")


def _cmd_research(args: list) -> None:
    """
    aiglos research <subcommand> [args]

    Subcommands:
      verify [--rule T37] [--all] [--force]
           Verify rules against NVD, OWASP, MITRE ATLAS.
           --rule: verify a single rule
           --all:  verify all 39 rules (takes ~30s due to NVD rate limits)
           --force: re-verify even if cached

      report [--format markdown|json|summary]
           Generate a compliance report mapping all rules to their
           evidence trail. Formats: markdown (default), json, summary.

      scan [--days 7]
           Scan NVD and GitHub Security Advisories for new AI agent
           threat patterns in the past N days.
    """
    from aiglos.adaptive.observation import ObservationGraph
    from aiglos.autoresearch.citation_verifier import CitationVerifier
    from aiglos.autoresearch.threat_literature import ThreatLiteratureSearch
    from aiglos.autoresearch.verified_rule_engine import VerifiedRuleEngine
    from aiglos.autoresearch.compliance_report import ComplianceReportGenerator

    graph  = ObservationGraph()
    subcmd = args[0] if args else "report"
    rest   = args[1:]

    if subcmd == "verify":
        rule_id  = None
        all_rules = False
        force    = False
        i = 0
        while i < len(rest):
            if rest[i] == "--rule" and i + 1 < len(rest):
                rule_id = rest[i + 1]; i += 2
            elif rest[i] == "--all":
                all_rules = True; i += 1
            elif rest[i] == "--force":
                force = True; i += 1
            else:
                i += 1

        verifier = CitationVerifier(graph=graph)

        if rule_id:
            print(f"\n  Verifying {rule_id}...")
            citation = verifier.verify_rule(rule_id, force_refresh=force)
            print(f"  {rule_id}: {citation.reference_id} [{citation.source}] "
                  f"{citation.confidence:.0%} -- {citation.status.value}")
            if citation.evidence_summary:
                print(f"  {citation.evidence_summary[:120]}")

        elif all_rules:
            all_rule_ids = [f"T{i:02d}" for i in range(1, 67)] + ["T36_AGENTDEF"]
            print(f"\n  Verifying {len(all_rule_ids)} rules against NVD, OWASP, MITRE ATLAS...")
            print(f"  (This takes ~30s due to NVD rate limits)")
            engine = VerifiedRuleEngine(graph=graph)
            result = engine.run_with_verification(
                category="ALL", rounds=0, adversarial=False,
                scan_literature=False,
            )
            summary = result.summary()
            print(f"\n  Coverage: {summary['citation_coverage']:.0%} "
                  f"({summary['verified_rules']}/{summary['citation_coverage'] and len(result.citations)} verified)")
            if summary["unverified_rules"]:
                print(f"  Unverified: {', '.join(summary['unverified_rules'])}")
            else:
                print(f"  All rules verified.")

        else:
            print("Usage: aiglos research verify --rule T37  OR  --all")

    elif subcmd == "report":
        fmt = "markdown"
        for token in rest:
            if token in ("markdown", "json", "summary"):
                fmt = token

        print(f"\n  Generating compliance report ({fmt})...")
        gen    = ComplianceReportGenerator(graph=graph)
        report = gen.generate(save=True)

        if fmt == "summary":
            print(report.executive_summary())
        elif fmt == "json":
            print(report.to_json()[:2000] + "\n  ... (full report saved to ~/.aiglos/reports/)")
        else:
            print(report.executive_summary())
            print(f"  Full report saved to ~/.aiglos/reports/")
            print(f"  Run with --format json for machine-readable output.")

    elif subcmd == "scan":
        days = 7
        for i, token in enumerate(rest):
            if token == "--days" and i + 1 < len(rest):
                try:
                    days = int(rest[i + 1])
                except ValueError:
                    pass

        print(f"\n  Scanning threat intelligence (past {days} days)...")
        searcher = ThreatLiteratureSearch(graph=graph)
        signals  = searcher.scan_new_threats(since_days=days)

        if not signals:
            print(f"  No new AI agent threat signals found in past {days} days.")
            return

        print(f"  {len(signals)} new threat signal(s) found:")
        print("  " + "─" * 60)
        for sig in signals[:10]:
            icon = "🔴" if sig.relevance_score >= 0.70 else "🟡"
            rule = f" → {sig.suggested_rule}" if sig.suggested_rule else ""
            print(f"  {icon} [{sig.source}] {sig.reference_id}{rule}")
            print(f"     {sig.title[:70]}")
            print(f"     relevance={sig.relevance_score:.0%} "
                  f"keywords={', '.join(sig.keywords_matched[:3])}")
            print()

        gaps = searcher.coverage_gaps()
        if gaps:
            print(f"  Coverage gaps (no recent signals): {', '.join(gaps[:5])}")
            print(f"  Run `aiglos research verify --all` to check citations.")

    else:
        print(f"Unknown research subcommand: {subcmd}")
        print("Usage: aiglos research verify|report|scan")


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

    if cmd == "audit":
        _cmd_audit(args)
        return

    if cmd == "skill":
        _cmd_skill_reputation(args)
        return

    if cmd == "baseline":
        _cmd_baseline(args)
        return

    if cmd == "scan-exposed":
        _cmd_scan_exposed(args)
        return

    if cmd == "benchmark":
        _cmd_benchmark(args)
        return

    if cmd == "reputation":
        _cmd_reputation(args)
        return

    if cmd == "override":
        _cmd_override(args)
        return

    if cmd == "honeypot":
        _cmd_honeypot(args)
        return

    if cmd == "research":
        _cmd_research(args)
        return

    if cmd == "policy":
        _cmd_policy(args)
        return

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

    if cmd == "trace":
        _cmd_trace(rest)
        return

    if cmd == "forecast":
        _cmd_forecast(rest)
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
