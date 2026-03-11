"""
python -m aiglos — entry point for CLI usage.

Usage:
    python -m aiglos demo           # run the OpenClaw demo
    python -m aiglos demo hermes    # run the hermes-agent demo
    python -m aiglos version        # print version
    python -m aiglos check <tool>   # check a tool call interactively
    python -m aiglos scan-skill <name> # scan a ClawHub/SkillsMP skill
"""
import sys


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] == "version":
        from aiglos import __version__
        print(f"aiglos v{__version__}")
        return

    if args[0] == "demo":
        target = args[1] if len(args) > 1 else "openclaw"
        if target == "hermes":
            from aiglos.integrations.hermes import _run_demo
            _run_demo()
        else:
            from aiglos.integrations.openclaw import _run_demo
            _run_demo()
        return

    if args[0] == "check":
        tool_name = args[1] if len(args) > 1 else "terminal"
        import json
        tool_args = json.loads(args[2]) if len(args) > 2 else {}
        import aiglos
        aiglos.attach(agent_name="cli", policy="enterprise")
        result = aiglos.check(tool_name, tool_args)
        icon = "BLOCK" if result.blocked else ("WARN" if result.warned else "ALLOW")
        print(f"[{icon}] {tool_name}  score={result.score:.2f}  {result.reason}")
        return

    elif args[0] == "scan-skill":
        from aiglos.scan_skill import main as ss_main
        ss_main(args[1:])
        return

    elif args[0] == "autoresearch":
        from aiglos.autoresearch.loop import main as ar_main
        ar_main(args[1:])
        return

    else:
        print(f"Unknown command: {args[0]}")
        print("Usage: python -m aiglos [demo|demo hermes|scan-skill|autoresearch|version|check <tool>]")
        sys.exit(1)


if __name__ == "__main__":
    main()
