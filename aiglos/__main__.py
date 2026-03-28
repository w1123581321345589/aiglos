"""
aiglos CLI entry point.

Usage:
    python -m aiglos launch
    python -m aiglos scan-deps
    python -m aiglos validate-prompt <file>
    python -m aiglos agents scaffold
    python -m aiglos benchmark run
    python -m aiglos --version
"""

from __future__ import annotations

import sys


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("aiglos -- AI agent security runtime")
        print()
        print("Commands:")
        print("  launch                   OpenClaw production-ready in 5 minutes")
        print("  scan-deps                Check for compromised packages")
        print("  validate-prompt <file>   Score a skill/prompt file")
        print("  agents scaffold          NL to declare_subagent() config")
        print("  benchmark run            Run GOVBENCH")
        print("  scan-message <text>      Scan a message for C2/exfil signals")
        print("  --version                Show version")
        print()
        print("Usage:")
        print("  aiglos launch")
        print("  aiglos scan-deps")
        print("  aiglos validate-prompt .aiglos/soul.md")
        return

    if args[0] in ("--version", "-V"):
        from aiglos import __version__
        print(f"aiglos {__version__}")
        return

    cmd = args[0]

    if cmd == "launch":
        from aiglos.cli.launch import launch
        desc = None
        output_dir = None
        non_interactive = False
        i = 1
        while i < len(args):
            if args[i] == "--from" and i + 1 < len(args):
                desc = args[i + 1]
                non_interactive = True
                i += 2
            elif args[i] == "--output-dir" and i + 1 < len(args):
                output_dir = args[i + 1]
                i += 2
            elif args[i] == "--non-interactive":
                non_interactive = True
                i += 1
            else:
                i += 1
        launch(
            from_description=desc,
            output_dir=output_dir,
            non_interactive=non_interactive,
        )

    elif cmd == "scan-deps":
        from aiglos.cli.scan_deps import scan, print_scan_report
        quick = "--quick" in args
        result = scan(quick=quick)
        print_scan_report(result)

    elif cmd == "validate-prompt":
        from aiglos.cli.validate_prompt import run
        files = [a for a in args[1:] if not a.startswith("-")]
        run_all = "--all" in args
        if run_all:
            import glob
            files = glob.glob(".aiglos/*.md")
        if not files:
            print("Usage: aiglos validate-prompt <file> [<file2> ...]")
            print("       aiglos validate-prompt --all")
            sys.exit(1)
        for f in files:
            run(f)

    elif cmd == "agents" and len(args) > 1 and args[1] == "scaffold":
        from aiglos.cli.scaffold import run_scaffold_wizard
        run_scaffold_wizard()

    elif cmd == "benchmark" and len(args) > 1 and args[1] == "run":
        from aiglos.benchmark.govbench import GovBench
        bench = GovBench()
        result = bench.run()
        print(f"Grade: {result.grade}  ({result.score}/100)")
        for dim in result.dimensions:
            print(f"  {dim.name}: {dim.score}/{dim.max_score}")

    elif cmd == "scan-message":
        from aiglos.cli import _cmd_scan_message
        _cmd_scan_message(args[1:])

    else:
        print(f"Unknown command: {cmd}")
        print("Run 'aiglos --help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
