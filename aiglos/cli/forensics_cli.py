"""
aiglos forensics -- CLI for querying the tamper-evident forensic store.

Usage:
  aiglos forensics query
  aiglos forensics query --date 2026-03-12
  aiglos forensics query --agent reporting-pipeline
  aiglos forensics query --threat T86
  aiglos forensics stats
  aiglos forensics verify --session <session_id>
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from aiglos.forensics import ForensicStore


def _fmt_threats(threats: list) -> str:
    if not threats:
        return "none"
    return ", ".join(f"{t['threat_class']}(x{t['count']})" for t in threats[:6])


def _fmt_campaigns(campaigns: list) -> str:
    if not campaigns:
        return "none"
    return ", ".join(campaigns[:3])


def cmd_query(args: argparse.Namespace) -> int:
    store = ForensicStore()

    records = store.query(
        date    = args.date,
        agent   = args.agent,
        threat  = args.threat,
        policy  = args.policy,
        session = args.session,
        since   = args.since,
        limit   = args.limit,
    )

    if not records:
        print("No sessions found matching the query.")
        return 1

    if args.json:
        print(json.dumps([r.as_dict() for r in records], indent=2))
        return 0

    print(f"\nAiglos Forensic Query -- {len(records)} session(s) found")
    print(f"{'='*72}")

    for r in records:
        integrity = "VERIFIED" if r.verify_integrity() else "HASH MISMATCH"
        sig_status = "SIGNED" if r.signature else "unsigned"
        print(f"\nSession:  {r.session_id}")
        print(f"Agent:    {r.agent_name}   Policy: {r.policy}")
        print(f"Closed:   {r.closed_at[:19]} UTC")
        print(f"Calls:    {r.total_calls} total  |  {r.blocked_calls} blocked  |  {r.warned_calls} warned")
        print(f"Threats:  {_fmt_threats(r.threats)}")
        if r.campaigns:
            print(f"Campaigns: {_fmt_campaigns(r.campaigns)}")
        if r.govbench_score is not None:
            print(f"GOVBENCH: {r.govbench_score:.2f}")
        print(f"Artifact: {integrity}  |  {sig_status}")
        if r.artifact_hash:
            print(f"Hash:     {r.artifact_hash[:16]}...")

        if args.denials and r.denials:
            print(f"Denials ({len(r.denials)}):")
            for d in r.denials[:10]:
                print(f"  [{d['verdict']:5}] {d['timestamp'][:19]}  "
                      f"{d['tool_name']:30} {d['threat_class']:6} score={d['score']:.2f}")
            if len(r.denials) > 10:
                print(f"  ... and {len(r.denials)-10} more")

    print(f"\n{'='*72}")
    print(f"Store: {store.db_path}")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    store = ForensicStore()
    stats = store.stats()

    if args.json:
        print(json.dumps(stats, indent=2))
        return 0

    print(f"\nAiglos Forensic Store Stats")
    print(f"{'='*40}")
    print(f"Total sessions:  {stats['total_sessions']}")
    print(f"Unique agents:   {stats['unique_agents']}")
    print(f"Total denials:   {stats['total_denials']}")
    print(f"Signed sessions: {stats['signed_sessions']}")
    if stats['oldest_session']:
        print(f"Date range:      {stats['oldest_session'][:19]} -> {stats['newest_session'][:19]}")
    print(f"Store:           {stats['db_path']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if not args.session:
        print("Error: --session required for verify command")
        return 2

    store = ForensicStore()
    result = store.verify_chain(args.session)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("hash_ok") else 2

    if "error" in result:
        print(f"Error: {result['error']}")
        return 2

    status = "OK" if result["hash_ok"] else "FAILED"
    sig_status = "YES" if result["has_signature"] else "NO"
    print(f"\nSession:   {result['session_id']}")
    print(f"Agent:     {result['agent_name']}")
    print(f"Closed:    {result['closed_at'][:19]} UTC")
    print(f"Hash:      {status}")
    print(f"Signed:    {sig_status}")

    return 0 if result["hash_ok"] else 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="aiglos forensics",
        description="Query the Aiglos tamper-evident forensic store.",
    )
    sub = parser.add_subparsers(dest="command")

    qp = sub.add_parser("query", help="Query forensic sessions")
    qp.add_argument("--date",    help="Filter by date prefix (e.g. 2026-03-12)")
    qp.add_argument("--agent",   help="Filter by agent name (substring)")
    qp.add_argument("--threat",  help="Filter by threat class (e.g. T86)")
    qp.add_argument("--policy",  help="Filter by policy tier (e.g. federal)")
    qp.add_argument("--session", help="Filter by session ID (prefix)")
    qp.add_argument("--since",   help="Only sessions closed after ISO datetime")
    qp.add_argument("--limit",   type=int, default=50, help="Max results (default 50)")
    qp.add_argument("--denials", action="store_true", help="Show individual denial events")
    qp.add_argument("--json",    action="store_true", help="Output JSON")

    sp = sub.add_parser("stats", help="Show store statistics")
    sp.add_argument("--json", action="store_true", help="Output JSON")

    vp = sub.add_parser("verify", help="Verify session artifact integrity")
    vp.add_argument("--session", required=True, help="Session ID to verify")
    vp.add_argument("--json",    action="store_true", help="Output JSON")

    args = parser.parse_args(argv)

    if args.command == "query":
        return cmd_query(args)
    elif args.command == "stats":
        return cmd_stats(args)
    elif args.command == "verify":
        return cmd_verify(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
