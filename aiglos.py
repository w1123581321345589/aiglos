"""
aiglos.py — Single-file drop-in entry point for the Aiglos security stack.

Drop this file into any MCP-enabled project and run:

    python aiglos.py scan          # Full autonomous security scan
    python aiglos.py probe         # Red team adversarial self-test
    python aiglos.py compliance    # CMMC + NDAA §1513 readiness report
    python aiglos.py daemon        # Start continuous monitoring
    python aiglos.py status        # Live system status

Or import directly:

    from aiglos import Aiglos
    aiglos = Aiglos()
    await aiglos.scan()

Architecture map
----------------
This file is the complete index of the Aiglos codebase. Every module,
its purpose, its T-number, and how it connects to every other module.

    aiglos_core/
    ├── proxy/
    │   ├── __init__.py         T1  MCP proxy intercept (sits between LLM ↔ MCP server)
    │   ├── trust.py            T2  Session trust scoring (per-call risk score 0-1)
    │   ├── trust_fabric.py     T8  Multi-agent attestation (cryptographic trust chain)
    │   └── oauth.py            T25 OAuth Confused Deputy Detector (CVE-2025-6514)
    │
    ├── audit/
    │   └── __init__.py         T3  SQLite audit log (WAL mode, tamper-evident)
    │
    ├── types.py                     Shared dataclasses: SecurityEvent, Severity, EventType
    │
    ├── autonomous/
    │   ├── engine.py           T23 Autonomous engine orchestrator (3-layer: engine/intel/hunter)
    │   ├── intel.py            T22 Threat intelligence refresh (NVD + community feeds)
    │   ├── hunter.py           T21 Proactive threat hunter (6 hunt modules, runs every 5 min)
    │   ├── sampler.py          T24 MCP Sampling Monitor (Unit 42 3-vector attack detection)
    │   └── sca.py              T26 Supply Chain Scanner (Postmark/Smithery/mcp-server-git CVEs)
    │
    ├── compliance/
    │   ├── __init__.py         T18 CMMC 2.0 compliance mapper (NIST 800-171 controls)
    │   ├── report_pdf.py       T19 PDF report generator
    │   └── s1513.py            T28 NDAA FY2026 §1513 AI/ML compliance mapper
    │
    └── policy/
        └── engine.py           T5  OPA-compatible policy engine (YAML rules, BLOCK/ALERT/LOG)

    aiglos_probe.py             T27 Red Team Probe (5 adversarial probe types, CLI + CI/CD)
    aiglos_cli/main.py               CLI: scan, probe, report, daemon, s1513, intel
    aiglos_policy.yaml               Default policy rules (defense profile)
    aiglos_trust.yaml                Trust registry (allowed servers + blocked packages)

Data flow
---------
    MCP Client
        |
        v
    AiglosProxy (T1)
        |-- TrustScorer (T2)        per-call risk score
        |-- CredentialScanner        regex: API keys, tokens, secrets
        |-- InjectionDetector        prompt injection, path traversal, cmd injection
        |-- AttestationEngine (T7)   RSA-2048 signed session attestation
        |-- AlertDispatcher (T15)    webhook/Slack/SIEM on CRITICAL/HIGH
        |
        v
    AuditLog (T3)  ←─────────────────────────────────────────────┐
        |                                                          |
        v                                                          |
    AutonomousEngine (T23)                                         |
        |-- ThreatIntelligence (T22)  NVD + community feeds       |
        |   └── SupplyChainScanner (T26)  on every refresh        |
        |                                                          |
        └── ThreatHunter (T21)  6 modules, every 5 min            |
            |-- exposure           tool permission exposure        |
            |-- credential_scan    secrets in historical calls     |
            |-- injection_hunt     injection patterns in history   |
            |-- behavioral_trend   baseline deviation              |
            |-- policy_trend       policy rule drift               |
            └── sampling_monitor (T24)  sampling channel attacks──┘

    OAuthConfusedDeputy (T25)   called from proxy on OAuth callbacks
    RedTeamProbe (T27)          called on-demand or in CI/CD

Compliance coverage
-------------------
    CMMC Level 2 (110 controls):
        3.1.x  Access Control         ← proxy BLOCK actions, min-privilege tool rules
        3.3.x  Audit & Accountability ← AuditLog, signed attestation
        3.5.x  Identification & Auth  ← AttestationEngine, TrustFabric, OAuth detector
        3.6.x  Incident Response      ← AlertDispatcher, engine SUSPENDED state
        3.13.x Comms Protection       ← CredentialScanner, OAuth scope enforcement
        3.14.x System Integrity       ← ThreatHunter, SCA, SamplingMonitor

    NDAA FY2026 §1513 (18 controls across 6 domains):
        Domain 1: Model Integrity     ← Attestation, SCA (T26)
        Domain 2: Runtime Monitoring  ← AutonomousEngine (T23), SamplingMonitor (T24)
        Domain 3: Access Control      ← OPA Policy (T5), OAuthDetector (T25), TrustFabric (T8)
        Domain 4: Audit Trail         ← AuditLog (T3), signed attestation (T7)
        Domain 5: Anomaly Detection   ← proxy pipeline, ThreatHunter, RedTeamProbe (T27)
        Domain 6: Incident Response   ← AlertDispatcher, engine suspend, forensic replay

Attack vector coverage (documented 2025-2026)
----------------------------------------------
    CVE-2025-6514  (CVSS 9.6)  mcp-remote OAuth RCE       → T25 OAuthConfusedDeputy
    CVE-2025-68143             mcp-server-git path init    → T26 SupplyChainScanner
    CVE-2026-22807             mcp-server-git xss embed    → T26 SupplyChainScanner
    CVE-2026-23947             mcp-server-git xss embed    → T26 SupplyChainScanner
    Unit 42 (Dec 2025)         Sampling channel 3-vectors  → T24 SamplingMonitor
    Postmark impersonation     NPM package exfil            → T26 SupplyChainScanner
    Smithery path traversal    Build config arbitrary read  → T26 SupplyChainScanner
    OWASP Agentic #1           Tool description injection   → proxy + T27 probe
    OWASP Agentic #2           Tool poisoning               → TrustScorer + hunter
    OWASP Agentic #5           OAuth confused deputy        → T25 OAuthConfusedDeputy
    Endor Labs 82%             Path traversal in MCP impls  → T27 path_traversal probe
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import structlog
    logger = structlog.get_logger("aiglos")
except ImportError:
    import logging
    logger = logging.getLogger("aiglos")


# ---------------------------------------------------------------------------
# Unified Aiglos facade
# ---------------------------------------------------------------------------

class Aiglos:
    """
    Single entry point for the complete Aiglos security stack.

    Usage:
        aiglos = Aiglos(audit_db="aiglos_audit.db")

        # Run full autonomous scan (all 6 hunt modules)
        results = await aiglos.scan()

        # Red team probe (all 5 adversarial probe types)
        probe_reports = await aiglos.probe()

        # Generate compliance report (CMMC + §1513)
        report = await aiglos.compliance_report()

        # Start continuous monitoring daemon
        await aiglos.daemon(scan_interval=300, intel_interval=3600)
    """

    MODULE_MAP = {
        "T1":  ("aiglos_core.proxy",                  "AiglosProxy",            "MCP proxy intercept"),
        "T2":  ("aiglos_core.proxy.trust",             "TrustScorer",            "Session trust scoring"),
        "T3":  ("aiglos_core.audit",                   "AuditLog",               "SQLite audit log"),
        "T5":  ("aiglos_core.policy.engine",           "PolicyEngine",           "OPA-compatible policy engine"),
        "T7":  ("aiglos_core.proxy",                   "AttestationEngine",      "RSA-2048 session attestation"),
        "T8":  ("aiglos_core.proxy.trust_fabric",      "TrustFabric",            "Multi-agent attestation"),
        "T15": ("aiglos_core.proxy",                   "AlertDispatcher",        "Webhook/Slack/SIEM alerts"),
        "T18": ("aiglos_core.compliance",              "CMMCComplianceMapper",   "CMMC 2.0 compliance mapper"),
        "T19": ("aiglos_core.compliance.report_pdf",   "generate_pdf_report",    "PDF report generator"),
        "T21": ("aiglos_core.autonomous.hunter",       "ThreatHunter",           "Proactive threat hunter (6 modules)"),
        "T22": ("aiglos_core.autonomous.intel",        "ThreatIntelligence",     "Threat intelligence refresh"),
        "T23": ("aiglos_core.autonomous.engine",       "AutonomousEngine",       "Autonomous engine orchestrator"),
        "T24": ("aiglos_core.autonomous.sampler",      "SamplingMonitor",        "MCP sampling channel monitor"),
        "T25": ("aiglos_core.proxy.oauth",             "OAuthConfusedDeputy",    "OAuth confused deputy detector"),
        "T26": ("aiglos_core.autonomous.sca",          "SupplyChainScanner",     "Supply chain scanner"),
        "T27": ("aiglos_probe",                        "ProbeEngine",            "Red team adversarial probe"),
        "T28": ("aiglos_core.compliance.s1513",        "Section1513Mapper",      "NDAA §1513 compliance mapper"),
    }

    def __init__(
        self,
        audit_db: str = "aiglos_audit.db",
        policy_file: str = "aiglos_policy.yaml",
        trust_file: str = "aiglos_trust.yaml",
    ):
        self.audit_db = audit_db
        self.policy_file = policy_file
        self.trust_file = trust_file

    # ------------------------------------------------------------------
    # scan — runs all 6 hunt modules via ThreatHunter
    # ------------------------------------------------------------------

    async def scan(self):
        """Run full autonomous security scan (all 6 hunt modules)."""
        from aiglos_core.autonomous.hunter import ThreatHunter
        hunter = ThreatHunter(
            audit_db_path=self.audit_db,
            config_paths=[self.policy_file, self.trust_file],
        )
        result = await hunter.run_full_scan()
        return result

    # ------------------------------------------------------------------
    # probe — red team adversarial self-test
    # ------------------------------------------------------------------

    async def probe(self, target: str | None = None, probe_types: list[str] | None = None):
        """Red team probe: adversarial self-testing (T27)."""
        from aiglos_probe import ProbeEngine
        engine = ProbeEngine(audit_db=self.audit_db)
        if target:
            return [await engine.probe_server(target, probe_types)]
        return await engine.probe_all(probe_types)

    # ------------------------------------------------------------------
    # compliance_report — CMMC + §1513
    # ------------------------------------------------------------------

    async def compliance_report(self, org_name: str = "Your Organization"):
        """Generate CMMC Level 2 + NDAA §1513 compliance report."""
        from aiglos_core.compliance import CMMCComplianceMapper, build_compliance_report
        from aiglos_core.compliance.s1513 import Section1513Mapper

        # CMMC
        cmmc_report = build_compliance_report(
            audit_db=self.audit_db,
            org_name=org_name,
        )

        # Section 1513
        s1513_mapper = Section1513Mapper(audit_db=self.audit_db)
        s1513_report = s1513_mapper.build_report()

        return {"cmmc": cmmc_report, "s1513": s1513_report}

    # ------------------------------------------------------------------
    # intel — refresh threat intelligence
    # ------------------------------------------------------------------

    async def intel(self):
        """Refresh threat intelligence (NVD + community feeds + SCA)."""
        from aiglos_core.autonomous.intel import ThreatIntelligence
        ie = ThreatIntelligence(
            policy_file=self.policy_file,
            trust_file=self.trust_file,
        )
        return await ie.refresh()

    # ------------------------------------------------------------------
    # daemon — continuous monitoring
    # ------------------------------------------------------------------

    async def daemon(
        self,
        scan_interval: int = 300,
        intel_interval: int = 3600,
    ):
        """
        Run continuous monitoring. scan_interval and intel_interval are in seconds.
        Call this from your application startup for always-on protection.
        """
        from aiglos_core.autonomous.engine import AutonomousEngine
        engine = AutonomousEngine(
            audit_db=self.audit_db,
            policy_file=self.policy_file,
            trust_file=self.trust_file,
            scan_interval=scan_interval,
            intel_interval=intel_interval,
        )
        await engine.run()

    # ------------------------------------------------------------------
    # status — live system summary
    # ------------------------------------------------------------------

    async def status(self) -> dict:
        """Return live status summary of all modules."""
        from aiglos_core.audit import AuditLog
        try:
            audit = AuditLog(self.audit_db)
            events = audit.get_recent_events(limit=100)
            critical = sum(1 for e in events if e.get("severity") == "critical")
            high = sum(1 for e in events if e.get("severity") == "high")
        except Exception:
            events, critical, high = [], 0, 0

        s1513_score = None
        try:
            from aiglos_core.compliance.s1513 import Section1513Mapper
            s1513_score = Section1513Mapper(self.audit_db).build_report().overall_score_pct
        except Exception:
            pass

        return {
            "audit_db": self.audit_db,
            "recent_events": len(events),
            "critical_events": critical,
            "high_events": high,
            "s1513_score_pct": s1513_score,
            "modules_available": list(self.MODULE_MAP.keys()),
        }

    # ------------------------------------------------------------------
    # Introspection: verify module availability
    # ------------------------------------------------------------------

    def check_modules(self) -> dict[str, bool]:
        """
        Attempt to import every module and return a pass/fail map.
        Useful for confirming a clean install.
        """
        import importlib
        results = {}
        for t_num, (module_path, class_name, _description) in self.MODULE_MAP.items():
            try:
                mod = importlib.import_module(module_path)
                results[t_num] = hasattr(mod, class_name) or callable(getattr(mod, class_name, None))
            except ImportError:
                results[t_num] = False
        return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

HELP = """
Aiglos — Autonomous AI Agent Security Runtime

Commands:
  scan        Run full security scan (all 6 hunt modules)
  probe       Red team adversarial self-test (T27)
  compliance  CMMC + NDAA §1513 readiness report (T18/T28)
  intel       Refresh threat intelligence (T22)
  daemon      Start continuous monitoring (T23)
  status      Live system status + module health check
  modules     List all modules with T-numbers and descriptions

Options:
  --db PATH       Audit database path (default: aiglos_audit.db)
  --org NAME      Organization name for compliance reports
  --target ID     Probe specific MCP server by ID
  --json          Output as JSON

Examples:
  python aiglos.py scan
  python aiglos.py probe --target filesystem
  python aiglos.py compliance --org "Acme Corp" --json
  python aiglos.py status
"""


async def _main():
    import argparse
    parser = argparse.ArgumentParser(description="Aiglos AI Security Runtime", add_help=False)
    parser.add_argument("command", nargs="?", default="status",
                        choices=["scan", "probe", "compliance", "intel",
                                 "daemon", "status", "modules", "help"])
    parser.add_argument("--db", default="aiglos_audit.db")
    parser.add_argument("--org", default="Your Organization")
    parser.add_argument("--target", default=None)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help or args.command == "help":
        print(HELP)
        return

    aiglos = Aiglos(audit_db=args.db)

    if args.command == "modules":
        print("\nAiglos Module Map\n" + "="*60)
        for t, (path, cls, desc) in Aiglos.MODULE_MAP.items():
            available = "✅" if _try_import(path, cls) else "❌"
            print(f"  {available} {t:<5} {desc:<40} {path}.{cls}")
        available_count = sum(1 for t, (p, c, _) in Aiglos.MODULE_MAP.items() if _try_import(p, c))
        print(f"\n  {available_count}/{len(Aiglos.MODULE_MAP)} modules available\n")
        return

    if args.command == "status":
        status = await aiglos.status()
        if args.json_output:
            print(json.dumps(status, indent=2))
            return
        print("\nAiglos Status")
        print("=" * 40)
        print(f"  Audit DB:       {status['audit_db']}")
        print(f"  Recent events:  {status['recent_events']}")
        print(f"  Critical:       {status['critical_events']}")
        print(f"  High:           {status['high_events']}")
        if status['s1513_score_pct'] is not None:
            print(f"  §1513 score:    {status['s1513_score_pct']:.0f}%")
        modules = aiglos.check_modules()
        available = sum(modules.values())
        print(f"  Modules ready:  {available}/{len(modules)}")
        if available < len(modules):
            missing = [t for t, ok in modules.items() if not ok]
            print(f"  Missing:        {', '.join(missing)}")
        print()
        return

    if args.command == "scan":
        print("\nRunning Aiglos full scan...")
        result = await aiglos.scan()
        if args.json_output:
            print(json.dumps({
                "findings": len(result.findings),
                "critical": result.critical_count,
                "high": result.high_count,
                "modules": result.hunts_run,
                "duration_s": result.duration_s,
            }, indent=2))
            return
        icon = "🔴" if result.critical_count else "🟡" if result.high_count else "✅"
        print(f"\n  {icon} Scan complete: {len(result.findings)} findings "
              f"({result.critical_count} critical, {result.high_count} high) "
              f"in {result.duration_s}s")
        for f in result.findings[:10]:
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "⚪")
            print(f"  {sev_icon} [{f.severity.upper()}] {f.title}")
        print()
        return

    if args.command == "probe":
        print("\nRunning Aiglos red team probe...")
        reports = await aiglos.probe(target=args.target)
        if args.json_output:
            print(json.dumps([r.to_dict() for r in reports], indent=2))
            return
        for report in reports:
            vuln = report.vulnerable_count
            print(f"\n  {'🔴' if vuln else '✅'} {report.target}: {vuln} vulnerable, "
                  f"{report.hardened_count} hardened ({report.duration_s:.1f}s)")
            for f in report.findings:
                if f.verdict == "VULNERABLE":
                    print(f"    🔴 [{f.severity.upper()}] {f.title}")
        print()
        return

    if args.command == "compliance":
        print("\nGenerating compliance report...")
        from aiglos_core.compliance.s1513 import Section1513Mapper
        s1513 = Section1513Mapper(audit_db=args.db)
        report = s1513.build_report()
        if args.json_output:
            print(report.to_json())
            return
        print(report.summary())
        print()
        return

    if args.command == "intel":
        print("\nRefreshing threat intelligence...")
        result = await aiglos.intel()
        print(f"  Sources: {', '.join(result.sources_checked) or 'none'}")
        print(f"  New indicators: {result.new_indicators}")
        print(f"  New rules: {result.new_policy_rules}")
        if result.errors:
            for e in result.errors:
                print(f"  Error: {e}")
        print()
        return

    if args.command == "daemon":
        print("\nStarting Aiglos continuous monitoring daemon...")
        print("  Press Ctrl+C to stop.\n")
        await aiglos.daemon()


def _try_import(module_path: str, class_name: str) -> bool:
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return hasattr(mod, class_name)
    except ImportError:
        return False


def main():
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("\n  Aiglos daemon stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
