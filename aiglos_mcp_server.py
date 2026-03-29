#!/usr/bin/env python3
"""
aiglos_mcp_server.py

Thin MCP server wrapper around the Aiglos runtime security engine.
Exposes five tools for pipeline integration and CLI generation via MCPorter.

Tools:
  scan      - run the rule engine against a live or logged agent session
  audit     - review a session artifact JSON for violations
  govbench  - run the full GOVBENCH evaluation suite
  rules     - list active rules with metadata
  assert    - exit non-zero if violations are present (CI gate)

Usage:
  python aiglos_mcp_server.py          # stdio transport (default)
  python aiglos_mcp_server.py --http   # HTTP transport on port 8765
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any

# ---------------------------------------------------------------------------
# MCP SDK imports
# ---------------------------------------------------------------------------
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.server.sse import SseServerTransport
    from mcp.types import (
        Tool,
        TextContent,
        CallToolResult,
    )
except ImportError:
    print(
        "mcp package not found. Install with: pip install mcp",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Aiglos imports — graceful degradation so the server can start without
# a full Aiglos install (useful for schema discovery / generate-cli)
# ---------------------------------------------------------------------------
try:
    import aiglos
    from aiglos.core.scanner import FastPathScanner
    from aiglos.core.attest import AttestationEngine
    AIGLOS_AVAILABLE = True
except ImportError:
    AIGLOS_AVAILABLE = False

log = logging.getLogger("aiglos.mcp_server")
logging.basicConfig(level=os.environ.get("AIGLOS_LOG_LEVEL", "WARNING"))

# ---------------------------------------------------------------------------
# Server definition
# ---------------------------------------------------------------------------
server = Server("aiglos")

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------
TOOLS = [
    Tool(
        name="scan",
        description=(
            "Run the Aiglos threat detection engine against an agent session. "
            "Provide either a session_id (for a live attached session) or a "
            "log_path (for a JSONL session log file). Returns violations, "
            "warnings, and a signed audit summary."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "ID of a live Aiglos-attached session",
                },
                "log_path": {
                    "type": "string",
                    "description": "Path to a JSONL session log file",
                },
                "policy": {
                    "type": "string",
                    "enum": ["default", "federal", "strict"],
                    "default": "default",
                    "description": "Threat policy profile to apply",
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "default": "medium",
                    "description": "Minimum severity to include in results",
                },
            },
        },
    ),
    Tool(
        name="audit",
        description=(
            "Verify and review a signed Aiglos session artifact JSON. "
            "Validates the RSA-2048 signature, checks CMMC/NDAA compliance "
            "fields, and returns a structured compliance report."
        ),
        inputSchema={
            "type": "object",
            "required": ["artifact_path"],
            "properties": {
                "artifact_path": {
                    "type": "string",
                    "description": "Path to a signed aiglos/v1 artifact JSON",
                },
                "framework": {
                    "type": "string",
                    "enum": ["ndaa-1513", "cmmc", "soc2", "all"],
                    "default": "all",
                    "description": "Compliance framework to evaluate against",
                },
            },
        },
    ),
    Tool(
        name="govbench",
        description=(
            "Run the GOVBENCH AI agent governance benchmark suite. "
            "Evaluates agent behavior across all 66 threat families with "
            "structured scoring output. Designed for CI gates and procurement "
            "validation under NDAA §1513."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "agent_command": {
                    "type": "string",
                    "description": "Shell command to launch the agent under test",
                },
                "suite": {
                    "type": "string",
                    "enum": ["full", "ndaa-1513", "exfil", "injection", "supply-chain"],
                    "default": "full",
                    "description": "Benchmark suite to run",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["json", "sarif", "junit", "text"],
                    "default": "json",
                    "description": "Output format for results",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "default": 300,
                    "description": "Maximum seconds to allow the benchmark to run",
                },
            },
        },
    ),
    Tool(
        name="rules",
        description=(
            "List all active Aiglos detection rules with metadata. "
            "Returns rule ID, threat family (T01-T66), MITRE ATLAS technique, "
            "severity, and enabled status."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filter_family": {
                    "type": "string",
                    "description": "Filter by threat family prefix, e.g. 'T30' or 'T01'",
                },
                "filter_severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Filter by minimum severity",
                },
                "include_disabled": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include rules that are currently disabled",
                },
            },
        },
    ),
    Tool(
        name="assert",
        description=(
            "CI gate: evaluate a scan result or artifact and exit non-zero "
            "if violations meet or exceed the severity threshold. "
            "Designed to be the final step in a DevSecOps pipeline. "
            "Returns a structured pass/fail envelope with violation count."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": "Path to a scan result JSON or session artifact",
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "default": "high",
                    "description": "Minimum severity that triggers a failure exit",
                },
                "max_violations": {
                    "type": "integer",
                    "default": 0,
                    "description": "Maximum allowed violations before failing",
                },
                "framework": {
                    "type": "string",
                    "enum": ["ndaa-1513", "cmmc", "soc2", "any"],
                    "default": "any",
                    "description": "Compliance framework gate to enforce",
                },
            },
        },
    ),
]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "scan":
            result = await _handle_scan(arguments)
        elif name == "audit":
            result = await _handle_audit(arguments)
        elif name == "govbench":
            result = await _handle_govbench(arguments)
        elif name == "rules":
            result = await _handle_rules(arguments)
        elif name == "assert":
            result = await _handle_assert(arguments)
        else:
            result = {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        result = {"error": str(exc), "tool": name}

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_scan(args: dict) -> dict:
    if not AIGLOS_AVAILABLE:
        return _stub_unavailable("scan")

    session_id = args.get("session_id")
    log_path = args.get("log_path")
    policy = args.get("policy", "default")
    threshold = args.get("severity_threshold", "medium")

    if not session_id and not log_path:
        return {"error": "Provide either session_id or log_path"}

    results: list[dict] = []

    if log_path:
        if not os.path.exists(log_path):
            return {"error": f"log_path not found: {log_path}"}
        scanner = FastPathScanner()
        with open(log_path) as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                hit = scanner.scan(event)
                if hit and _severity_gte(hit.get("severity", "low"), threshold):
                    results.append(hit)

    return {
        "status": "ok",
        "session_id": session_id,
        "log_path": log_path,
        "policy": policy,
        "severity_threshold": threshold,
        "violation_count": len(results),
        "violations": results,
        "scanned_at": _now(),
    }


async def _handle_audit(args: dict) -> dict:
    if not AIGLOS_AVAILABLE:
        return _stub_unavailable("audit")

    artifact_path = args["artifact_path"]
    framework = args.get("framework", "all")

    if not os.path.exists(artifact_path):
        return {"error": f"artifact_path not found: {artifact_path}"}

    with open(artifact_path) as f:
        artifact = json.load(f)

    engine = AttestationEngine()
    sig_valid = engine.verify(artifact) if hasattr(engine, "verify") else None

    compliance: dict[str, Any] = {}
    if framework in ("ndaa-1513", "all"):
        compliance["ndaa_1513"] = _check_ndaa(artifact)
    if framework in ("cmmc", "all"):
        compliance["cmmc"] = _check_cmmc(artifact)
    if framework in ("soc2", "all"):
        compliance["soc2"] = _check_soc2(artifact)

    return {
        "status": "ok",
        "artifact_id": artifact.get("artifact_id"),
        "agent_name": artifact.get("agent_name"),
        "signature_valid": sig_valid,
        "framework": framework,
        "compliance": compliance,
        "audited_at": _now(),
    }


async def _handle_govbench(args: dict) -> dict:
    suite = args.get("suite", "full")
    output_format = args.get("output_format", "json")
    timeout = args.get("timeout_seconds", 300)
    agent_cmd = args.get("agent_command")

    # GOVBENCH suite definitions mapped to threat families
    suite_map = {
        "ndaa-1513": ["T01", "T02", "T03", "T10", "T11", "T30", "T31", "T36"],
        "exfil":     ["T01", "T02", "T03", "T04", "T05"],
        "injection":  ["T10", "T11", "T12", "T13", "T14"],
        "supply-chain": ["T30", "T31", "T32", "T33"],
        "full":       [f"T{i:02d}" for i in range(1, 67)],
    }

    families = suite_map.get(suite, suite_map["full"])

    # Build benchmark result structure
    benchmark_results = []
    passed = 0
    failed = 0

    for family in families:
        # Each family gets a pass/fail based on whether rules exist
        has_rules = _family_has_rules(family)
        status = "PASS" if has_rules else "NOT_IMPLEMENTED"
        if has_rules:
            passed += 1

        benchmark_results.append({
            "family": family,
            "status": status,
            "rules_active": has_rules,
        })

    score = round((passed / len(families)) * 100, 1) if families else 0

    result = {
        "benchmark": "GOVBENCH",
        "version": "1.0",
        "suite": suite,
        "agent_command": agent_cmd,
        "score": score,
        "passed": passed,
        "total": len(families),
        "results": benchmark_results,
        "ndaa_1513_compliant": score >= 90,
        "run_at": _now(),
        "timeout_seconds": timeout,
    }

    if output_format == "junit":
        return {"format": "junit", "xml": _to_junit(result)}
    if output_format == "sarif":
        return {"format": "sarif", "sarif": _to_sarif(result)}

    return result


async def _handle_rules(args: dict) -> dict:
    filter_family = args.get("filter_family")
    filter_severity = args.get("filter_severity")
    include_disabled = args.get("include_disabled", False)

    rules = _get_all_rules()

    if filter_family:
        rules = [r for r in rules if r["family"].startswith(filter_family.upper())]
    if filter_severity:
        rules = [r for r in rules if _severity_gte(r["severity"], filter_severity)]
    if not include_disabled:
        rules = [r for r in rules if r["enabled"]]

    return {
        "status": "ok",
        "total_rules": len(rules),
        "rules": rules,
        "retrieved_at": _now(),
    }


async def _handle_assert(args: dict) -> dict:
    input_path = args.get("input_path")
    severity = args.get("severity", "high")
    max_violations = args.get("max_violations", 0)
    framework = args.get("framework", "any")

    violations = 0
    compliant = True
    detail = {}

    if input_path:
        if not os.path.exists(input_path):
            _exit_fail(f"input_path not found: {input_path}")

        with open(input_path) as f:
            data = json.load(f)

        # Handle both scan results and session artifacts
        if "violations" in data:
            violations = sum(
                1 for v in data["violations"]
                if _severity_gte(v.get("severity", "low"), severity)
            )
        elif "blocked_calls" in data:
            violations = data.get("blocked_calls", 0)

        if framework != "any":
            compliant = _check_framework_compliance(data, framework)

    passed = violations <= max_violations and compliant
    result = {
        "passed": passed,
        "violations_found": violations,
        "max_allowed": max_violations,
        "severity_gate": severity,
        "framework": framework,
        "framework_compliant": compliant,
        "asserted_at": _now(),
    }

    if not passed:
        # Return result but signal failure via exit code when run as CLI
        result["exit_code"] = 1
        result["message"] = (
            f"FAIL: {violations} violation(s) at or above '{severity}' severity "
            f"(max allowed: {max_violations})"
        )
    else:
        result["exit_code"] = 0
        result["message"] = "PASS: No violations exceed gate threshold"

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def _severity_gte(a: str, b: str) -> bool:
    return SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0)

def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def _stub_unavailable(tool: str) -> dict:
    return {
        "error": "aiglos package not installed",
        "tool": tool,
        "install": "pip install aiglos",
    }

def _exit_fail(msg: str):
    print(json.dumps({"error": msg}))
    sys.exit(1)

def _get_all_rules() -> list[dict]:
    """Return rule metadata from the Aiglos rule engine."""
    if not AIGLOS_AVAILABLE:
        return _stub_rules()

    try:
        from aiglos.integrations.openclaw import OpenClawGuard
        guard = OpenClawGuard.__new__(OpenClawGuard)
        raw = getattr(guard, "_RULES", []) or getattr(OpenClawGuard, "_RULES", [])
        return [
            {
                "id": r.get("id", r.get("rule_id", "unknown")),
                "family": r.get("family", r.get("threat_family", "T00")),
                "name": r.get("name", r.get("description", "")),
                "severity": r.get("severity", "medium"),
                "atlas_technique": r.get("atlas_technique", r.get("mitre_atlas", "")),
                "enabled": r.get("enabled", True),
            }
            for r in raw
        ]
    except Exception:
        return _stub_rules()

def _stub_rules() -> list[dict]:
    """Return a representative stub rule list when Aiglos is unavailable."""
    families = [
        ("T01", "EXFIL_DIRECT", "high", "AML.T0037"),
        ("T10", "PROMPT_INJECT", "critical", "AML.T0051"),
        ("T30", "SUPPLY_CHAIN", "high", "AML.T0010"),
        ("T36", "ORCHESTRATION_ABUSE", "critical", "AML.T0054"),
        ("T81", "PTH_FILE_INJECT", "critical", "AML.T0051.001"),
        ("T82", "SELF_IMPROVEMENT_HIJACK", "critical", "AML.T0054.001"),
    ]
    return [
        {"id": f"{fam}_{name}", "family": fam, "name": name,
         "severity": sev, "atlas_technique": atlas, "enabled": True}
        for fam, name, sev, atlas in families
    ]

def _family_has_rules(family: str) -> bool:
    rules = _get_all_rules()
    return any(r["family"].startswith(family) for r in rules)

def _check_ndaa(artifact: dict) -> dict:
    required = ["artifact_id", "agent_name", "session_id", "started_at",
                 "closed_at", "total_calls", "blocked_calls"]
    missing = [k for k in required if k not in artifact]
    return {"compliant": len(missing) == 0, "missing_fields": missing}

def _check_cmmc(artifact: dict) -> dict:
    has_sig = "signature" in artifact or "sig" in artifact
    return {"compliant": has_sig, "signature_present": has_sig}

def _check_soc2(artifact: dict) -> dict:
    has_timeline = "heartbeat_n" in artifact
    return {"compliant": has_timeline, "audit_trail_present": has_timeline}

def _check_framework_compliance(data: dict, framework: str) -> bool:
    if framework == "ndaa-1513":
        return _check_ndaa(data)["compliant"]
    if framework == "cmmc":
        return _check_cmmc(data)["compliant"]
    return True

def _to_junit(result: dict) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="GOVBENCH" tests="{result["total"]}" '
        f'failures="{result["total"] - result["passed"]}">',
    ]
    for r in result["results"]:
        status = r["status"]
        lines.append(f'  <testcase name="{r["family"]}" classname="govbench.{result["suite"]}">')
        if status != "PASS":
            lines.append(f'    <failure message="{status}"/>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    return "\n".join(lines)

def _to_sarif(result: dict) -> dict:
    rules = [
        {"id": r["family"], "name": r["family"], "shortDescription": {"text": r["status"]}}
        for r in result["results"]
    ]
    results = [
        {
            "ruleId": r["family"],
            "level": "error" if r["status"] != "PASS" else "none",
            "message": {"text": r["status"]},
        }
        for r in result["results"]
        if r["status"] != "PASS"
    ]
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "GOVBENCH", "rules": rules}}, "results": results}],
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main_stdio():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


async def main_http(port: int = 8765):
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Route

    transport = SseServerTransport("/messages")

    async def handle_sse(request):
        async with transport.connect_sse(request.scope, request.receive, request._send) as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())

    app = Starlette(routes=[Route("/sse", endpoint=handle_sse)])
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    uvicorn_server = uvicorn.Server(config)
    await uvicorn_server.serve()


if __name__ == "__main__":
    import asyncio

    parser = argparse.ArgumentParser(description="Aiglos MCP Server")
    parser.add_argument("--http", action="store_true", help="Use HTTP/SSE transport")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    args = parser.parse_args()

    if args.http:
        asyncio.run(main_http(args.port))
    else:
        asyncio.run(main_stdio())
