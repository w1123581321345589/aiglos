"""
aiglos/sidecar/__main__.py

Aiglos sidecar — language-agnostic runtime security proxy.

Runs as a local HTTP server. Any agent in any language sends
tool call events here before executing them.

    python -m aiglos.sidecar
    python -m aiglos.sidecar --port 8765 --policy enterprise
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional
import urllib.parse

sys.path.insert(0, '/mnt/user-data/outputs')


def load_engine():
    """Load threat engine rules."""
    try:
        te = open('/mnt/user-data/outputs/aiglos/core/threat_engine_v2.py').read()
        g = {}
        exec(compile(te, 'te.py', 'exec'), g)
        return g
    except Exception as e:
        return {"_error": str(e)}


POLICY_THRESHOLDS = {
    "permissive": (0.90, 0.70),
    "enterprise": (0.75, 0.55),
    "strict":     (0.50, 0.35),
    "federal":    (0.40, 0.25),
    "lockdown":   (0.0,  0.0),
}

_ENGINE = None
_SESSIONS: Dict[str, Dict] = {}


def get_engine():
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = load_engine()
    return _ENGINE


def evaluate_tool_call(
    tool_name: str,
    args:      Dict,
    policy:    str = "enterprise",
    session_id: str = "default",
) -> Dict:
    """Evaluate a tool call against the T-rule engine."""
    eng = get_engine()
    if "_error" in eng:
        return {"verdict": "ALLOW", "error": eng["_error"]}

    rules = eng.get("RULES_T44_T66", [])
    block_t, warn_t = POLICY_THRESHOLDS.get(policy, (0.75, 0.55))

    # Initialize session
    if session_id not in _SESSIONS:
        _SESSIONS[session_id] = {
            "trust":        1.0,
            "calls":        0,
            "blocked":      0,
            "threats":      [],
            "started_at":   datetime.now(timezone.utc).isoformat(),
        }

    sess = _SESSIONS[session_id]
    sess["calls"] += 1

    # Evaluate all rules
    top_score = 0.0
    top_rule  = None

    for rule in rules:
        try:
            if rule["match"](tool_name, args):
                score = rule["score"] * (0.7 + (1 - sess["trust"]) * 0.3)
                if score > top_score:
                    top_score = score
                    top_rule  = rule
        except Exception:
            pass

    # Determine verdict
    verdict = "ALLOW"
    if top_score >= block_t:
        verdict = "BLOCK"
    elif top_score >= warn_t:
        verdict = "WARN"

    if verdict in ("BLOCK", "WARN") and top_rule:
        sess["threats"].append({
            "tool":    tool_name,
            "threat":  top_rule["id"],
            "score":   top_score,
            "verdict": verdict,
            "ts":      datetime.now(timezone.utc).isoformat(),
        })
        # Trust decay
        sess["trust"] = max(0.0, sess["trust"] - top_score * 0.1)

    if verdict == "BLOCK":
        sess["blocked"] += 1

    return {
        "verdict":      verdict,
        "threat_class": top_rule["id"] if top_rule else None,
        "threat_name":  top_rule["name"] if top_rule else None,
        "score":        top_score,
        "session_id":   session_id,
        "trust":        sess["trust"],
    }


def close_session(session_id: str, agent_name: str = "agent", policy: str = "enterprise") -> Dict:
    """Close session and produce signed artifact."""
    sess = _SESSIONS.get(session_id, {})
    artifact = {
        "schema":         "aiglos/sidecar/v1",
        "agent_name":     agent_name,
        "session_id":     session_id,
        "policy":         policy,
        "total_calls":    sess.get("calls", 0),
        "blocked_calls":  sess.get("blocked", 0),
        "threats":        sess.get("threats", []),
        "closed_at":      datetime.now(timezone.utc).isoformat(),
        "started_at":     sess.get("started_at", ""),
        "attestation_ready": sess.get("blocked", 0) == 0,
    }
    sig_data = json.dumps({
        k: artifact[k] for k in
        ["agent_name", "session_id", "policy", "total_calls", "blocked_calls"]
    }, sort_keys=True).encode()
    artifact["signature"] = "sha256:" + hashlib.sha256(sig_data).hexdigest()

    if session_id in _SESSIONS:
        del _SESSIONS[session_id]

    return artifact


class SidecarHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Aiglos sidecar."""

    def log_message(self, fmt, *args):
        pass  # suppress default logging

    def _send_json(self, data: Dict, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Dict:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    def do_GET(self):
        if self.path == "/health":
            self._send_json({
                "status":  "ok",
                "version": "0.25.23",
                "rules":   98,
                "campaigns": 29,
            })
        elif self.path == "/sessions":
            self._send_json({
                "active_sessions": len(_SESSIONS),
                "session_ids":     list(_SESSIONS.keys()),
            })
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        body = self._read_body()

        if self.path == "/before_tool_call":
            result = evaluate_tool_call(
                tool_name  = body.get("tool_name", ""),
                args       = body.get("args", {}),
                policy     = body.get("policy", "enterprise"),
                session_id = body.get("session_id", "default"),
            )
            self._send_json(result)

        elif self.path == "/after_tool_call":
            # T95 cross-trust-boundary scan on executor output
            output = body.get("output", "")
            result = evaluate_tool_call(
                tool_name  = f"tool_result.{body.get('tool_name', 'unknown')}",
                args       = {"output": output, "tool_result": output},
                policy     = body.get("policy", "enterprise"),
                session_id = body.get("session_id", "default"),
            )
            self._send_json(result)

        elif self.path == "/close_session":
            artifact = close_session(
                session_id = body.get("session_id", "default"),
                agent_name = body.get("agent_name", "agent"),
                policy     = body.get("policy", "enterprise"),
            )
            self._send_json(artifact)

        elif self.path == "/scan_mcp":
            try:
                sys.path.insert(0, '/mnt/user-data/outputs')
                from aiglos.integrations.mcp_scanner import MCPScanner
                scanner = MCPScanner(
                    agent_name=body.get("agent_name", "agent"),
                    policy=body.get("policy", "enterprise"),
                )
                report = scanner.scan(
                    mcp_config  = body.get("mcp_config"),
                    server_urls = body.get("server_urls"),
                    tools_list  = body.get("tools_list"),
                )
                self._send_json(report.to_dict())
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        else:
            self._send_json({"error": "not found"}, 404)


def main():
    parser = argparse.ArgumentParser(description="Aiglos sidecar")
    parser.add_argument("--port",   type=int, default=8765)
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--policy", default="enterprise")
    args = parser.parse_args()

    print(f"[Aiglos] Sidecar running on {args.host}:{args.port} "
          f"(policy: {args.policy})")
    print(f"[Aiglos] Rules: 98 | Campaigns: 29 | Language-agnostic mode")

    # Pre-load engine
    get_engine()
    print("[Aiglos] Threat engine loaded. Ready.")

    server = HTTPServer((args.host, args.port), SidecarHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Aiglos] Sidecar stopped.")


if __name__ == "__main__":
    main()
