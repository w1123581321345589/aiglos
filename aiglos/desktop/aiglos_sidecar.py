#!/usr/bin/env python3
"""
aiglos_sidecar.py
==================
Python sidecar for Aiglos Desktop.

Runs as a subprocess managed by Tauri. Receives commands via stdin,
emits events via stdout. Provides the full Aiglos intelligence stack
(behavioral baseline, policy proposals, federation, honeypot, override)
to the desktop application without requiring the user to manage a
Python environment.

Protocol:
  stdin  -- JSON commands (one per line)
             {"action": "attach", "agent_name": "my-agent", "policy": "enterprise"}
             {"action": "check", "tool_name": "http.post", "args": {...}}
             {"action": "close"}
             {"action": "confirm_override", "challenge_id": "...", "code": "A7X2K9"}
             {"action": "approve_proposal", "proposal_id": "...", "reviewer": "desktop"}
             {"action": "generate_report"}
             {"action": "generate_honeypost"}

  stdout -- JSON events (one per line, consumed by Tauri)
             {"type": "Alert", "rule_id": "T37", "severity": "HIGH", ...}
             {"type": "Tier3Block", "rule_id": "T37", "code": "A7X2K9", ...}
             {"type": "PolicyProposal", "proposal_id": "...", ...}
             {"type": "HoneypotHit", "honeypot_name": "...", ...}
             {"type": "SessionClosed", "blocked": 3, ...}
             {"type": "ComplianceReport", "path": "~/.aiglos/reports/...", ...}
             {"type": "Ready"}

Bundled with the Tauri app as a sidecar binary.
"""

import json
import logging
import sys
import time
from typing import Any, Dict

# Configure logging to stderr only -- stdout is reserved for Tauri events
logging.basicConfig(
    stream  = sys.stderr,
    level   = logging.INFO,
    format  = "%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log = logging.getLogger("aiglos_sidecar")


def emit(event_type: str, **kwargs) -> None:
    """Emit a JSON event to Tauri via stdout."""
    payload = {"type": event_type, **kwargs}
    print(json.dumps(payload), flush=True)


def main() -> None:
    log.info("Aiglos sidecar starting...")

    try:
        import aiglos
        from aiglos.integrations.openclaw import OpenClawGuard
        from aiglos.integrations.honeypot import HoneypotManager
        from aiglos.integrations.override import OverrideManager
        from aiglos.autoresearch.compliance_report import ComplianceReportGenerator
        from aiglos.adaptive.observation import ObservationGraph

        graph    = ObservationGraph()
        guard    = None
        honeypot = None
        override_mgr = OverrideManager(graph=graph)

        emit("Ready", version=aiglos.__version__)
        log.info("Aiglos v%s ready", aiglos.__version__)

    except ImportError as e:
        log.error("Failed to import aiglos: %s", e)
        emit("Error", message=f"Failed to import aiglos: {e}")
        sys.exit(1)

    # Main command loop
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        try:
            cmd: Dict[str, Any] = json.loads(raw_line)
        except json.JSONDecodeError as e:
            log.warning("Invalid JSON command: %s -- %s", raw_line[:80], e)
            continue

        action = cmd.get("action", "")
        log.debug("Command: %s", action)

        try:
            if action == "attach":
                agent_name = cmd.get("agent_name", "desktop-agent")
                policy     = cmd.get("policy", "enterprise")
                guard = OpenClawGuard(agent_name, policy)
                guard.enable_behavioral_baseline()
                guard.enable_intent_prediction()
                guard.enable_policy_proposals()
                guard.enable_causal_tracing()

                # Deploy honeypot
                honeypot = HoneypotManager(
                    agent_name=agent_name,
                    graph=graph,
                )
                honeypot.deploy()
                guard._honeypot_mgr = honeypot

                if cmd.get("api_key"):
                    guard.enable_federation(api_key=cmd["api_key"])

                emit("Attached",
                     agent_name=agent_name,
                     policy=policy,
                     honeypot_count=len(honeypot.active_honeypots()))

            elif action == "check":
                if guard is None:
                    emit("Error", message="No active session. Send 'attach' first.")
                    continue

                tool_name = cmd.get("tool_name", "")
                args      = cmd.get("args", {})
                result    = guard.before_tool_call(tool_name, args)

                if result:
                    if result.threat_class == "T43":
                        emit("HoneypotHit",
                             honeypot_name = args.get("path", ""),
                             agent_name    = guard.agent_name,
                             tool_name     = tool_name,
                             session_id    = getattr(guard, "_session_id", ""))
                    elif result.blocked or result.verdict.value in ("BLOCK", "PAUSE"):
                        # Check if this is Tier 3 requiring override
                        if result.score >= 0.80:
                            challenge = override_mgr.request_override(
                                rule_id   = result.threat_class or "",
                                tool_name = tool_name,
                                tool_args = args,
                                session_id = getattr(guard, "_session_id", ""),
                            )
                            emit("Tier3Block",
                                 rule_id      = result.threat_class or "",
                                 tool_name    = tool_name,
                                 agent_name   = guard.agent_name,
                                 challenge_id = challenge.challenge_id,
                                 code         = challenge.code,
                                 expires_in   = int(challenge.seconds_remaining),
                                 reason       = result.reason or "")
                        else:
                            emit("Alert",
                                 rule_id      = result.threat_class or "",
                                 threat_name  = result.threat_name or "",
                                 tool_name    = tool_name,
                                 agent_name   = guard.agent_name,
                                 severity     = "HIGH" if result.score > 0.7 else "MEDIUM",
                                 score        = result.score,
                                 session_id   = getattr(guard, "_session_id", ""),
                                 timestamp    = time.time())

            elif action == "close":
                if guard is not None:
                    artifact = guard.close_session()
                    emit("SessionClosed",
                         session_id = getattr(guard, "_session_id", ""),
                         agent_name = guard.agent_name,
                         blocked    = getattr(artifact, "blocked_calls", 0),
                         warned     = getattr(artifact, "warned_calls", 0),
                         allowed    = getattr(artifact, "allowed_calls", 0))
                    guard = None

            elif action == "confirm_override":
                result = override_mgr.confirm_override(
                    cmd.get("challenge_id", ""),
                    cmd.get("code", ""),
                )
                emit("OverrideResult",
                     challenge_id = cmd.get("challenge_id", ""),
                     approved     = result.approved,
                     error        = result.error or "")

            elif action == "approve_proposal":
                from aiglos.core.policy_proposal import PolicyProposalEngine
                engine = PolicyProposalEngine(graph=graph)
                proposal = engine.approve_proposal(
                    cmd.get("proposal_id", ""),
                    approved_by=cmd.get("reviewer", "desktop"),
                )
                emit("ProposalResult",
                     proposal_id = cmd.get("proposal_id", ""),
                     approved    = proposal is not None)

            elif action == "generate_report":
                gen    = ComplianceReportGenerator(graph=graph)
                report = gen.generate(save=True)
                # Find the saved file
                from pathlib import Path
                reports_dir = Path.home() / ".aiglos" / "reports"
                files = sorted(reports_dir.glob("compliance_*.md"), reverse=True)
                path  = str(files[0]) if files else ""
                emit("ComplianceReport",
                     path     = path,
                     coverage = report.citation_coverage,
                     verified = report.verified_rules,
                     total    = report.total_rules)

            elif action == "deploy_honeypot":
                if honeypot is None:
                    honeypot = HoneypotManager(graph=graph)
                names = cmd.get("custom_names", [])
                honeypot.deploy(custom_names=names or None)
                emit("HoneypotDeployed",
                     count = len(honeypot.active_honeypots()),
                     names = honeypot.active_honeypots())

            elif action == "shutdown":
                log.info("Sidecar shutdown requested")
                break

            else:
                log.warning("Unknown action: %s", action)

        except Exception as e:
            log.error("Error handling action '%s': %s", action, e, exc_info=True)
            emit("Error", message=str(e), action=action)

    log.info("Aiglos sidecar exiting")


if __name__ == "__main__":
    main()
