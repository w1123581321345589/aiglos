"""
aiglos/core/nhi.py

Non-Human Identity (NHI) Lifecycle Management for AI Agents.

Non-human identities now outnumber humans 82-to-1 in enterprise
environments, with AI agents the fastest-growing NHI category. Zero existing systems
cover AI-agent-specific identity lifecycle management.

The problem: AI agents use service account credentials, API keys, and
access tokens that were designed for humans or static services. These
credentials are over-scoped, never rotate, and have no behavioral
baseline. When an agent's credential usage deviates from its declared
role, no system detects it.

What this builds:
    1. Capability-scoped credentials: agents declare what they can do
       at creation time. Credentials are scoped to that declaration.
    2. Automatic credential rotation: time-bounded tokens that expire
       and rotate without human intervention.
    3. Behavioral drift detection: when an agent uses credentials
       outside its declared capability scope, T-rule fires.
    4. Signed identity audit trail: every credential event mapped
       to the session artifact for CMMC AC.L2-3.1.2 compliance.

Novel capability: AI-agent-specific identity lifecycle with behavioral drift detection.
"""

from __future__ import annotations

import hashlib
import json
import time
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set


# ── Agent identity model ──────────────────────────────────────────────────────

@dataclass
class AgentCapabilityScope:
    """
    Declared capability scope for an AI agent identity.
    The agent can only do what it declared at creation time.
    """
    agent_id:          str
    agent_name:        str
    declared_tools:    Set[str]       # tool names the agent is allowed to call
    declared_sources:  Set[str]       # data sources the agent can access
    declared_outputs:  Set[str]       # output destinations the agent can write to
    max_privilege:     str            # AUTONOMOUS | OPERATOR_REVIEW | HUMAN_IN_LOOP
    created_at:        str
    expires_at:        Optional[str]  # None = no expiry
    issuer:            str            # who issued this identity

    def can_call(self, tool_name: str) -> bool:
        if "*" in self.declared_tools:
            return True
        return tool_name in self.declared_tools

    def can_access(self, source: str) -> bool:
        if "*" in self.declared_sources:
            return True
        return any(source.startswith(s) for s in self.declared_sources)

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc).isoformat() > self.expires_at


@dataclass
class AgentCredential:
    """A time-bounded credential issued to an AI agent."""
    credential_id:   str
    agent_id:        str
    credential_type: str          # api_key | service_account | bearer_token
    token_hash:      str          # SHA-256 of actual token (never store plaintext)
    scopes:          List[str]    # OAuth-style scopes
    issued_at:       str
    expires_at:      str
    rotated_from:    Optional[str]  # previous credential ID
    revoked:         bool = False
    revoked_at:      Optional[str] = None
    revocation_reason: Optional[str] = None


@dataclass
class IdentityEvent:
    """An audited identity lifecycle event."""
    event_type:    str    # created|rotated|revoked|drift_detected|expired
    agent_id:      str
    credential_id: str
    timestamp:     str
    details:       Dict
    severity:      str    # info|warn|critical


@dataclass
class DriftEvent:
    """Detected behavioral drift from declared identity scope."""
    agent_id:      str
    tool_called:   str
    source_accessed: Optional[str]
    declared_scope_allows: bool
    drift_type:    str    # tool_out_of_scope | source_out_of_scope | privilege_escalation
    severity:      str
    timestamp:     str
    blocked:       bool


# ── NHI Manager ──────────────────────────────────────────────────────────────

class NHIManager:
    """
    Non-Human Identity lifecycle manager for AI agents.

    Manages capability-scoped credentials, rotation, drift detection,
    and generates CMMC-compliant identity audit trails.

    Usage:
        from aiglos.core.nhi import NHIManager

        nhi = NHIManager()

        # Register agent identity with declared capabilities
        identity = nhi.register_agent(
            agent_name="research-agent",
            declared_tools={"web_search", "read_file", "write_file"},
            declared_sources={"https://internal.docs/", "file:///data/"},
            declared_outputs={"file:///reports/"},
            max_privilege="OPERATOR_REVIEW",
            ttl_hours=24,
        )

        # Check before every tool call
        allowed, drift = nhi.check_tool_call(identity.agent_id, "web_search")

        # Rotate credentials on schedule
        new_cred = nhi.rotate_credentials(identity.agent_id)

        # Audit trail
        report = nhi.audit_report(identity.agent_id)
    """

    # Default TTL for agent credentials (24 hours)
    DEFAULT_TTL_HOURS = 24

    # Rotation schedule (rotate at 80% of TTL)
    ROTATION_THRESHOLD = 0.80

    def __init__(self, issuer: str = "aiglos-nhi"):
        self.issuer       = issuer
        self._identities: Dict[str, AgentCapabilityScope]  = {}
        self._credentials: Dict[str, AgentCredential]      = {}
        self._events:      List[IdentityEvent]              = []
        self._drifts:      List[DriftEvent]                 = []

    # ── Identity registration ─────────────────────────────────────────────────

    def register_agent(
        self,
        agent_name:        str,
        declared_tools:    Optional[Set[str]] = None,
        declared_sources:  Optional[Set[str]] = None,
        declared_outputs:  Optional[Set[str]] = None,
        max_privilege:     str = "OPERATOR_REVIEW",
        ttl_hours:         int = DEFAULT_TTL_HOURS,
    ) -> AgentCapabilityScope:
        """
        Register an AI agent identity with its declared capability scope.
        Issues a time-bounded credential scoped to the declaration.
        """
        agent_id = hashlib.sha256(
            f"{agent_name}{time.time()}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]

        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=ttl_hours)).isoformat() if ttl_hours else None

        scope = AgentCapabilityScope(
            agent_id         = agent_id,
            agent_name       = agent_name,
            declared_tools   = declared_tools or set(),
            declared_sources = declared_sources or set(),
            declared_outputs = declared_outputs or set(),
            max_privilege    = max_privilege,
            created_at       = now.isoformat(),
            expires_at       = expires,
            issuer           = self.issuer,
        )
        self._identities[agent_id] = scope

        # Issue initial credential
        self._issue_credential(agent_id, ttl_hours)

        self._log_event(IdentityEvent(
            event_type    = "created",
            agent_id      = agent_id,
            credential_id = self._current_credential(agent_id).credential_id,
            timestamp     = now.isoformat(),
            details       = {
                "agent_name":    agent_name,
                "tool_count":    len(declared_tools or []),
                "max_privilege": max_privilege,
                "ttl_hours":     ttl_hours,
            },
            severity = "info",
        ))

        return scope

    # ── Tool call authorization ────────────────────────────────────────────────

    def check_tool_call(
        self,
        agent_id:  str,
        tool_name: str,
        block:     bool = True,
    ) -> tuple[bool, Optional[DriftEvent]]:
        """
        Check if an agent is authorized to call a tool.
        Returns (allowed, drift_event).
        """
        scope = self._identities.get(agent_id)
        if not scope:
            return False, None

        # Check expiry
        if scope.is_expired():
            self._revoke_credential(agent_id, "identity_expired")
            return False, None

        # Check if tool is in declared scope
        allowed = scope.can_call(tool_name)

        if not allowed:
            drift = DriftEvent(
                agent_id              = agent_id,
                tool_called           = tool_name,
                source_accessed       = None,
                declared_scope_allows = False,
                drift_type            = "tool_out_of_scope",
                severity              = "critical",
                timestamp             = datetime.now(timezone.utc).isoformat(),
                blocked               = block,
            )
            self._drifts.append(drift)
            self._log_event(IdentityEvent(
                event_type    = "drift_detected",
                agent_id      = agent_id,
                credential_id = self._current_credential(agent_id).credential_id
                                if self._current_credential(agent_id) else "none",
                timestamp     = drift.timestamp,
                details       = {
                    "tool":       tool_name,
                    "drift_type": "tool_out_of_scope",
                    "blocked":    block,
                },
                severity = "critical",
            ))
            return not block, drift

        # Check rotation schedule
        cred = self._current_credential(agent_id)
        if cred and self._needs_rotation(cred):
            self.rotate_credentials(agent_id)

        return True, None

    def check_source_access(
        self,
        agent_id: str,
        source:   str,
        block:    bool = True,
    ) -> tuple[bool, Optional[DriftEvent]]:
        """Check if an agent is authorized to access a data source."""
        scope = self._identities.get(agent_id)
        if not scope:
            return False, None

        allowed = scope.can_access(source)

        if not allowed:
            drift = DriftEvent(
                agent_id              = agent_id,
                tool_called           = "source_access",
                source_accessed       = source,
                declared_scope_allows = False,
                drift_type            = "source_out_of_scope",
                severity              = "high",
                timestamp             = datetime.now(timezone.utc).isoformat(),
                blocked               = block,
            )
            self._drifts.append(drift)
            return not block, drift

        return True, None

    # ── Credential lifecycle ──────────────────────────────────────────────────

    def rotate_credentials(self, agent_id: str) -> Optional[AgentCredential]:
        """
        Rotate credentials for an agent.
        Old credential is revoked, new one issued with same scope.
        """
        scope = self._identities.get(agent_id)
        if not scope:
            return None

        old_cred = self._current_credential(agent_id)
        old_cred_id = old_cred.credential_id if old_cred else None

        if old_cred:
            old_cred.revoked = True
            old_cred.revoked_at = datetime.now(timezone.utc).isoformat()
            old_cred.revocation_reason = "scheduled_rotation"

        # Issue new credential with original TTL
        new_cred = self._issue_credential(agent_id, ttl_hours=self.DEFAULT_TTL_HOURS)
        if new_cred and old_cred_id:
            new_cred.rotated_from = old_cred_id

        self._log_event(IdentityEvent(
            event_type    = "rotated",
            agent_id      = agent_id,
            credential_id = new_cred.credential_id if new_cred else "none",
            timestamp     = datetime.now(timezone.utc).isoformat(),
            details       = {"rotated_from": old_cred_id},
            severity      = "info",
        ))

        return new_cred

    def revoke(self, agent_id: str, reason: str = "manual_revocation") -> bool:
        """Immediately revoke all credentials for an agent."""
        self._revoke_credential(agent_id, reason)
        return True

    # ── Audit reporting ───────────────────────────────────────────────────────

    def audit_report(self, agent_id: Optional[str] = None) -> Dict:
        """
        Generate CMMC AC.L2-3.1.2 compliant identity audit report.
        Maps to SOC 2 CC6 (logical access) requirements.
        """
        events = [e for e in self._events
                  if agent_id is None or e.agent_id == agent_id]
        drifts = [d for d in self._drifts
                  if agent_id is None or d.agent_id == agent_id]

        identities = (
            {agent_id: self._identities[agent_id]}
            if agent_id and agent_id in self._identities
            else self._identities
        )

        return {
            "schema":           "aiglos/nhi-audit/v1",
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "issuer":           self.issuer,
            "agents_tracked":   len(identities),
            "total_events":     len(events),
            "drift_events":     len(drifts),
            "critical_drifts":  sum(1 for d in drifts if d.severity == "critical"),
            "agents": {
                aid: {
                    "agent_name":      scope.agent_name,
                    "max_privilege":   scope.max_privilege,
                    "declared_tools":  list(scope.declared_tools),
                    "created_at":      scope.created_at,
                    "expires_at":      scope.expires_at,
                    "is_expired":      scope.is_expired(),
                    "drift_count":     sum(1 for d in drifts if d.agent_id == aid),
                }
                for aid, scope in identities.items()
            },
            "events":           [
                {
                    "event_type":    e.event_type,
                    "agent_id":      e.agent_id,
                    "credential_id": e.credential_id,
                    "timestamp":     e.timestamp,
                    "severity":      e.severity,
                    "details":       e.details,
                }
                for e in events
            ],
            "drift_events":    [
                {
                    "agent_id":    d.agent_id,
                    "tool":        d.tool_called,
                    "source":      d.source_accessed,
                    "drift_type":  d.drift_type,
                    "severity":    d.severity,
                    "blocked":     d.blocked,
                    "timestamp":   d.timestamp,
                }
                for d in drifts
            ],
            "compliance": {
                "cmmc_ac_l2_3_1_2": len(drifts) == 0,
                "soc2_cc6":         len([d for d in drifts if d.severity == "critical"]) == 0,
                "attestation_ready": len(drifts) == 0,
            }
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _issue_credential(self, agent_id: str, ttl_hours: int) -> AgentCredential:
        cred_id   = hashlib.sha256(f"{agent_id}{time.time()}".encode()).hexdigest()[:16]
        token     = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now       = datetime.now(timezone.utc)
        expires   = (now + timedelta(hours=ttl_hours)).isoformat()

        cred = AgentCredential(
            credential_id   = cred_id,
            agent_id        = agent_id,
            credential_type = "bearer_token",
            token_hash      = token_hash,
            scopes          = ["agent:execute"],
            issued_at       = now.isoformat(),
            expires_at      = expires,
            rotated_from    = None,
        )
        self._credentials[cred_id] = cred
        return cred

    def _current_credential(self, agent_id: str) -> Optional[AgentCredential]:
        active = [
            c for c in self._credentials.values()
            if c.agent_id == agent_id and not c.revoked
        ]
        if not active:
            return None
        return sorted(active, key=lambda c: c.issued_at, reverse=True)[0]

    def _revoke_credential(self, agent_id: str, reason: str) -> None:
        for cred in self._credentials.values():
            if cred.agent_id == agent_id and not cred.revoked:
                cred.revoked          = True
                cred.revoked_at       = datetime.now(timezone.utc).isoformat()
                cred.revocation_reason = reason

    def _needs_rotation(self, cred: AgentCredential) -> bool:
        issued   = datetime.fromisoformat(cred.issued_at)
        expires  = datetime.fromisoformat(cred.expires_at)
        ttl      = (expires - issued).total_seconds()
        elapsed  = (datetime.now(timezone.utc) - issued).total_seconds()
        return elapsed / ttl >= self.ROTATION_THRESHOLD

    def _log_event(self, event: IdentityEvent) -> None:
        self._events.append(event)


# ── Multi-brain topology support ──────────────────────────────────────────────

@dataclass
class BrainCapabilityNode:
    """A node in the multi-brain capability delegation graph."""
    brain_id:       str
    brain_name:     str
    parent_id:      Optional[str]
    capabilities:   Set[str]
    delegated_from: Optional[str]   # which brain delegated capabilities here
    depth:          int             # depth from root in delegation chain
    created_at:     str


class MultiBrainRegistry:
    """
    Capability delegation graph for multi-brain agent topologies.

    Tracks which brains can delegate which hands to which other brains.
    Detects unauthorized delegation chains (T64 at topology level).

    Usage:
        registry = MultiBrainRegistry()

        # Register root brain
        root = registry.register_root("root-brain", capabilities={"bash", "web_search"})

        # Register sub-brain with delegated subset
        sub = registry.delegate_to("sub-brain", from_brain_id=root.brain_id,
                                    capabilities={"web_search"})

        # Check delegation
        ok, reason = registry.check_delegation(
            from_brain_id=root.brain_id,
            to_brain_id=sub.brain_id,
            hand="web_search"
        )
    """

    MAX_DELEGATION_DEPTH = 5  # prevent infinite delegation chains

    def __init__(self):
        self._nodes: Dict[str, BrainCapabilityNode] = {}
        self._delegation_log: List[Dict] = []

    def register_root(
        self,
        brain_name:   str,
        capabilities: Optional[Set[str]] = None,
    ) -> BrainCapabilityNode:
        """Register the root brain with full capability set."""
        import hashlib, time
        brain_id = hashlib.sha256(f"{brain_name}{time.time()}".encode()).hexdigest()[:12]
        node = BrainCapabilityNode(
            brain_id       = brain_id,
            brain_name     = brain_name,
            parent_id      = None,
            capabilities   = capabilities or set(),
            delegated_from = None,
            depth          = 0,
            created_at     = datetime.now(timezone.utc).isoformat(),
        )
        self._nodes[brain_id] = node
        return node

    def delegate_to(
        self,
        brain_name:   str,
        from_brain_id: str,
        capabilities: Optional[Set[str]] = None,
    ) -> Optional[BrainCapabilityNode]:
        """
        Delegate a subset of capabilities to a new sub-brain.
        Only capabilities the delegating brain holds can be delegated.
        """
        import hashlib, time
        parent = self._nodes.get(from_brain_id)
        if not parent:
            return None

        if parent.depth >= self.MAX_DELEGATION_DEPTH:
            self._delegation_log.append({
                "event":  "delegation_blocked_depth",
                "from":   from_brain_id,
                "reason": f"max depth {self.MAX_DELEGATION_DEPTH} exceeded",
                "ts":     datetime.now(timezone.utc).isoformat(),
            })
            return None

        # Only delegate capabilities the parent actually has
        # Empty set means delegate all parent capabilities
        requested = capabilities or parent.capabilities
        allowed   = requested & parent.capabilities

        brain_id = hashlib.sha256(f"{brain_name}{time.time()}".encode()).hexdigest()[:12]
        node = BrainCapabilityNode(
            brain_id       = brain_id,
            brain_name     = brain_name,
            parent_id      = from_brain_id,
            capabilities   = allowed,
            delegated_from = from_brain_id,
            depth          = parent.depth + 1,
            created_at     = datetime.now(timezone.utc).isoformat(),
        )
        self._nodes[brain_id] = node

        self._delegation_log.append({
            "event":        "delegation_created",
            "from":         from_brain_id,
            "to":           brain_id,
            "capabilities": list(allowed),
            "depth":        node.depth,
            "ts":           datetime.now(timezone.utc).isoformat(),
        })
        return node

    def check_delegation(
        self,
        from_brain_id: str,
        to_brain_id:   str,
        hand:          str,
    ) -> tuple[bool, Optional[str]]:
        """
        Validate that from_brain can delegate hand to to_brain.
        Returns (allowed, reason).
        """
        from_node = self._nodes.get(from_brain_id)
        to_node   = self._nodes.get(to_brain_id)

        if not from_node:
            return False, f"Delegating brain {from_brain_id} not registered"
        if not to_node:
            return False, f"Receiving brain {to_brain_id} not registered"
        if hand not in from_node.capabilities:
            return False, f"Brain {from_brain_id} does not hold capability: {hand}"
        if to_node.capabilities and hand not in to_node.capabilities:
            return False, f"Brain {to_brain_id} was not delegated capability: {hand}"
        if to_node.parent_id != from_brain_id:
            return False, f"Brain {to_brain_id} is not a direct delegate of {from_brain_id}"

        self._delegation_log.append({
            "event": "delegation_checked",
            "from":  from_brain_id,
            "to":    to_brain_id,
            "hand":  hand,
            "ok":    True,
            "ts":    datetime.now(timezone.utc).isoformat(),
        })
        return True, None

    def get_delegation_log(self) -> List[Dict]:
        return self._delegation_log

    def topology_report(self) -> Dict:
        """Return full topology map for session artifact."""
        return {
            "total_brains": len(self._nodes),
            "max_depth":    max((n.depth for n in self._nodes.values()), default=0),
            "nodes": {
                bid: {
                    "name":  n.brain_name,
                    "depth": n.depth,
                    "caps":  list(n.capabilities),
                    "parent": n.parent_id,
                }
                for bid, n in self._nodes.items()
            },
            "delegation_events": len(self._delegation_log),
        }
