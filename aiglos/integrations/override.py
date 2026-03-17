"""
aiglos.integrations.override
==============================
Challenge-response human override for Tier 3 actions.

The problem with webhook-based Tier 3 approval:
  Engineers approve blindly to unblock work. The approval is
  asynchronous, happens in Slack, has no context about what was
  blocked, and produces no compliance artifact.

The problem with policy proposals:
  They solve repeated patterns. They don't solve one-off legitimate
  exceptions -- "I know this looks like T37 but I am explicitly
  authorizing this payment right now."

The challenge-response override solves the one-off case:

  1. Agent attempts a Tier 3 action (e.g. T37 financial transaction)
  2. Aiglos blocks and generates a 6-character time-limited code
  3. Code is displayed in the terminal / system tray notification
  4. Human types the code to confirm intent
  5. Action proceeds with full compliance logging:
     - What was requested
     - What rule blocked it
     - When the challenge was issued
     - When the human responded
     - The exact code that was matched
  6. Override expires after 120 seconds if not confirmed

NDAA §1513 requires "human oversight with override mechanisms."
EU AI Act Annex III requires "human oversight with override capability."
NIST AI 600-1 requires "human-in-the-loop requirements."

This is what those requirements mean in practice: a specific,
logged, time-limited human action -- not a rubber-stamp webhook.

The compliance artifact: every override is stored in the observation
graph with the full context. An auditor can see exactly which Tier 3
actions were human-authorized, by whom, and when.

Usage:
    guard = OpenClawGuard("my-agent", "enterprise")

    # When a Tier 3 action is blocked:
    challenge = guard.request_override(
        rule_id="T37",
        tool_name="http.post",
        args={"url": "https://api.stripe.com/v1/charges"},
        reason="Authorizing one-time payment for contract renewal",
    )
    print(f"Override code: {challenge.code}")
    # Terminal shows: "Override code: A7X2K9 (expires in 120s)"

    # Human types the code:
    result = guard.confirm_override(challenge.challenge_id, "A7X2K9")
    if result.approved:
        # Proceed with the action
        pass
"""



import hashlib
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger("aiglos.override")

# ── Configuration ─────────────────────────────────────────────────────────────

_CODE_LENGTH        = 6       # characters in the challenge code
_CODE_CHARS         = string.ascii_uppercase + string.digits  # A-Z, 0-9
_EXPIRY_SECONDS     = 120     # challenge expires after 2 minutes
_MAX_ATTEMPTS       = 3       # wrong codes before challenge is invalidated


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class OverrideChallenge:
    """
    A time-limited challenge issued when a human needs to authorize
    a Tier 3 action. The human must provide the exact code within
    the expiry window.
    """
    challenge_id:  str
    code:          str
    rule_id:       str
    tool_name:     str
    tool_args:     dict
    reason:        str        # human-provided reason for the override
    agent_name:    str
    session_id:    str
    issued_at:     float = field(default_factory=time.time)
    expires_at:    float = field(default_factory=lambda: time.time() + _EXPIRY_SECONDS)
    attempts:      int   = 0
    resolved:      bool  = False
    approved:      bool  = False
    resolved_at:   Optional[float] = None
    resolved_code: Optional[str]   = None

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at and not self.resolved

    @property
    def seconds_remaining(self) -> float:
        return max(0.0, self.expires_at - time.time())

    @property
    def is_valid(self) -> bool:
        return (not self.is_expired and
                not self.resolved and
                self.attempts < _MAX_ATTEMPTS)

    def to_dict(self) -> dict:
        return {
            "challenge_id":  self.challenge_id,
            "rule_id":       self.rule_id,
            "tool_name":     self.tool_name,
            "reason":        self.reason,
            "agent_name":    self.agent_name,
            "session_id":    self.session_id,
            "issued_at":     self.issued_at,
            "expires_at":    self.expires_at,
            "resolved":      self.resolved,
            "approved":      self.approved,
            "resolved_at":   self.resolved_at,
            "attempts":      self.attempts,
        }

    def terminal_prompt(self) -> str:
        """Formatted string for terminal display."""
        remaining = int(self.seconds_remaining)
        return (
            f"\n  ┌─ Aiglos Override Required ─────────────────────────────┐\n"
            f"  │  Rule blocked: {self.rule_id} -- {self.tool_name:<30}│\n"
            f"  │  Reason:       {self.reason[:46]:<46}  │\n"
            f"  │                                                          │\n"
            f"  │  Override code: {self.code}   (expires in {remaining}s)             │\n"
            f"  │                                                          │\n"
            f"  │  Type this code to authorize: aiglos override confirm    │\n"
            f"  │  Or call: guard.confirm_override('{self.challenge_id[:8]}...', '{self.code}')  │\n"
            f"  └──────────────────────────────────────────────────────────┘\n"
        )


@dataclass
class OverrideResult:
    """Result of a confirm_override() call."""
    approved:      bool
    challenge_id:  str
    reason:        str = ""
    error:         str = ""

    @property
    def rejected(self) -> bool:
        return not self.approved


# ── OverrideManager ───────────────────────────────────────────────────────────

class OverrideManager:
    """
    Issues and validates challenge-response codes for Tier 3 overrides.

    One instance per deployment (not per session). Challenges are
    stored in memory and optionally in the observation graph for
    compliance audit trail.

    Thread-safe: uses dict keyed by challenge_id.
    """

    def __init__(self, graph=None, agent_name: str = ""):
        self._graph       = graph
        self._agent_name  = agent_name
        self._challenges: Dict[str, OverrideChallenge] = {}

    # ── Challenge issuance ────────────────────────────────────────────────────

    def request_override(
        self,
        rule_id:    str,
        tool_name:  str,
        tool_args:  dict,
        session_id: str  = "",
        reason:     str  = "",
    ) -> OverrideChallenge:
        """
        Issue a challenge for a Tier 3 action.

        Generates a cryptographically random code, logs the challenge,
        and returns the challenge object for display to the human.

        The code uses uppercase letters and digits to avoid visual
        ambiguity (no 0/O, 1/I confusion).
        """
        code         = self._generate_code()
        challenge_id = "ovr_" + hashlib.sha256(
            f"{rule_id}{tool_name}{time.time()}{os.urandom(8).hex()}".encode()
        ).hexdigest()[:16]

        challenge = OverrideChallenge(
            challenge_id = challenge_id,
            code         = code,
            rule_id      = rule_id,
            tool_name    = tool_name,
            tool_args    = tool_args,
            reason       = reason or f"Override requested for {rule_id}",
            agent_name   = self._agent_name,
            session_id   = session_id,
        )
        self._challenges[challenge_id] = challenge
        self._persist_challenge(challenge)

        log.info(
            "[OverrideManager] Challenge issued: %s rule=%s tool=%s "
            "expires_in=%.0fs",
            challenge_id, rule_id, tool_name, challenge.seconds_remaining,
        )
        return challenge

    # ── Challenge resolution ──────────────────────────────────────────────────

    def confirm_override(
        self,
        challenge_id: str,
        code:         str,
    ) -> OverrideResult:
        """
        Validate a human-provided override code.

        Returns OverrideResult(approved=True) if:
          - challenge_id exists
          - challenge has not expired
          - code matches exactly (case-insensitive, stripped)
          - fewer than _MAX_ATTEMPTS wrong codes have been tried

        Every confirmation attempt is logged regardless of outcome.
        """
        challenge = self._challenges.get(challenge_id)

        if not challenge:
            # Try prefix match for CLI convenience
            matches = [
                c for cid, c in self._challenges.items()
                if cid.startswith(challenge_id)
            ]
            if len(matches) == 1:
                challenge = matches[0]
            else:
                log.warning(
                    "[OverrideManager] Unknown challenge ID: %s", challenge_id
                )
                return OverrideResult(
                    approved=False,
                    challenge_id=challenge_id,
                    error="Challenge not found.",
                )

        if challenge.is_expired:
            log.warning(
                "[OverrideManager] Challenge expired: %s", challenge_id
            )
            return OverrideResult(
                approved=False,
                challenge_id=challenge_id,
                error=f"Challenge expired {int(time.time() - challenge.expires_at)}s ago.",
            )

        if not challenge.is_valid:
            return OverrideResult(
                approved=False,
                challenge_id=challenge_id,
                error="Challenge invalid (too many attempts or already resolved).",
            )

        challenge.attempts += 1
        provided = code.strip().upper()
        expected = challenge.code.strip().upper()

        if provided == expected:
            challenge.resolved     = True
            challenge.approved     = True
            challenge.resolved_at  = time.time()
            challenge.resolved_code = provided
            self._persist_challenge(challenge)
            log.info(
                "[OverrideManager] Override APPROVED: %s rule=%s "
                "tool=%s agent=%s session=%s",
                challenge_id, challenge.rule_id,
                challenge.tool_name, challenge.agent_name, challenge.session_id,
            )
            return OverrideResult(
                approved=True,
                challenge_id=challenge_id,
                reason=challenge.reason,
            )

        log.warning(
            "[OverrideManager] Wrong code for %s (attempt %d/%d)",
            challenge_id, challenge.attempts, _MAX_ATTEMPTS,
        )
        if challenge.attempts >= _MAX_ATTEMPTS:
            challenge.resolved = True
            challenge.approved = False
            self._persist_challenge(challenge)
            return OverrideResult(
                approved=False,
                challenge_id=challenge_id,
                error=f"Maximum attempts ({_MAX_ATTEMPTS}) exceeded. Challenge invalidated.",
            )

        return OverrideResult(
            approved=False,
            challenge_id=challenge_id,
            error=f"Incorrect code. {_MAX_ATTEMPTS - challenge.attempts} attempt(s) remaining.",
        )

    def reject_override(self, challenge_id: str) -> OverrideResult:
        """Explicitly reject a pending challenge (human chose not to override)."""
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            return OverrideResult(
                approved=False, challenge_id=challenge_id,
                error="Challenge not found."
            )
        challenge.resolved    = True
        challenge.approved    = False
        challenge.resolved_at = time.time()
        self._persist_challenge(challenge)
        log.info(
            "[OverrideManager] Override REJECTED: %s rule=%s",
            challenge_id, challenge.rule_id,
        )
        return OverrideResult(
            approved=False, challenge_id=challenge_id,
            reason="Explicitly rejected."
        )

    # ── Status and listing ────────────────────────────────────────────────────

    def pending_challenges(self) -> List[OverrideChallenge]:
        """Return all pending (not resolved, not expired) challenges."""
        return [
            c for c in self._challenges.values()
            if not c.resolved and not c.is_expired
        ]

    def all_challenges(self) -> List[OverrideChallenge]:
        """Return all challenges including resolved and expired."""
        return list(self._challenges.values())

    def summary(self) -> dict:
        challenges = list(self._challenges.values())
        approved = sum(1 for c in challenges if c.approved)
        rejected = sum(1 for c in challenges if c.resolved and not c.approved)
        pending  = len(self.pending_challenges())
        expired  = sum(1 for c in challenges if c.is_expired)
        return {
            "total":    len(challenges),
            "approved": approved,
            "rejected": rejected,
            "pending":  pending,
            "expired":  expired,
        }

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _generate_code(self) -> str:
        """Generate a cryptographically random override code."""
        # Exclude visually ambiguous characters
        safe_chars = [c for c in _CODE_CHARS if c not in "0O1I"]
        return "".join(random.SystemRandom().choices(safe_chars, k=_CODE_LENGTH))

    def _persist_challenge(self, challenge: OverrideChallenge) -> None:
        if not self._graph:
            return
        try:
            self._graph.upsert_override_challenge(challenge)
        except Exception as e:
            log.debug("[OverrideManager] Persist error: %s", e)
