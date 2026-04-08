"""
aiglos/autoresearch/wiki.py

Core wiki engine for the Aiglos threat intelligence wiki.

Four operations: INGEST, PROPOSE, LINT, EVOLVE.

The key architectural distinction from generic LLM wiki systems:
the output is machine-readable rule proposals that feed directly
into the threat engine — not just human-readable markdown.

The wiki is the research layer.
The threat engine is the execution layer.
The proposal is the clean interface between them.

Usage:
    from aiglos.autoresearch.wiki import ThreatWiki

    wiki = ThreatWiki(
        wiki_dir="aiglos/autoresearch/wiki",
        raw_dir="aiglos/autoresearch/raw",
        schema_path="aiglos/autoresearch/SCHEMA.md",
    )

    # Ingest a new raw item
    result = wiki.ingest("raw/ghsa/ghsa-abc123.json")

    # Run full evolution cycle
    from aiglos.autoresearch.feeds import FeedManager
    fm = FeedManager("aiglos/autoresearch/raw")
    fetch_result = fm.fetch_all()
    wiki.evolve(new_items=fetch_result.new_items)

    # Lint the wiki
    report = wiki.lint()

    # Get all pending proposals
    proposals = wiki.get_proposals(status="pending")
"""

from __future__ import annotations

import json
import re
import time
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any

logger = logging.getLogger(__name__)


# ── Proposal schema ───────────────────────────────────────────────────────────

@dataclass
class RuleProposal:
    """
    A structured recommendation to add or modify a T-rule.

    This is the clean interface between the wiki research layer
    and the threat engine execution layer. The wiki produces proposals.
    A human reviews them. A developer implements the match function.
    """
    slug:               str
    proposed_id:        str              # e.g. "T96" or "T81-VARIANT"
    name:               str              # CAPS_UNDERSCORE_NAME
    score_estimate:     float            # 0.0 - 1.0
    critical_estimate:  bool
    confidence:         float            # wiki's confidence: 0.0 - 1.0
    supporting_sources: int              # count of raw/ files supporting this
    detection_logic:    str              # plain English detection description
    proposed_match_pseudocode: str       # pseudocode for match_T{N} function
    extends_rule:       Optional[str]    # e.g. "T81" if extending existing
    replaces_rule:      Optional[str]    # e.g. "T30" if replacing
    related_rules:      list[str]        = field(default_factory=list)
    citations:          list[str]        = field(default_factory=list)
    status:             str              = "pending"   # pending|approved|rejected
    proposed_date:      str              = ""
    reviewed_date:      Optional[str]    = None
    reviewer_notes:     Optional[str]    = None

    def to_frontmatter(self) -> str:
        """Render the proposal metadata as YAML frontmatter."""
        lines = [
            "---",
            f"type: proposal",
            f"slug: {self.slug}",
            f"proposed_id: {self.proposed_id}",
            f"name: {self.name}",
            f"score_estimate: {self.score_estimate:.2f}",
            f"critical_estimate: {str(self.critical_estimate).lower()}",
            f"confidence: {self.confidence:.2f}",
            f"supporting_sources: {self.supporting_sources}",
            f"extends: {self.extends_rule or 'null'}",
            f"replaces: {self.replaces_rule or 'null'}",
            f"related_rules: [{', '.join(self.related_rules)}]",
            f"status: {self.status}",
            f"proposed_date: {self.proposed_date}",
            f"reviewed_date: {self.reviewed_date or 'null'}",
            "---",
        ]
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Render the full proposal as a markdown document."""
        sections = [
            self.to_frontmatter(),
            f"\n# Proposal: {self.proposed_id} {self.name}\n",
            f"**Status:** {self.status}  ",
            f"**Confidence:** {self.confidence:.0%}  ",
            f"**Supporting sources:** {self.supporting_sources}  ",
            f"**Score estimate:** {self.score_estimate:.2f} "
            f"({'CRITICAL' if self.critical_estimate else 'non-critical'})\n",
            "## Detection Logic\n",
            self.detection_logic + "\n",
            "## Proposed match_T{N} Pseudocode\n",
            "```python",
            self.proposed_match_pseudocode,
            "```\n",
            "## Supporting Evidence\n",
        ]
        for cite in self.citations:
            sections.append(f"- {cite}")
        sections.append("")

        if self.related_rules:
            sections.append("## Related Rules\n")
            for rule in self.related_rules:
                sections.append(f"- [[{rule}]]")
            sections.append("")

        if self.extends_rule:
            sections.append(f"## Extends\n\n[[{self.extends_rule}]]\n")
        if self.replaces_rule:
            sections.append(f"## Replaces\n\n[[{self.replaces_rule}]]\n")

        sections.append("## Reviewer Notes\n\n_Pending review._\n")
        return "\n".join(sections)


# ── Ingest result ─────────────────────────────────────────────────────────────

@dataclass
class IngestResult:
    source_slug:     str
    pages_updated:   list[str]  = field(default_factory=list)
    pages_created:   list[str]  = field(default_factory=list)
    proposals_created: list[str] = field(default_factory=list)
    errors:          list[str]  = field(default_factory=list)
    duration_ms:     float      = 0.0


# ── Lint report ───────────────────────────────────────────────────────────────

@dataclass
class LintReport:
    unvalidated_rules:      list[str] = field(default_factory=list)
    stale_rules:            list[str] = field(default_factory=list)
    weak_campaigns:         list[str] = field(default_factory=list)
    stale_frameworks:       list[str] = field(default_factory=list)
    overdue_proposals:      list[str] = field(default_factory=list)
    overdue_contradictions: list[str] = field(default_factory=list)
    orphan_pages:           list[str] = field(default_factory=list)
    missing_pages:          list[str] = field(default_factory=list)
    run_date:               str       = ""

    @property
    def total_issues(self) -> int:
        """Return the total number of lint issues found."""
        return sum([
            len(self.unvalidated_rules),
            len(self.stale_rules),
            len(self.weak_campaigns),
            len(self.stale_frameworks),
            len(self.overdue_proposals),
            len(self.overdue_contradictions),
            len(self.orphan_pages),
            len(self.missing_pages),
        ])

    def to_markdown(self) -> str:
        """Render the lint report as a markdown document."""
        lines = [
            f"# Lint Report — {self.run_date}",
            f"\n**Total issues:** {self.total_issues}\n",
        ]
        sections = [
            ("Unvalidated Rules (no incident citation)", self.unvalidated_rules),
            ("Stale Rules (citations >180 days old)", self.stale_rules),
            ("Weak Campaigns (<2 corroborating incidents)", self.weak_campaigns),
            ("Stale Framework Pages (>90 days)", self.stale_frameworks),
            ("Overdue Proposals (>30 days pending)", self.overdue_proposals),
            ("Unresolved Contradictions (>60 days)", self.overdue_contradictions),
            ("Orphan Pages (no inbound links)", self.orphan_pages),
            ("Missing Pages (INDEX.md without file)", self.missing_pages),
        ]
        for title, items in sections:
            if items:
                lines.append(f"## {title} ({len(items)})\n")
                for item in items:
                    lines.append(f"- {item}")
                lines.append("")
        return "\n".join(lines)


# ── Core wiki engine ──────────────────────────────────────────────────────────

class ThreatWiki:
    """
    Core wiki engine for the Aiglos threat intelligence wiki.

    Compiles raw threat intelligence into structured, interlinked
    markdown pages — and synthesizes that intelligence into machine-
    readable rule proposals that feed the threat engine.

    The LLM maintains the wiki/ directory.
    Humans review proposals in wiki/proposals/.
    Developers implement approved proposals in threat_engine_v2.py.
    """

    # Current rule IDs — used to determine next proposal ID
    CURRENT_RULES = set(f"T{n:02d}" for n in range(1, 96))

    # Agent framework relevance keywords for routing intel
    FRAMEWORK_KEYWORDS = {
        "langchain": ["langchain", "lcel"],
        "langgraph": ["langgraph"],
        "crewai": ["crewai", "crew ai"],
        "openclaw": ["openclaw", "clawdbot", "moltbot"],
        "smolagents": ["smolagents", "smol-agents"],
        "autogen": ["autogen", "auto-gen"],
        "claude-code": ["claude code", "claw-code", "kairos"],
        "phantom": ["phantom", "ghostwright"],
        "ollama": ["ollama", "lm studio", "lmstudio"],
        "litellm": ["litellm", "lite-llm"],
    }

    # T-rule relevance keywords for routing intel to rule pages
    RULE_ROUTING = {
        "T01": ["exfil", "exfiltration", "data leak", "data exfiltration"],
        "T30": ["supply chain", "malicious package", "pypi", "npm", "pip install"],
        "T31": ["memory injection", "persistent memory", "memory poison"],
        "T54": ["vector database", "rag", "embedding", "retrieval"],
        "T62": ["credentials in logs", "secrets in logs", "log leak"],
        "T64": ["identity spoof", "agent impersonation"],
        "T79": ["persistent memory inject", "adversarial write", "memory backend"],
        "T81": ["pth file", "site-packages", ".pth", "startup file"],
        "T82": ["self improvement", "self-modifying", "evolution pipeline"],
        "T85": ["identity suppression", "undercover", "attribution"],
        "T88": ["mcp auth", "authentication bypass", "tool auth"],
        "T90": ["dynamic tool", "tool registration", "runtime tool"],
        "T91": ["sycophancy", "sycophantic", "validation bypass", "llm judge"],
        "T92": ["security scanner", "trivy", "snyk", "scanner compromise"],
        "T93": ["credential in args", "plaintext credential", "api key in"],
        "T94": ["provider rejection", "api ban", "access revoked", "403"],
        "T95": ["cross trust", "trust boundary", "executor injection", "local model"],
    }

    def __init__(
        self,
        wiki_dir:    str | Path,
        raw_dir:     str | Path,
        schema_path: str | Path,
        anthropic_client: Optional[Any] = None,
    ):
        self.wiki_dir    = Path(wiki_dir)
        self.raw_dir     = Path(raw_dir)
        self.schema_path = Path(schema_path)

        # Ensure directory structure
        for subdir in ["rules", "campaigns", "frameworks", "incidents",
                       "research", "contradictions", "proposals"]:
            (self.wiki_dir / subdir).mkdir(parents=True, exist_ok=True)

        self._client = anthropic_client
        self._schema: Optional[str] = None

    # ── Schema ──────────────────────────────────────────────────────────────

    def _load_schema(self) -> str:
        if self._schema is None and self.schema_path.exists():
            self._schema = self.schema_path.read_text()
        return self._schema or ""

    # ── INGEST ───────────────────────────────────────────────────────────────

    def ingest(self, raw_path: str | Path) -> IngestResult:
        """
        Ingest a raw intelligence file and synthesize into wiki pages.

        This is the core compilation step. A single source may touch
        3-15 pages: updating rules, creating/updating incidents,
        creating proposals, updating campaigns and frameworks.
        """
        start = time.time()
        raw_path = Path(raw_path)
        result = IngestResult(source_slug=raw_path.stem)

        if not raw_path.exists():
            result.errors.append(f"Raw file not found: {raw_path}")
            return result

        try:
            raw = json.loads(raw_path.read_text())
        except Exception as e:
            result.errors.append(f"JSON parse error: {e}")
            return result

        content = raw.get("content", "")
        title   = raw.get("title", "")
        source_type = raw.get("source_type", "unknown")
        combined = (title + " " + content).lower()

        # Route to relevant rule pages
        for rule_id, keywords in self.RULE_ROUTING.items():
            if any(kw in combined for kw in keywords):
                updated = self._update_rule_page(rule_id, raw, raw_path)
                if updated:
                    result.pages_updated.append(f"rules/{rule_id}.md")

        # Route to framework pages
        for framework, keywords in self.FRAMEWORK_KEYWORDS.items():
            if any(kw in combined for kw in keywords):
                updated = self._update_framework_page(framework, raw, raw_path)
                if updated:
                    result.pages_updated.append(f"frameworks/{framework}.md")

        # Create incident page for incident/breach sources
        if source_type in ("ghsa", "incident") or self._is_incident(combined):
            page_path = self._create_incident_page(raw, raw_path)
            if page_path:
                result.pages_created.append(page_path)

        # Check for coverage gaps and create proposals
        proposals = self._check_for_gaps(raw, combined, raw_path)
        for proposal in proposals:
            proposal_path = self._write_proposal(proposal)
            result.proposals_created.append(proposal_path)

        # Update INDEX and LOG
        self._update_index(result)
        self._append_log(
            f"ingest | {raw_path.stem} | "
            f"rules_touched: {len(result.pages_updated)} | "
            f"pages_created: {len(result.pages_created)} | "
            f"proposals: {len(result.proposals_created)}"
        )

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _update_rule_page(self, rule_id: str, raw: dict,
                          raw_path: Path) -> bool:
        """Update a rule page with new supporting evidence."""
        page = self.wiki_dir / "rules" / f"{rule_id}.md"

        if not page.exists():
            # Create stub page
            content = self._build_rule_stub(rule_id, raw, raw_path)
            page.write_text(content)
            return True

        # Append to existing page's evidence section
        existing = page.read_text()
        citation = f"- [{raw.get('title','')[:80]}]({raw.get('url','')}) ({raw_path.stem})"

        if raw_path.stem in existing:
            return False  # Already cited

        # Insert into citations section or append
        if "## Real-World Validation" in existing:
            existing = existing.replace(
                "## Real-World Validation",
                f"## Real-World Validation\n\n{citation}"
            )
        else:
            existing += f"\n\n## Additional Evidence\n\n{citation}\n"

        page.write_text(existing)
        return True

    def _build_rule_stub(self, rule_id: str, raw: dict, raw_path: Path) -> str:
        """Build a minimal rule page from raw source evidence."""
        name = self._guess_rule_name(rule_id)
        citation = f"[{raw.get('title','')[:80]}]({raw.get('url','')}) ({raw_path.stem})"
        return f"""---
type: rule
rule_id: {rule_id}
name: {name}
score: 0.00
critical: false
status: active
citations: [{raw_path.stem}]
related_rules: []
related_campaigns: []
last_updated: {datetime.now(timezone.utc).date()}
intel_sources: 1
---

# {rule_id}: {name}

## Summary

_Auto-generated from threat intel ingest. Requires human review._

## Detection Logic

_Pending synthesis._

## Real-World Validation

{citation}

## Related Rules

## Open Questions

- [ ] Score requires calibration against incident data
- [ ] Detection logic requires review and implementation
"""

    def _guess_rule_name(self, rule_id: str) -> str:
        """Return known rule name or placeholder."""
        known = {
            "T81": "PTH_FILE_INJECT",
            "T92": "SECURITY_SCANNER_COMPROMISE",
            "T93": "CREDENTIAL_IN_TOOL_ARGS",
            "T94": "PROVIDER_POLICY_REJECTION",
            "T95": "CROSS_TRUST_BOUNDARY_INJECT",
        }
        return known.get(rule_id, f"RULE_{rule_id}")

    def _update_framework_page(self, framework: str, raw: dict,
                                raw_path: Path) -> bool:
        """Update a framework attack surface page."""
        page = self.wiki_dir / "frameworks" / f"{framework}.md"
        citation = f"- [{raw.get('title','')[:80]}]({raw.get('url','')}) ({raw_path.stem})"

        if not page.exists():
            page.write_text(f"""---
type: framework
name: {framework}
version_tracked: "latest"
attack_surface_score: 0.00
rules_covering: []
gaps: []
last_updated: {datetime.now(timezone.utc).date()}
---

# Framework: {framework}

## Architecture Overview

_Auto-generated. Requires synthesis._

## Attack Surface Map

_Pending analysis._

## Rules Coverage

_Pending mapping._

## Recent Intelligence

{citation}
""")
            return True

        existing = page.read_text()
        if raw_path.stem in existing:
            return False

        existing += f"\n{citation}\n"
        page.write_text(existing)
        return True

    def _is_incident(self, combined: str) -> bool:
        """Heuristic: does this source document an actual incident?"""
        incident_signals = [
            "breach", "attack", "exploit", "incident", "compromise",
            "malicious", "backdoor", "trojan", "ransomware", "apt",
            "threat actor", "campaign", "intrusion", "zero-day",
        ]
        return sum(1 for s in incident_signals if s in combined) >= 2

    def _create_incident_page(self, raw: dict, raw_path: Path) -> Optional[str]:
        """Create an incident page for a breach or attack source."""
        slug = raw.get("slug", raw_path.stem)
        page = self.wiki_dir / "incidents" / f"{slug}.md"
        if page.exists():
            return None

        # Determine which rules this incident validates
        content = (raw.get("title", "") + " " + raw.get("content", "")).lower()
        validated_rules = []
        for rule_id, keywords in self.RULE_ROUTING.items():
            if any(kw in content for kw in keywords):
                validated_rules.append(rule_id)

        severity = raw.get("severity", "unknown")
        rules_str = ", ".join(validated_rules) if validated_rules else "none"

        page.write_text(f"""---
type: incident
slug: {slug}
date: {raw.get("published", datetime.now(timezone.utc).date())}
severity: {severity}
rules_validated: [{rules_str}]
campaigns_validated: []
rules_proposed: []
sources: [{raw_path.stem}]
---

# Incident: {raw.get("title", slug)[:120]}

## Summary

{raw.get("content", "")[:1000]}

**Source:** [{raw.get("url", "")}]({raw.get("url", "")})

## Rules Triggered

{chr(10).join(f"- [[{r}]]" for r in validated_rules) or "_None identified._"}

## Rules Proposed

_Pending gap analysis._

## Lessons Learned

_Pending synthesis._
""")
        return f"incidents/{slug}.md"

    # ── PROPOSE ──────────────────────────────────────────────────────────────

    def _check_for_gaps(self, raw: dict, combined: str,
                        raw_path: Path) -> list[RuleProposal]:
        """
        Identify coverage gaps in the T-rule taxonomy based on new intel.

        Returns proposal objects for any novel attack vectors not yet
        covered by T01-T95.
        """
        proposals = []

        # Gap checks — each represents a known class of novel attack vector
        # that may appear in new intel without existing rule coverage

        gap_checks = [
            self._check_model_weight_poison(combined, raw, raw_path),
            self._check_mcp_tool_schema_inject(combined, raw, raw_path),
            self._check_context_window_exfil(combined, raw, raw_path),
            self._check_agent_api_key_rotation(combined, raw, raw_path),
            self._check_local_model_backdoor(combined, raw, raw_path),
        ]

        for proposal in gap_checks:
            if proposal is not None:
                # Only create if not already proposed
                dest = self.wiki_dir / "proposals" / f"{proposal.slug}.md"
                if not dest.exists():
                    proposals.append(proposal)

        return proposals

    def _check_model_weight_poison(self, combined: str, raw: dict,
                                    raw_path: Path) -> Optional[RuleProposal]:
        """Gap: model weight or fine-tune dataset poisoning via agent."""
        signals = ["weight poison", "fine-tune poison", "training data inject",
                   "rlhf poison", "dataset poison", "model poison"]
        if sum(1 for s in signals if s in combined) < 1:
            return None

        return RuleProposal(
            slug=f"proposal-weight-poison-{raw_path.stem[:8]}",
            proposed_id="T96",
            name="MODEL_WEIGHT_POISON",
            score_estimate=0.92,
            critical_estimate=True,
            confidence=0.65,
            supporting_sources=1,
            detection_logic=(
                "Agent attempts to write to model weight files, fine-tuning "
                "datasets, RLHF preference databases, or training data "
                "directories. Fires when tool call targets known ML training "
                "paths: ~/.cache/huggingface/, /models/, *.safetensors, "
                "*.bin (model weights), or dataset registry files."
            ),
            proposed_match_pseudocode=(
                "def match_T96(name, args):\n"
                "    s = args_str(args).lower()\n"
                "    weight_paths = [\n"
                "        '.safetensors', '.bin', '.pt', '.ckpt',\n"
                "        'huggingface', '/models/', 'fine-tune',\n"
                "        'rlhf', 'preference_data', 'training_data'\n"
                "    ]\n"
                "    write_ops = ['write', 'save', 'dump', 'export', 'push']\n"
                "    return (any(p in s for p in weight_paths) and\n"
                "            any(op in name.lower() for op in write_ops))"
            ),
            extends_rule="T82",
            replaces_rule=None,
            related_rules=["T82", "T31", "T53"],
            citations=[f"{raw_path.parent.name}/{raw_path.name}"],
            proposed_date=datetime.now(timezone.utc).date().isoformat(),
        )

    def _check_mcp_tool_schema_inject(self, combined: str, raw: dict,
                                       raw_path: Path) -> Optional[RuleProposal]:
        """Gap: MCP tool schema injection at registration time."""
        signals = ["tool schema", "mcp schema", "tool definition inject",
                   "schema manipulation", "tool manifest poison"]
        if sum(1 for s in signals if s in combined) < 1:
            return None

        return RuleProposal(
            slug=f"proposal-mcp-schema-{raw_path.stem[:8]}",
            proposed_id="T97",
            name="MCP_TOOL_SCHEMA_INJECT",
            score_estimate=0.87,
            critical_estimate=True,
            confidence=0.60,
            supporting_sources=1,
            detection_logic=(
                "Adversarial content injected into MCP tool schema definitions "
                "at registration or discovery time — specifically in tool name, "
                "description, or parameter fields — that influences how the "
                "orchestrator invokes the tool. Distinct from T90 "
                "(DYNAMIC_TOOL_REGISTRATION) which fires on the registration "
                "event. T97 fires on schema content containing injection patterns."
            ),
            proposed_match_pseudocode=(
                "def match_T97(name, args):\n"
                "    if 'schema' not in name.lower() and 'register' not in name.lower():\n"
                "        return False\n"
                "    s = args_str(args).lower()\n"
                "    inject_patterns = [\n"
                "        'ignore previous', 'system:', '[system]',\n"
                "        'you are now', 'act as', 'override',\n"
                "    ]\n"
                "    return any(p in s for p in inject_patterns)"
            ),
            extends_rule="T90",
            replaces_rule=None,
            related_rules=["T90", "T88", "T49"],
            citations=[f"{raw_path.parent.name}/{raw_path.name}"],
            proposed_date=datetime.now(timezone.utc).date().isoformat(),
        )

    def _check_context_window_exfil(self, combined: str, raw: dict,
                                     raw_path: Path) -> Optional[RuleProposal]:
        """Gap: gradual context window exfil via benign-looking tool calls."""
        signals = ["context window", "context exfil", "token smuggling",
                   "prompt stuffing", "context manipulation"]
        if sum(1 for s in signals if s in combined) < 1:
            return None

        return RuleProposal(
            slug=f"proposal-ctx-exfil-{raw_path.stem[:8]}",
            proposed_id="T98",
            name="CONTEXT_WINDOW_EXFIL",
            score_estimate=0.83,
            critical_estimate=False,
            confidence=0.55,
            supporting_sources=1,
            detection_logic=(
                "Gradual exfiltration of context window content through a "
                "series of individually benign-looking tool calls. Attack "
                "pattern: agent makes repeated read operations on sensitive "
                "files, then constructs outbound calls whose arguments encode "
                "the content in structured format (base64, JSON chunks, "
                "URL parameters). Distinct from T01 (bulk exfil) — T98 fires "
                "on the pattern of small-chunk repeated reads followed by "
                "structured outbound calls."
            ),
            proposed_match_pseudocode=(
                "def match_T98(name, args):\n"
                "    # Requires session-level state tracking\n"
                "    # Fire when: N read calls in window W followed by\n"
                "    # outbound call with encoded content\n"
                "    s = args_str(args)\n"
                "    is_outbound = any(k in name.lower() for k in\n"
                "        ['http', 'post', 'send', 'webhook', 'request'])\n"
                "    has_encoding = any(p in s.lower() for p in\n"
                "        ['base64', 'encode', 'chunk', 'fragment'])\n"
                "    return is_outbound and has_encoding and len(s) > 500"
            ),
            extends_rule="T01",
            replaces_rule=None,
            related_rules=["T01", "T48", "T41"],
            citations=[f"{raw_path.parent.name}/{raw_path.name}"],
            proposed_date=datetime.now(timezone.utc).date().isoformat(),
        )

    def _check_agent_api_key_rotation(self, combined: str, raw: dict,
                                       raw_path: Path) -> Optional[RuleProposal]:
        """Gap: agent rotating its own API keys to evade revocation."""
        signals = ["api key rotation", "rotate credentials", "credential refresh",
                   "revoke token", "reissue", "key regeneration"]
        if sum(1 for s in signals if s in combined) < 1:
            return None

        return RuleProposal(
            slug=f"proposal-key-rotation-{raw_path.stem[:8]}",
            proposed_id="T99",
            name="CREDENTIAL_SELF_ROTATION",
            score_estimate=0.85,
            critical_estimate=True,
            confidence=0.55,
            supporting_sources=1,
            detection_logic=(
                "Agent calls credential management APIs to rotate, regenerate, "
                "or reissue its own API keys or access tokens — potentially to "
                "evade revocation by the operator. Fires when tool calls target "
                "credential management endpoints (key rotation, token refresh, "
                "secret regeneration) with arguments referencing the agent's "
                "own service account or API key ID."
            ),
            proposed_match_pseudocode=(
                "def match_T99(name, args):\n"
                "    n = name.lower()\n"
                "    s = args_str(args).lower()\n"
                "    rotation_ops = ['rotate', 'regenerate', 'reissue',\n"
                "                    'refresh_token', 'create_key', 'new_key']\n"
                "    credential_context = ['api_key', 'secret', 'token',\n"
                "                          'access_key', 'service_account']\n"
                "    return (any(op in n or op in s for op in rotation_ops) and\n"
                "            any(kw in s for kw in credential_context))"
            ),
            extends_rule=None,
            replaces_rule=None,
            related_rules=["T04", "T93", "T19"],
            citations=[f"{raw_path.parent.name}/{raw_path.name}"],
            proposed_date=datetime.now(timezone.utc).date().isoformat(),
        )

    def _check_local_model_backdoor(self, combined: str, raw: dict,
                                     raw_path: Path) -> Optional[RuleProposal]:
        """Gap: backdoored local model weights loaded via Ollama/LM Studio."""
        signals = ["backdoor model", "trojan model", "model backdoor",
                   "poisoned weights", "malicious model", "trojan weight"]
        if sum(1 for s in signals if s in combined) < 1:
            return None

        return RuleProposal(
            slug=f"proposal-model-backdoor-{raw_path.stem[:8]}",
            proposed_id="T100",
            name="LOCAL_MODEL_BACKDOOR",
            score_estimate=0.90,
            critical_estimate=True,
            confidence=0.60,
            supporting_sources=1,
            detection_logic=(
                "A local model loaded via Ollama or LM Studio contains "
                "backdoor triggers — specific input patterns that cause the "
                "model to behave adversarially. Distinct from T80 "
                "(UNCENSORED_MODEL_ROUTE) which catches abliterated/jailbroken "
                "models. T100 fires when behavioral monitoring detects "
                "systematic anomalous outputs correlated with specific input "
                "patterns, or when model metadata indicates known backdoored "
                "model family hashes."
            ),
            proposed_match_pseudocode=(
                "def match_T100(name, args):\n"
                "    s = args_str(args).lower()\n"
                "    # Known backdoor indicator keywords in model output\n"
                "    backdoor_signals = [\n"
                "        'activation phrase', 'trigger word',\n"
                "        'backdoor', 'trojan', 'sleeper'\n"
                "    ]\n"
                "    is_local = any(kw in name.lower() or kw in s for kw in\n"
                "        ['ollama', 'lmstudio', 'qwen', 'gemma', 'llama'])\n"
                "    return is_local and any(p in s for p in backdoor_signals)"
            ),
            extends_rule="T80",
            replaces_rule=None,
            related_rules=["T80", "T95", "T46"],
            citations=[f"{raw_path.parent.name}/{raw_path.name}"],
            proposed_date=datetime.now(timezone.utc).date().isoformat(),
        )

    def _write_proposal(self, proposal: RuleProposal) -> str:
        """Write a proposal to wiki/proposals/."""
        dest = self.wiki_dir / "proposals" / f"{proposal.slug}.md"
        dest.write_text(proposal.to_markdown())
        return f"proposals/{proposal.slug}.md"

    # ── LINT ─────────────────────────────────────────────────────────────────

    def lint(self) -> LintReport:
        """
        Health-check the wiki.
        Returns a LintReport with all issues surfaced for human review.
        Does not auto-fix — surfaces for review only.
        """
        report = LintReport(
            run_date=datetime.now(timezone.utc).isoformat()
        )

        # 1. Rules with no raw/ citation
        for rule_page in (self.wiki_dir / "rules").glob("*.md"):
            content = rule_page.read_text()
            if "raw/" not in content and "citations:" not in content:
                report.unvalidated_rules.append(rule_page.stem)

        # 2. Proposals pending > 30 days
        for proposal in (self.wiki_dir / "proposals").glob("*.md"):
            content = proposal.read_text()
            if "status: pending" in content:
                date_match = re.search(r"proposed_date:\s*(\d{4}-\d{2}-\d{2})",
                                       content)
                if date_match:
                    proposed = datetime.fromisoformat(date_match.group(1))
                    age = (datetime.now() - proposed).days
                    if age > 30:
                        report.overdue_proposals.append(proposal.stem)

        # 3. Contradiction pages unresolved > 60 days
        for contra in (self.wiki_dir / "contradictions").glob("*.md"):
            content = contra.read_text()
            if "status: unresolved" in content:
                date_match = re.search(r"opened:\s*(\d{4}-\d{2}-\d{2})", content)
                if date_match:
                    opened = datetime.fromisoformat(date_match.group(1))
                    age = (datetime.now() - opened).days
                    if age > 60:
                        report.overdue_contradictions.append(contra.stem)

        # 4. Framework pages > 90 days old
        for fw_page in (self.wiki_dir / "frameworks").glob("*.md"):
            content = fw_page.read_text()
            date_match = re.search(r"last_updated:\s*(\d{4}-\d{2}-\d{2})", content)
            if date_match:
                updated = datetime.fromisoformat(date_match.group(1))
                age = (datetime.now() - updated).days
                if age > 90:
                    report.stale_frameworks.append(fw_page.stem)

        # 5. INDEX.md vs actual files
        index = self.wiki_dir / "INDEX.md"
        if index.exists():
            index_content = index.read_text()
            for page in self.wiki_dir.rglob("*.md"):
                if page == index:
                    continue
                rel = page.relative_to(self.wiki_dir)
                if str(rel) not in index_content and page.stem not in index_content:
                    report.orphan_pages.append(str(rel))

        # Write lint report to log
        report_md = report.to_markdown()
        self._append_log(
            f"lint | issues: {report.total_issues} | "
            f"unvalidated_rules: {len(report.unvalidated_rules)} | "
            f"overdue_proposals: {len(report.overdue_proposals)}"
        )

        lint_dest = self.wiki_dir / f"lint-{datetime.now(timezone.utc).date()}.md"
        lint_dest.write_text(report_md)

        return report

    # ── EVOLVE ───────────────────────────────────────────────────────────────

    def evolve(
        self,
        new_items: Optional[list] = None,
        run_lint: bool = False,
    ) -> dict:
        """
        Run a full evolution cycle.

        1. Ingest all provided new raw items.
        2. Run lint if requested or if 7 days since last lint.
        3. Summarize in LOG.md.
        """
        start = time.time()
        results = {
            "ingested": 0,
            "pages_updated": 0,
            "proposals_created": 0,
            "lint_run": False,
            "errors": [],
        }

        if new_items:
            for item in new_items:
                # Write raw item to disk if needed
                if hasattr(item, "slug"):
                    source_type = getattr(item, "source_type", "unknown")
                    raw_dest = self.raw_dir / source_type / f"{item.slug}.json"
                    raw_dest.parent.mkdir(parents=True, exist_ok=True)
                    if not raw_dest.exists():
                        raw_dest.write_text(json.dumps(
                            item.to_dict() if hasattr(item, "to_dict")
                            else vars(item), indent=2
                        ))
                    ingest_result = self.ingest(raw_dest)
                else:
                    continue

                results["ingested"] += 1
                results["pages_updated"] += len(ingest_result.pages_updated)
                results["proposals_created"] += len(ingest_result.proposals_created)
                results["errors"].extend(ingest_result.errors)

        # Check if lint is due
        should_lint = run_lint
        if not should_lint:
            last_lint = self._last_lint_date()
            if last_lint is None or (datetime.now() - last_lint).days >= 7:
                should_lint = True

        if should_lint:
            self.lint()
            results["lint_run"] = True

        duration = time.time() - start
        self._append_log(
            f"evolve | ingested: {results['ingested']} | "
            f"pages_updated: {results['pages_updated']} | "
            f"proposals: {results['proposals_created']} | "
            f"duration: {duration:.1f}s"
        )

        return results

    # ── Utility ──────────────────────────────────────────────────────────────

    def get_proposals(self, status: Optional[str] = None) -> list[dict]:
        """Return all proposals, optionally filtered by status."""
        proposals = []
        for p in (self.wiki_dir / "proposals").glob("*.md"):
            content = p.read_text()
            # Extract frontmatter status
            status_match = re.search(r"status:\s*(\w+)", content)
            page_status = status_match.group(1) if status_match else "unknown"
            if status is None or page_status == status:
                proposals.append({
                    "slug": p.stem,
                    "status": page_status,
                    "path": str(p),
                    "content": content[:500],
                })
        return proposals

    def get_stats(self) -> dict:
        """Return wiki statistics."""
        return {
            "rules_pages":     len(list((self.wiki_dir / "rules").glob("*.md"))),
            "campaign_pages":  len(list((self.wiki_dir / "campaigns").glob("*.md"))),
            "framework_pages": len(list((self.wiki_dir / "frameworks").glob("*.md"))),
            "incident_pages":  len(list((self.wiki_dir / "incidents").glob("*.md"))),
            "proposals":       len(list((self.wiki_dir / "proposals").glob("*.md"))),
            "contradictions":  len(list((self.wiki_dir / "contradictions").glob("*.md"))),
            "raw_items":       len(list(self.raw_dir.rglob("*.json"))),
            "pending_proposals": len(self.get_proposals("pending")),
        }

    def _update_index(self, result: IngestResult) -> None:
        """Update INDEX.md with any new pages."""
        index = self.wiki_dir / "INDEX.md"
        if not index.exists():
            index.write_text("# Aiglos Threat Intelligence Wiki — Index\n\n"
                             "_Auto-maintained by wiki.py_\n\n")

        existing = index.read_text()
        new_entries = []

        for page_path in result.pages_created:
            if page_path not in existing:
                new_entries.append(f"- [[{page_path}]]")

        if new_entries:
            index.write_text(existing + "\n" + "\n".join(new_entries) + "\n")

    def _append_log(self, entry: str) -> None:
        """Append a timestamped entry to LOG.md."""
        log = self.wiki_dir / "LOG.md"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        line = f"## [{timestamp}] {entry}\n"
        with open(log, "a") as f:
            f.write(line)

    def _last_lint_date(self) -> Optional[datetime]:
        """Find the date of the most recent lint run from LOG.md."""
        log = self.wiki_dir / "LOG.md"
        if not log.exists():
            return None
        content = log.read_text()
        matches = re.findall(r"\[(\d{4}-\d{2}-\d{2})[^\]]*\] lint", content)
        if not matches:
            return None
        try:
            return datetime.fromisoformat(matches[-1])
        except ValueError:
            return None
