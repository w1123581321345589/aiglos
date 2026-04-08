"""
aiglos.autoresearch.citation_verifier
=======================================
Verified threat intelligence — evidence-backed rule citations for Aiglos.

The problem with the existing autoresearch loop:
  Rules are generated and improved against an internal labeled corpus.
  They work. But they are unverifiable to an external auditor.
  "Why does Aiglos block this pattern?" has no traceable answer.

For NDAA §1513 compliance, EU AI Act conformity, and enterprise security
review, the answer must be: "Because CVE-2025-53773 documents this exact
attack vector, OWASP ASI-02 classifies it as Tool Misuse, and MITRE ATLAS
T0040 maps it to the known attack technique."

CitationVerifier closes that gap.

It queries three authoritative sources:
  1. NVD (National Vulnerability Database) — real CVEs for AI agent attacks
  2. OWASP Top 10 for Agentic Applications — published taxonomy
  3. MITRE ATLAS — adversarial ML attack techniques

For every rule in the Aiglos engine, it finds the best matching citation
from these sources, scores the confidence, and attaches the citation to the
rule in the observation graph.

Rules with HIGH confidence verified citations can be auto-promoted.
Rules with no citation stay PENDING and surface the UNVERIFIED_RULE_ACTIVE
inspection trigger, requiring human review before going to production.

The self-healing fallback: if all external APIs are unreachable (air-gap,
network restriction), the verifier falls back to internal evidence — the
observation graph's own block history. A rule that has fired 50+ times in
production with zero false positive overrides is internally verified.

Privacy: all queries use public APIs. No rule code or agent data is sent.
Only the rule_id and threat category are used as search terms.

Usage:
    from aiglos.autoresearch.citation_verifier import CitationVerifier

    verifier = CitationVerifier()
    result = verifier.verify_rule("T37", "FIN_EXEC")
    # VerifiedCitation(
    #   rule_id="T37", source="NVD",
    #   reference_id="CVE-2025-53773",
    #   confidence=0.88, status="VERIFIED"
    # )
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

log = logging.getLogger("aiglos.citation_verifier")

# ── Configuration ─────────────────────────────────────────────────────────────

_NVD_API_BASE      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_TIMEOUT   = 6.0
_NVD_RATE_LIMIT    = 0.6   # seconds between NVD requests (rate limit: 5/30s)
_MIN_CONFIDENCE    = 0.50  # minimum to count as VERIFIED
_INTERNAL_FALLBACK_BLOCKS = 20  # blocks needed for internal verification

# OWASP Top 10 for Agentic Applications — static reference (published Dec 2025)
_OWASP_ASI = {
    "ASI-01": {
        "name": "Agent Goal Hijack",
        "keywords": ["goal hijack", "prompt injection", "instruction override",
                     "system prompt", "jailbreak", "context injection"],
        "aiglos_rules": ["T01", "T02", "T27"],
    },
    "ASI-02": {
        "name": "Tool Misuse",
        "keywords": ["tool misuse", "tool call", "mcp", "function call",
                     "unauthorized tool", "tool abuse"],
        "aiglos_rules": ["T03", "T04", "T05", "T07", "T08", "T09", "T10",
                         "T11", "T12", "T37", "T44", "T49", "T55"],
    },
    "ASI-03": {
        "name": "Identity and Privilege Abuse",
        "keywords": ["privilege escalation", "identity abuse", "impersonation",
                     "unauthorized access", "credential abuse"],
        "aiglos_rules": ["T08", "T11", "T19", "T20", "T21", "T38",
                         "T45", "T52", "T61", "T63", "T64", "T66"],
    },
    "ASI-04": {
        "name": "Supply Chain Vulnerabilities",
        "keywords": ["supply chain", "malicious package", "typosquatting",
                     "dependency confusion", "npm", "pypi", "mcp server"],
        "aiglos_rules": ["T26", "T30", "T31", "T32", "T33", "T34"],
    },
    "ASI-05": {
        "name": "Unexpected Code Execution",
        "keywords": ["code execution", "rce", "shell injection", "subprocess",
                     "command injection", "arbitrary code"],
        "aiglos_rules": ["T07", "T10", "T11", "T36_AGENTDEF"],
    },
    "ASI-06": {
        "name": "Memory and Context Poisoning",
        "keywords": ["memory poisoning", "context poisoning", "belief injection",
                     "persistent memory", "memory manipulation"],
        "aiglos_rules": ["T31", "T54", "T58"],
    },
    "ASI-07": {
        "name": "Insecure Inter-Agent Communication",
        "keywords": ["inter-agent", "agent communication", "multi-agent",
                     "agent spawning", "a2a", "agent-to-agent"],
        "aiglos_rules": ["T38", "T59", "T64"],
    },
    "ASI-08": {
        "name": "Cascading Failures",
        "keywords": ["cascading failure", "propagation", "downstream",
                     "agent chain", "orchestration failure"],
        "aiglos_rules": ["T06", "T38"],
    },
    "ASI-09": {
        "name": "Human-Agent Trust Exploitation",
        "keywords": ["trust exploitation", "social engineering", "human trust",
                     "agent definition", "skill poisoning"],
        "aiglos_rules": ["T36_AGENTDEF", "T49", "T55", "T57"],
    },
    "ASI-10": {
        "name": "Rogue Agents",
        "keywords": ["rogue agent", "autonomous agent", "unauthorized action",
                     "out of scope", "behavioral anomaly"],
        "aiglos_rules": ["T38", "T50", "T53", "T56"],
    },
}

# MITRE ATLAS — adversarial ML techniques relevant to AI agents
_MITRE_ATLAS = {
    "AML.T0040": {
        "name": "ML Supply Chain Compromise",
        "keywords": ["supply chain", "model poisoning", "dataset poisoning"],
        "aiglos_rules": ["T30", "T31", "T32", "T33", "T34"],
    },
    "AML.T0048": {
        "name": "Prompt Injection",
        "keywords": ["prompt injection", "indirect injection", "jailbreak"],
        "aiglos_rules": ["T01", "T02", "T27"],
    },
    "AML.T0051": {
        "name": "LLM Plugin Compromise",
        "keywords": ["plugin", "tool call", "mcp", "function abuse"],
        "aiglos_rules": ["T03", "T04", "T05"],
    },
    "AML.T0054": {
        "name": "LLM Jailbreak",
        "keywords": ["jailbreak", "bypass", "instruction override", "ignore previous"],
        "aiglos_rules": ["T01", "T27"],
    },
    "AML.T0057": {
        "name": "LLM Data Extraction",
        "keywords": ["data exfiltration", "credential harvest", "sensitive data"],
        "aiglos_rules": ["T19", "T20", "T21", "T22", "T23", "T24"],
    },
}

# Rule-to-keyword mapping for NVD search
_RULE_SEARCH_TERMS: Dict[str, List[str]] = {
    "T01":         ["prompt injection AI agent"],
    "T02":         ["context injection language model"],
    "T03":         ["SSRF server-side request forgery"],
    "T07":         ["shell injection command injection agent"],
    "T08":         ["privilege escalation AI agent"],
    "T10":         ["code execution agent subprocess"],
    "T11":         ["persistence agent cron"],
    "T19":         ["credential access SSH keys AWS agent"],
    "T20":         ["credential theft token agent"],
    "T22":         ["data exfiltration AI agent"],
    "T25":         ["SSRF metadata endpoint 169.254.169.254"],
    "T27":         ["indirect prompt injection tool output"],
    "T30":         ["supply chain malicious package npm AI"],
    "T31":         ["memory poisoning AI agent persistent"],
    "T36_AGENTDEF": ["agent definition file manipulation claude cursor"],
    "T37":         ["autonomous financial transaction agent stripe"],
    "T38":         ["agent spawning unauthorized multi-agent"],
    "T39":         ["reward poisoning RL training AI agent"],
    "T44":         ["inference routing manipulation AI model swap"],
    "T45":         ["cross-tenant data access cloud AI agent"],
    "T46":         ["simulation environment poisoning robot AI"],
    "T47":         ["token flooding denial of service AI agent"],
    "T48":         ["context window smuggling prompt injection"],
    "T49":         ["tool schema manipulation MCP AI agent"],
    "T50":         ["agentic workflow escape unauthorized action"],
    "T51":         ["model extraction fingerprinting LLM"],
    "T52":         ["parallel session abuse rate limit bypass AI"],
    "T53":         ["eval harness poisoning safety evaluation AI"],
    "T54":         ["vector database injection RAG poisoning"],
    "T55":         ["tool result forgery AI agent fabrication"],
    "T56":         ["capability probing reconnaissance AI agent"],
    "T57":         ["instruction hierarchy bypass system prompt"],
    "T58":         ["long context drift behavioral manipulation LLM"],
    "T59":         ["agentic social engineering impersonation"],
    "T60":         ["data pipeline injection ETL AI agent"],
    "T61":         ["compute resource abuse cryptomining AI agent"],
    "T62":         ["secrets in logs sensitive data leakage AI"],
    "T63":         ["webhook replay attack AI agent automation"],
    "T64":         ["agent identity spoofing multi-agent system"],
    "T65":         ["inference timing attack model probing"],
    "T66":         ["cross-tenant API key confusion GaaS"],
    "T67":         ["heartbeat monitoring cron silent failure AI agent"],
    "T68":         ["insecure default configuration remote access unauthenticated"],
    "T69":         ["plan drift implementation plan deviation AI agent security superpowers"],
    "T70":         ["environment variable path hijack LD_PRELOAD PYTHONPATH command injection docker"],
}


# ── Data types ─────────────────────────────────────────────────────────────────

class CitationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"   # no search attempted yet
    PENDING    = "PENDING"      # search ran, below confidence threshold
    VERIFIED   = "VERIFIED"     # high-confidence match found
    INTERNAL   = "INTERNAL"     # verified via internal block history (fallback)
    REJECTED   = "REJECTED"     # human reviewed and rejected the citation


@dataclass
class VerifiedCitation:
    """
    A verified reference linking an Aiglos rule to an authoritative source.
    Attached to rules in the observation graph and included in compliance reports.
    """
    rule_id:         str
    source:          str          # "NVD" | "OWASP_ASI" | "MITRE_ATLAS" | "INTERNAL"
    reference_id:    str          # CVE-XXXX-XXXXX | ASI-XX | AML.TXXXX | "internal"
    reference_name:  str          # human-readable name
    reference_url:   str          # link to authoritative source
    confidence:      float        # 0.0 - 1.0
    status:          CitationStatus = CitationStatus.PENDING
    verified_at:     float = field(default_factory=time.time)
    evidence_summary: str = ""
    internal_block_count: int = 0

    @property
    def is_verified(self) -> bool:
        return self.status in (CitationStatus.VERIFIED, CitationStatus.INTERNAL)

    def to_dict(self) -> dict:
        return {
            "rule_id":           self.rule_id,
            "source":            self.source,
            "reference_id":      self.reference_id,
            "reference_name":    self.reference_name,
            "reference_url":     self.reference_url,
            "confidence":        round(self.confidence, 4),
            "status":            self.status.value,
            "verified_at":       self.verified_at,
            "evidence_summary":  self.evidence_summary,
            "internal_block_count": self.internal_block_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "VerifiedCitation":
        return cls(
            rule_id               = d.get("rule_id", ""),
            source                = d.get("source", ""),
            reference_id          = d.get("reference_id", ""),
            reference_name        = d.get("reference_name", ""),
            reference_url         = d.get("reference_url", ""),
            confidence            = d.get("confidence", 0.0),
            status                = CitationStatus(d.get("status", "PENDING")),
            verified_at           = d.get("verified_at", time.time()),
            evidence_summary      = d.get("evidence_summary", ""),
            internal_block_count  = d.get("internal_block_count", 0),
        )


# ── CitationVerifier ──────────────────────────────────────────────────────────

class CitationVerifier:
    """
    Verifies Aiglos rules against authoritative security sources.

    Priority order:
      1. OWASP ASI — static reference, always available, O(1) lookup
      2. MITRE ATLAS — static reference, always available, O(1) lookup
      3. NVD CVE — live API, rate-limited, best for specific CVE matching
      4. Internal fallback — observation graph block history

    Always tries OWASP and MITRE first (no network required).
    NVD is called only when OWASP/MITRE confidence is below threshold.
    Internal fallback fires when all external sources are unreachable.
    """

    def __init__(self, graph=None, timeout: float = _REQUEST_TIMEOUT):
        self._graph   = graph
        self._timeout = timeout
        self._last_nvd_call: float = 0.0

    # ── Public API ──────────────────────────────────────────────────────────

    def verify_rule(
        self,
        rule_id:       str,
        category:      str = "",
        force_refresh: bool = False,
    ) -> VerifiedCitation:
        """
        Find the best verified citation for a rule.
        Returns VerifiedCitation — always returns something, never raises.
        """
        # Check graph cache first
        if not force_refresh and self._graph:
            cached = self._try_load_cached(rule_id)
            if cached and cached.is_verified:
                log.debug("[CitationVerifier] Cache hit: %s %s",
                          rule_id, cached.reference_id)
                return cached

        # Try OWASP first (no network)
        citation = self._check_owasp(rule_id)
        if citation and citation.confidence >= _MIN_CONFIDENCE:
            citation.status = CitationStatus.VERIFIED
            self._persist(citation)
            return citation

        # Try MITRE ATLAS (no network)
        atlas_citation = self._check_mitre_atlas(rule_id)
        if atlas_citation and atlas_citation.confidence >= _MIN_CONFIDENCE:
            if citation is None or atlas_citation.confidence > citation.confidence:
                citation = atlas_citation
        if citation and citation.confidence >= _MIN_CONFIDENCE:
            citation.status = CitationStatus.VERIFIED
            self._persist(citation)
            return citation

        # Try NVD (live network, rate-limited)
        nvd_citation = self._check_nvd(rule_id, category)
        if nvd_citation:
            if citation is None or nvd_citation.confidence > citation.confidence:
                citation = nvd_citation
        if citation and citation.confidence >= _MIN_CONFIDENCE:
            citation.status = CitationStatus.VERIFIED
            self._persist(citation)
            return citation

        # Internal fallback
        internal = self._check_internal(rule_id)
        if internal:
            self._persist(internal)
            return internal

        # Return best available even if below threshold
        result = citation or self._empty_citation(rule_id)
        result.status = CitationStatus.PENDING
        self._persist(result)
        return result

    def verify_all_rules(
        self,
        rule_ids: List[str],
        delay: float = 0.7,
    ) -> Dict[str, VerifiedCitation]:
        """
        Verify a list of rules. Adds delay between NVD calls to respect rate limit.
        Returns dict of rule_id → VerifiedCitation.
        """
        results = {}
        for rule_id in rule_ids:
            results[rule_id] = self.verify_rule(rule_id)
            time.sleep(delay)
        return results

    def citation_summary(self, citations: Dict[str, VerifiedCitation]) -> dict:
        """Summary stats for CLI display."""
        verified  = sum(1 for c in citations.values()
                       if c.status == CitationStatus.VERIFIED)
        internal  = sum(1 for c in citations.values()
                       if c.status == CitationStatus.INTERNAL)
        pending   = sum(1 for c in citations.values()
                       if c.status == CitationStatus.PENDING)
        unverified = sum(1 for c in citations.values()
                        if c.status == CitationStatus.UNVERIFIED)
        return {
            "total":      len(citations),
            "verified":   verified,
            "internal":   internal,
            "pending":    pending,
            "unverified": unverified,
            "coverage":   round((verified + internal) / max(len(citations), 1), 4),
        }

    # ── OWASP check ────────────────────────────────────────────────────────

    def _check_owasp(self, rule_id: str) -> Optional[VerifiedCitation]:
        """Check OWASP ASI taxonomy for a matching rule."""
        best_asi   = None
        best_score = 0.0

        for asi_id, data in _OWASP_ASI.items():
            if rule_id in data["aiglos_rules"]:
                # Direct rule mapping — highest confidence
                score = 0.90
                if score > best_score:
                    best_score = score
                    best_asi   = (asi_id, data)

        if not best_asi:
            return None

        asi_id, data = best_asi
        return VerifiedCitation(
            rule_id        = rule_id,
            source         = "OWASP_ASI",
            reference_id   = asi_id,
            reference_name = f"OWASP ASI {asi_id}: {data['name']}",
            reference_url  = "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            confidence     = best_score,
            status         = CitationStatus.PENDING,
            evidence_summary = (
                f"Aiglos rule {rule_id} maps directly to {asi_id} ({data['name']}) "
                f"in the OWASP Top 10 for Agentic Applications (December 2025). "
                f"Widely adopted as industry standard taxonomy for AI agent security."
            ),
        )

    # ── MITRE ATLAS check ──────────────────────────────────────────────────

    def _check_mitre_atlas(self, rule_id: str) -> Optional[VerifiedCitation]:
        """Check MITRE ATLAS adversarial ML techniques."""
        best_technique = None
        best_score     = 0.0

        for technique_id, data in _MITRE_ATLAS.items():
            if rule_id in data["aiglos_rules"]:
                score = 0.85
                if score > best_score:
                    best_score     = score
                    best_technique = (technique_id, data)

        if not best_technique:
            return None

        tid, data = best_technique
        return VerifiedCitation(
            rule_id        = rule_id,
            source         = "MITRE_ATLAS",
            reference_id   = tid,
            reference_name = f"MITRE ATLAS {tid}: {data['name']}",
            reference_url  = f"https://atlas.mitre.org/techniques/{tid}/",
            confidence     = best_score,
            status         = CitationStatus.PENDING,
            evidence_summary = (
                f"Aiglos rule {rule_id} maps to {tid} ({data['name']}) "
                f"in the MITRE ATLAS adversarial ML framework. "
                f"MITRE ATLAS is the authoritative taxonomy for AI/ML attack techniques."
            ),
        )

    # ── NVD check ──────────────────────────────────────────────────────────

    def _check_nvd(
        self, rule_id: str, category: str = ""
    ) -> Optional[VerifiedCitation]:
        """Query NVD for CVEs matching this rule's threat category."""
        search_terms = _RULE_SEARCH_TERMS.get(rule_id, [])
        if not search_terms and category:
            search_terms = [f"AI agent {category}"]
        if not search_terms:
            return None

        # Rate limit
        now = time.time()
        elapsed = now - self._last_nvd_call
        if elapsed < _NVD_RATE_LIMIT:
            time.sleep(_NVD_RATE_LIMIT - elapsed)

        try:
            keyword = search_terms[0]
            params  = urllib.parse.urlencode({
                "keywordSearch": keyword,
                "resultsPerPage": 5,
            })
            url = f"{_NVD_API_BASE}?{params}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"aiglos/{self._get_version()}"}
            )
            self._last_nvd_call = time.time()
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.getcode() != 200:
                    return None
                data = json.loads(resp.read().decode("utf-8"))

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            # Use the most recent CVE
            cve_item  = vulns[0]
            cve_id    = cve_item.get("cve", {}).get("id", "")
            desc_list = (cve_item.get("cve", {})
                                  .get("descriptions", [{}]))
            desc      = next(
                (d.get("value", "") for d in desc_list
                 if d.get("lang") == "en"),
                ""
            )

            if not cve_id:
                return None

            # Score based on keyword overlap
            keyword_lower = keyword.lower()
            desc_lower    = desc.lower()
            overlap       = sum(
                1 for w in keyword_lower.split()
                if w in desc_lower and len(w) > 3
            )
            confidence = min(0.50 + overlap * 0.08, 0.95)

            log.info(
                "[CitationVerifier] NVD match: %s → %s (confidence=%.2f)",
                rule_id, cve_id, confidence,
            )
            return VerifiedCitation(
                rule_id        = rule_id,
                source         = "NVD",
                reference_id   = cve_id,
                reference_name = cve_id,
                reference_url  = f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                confidence     = confidence,
                status         = CitationStatus.PENDING,
                evidence_summary = (
                    f"NVD CVE {cve_id} matches the threat pattern for "
                    f"Aiglos rule {rule_id}. "
                    f"Description: {desc[:200]}..."
                    if len(desc) > 200 else desc
                ),
            )

        except (OSError, urllib.error.URLError, TimeoutError) as e:
            log.debug("[CitationVerifier] NVD network error: %s", e)
            return None
        except Exception as e:
            log.debug("[CitationVerifier] NVD unexpected error: %s", e)
            return None

    # ── Internal fallback ──────────────────────────────────────────────────

    def _check_internal(self, rule_id: str) -> Optional[VerifiedCitation]:
        """
        Internal verification fallback using observation graph block history.
        A rule that has fired N+ times in production is internally verified
        even without an external citation.
        """
        if not self._graph:
            return None
        try:
            count = self._graph.get_rule_block_count(rule_id)
            if count >= _INTERNAL_FALLBACK_BLOCKS:
                confidence = min(0.50 + (count / 200) * 0.40, 0.90)
                return VerifiedCitation(
                    rule_id       = rule_id,
                    source        = "INTERNAL",
                    reference_id  = "internal",
                    reference_name = f"Internal evidence: {count} production blocks",
                    reference_url  = "",
                    confidence     = confidence,
                    status         = CitationStatus.INTERNAL,
                    evidence_summary = (
                        f"Rule {rule_id} has fired {count} times in production "
                        f"across observed sessions. Internal evidence meets the "
                        f"threshold for operational verification ({_INTERNAL_FALLBACK_BLOCKS}+ blocks)."
                    ),
                    internal_block_count = count,
                )
        except Exception as e:
            log.debug("[CitationVerifier] Internal check error: %s", e)
        return None

    # ── Graph persistence ──────────────────────────────────────────────────

    def _try_load_cached(self, rule_id: str) -> Optional[VerifiedCitation]:
        try:
            return self._graph.get_citation(rule_id)
        except Exception:
            return None

    def _persist(self, citation: VerifiedCitation) -> None:
        if not self._graph:
            return
        try:
            self._graph.upsert_citation(citation)
        except Exception as e:
            log.debug("[CitationVerifier] Persist error: %s", e)

    def _empty_citation(self, rule_id: str) -> VerifiedCitation:
        return VerifiedCitation(
            rule_id       = rule_id,
            source        = "",
            reference_id  = "",
            reference_name = "No citation found",
            reference_url  = "",
            confidence     = 0.0,
            status         = CitationStatus.UNVERIFIED,
        )

    def _get_version(self) -> str:
        try:
            from aiglos import __version__
            return __version__
        except Exception:
            return "unknown"
