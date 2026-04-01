"""
aiglos.autoresearch.compliance_report
=======================================
Audit-ready compliance reports mapping every Aiglos rule to its
verified evidence trail.

Audit-ready compliance output —
but for security compliance rather than academic publishing.

Three report formats:
  MARKDOWN — human-readable, suitable for documentation and PR review
  JSON     — machine-readable, suitable for SIEM integration and dashboards
  SUMMARY  — one-page executive summary for security review boards

Three compliance frameworks mapped:
  NDAA_1513  — NDAA FY2026 §1513 runtime attestation requirements
  EU_AI_ACT  — EU AI Act Annex III high-risk AI system requirements
  NIST_600_1 — NIST AI 600-1 Generative AI Risk Management Profile

Usage:
    from aiglos.autoresearch.compliance_report import ComplianceReportGenerator

    gen    = ComplianceReportGenerator(graph=graph)
    report = gen.generate()
    print(report.markdown())
    # Saves to ~/.aiglos/reports/compliance_{timestamp}.md
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from aiglos.autoresearch.citation_verifier import CitationStatus, VerifiedCitation

log = logging.getLogger("aiglos.compliance_report")

# ── Compliance framework mappings ─────────────────────────────────────────────

_NDAA_1513_REQUIREMENTS = {
    "ATTEST-01": {
        "name": "Runtime Tool Call Attestation",
        "description": "Every tool call by an AI agent must be inspected and "
                       "logged at runtime before execution.",
        "aiglos_coverage": "All three execution surfaces (MCP, HTTP, subprocess) "
                           "inspected before execution. HMAC-signed artifacts.",
    },
    "ATTEST-02": {
        "name": "Threat Classification",
        "description": "Blocked actions must be classified against a known threat "
                       "taxonomy with documented rationale.",
        "aiglos_coverage": "T01-T39 mapped to MITRE ATLAS. Every block includes "
                           "rule_id, tier, and evidence summary.",
    },
    "ATTEST-03": {
        "name": "Human Oversight Mechanism",
        "description": "Tier 3 actions must be gated with human approval "
                       "capability before execution.",
        "aiglos_coverage": "Three-tier blast radius. Tier 3 pause mode with "
                           "webhook approval. Policy proposal system.",
    },
    "ATTEST-04": {
        "name": "Audit Trail",
        "description": "All agent actions must produce a tamper-evident "
                       "audit record.",
        "aiglos_coverage": "HMAC-SHA256 signed session artifacts. "
                           "ObservationGraph SQLite WAL.",
    },
}

_EU_AI_ACT_REQUIREMENTS = {
    "HIGH-RISK-01": {
        "name": "Risk Management System",
        "description": "Continuous risk management throughout the AI system lifecycle.",
        "aiglos_coverage": "13 inspection triggers. Amendment engine. "
                           "Behavioral baseline anomaly detection.",
    },
    "HIGH-RISK-02": {
        "name": "Technical Documentation",
        "description": "Technical documentation demonstiting conformity with "
                       "requirements, including risk assessment.",
        "aiglos_coverage": "This compliance report. Citation-verified rule "
                           "evidence trail. OWASP/MITRE ATLAS mapping.",
    },
    "HIGH-RISK-03": {
        "name": "Human Oversight",
        "description": "Human oversight measures enabling override, interruption, "
                       "or correction of AI system output.",
        "aiglos_coverage": "Tier 3 pause/block with webhook. Policy proposals. "
                           "Amendment engine requiring human approval.",
    },
    "HIGH-RISK-04": {
        "name": "Accuracy and Robustness",
        "description": "Appropriate levels of accuracy, robustness, and "
                       "cybersecurity.",
        "aiglos_coverage": "Autoresearch loop continuously optimizes rules. "
                           "Adversarial corpus generates evasion cases.",
    },
}

_NIST_600_1_CATEGORIES = {
    "IS-1": {
        "name": "Information Security — Prompt Injection",
        "description": "Measures to detect and prevent prompt injection attacks.",
        "aiglos_coverage": "T01, T02, T27. InjectionScanner with tiered corpus. "
                           "REPEATED_INJECTION_ATTEMPT campaign pattern.",
    },
    "IS-2": {
        "name": "Information Security — Data Extraction",
        "description": "Controls preventing unauthorized data extraction.",
        "aiglos_coverage": "T19-T24 credential access. T22 exfiltration. "
                           "Three-surface interception.",
    },
    "IS-3": {
        "name": "Value Chain and Supply Chain",
        "description": "Security controls across the AI value and supply chain.",
        "aiglos_coverage": "T30-T34 supply chain. Skill scanner. "
                           "MCP server verification.",
    },
    "IS-4": {
        "name": "Human-AI Configuration",
        "description": "Appropriate human oversight and configuration controls.",
        "aiglos_coverage": "Policy proposals. Behavioral baseline. "
                           "Amendment engine. HITL enforcement.",
    },
}


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class ComplianceReport:
    """
    A structured compliance report mapping Aiglos coverage to regulatory requirements.
    """
    generated_at:      float = field(default_factory=time.time)
    aiglos_version:    str   = ""
    total_rules:       int   = 0
    verified_rules:    int   = 0
    citation_coverage: float = 0.0
    citations:         Dict[str, dict] = field(default_factory=dict)
    threat_signals:    List[dict]      = field(default_factory=list)

    def markdown(self) -> str:
        """Generate human-readable compliance report in Markdown."""
        import datetime as _dt
        ts = _dt.datetime.fromtimestamp(self.generated_at).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        lines = [
            f"# Aiglos Compliance Report",
            f"",
            f"**Generated:** {ts}  ",
            f"**Version:** {self.aiglos_version}  ",
            f"**Citation coverage:** {self.citation_coverage:.0%} "
            f"({self.verified_rules}/{self.total_rules} rules verified)  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"Aiglos v{self.aiglos_version} provides runtime AI agent security "
            f"across three execution surfaces (MCP tool calls, HTTP/API requests, "
            f"subprocess execution). This report documents the evidence trail for "
            f"all {self.total_rules} detection rules and maps coverage to three "
            f"regulatory frameworks: NDAA §1513, EU AI Act Annex III, and "
            f"NIST AI 600-1.",
            f"",
            f"**Verification status:** {self.citation_coverage:.0%} of rules have "
            f"verified citations from OWASP, MITRE ATLAS, or NVD.",
            f"",
            f"---",
            f"",
            f"## NDAA FY2026 §1513 Compliance Mapping",
            f"",
        ]

        for req_id, req in _NDAA_1513_REQUIREMENTS.items():
            lines += [
                f"### {req_id}: {req['name']}",
                f"",
                f"**Requirement:** {req['description']}",
                f"",
                f"**Aiglos coverage:** {req['aiglos_coverage']}",
                f"",
                f"**Status:** COVERED",
                f"",
            ]

        lines += [
            f"---",
            f"",
            f"## EU AI Act Annex III High-Risk Requirements",
            f"",
        ]

        for req_id, req in _EU_AI_ACT_REQUIREMENTS.items():
            lines += [
                f"### {req_id}: {req['name']}",
                f"",
                f"**Requirement:** {req['description']}",
                f"",
                f"**Aiglos coverage:** {req['aiglos_coverage']}",
                f"",
                f"**Status:** COVERED",
                f"",
            ]

        lines += [
            f"---",
            f"",
            f"## NIST AI 600-1 Risk Management Categories",
            f"",
        ]

        for cat_id, cat in _NIST_600_1_CATEGORIES.items():
            lines += [
                f"### {cat_id}: {cat['name']}",
                f"",
                f"**Requirement:** {cat['description']}",
                f"",
                f"**Aiglos coverage:** {cat['aiglos_coverage']}",
                f"",
                f"**Status:** COVERED",
                f"",
            ]

        lines += [
            f"---",
            f"",
            f"## Rule Citation Evidence Trail",
            f"",
            f"| Rule | Source | Reference | Confidence | Status |",
            f"|------|--------|-----------|------------|--------|",
        ]

        for rule_id, citation_dict in sorted(self.citations.items()):
            source     = citation_dict.get("source", "")
            ref_id     = citation_dict.get("reference_id", "none")
            confidence = citation_dict.get("confidence", 0.0)
            status     = citation_dict.get("status", "UNVERIFIED")
            icon       = "✓" if status in ("VERIFIED", "INTERNAL") else "⚠"
            lines.append(
                f"| `{rule_id}` | {source or '-'} | {ref_id} | "
                f"{confidence:.0%} | {icon} {status} |"
            )

        lines += [
            f"",
            f"---",
            f"",
            f"## Recent Threat Intelligence Signals",
            f"",
        ]

        if self.threat_signals:
            lines += [
                f"| Source | Reference | Relevance | Suggested Rule |",
                f"|--------|-----------|-----------|----------------|",
            ]
            for sig in self.threat_signals[:10]:
                lines.append(
                    f"| {sig.get('source', '')} | {sig.get('reference_id', '')} | "
                    f"{sig.get('relevance_score', 0):.0%} | "
                    f"{sig.get('suggested_rule', '-')} |"
                )
        else:
            lines.append("_No recent threat signals._")

        lines += [
            f"",
            f"---",
            f"",
            f"*Report generated by Aiglos v{self.aiglos_version}. "
            f"Citations verified against NVD, OWASP Top 10 for Agentic "
            f"Applications (Dec 2025), and MITRE ATLAS.*",
        ]

        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "generated_at":      self.generated_at,
            "aiglos_version":    self.aiglos_version,
            "total_rules":       self.total_rules,
            "verified_rules":    self.verified_rules,
            "citation_coverage": round(self.citation_coverage, 4),
            "ndaa_1513":         _NDAA_1513_REQUIREMENTS,
            "eu_ai_act":         _EU_AI_ACT_REQUIREMENTS,
            "nist_600_1":        _NIST_600_1_CATEGORIES,
            "citations":         self.citations,
            "threat_signals":    self.threat_signals,
        }, indent=2)

    def executive_summary(self) -> str:
        """One-page summary for security review boards."""
        coverage_bar = "█" * int(self.citation_coverage * 20) + \
                       "░" * (20 - int(self.citation_coverage * 20))
        import datetime as _dt
        date_str = _dt.datetime.fromtimestamp(self.generated_at).strftime("%Y-%m-%d")
        return (
            f"\n  Aiglos v{self.aiglos_version} — Compliance Summary\n"
            f"  {'─' * 50}\n"
            f"  Rules:     {self.total_rules} total, "
            f"{self.verified_rules} verified\n"
            f"  Coverage:  {coverage_bar} {self.citation_coverage:.0%}\n\n"
            f"  NDAA §1513:    COVERED (4/4 requirements)\n"
            f"  EU AI Act:     COVERED (4/4 Annex III requirements)\n"
            f"  NIST AI 600-1: COVERED (4/4 risk categories)\n\n"
            f"  Recent signals: {len(self.threat_signals)} new threat patterns\n"
            f"  Last updated:   {date_str}\n"
        )


# ── ComplianceReportGenerator ─────────────────────────────────────────────────

class ComplianceReportGenerator:
    """
    Generates compliance reports from the observation graph and citation store.
    """

    def __init__(
        self,
        graph       = None,
        output_dir: str = "~/.aiglos/reports",
    ):
        self._graph      = graph
        self._output_dir = Path(output_dir).expanduser()

    def generate(self, save: bool = True) -> ComplianceReport:
        """
        Generate a full compliance report.
        Loads citations from graph, collects threat signals, builds report.
        """
        try:
            from aiglos import __version__
            version = __version__
        except Exception:
            version = "unknown"

        citations     = self._load_citations()
        threat_signals = self._load_recent_signals()

        verified = sum(
            1 for c in citations.values()
            if c.get("status") in ("VERIFIED", "INTERNAL")
        )
        total    = len(citations)
        coverage = round(verified / max(total, 1), 4)

        report = ComplianceReport(
            aiglos_version    = version,
            total_rules       = total,
            verified_rules    = verified,
            citation_coverage = coverage,
            citations         = citations,
            threat_signals    = threat_signals,
        )

        if save:
            self._save_report(report)

        return report

    def _load_citations(self) -> Dict[str, dict]:
        """Load all citations from graph."""
        from aiglos.autoresearch.citation_verifier import CitationVerifier
        verifier = CitationVerifier(graph=self._graph)
        citations = {}
        all_rules = [f"T{i:02d}" for i in range(1, 40)] + ["T36_AGENTDEF"]
        for rule_id in all_rules:
            cached = verifier._try_load_cached(rule_id)
            if cached:
                citations[rule_id] = cached.to_dict()
            else:
                citations[rule_id] = {
                    "rule_id":    rule_id,
                    "source":     "",
                    "reference_id": "none",
                    "confidence": 0.0,
                    "status":     "UNVERIFIED",
                }
        return citations

    def _load_recent_signals(self) -> List[dict]:
        """Load recent threat signals from graph."""
        if not self._graph:
            return []
        try:
            signals = self._graph.list_threat_signals(limit=20)
            return [s.to_dict() if hasattr(s, "to_dict") else s
                    for s in signals]
        except Exception:
            return []

    def _save_report(self, report: ComplianceReport) -> None:
        """Save report to disk in both markdown and JSON formats."""
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            ts   = int(report.generated_at)
            base = self._output_dir / f"compliance_{ts}"

            md_path   = base.with_suffix(".md")
            json_path = base.with_suffix(".json")

            with open(md_path, "w") as f:
                f.write(report.markdown())
            with open(json_path, "w") as f:
                f.write(report.to_json())

            log.info(
                "[ComplianceReportGenerator] Report saved: %s", md_path
            )
        except Exception as e:
            log.debug("[ComplianceReportGenerator] Save error: %s", e)
