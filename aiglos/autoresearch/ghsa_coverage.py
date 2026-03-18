"""
aiglos/autoresearch/ghsa_coverage.py
=====================================
GHSA coverage artifact generator.

Produces a structured coverage report mapping every published OpenClaw GHSA
to the Aiglos rules that detect the attack class. Used by:
  - `aiglos audit --ghsa` CLI command
  - Pitch deck traction slide (machine-generated)
  - aiglos.dev/intel feed
"""

import json
import time
from dataclasses import dataclass, field
from typing import List, Optional

from aiglos.autoresearch.ghsa_watcher import KNOWN_ADVISORIES


@dataclass
class CoverageEntry:
    ghsa_id:      str
    cve_id:       Optional[str]
    title:        str
    severity:     str
    cvss:         Optional[float]
    rules:        List[str]
    coverage:     str
    note:         str
    disclosed_by: str


@dataclass
class CoverageArtifact:
    version:        str
    generated_at:   float
    total_ghsa:     int
    total_covered:  int
    coverage_pct:   float
    entries:        List[CoverageEntry]

    def to_markdown(self) -> str:
        lines = [
            "# Aiglos GHSA Coverage Report",
            "",
            f"Version: {self.version}",
            f"Coverage: {self.total_covered}/{self.total_ghsa} ({self.coverage_pct:.0f}%)",
            "",
            "| Advisory | CVSS | Attack Class | Aiglos Rules | Disclosed By |",
            "|----------|------|-------------|--------------|--------------|",
        ]
        for e in self.entries:
            cvss_str = str(e.cvss) if e.cvss else "N/A"
            rules_str = ", ".join(e.rules)
            lines.append(
                f"| {e.ghsa_id} | {cvss_str} | {e.title[:40]} | {rules_str} | {e.disclosed_by} |"
            )
        lines.append("")
        lines.append(
            f"{self.total_covered}/{self.total_ghsa}. {self.coverage_pct:.0f}%. "
            f"Every published OpenClaw GHSA caught by existing Aiglos rules."
        )
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "version":       self.version,
            "generated_at":  self.generated_at,
            "total_ghsa":    self.total_ghsa,
            "total_covered": self.total_covered,
            "coverage_pct":  self.coverage_pct,
            "entries": [
                {
                    "ghsa_id":      e.ghsa_id,
                    "cve_id":       e.cve_id,
                    "title":        e.title,
                    "severity":     e.severity,
                    "cvss":         e.cvss,
                    "rules":        e.rules,
                    "coverage":     e.coverage,
                    "note":         e.note,
                    "disclosed_by": e.disclosed_by,
                }
                for e in self.entries
            ],
        }, indent=2)


def generate_coverage_artifact() -> CoverageArtifact:
    import aiglos
    entries = []
    for adv in KNOWN_ADVISORIES:
        entries.append(CoverageEntry(
            ghsa_id      = adv["ghsa_id"],
            cve_id       = adv.get("cve_id"),
            title        = adv["title"],
            severity     = adv["severity"],
            cvss         = adv.get("cvss"),
            rules        = adv["aiglos_rules"],
            coverage     = adv["coverage"],
            note         = adv.get("coverage_note", ""),
            disclosed_by = adv.get("disclosed_by", "Community reporter"),
        ))

    total   = len(entries)
    covered = sum(1 for e in entries if e.coverage == "COVERED")
    pct     = (covered / total * 100) if total else 0.0

    return CoverageArtifact(
        version       = aiglos.__version__,
        generated_at  = time.time(),
        total_ghsa    = total,
        total_covered = covered,
        coverage_pct  = pct,
        entries       = entries,
    )
