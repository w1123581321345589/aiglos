"""
aiglos/audit/report.py
========================
Human-readable audit report with letter grade.

Formats:
  summary   -- one-page executive summary with grade and top findings
  full      -- complete findings with remediation steps
  json      -- machine-readable for CI/CD and ClawKeeper integration
  briefing  -- morning briefing format (scheduled nightly audit output)
  clawkeeper -- merged format compatible with ClawKeeper audit JSON
"""


import json
import time
from pathlib import Path
from typing import Optional

from aiglos.audit.scanner import AuditResult, CheckResult

# ANSI colors -- auto-disabled on non-TTY
import sys
_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    if not _TTY:
        return text
    return f"\033[{code}m{text}\033[0m"

_RED    = lambda t: _c("91", t)
_ORANGE = lambda t: _c("33", t)
_YELLOW = lambda t: _c("93", t)
_GREEN  = lambda t: _c("92", t)
_CYAN   = lambda t: _c("96", t)
_BOLD   = lambda t: _c("1", t)
_DIM    = lambda t: _c("2", t)

_GRADE_COLORS = {
    "A": _GREEN,
    "B": lambda t: _c("92", t),
    "C": _YELLOW,
    "D": _ORANGE,
    "F": _RED,
}

_SEV_COLORS = {
    "CRITICAL": _RED,
    "FAIL":     _ORANGE,
    "WARN":     _YELLOW,
    "INFO":     _CYAN,
    "PASS":     _GREEN,
}


class AuditReporter:
    """Formats an AuditResult for display or export."""

    def __init__(self, result: AuditResult):
        self.result = result

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        r     = self.result
        grade = r.grade
        color = _GRADE_COLORS.get(grade, _DIM)

        lines = [
            "",
            f"  {_BOLD('Aiglos Security Audit')} -- v{r.aiglos_version}",
            f"  {'─' * 56}",
            f"  Grade: {color(_BOLD(grade))}  Score: {r.score}/100"
            + (f"  {'[deep scan]' if r.deep else ''}"),
            f"  Checks: {r.pass_count} passed, {r.warn_count} warned, "
            f"{r.fail_count} failed, {r.critical_count} critical",
            f"  Duration: {r.duration_ms:.0f}ms",
            "",
        ]

        findings = r.findings
        if not findings:
            lines.append(f"  {_GREEN('✓')} No issues found. Your deployment is clean.")
        else:
            lines.append(f"  {_BOLD('Top findings:')}")
            for f in findings[:8]:
                sev_color = _SEV_COLORS.get(f.severity, _DIM)
                lines.append(
                    f"  {sev_color(f.icon)} [{f.severity}] {f.name}"
                )
                if f.detail:
                    lines.append(f"      {_DIM(f.detail[:80])}")

        lines += ["", f"  Run {_CYAN('aiglos audit --deep')} for full findings.", ""]
        return "\n".join(lines)

    # ── Full report ───────────────────────────────────────────────────────────

    def full(self) -> str:
        r     = self.result
        grade = r.grade
        color = _GRADE_COLORS.get(grade, _DIM)

        lines = [
            "",
            f"  {_BOLD('Aiglos Security Audit')} v{r.aiglos_version}",
            f"  {'─' * 70}",
            f"  Grade: {color(_BOLD(grade))}  Score: {r.score}/100"
            + (f"  [deep scan]" if r.deep else ""),
            "",
        ]

        phases = {
            1: "Secrets & Credentials",
            2: "Agent Definition Integrity",
            3: "Runtime Configuration",
            4: "Aiglos Runtime Health",
            5: "Network & Host Exposure",
            0: "Deep Scan",
        }

        for phase_num, phase_name in sorted(phases.items()):
            phase_checks = [c for c in r.checks if c.phase == phase_num]
            if not phase_checks:
                continue

            lines += [
                f"  {_BOLD('Phase ' + str(phase_num or 'D') + ': ' + phase_name)}",
                "  " + "─" * 60,
            ]
            for check in phase_checks:
                sev_color = _SEV_COLORS.get(check.severity, _DIM)
                lines.append(
                    f"  {sev_color(check.icon)} [{check.severity:<8}] {check.name}"
                )
                if check.detail and check.severity not in ("PASS",):
                    lines.append(f"      {check.detail}")
                if check.remediation and check.severity not in ("PASS", "INFO"):
                    lines.append(f"      {_CYAN('→')} {check.remediation}")
                if check.evidence and check.severity in ("CRITICAL", "FAIL"):
                    lines.append(f"      {_DIM('Evidence: ' + check.evidence[:100])}")
            lines.append("")

        # Recommendations
        critical = [c for c in r.findings if c.severity == "CRITICAL"]
        fails    = [c for c in r.findings if c.severity == "FAIL"]

        if critical or fails:
            lines += [f"  {_BOLD('Immediate actions required:')}", ""]
            for i, c in enumerate(critical + fails, 1):
                lines.append(f"  {i}. {_BOLD(c.name)}")
                if c.remediation:
                    lines.append(f"     {c.remediation}")
            lines.append("")

        return "\n".join(lines)

    # ── Morning briefing ──────────────────────────────────────────────────────

    def briefing(self) -> str:
        """Morning briefing format for scheduled nightly audits."""
        import datetime
        r    = self.result
        date = datetime.datetime.fromtimestamp(r.scanned_at).strftime("%A %B %-d, %Y")
        grade = r.grade
        color = _GRADE_COLORS.get(grade, _DIM)

        lines = [
            "",
            f"  {_BOLD('Aiglos Security Briefing')} -- {date}",
            f"  {'─' * 56}",
            f"  Security grade:  {color(_BOLD(grade))}  ({r.score}/100)",
        ]

        prev = self._load_previous_grade()
        if prev and prev != grade:
            if ord(grade) > ord(prev):
                lines.append(f"  Grade change:    {_YELLOW(f'{prev} → {grade}')} (declined)")
            else:
                lines.append(f"  Grade change:    {_GREEN(f'{prev} → {grade}')} (improved)")

        lines += [""]

        findings = r.findings
        if not findings:
            lines.append(f"  {_GREEN('✓')} No issues found.")
        else:
            lines.append(f"  {_BOLD('Findings:')}")
            for f in findings[:6]:
                sev_color = _SEV_COLORS.get(f.severity, _DIM)
                lines.append(f"  {sev_color(f.icon)} {f.name}")

        lines += [
            "",
            f"  {_DIM('This report was generated automatically.')}",
            f"  {_DIM('Do not auto-fix. Review each finding manually.')}",
            f"  {_DIM('Run: aiglos audit --deep for full analysis.')}",
            "",
        ]
        return "\n".join(lines)

    # ── JSON export ───────────────────────────────────────────────────────────

    def to_json(self) -> str:
        r = self.result
        return json.dumps({
            "aiglos_version":  r.aiglos_version,
            "scanned_at":      r.scanned_at,
            "score":           r.score,
            "grade":           r.grade,
            "deep":            r.deep,
            "duration_ms":     r.duration_ms,
            "summary": {
                "pass":     r.pass_count,
                "warn":     r.warn_count,
                "fail":     r.fail_count,
                "critical": r.critical_count,
            },
            "checks": [
                {
                    "id":          c.check_id,
                    "phase":       c.phase,
                    "name":        c.name,
                    "severity":    c.severity,
                    "detail":      c.detail,
                    "remediation": c.remediation,
                    "evidence":    c.evidence,
                }
                for c in r.checks
            ],
            "findings": [
                {"name": c.name, "severity": c.severity, "remediation": c.remediation}
                for c in r.findings
            ],
        }, indent=2)

    # ── ClawKeeper-compatible JSON ────────────────────────────────────────────

    def to_clawkeeper_json(self, clawkeeper_audit: Optional[dict] = None) -> str:
        """
        Merged format that combines ClawKeeper host audit data with Aiglos
        runtime audit data. Pass the ClawKeeper audit JSON output directly.
        """
        r = self.result
        aiglos_section = {
            "source":   "aiglos",
            "version":  r.aiglos_version,
            "grade":    r.grade,
            "score":    r.score,
            "findings": [
                {"name": c.name, "severity": c.severity,
                 "phase": c.phase, "remediation": c.remediation}
                for c in r.findings
            ],
        }

        if clawkeeper_audit:
            merged = dict(clawkeeper_audit)
            merged["aiglos_runtime"] = aiglos_section
            merged["combined_grade"] = self._combined_grade(
                r.grade, clawkeeper_audit.get("grade", "C")
            )
        else:
            merged = {
                "combined_grade": r.grade,
                "aiglos_runtime": aiglos_section,
                "host_audit":     None,
                "note": (
                    "Pass ClawKeeper audit JSON via --clawkeeper flag for "
                    "combined host + runtime report."
                ),
            }

        return json.dumps(merged, indent=2)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, output_dir: Optional[Path] = None) -> Path:
        """Save report to disk. Returns saved path."""
        base = output_dir or (Path.home() / ".aiglos" / "reports")
        base.mkdir(parents=True, exist_ok=True)
        ts   = int(self.result.scanned_at)
        path = base / f"audit_{ts}.json"
        with open(path, "w") as f:
            f.write(self.to_json())
        # Also save current grade for trend tracking
        grade_path = base / "latest_grade.txt"
        with open(grade_path, "w") as f:
            f.write(self.result.grade)
        return path

    def _load_previous_grade(self) -> Optional[str]:
        try:
            path = Path.home() / ".aiglos" / "reports" / "latest_grade.txt"
            if path.exists():
                return path.read_text().strip()
        except Exception:
            pass
        return None

    def _combined_grade(self, aiglos_grade: str, clawkeeper_grade: str) -> str:
        """Return the worse of two letter grades."""
        return aiglos_grade if ord(aiglos_grade) > ord(clawkeeper_grade) \
               else clawkeeper_grade
