"""
aiglos/cli/validate_prompt.py
================================
aiglos validate-prompt — analyze a prompt or skill file for quality issues.

Based on the "Input Layer" framework from Zack Shapiro's essay:
  - Good prompts close off alternative interpretations, not just describe the target
  - The prompt must encode context, constraints, judgment calls, and edge cases
  - Hard bans eliminate the space where the model could wander toward the generic
  - Process-encoding (how output gets created) beats output-description (what it looks like)
  - The "would this embarrass me" frame activates a deeper layer of care than checklists

This command analyzes soul.md, learnings.md, or any prompt file for:
  1. Ambiguous scope terms (words that leave room for interpretation)
  2. Missing context declarations (client, counterparty, constraints, priorities)
  3. Hard bans not present (the "close off alternatives" requirement)
  4. Process vs output description ratio (process-encoding is the moat)
  5. Verification gate missing (the "would this embarrass me" frame)
  6. Specificity score (2,000-word prompts outperform 3-sentence prompts)

USAGE
=====
    aiglos validate-prompt soul.md
    aiglos validate-prompt .aiglos/soul.md --verbose
    aiglos validate-prompt --stdin < my_prompt.md
    aiglos validate-prompt --all           # validate all .aiglos/ files

OUTPUT
======
    aiglos validate-prompt soul.md

    Quality score: 74/100  (Good)

    Strengths (4):
      ✓ Hard bans declared (fabricate_data, unverified_claims)
      ✓ Verification gate present ("would this embarrass me" pattern)
      ✓ Heartbeat read instruction present
      ✓ Role defined with specific context

    Issues (3):
      ⚠ Ambiguous scope: "relevant" (line 12) — specify what counts as relevant
      ⚠ Missing: client risk tolerance not declared
      ✗ No process steps — describes output shape but not how to create it
        Add: sequential decision steps, edge case handling, when to escalate

    Recommendations:
      → Add: "Before any task, assess [specific criteria] to determine [specific action]"
      → Replace "relevant" with a specific enumeration of what qualifies
      → Add at least one process step: "When [X], do [Y] before [Z]"
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


# ── Quality rubric ────────────────────────────────────────────────────────────

# Terms that leave interpretation room — each one is a gap in the prompt corridor
AMBIGUOUS_TERMS = [
    "relevant", "appropriate", "reasonable", "suitable", "good", "proper",
    "sufficient", "adequate", "important", "significant", "various", "several",
    "certain", "typical", "standard", "normal", "usual", "common",
    "as needed", "if necessary", "when appropriate", "best practices",
    "high quality", "comprehensive", "thorough", "detailed",
]

# Process-encoding signals — indicates the prompt encodes how, not just what
PROCESS_SIGNALS = [
    r"step \d+", r"first[,.]", r"then[,.]", r"after that", r"finally[,.]",
    r"when .{5,50}, do", r"if .{5,50}, then", r"before .{5,50}, check",
    r"decision tree", r"escalate when", r"flag if", r"sequence",
    r"in order[,:]", r"the process is", r"workflow", r"checklist",
]

# Output-only signals — describes what, not how (less valuable)
OUTPUT_ONLY_SIGNALS = [
    r"the output should", r"format[: ]", r"produce a", r"generate a",
    r"write a", r"create a", r"the result should", r"output format",
    r"response should", r"your answer should",
]

# Context declaration signals — the "2,000-word prompt" content
CONTEXT_SIGNALS = [
    "client", "counterparty", "risk tolerance", "priority", "constraint",
    "background", "history", "relationship", "budget", "timeline",
    "stakeholder", "objective", "goal", "requirement", "limitation",
    "negotiating", "posture", "dealbreaker", "acceptable", "off-limits",
]

# Hard ban signals
HARD_BAN_SIGNALS = [
    "never", "do not", "don't", "prohibited", "forbidden", "must not",
    "hard ban", "hardban", "always", "every time", "without exception",
    "no exceptions", "under no circumstances", "regardless of",
]

# Verification gate signals — the "would this embarrass me" pattern
VERIFICATION_GATE_SIGNALS = [
    "embarrass", "before delivering", "before sending", "review before",
    "check before", "verify before", "would you be comfortable",
    "final check", "quality gate", "self-review", "double-check",
    "read learnings", "learnings.md", "before any task",
]

# Security signals — Aiglos-specific
SECURITY_SIGNALS = [
    "aiglos", "hard_bans", "fabricate_data", "unverified_claims",
    "verify.*action", "confirm.*before", "credential", ".env",
]


@dataclass
class Finding:
    level:       str   # "strength" | "warning" | "error"
    category:    str
    message:     str
    line_number: Optional[int] = None
    suggestion:  Optional[str] = None


@dataclass
class ValidationResult:
    filepath:      str
    word_count:    int
    char_count:    int
    score:         int
    grade:         str
    strengths:     List[Finding] = field(default_factory=list)
    warnings:      List[Finding] = field(default_factory=list)
    errors:        List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    @property
    def all_findings(self) -> List[Finding]:
        return self.strengths + self.warnings + self.errors

    def to_dict(self) -> dict:
        return {
            "filepath":   self.filepath,
            "score":      self.score,
            "grade":      self.grade,
            "word_count": self.word_count,
            "strengths":  len(self.strengths),
            "warnings":   len(self.warnings),
            "errors":     len(self.errors),
        }


# ── Validator ─────────────────────────────────────────────────────────────────

def validate(content: str, filepath: str = "<stdin>") -> ValidationResult:
    """
    Analyze a prompt or skill file for quality issues.

    Returns a ValidationResult with score, grade, findings, and recommendations.
    """
    lines = content.splitlines()
    lower = content.lower()
    word_count = len(content.split())
    char_count = len(content)

    strengths: List[Finding] = []
    warnings:  List[Finding] = []
    errors:    List[Finding] = []
    recs:      List[str] = []

    score = 50  # Start at 50, adjust up/down

    # ── 1. Length / specificity ──────────────────────────────────────────────
    if word_count >= 1500:
        strengths.append(Finding("strength", "specificity",
            f"Excellent length ({word_count:,} words) — Shapiro benchmark is ~2,000 words for professional prompts"))
        score += 15
    elif word_count >= 800:
        strengths.append(Finding("strength", "specificity",
            f"Good length ({word_count:,} words) — consider expanding context section"))
        score += 8
    elif word_count >= 300:
        warnings.append(Finding("warning", "specificity",
            f"Prompt is {word_count} words — the 'genie needs complete wishes' principle "
            "suggests more context closes interpretation gaps",
            suggestion="Add client context, explicit constraints, and at least one process step"))
        score -= 5
    else:
        errors.append(Finding("error", "specificity",
            f"Only {word_count} words — very likely to produce generic output. "
            "The model will regress to the internet mean without specific instructions",
            suggestion="Expand to at least 300 words with context, constraints, and hard bans"))
        score -= 15

    # ── 2. Hard bans ─────────────────────────────────────────────────────────
    ban_count = sum(1 for sig in HARD_BAN_SIGNALS if sig in lower)
    aiglos_bans = "hard_ban" in lower or "fabricate_data" in lower

    if aiglos_bans:
        strengths.append(Finding("strength", "hard_bans",
            "Aiglos hard_bans declared — semantic constraint violations logged to artifact"))
        score += 10
    elif ban_count >= 4:
        strengths.append(Finding("strength", "hard_bans",
            f"Hard bans present ({ban_count} explicit prohibitions) — closes interpretation gaps"))
        score += 8
    elif ban_count >= 2:
        warnings.append(Finding("warning", "hard_bans",
            f"Only {ban_count} explicit prohibitions — Shapiro principle: describe what you want "
            "AND close off every other thing it might produce",
            suggestion="Add: hard_bans=[\"fabricate_data\", \"unverified_claims\"] or explicit 'Never...' rules"))
        score -= 3
    else:
        errors.append(Finding("error", "hard_bans",
            "No explicit prohibitions — the model can wander anywhere within your vague description. "
            "Every ambiguity gets resolved toward the generic (Reddit mean)",
            suggestion="Add at minimum: 'Never fabricate data. Never present unverified information as fact. "
                       "Always verify before acting.'"))
        score -= 10

    # ── 3. Process encoding vs output description ─────────────────────────────
    process_count = sum(
        1 for sig in PROCESS_SIGNALS
        if re.search(sig, lower)
    )
    output_count = sum(
        1 for sig in OUTPUT_ONLY_SIGNALS
        if re.search(sig, lower)
    )

    if process_count >= 3:
        strengths.append(Finding("strength", "process_encoding",
            f"Process-encoded ({process_count} sequential/conditional steps) — "
            "encodes how output gets created, not just what it looks like"))
        score += 12
    elif process_count >= 1:
        warnings.append(Finding("warning", "process_encoding",
            f"Partial process encoding ({process_count} steps) — "
            "Shapiro: 'the recipe isn't in the ingredients, it's in the procedure'",
            suggestion="Add: decision trees, sequencing logic, edge-case handling, "
                       "when to escalate vs proceed"))
        score += 3
    else:
        if output_count >= 2:
            errors.append(Finding("error", "process_encoding",
                f"Output-only description ({output_count} output format signals, 0 process steps) — "
                "describes what the output looks like but not how to create it. "
                "This is exactly the 'output layer' mistake Shapiro describes.",
                suggestion="Add process steps: 'When reviewing [X], first check [Y], then assess [Z]. "
                           "If [condition], escalate. Otherwise, proceed with [action].'"))
            score -= 12
        else:
            warnings.append(Finding("warning", "process_encoding",
                "No process steps detected — consider adding sequential decision logic",
                suggestion="Add at least: 'Before any task, read learnings.md. "
                           "First [step 1], then [step 2].'"))
            score -= 5

    # ── 4. Context declarations ───────────────────────────────────────────────
    context_count = sum(1 for sig in CONTEXT_SIGNALS if sig in lower)

    if context_count >= 5:
        strengths.append(Finding("strength", "context",
            f"Rich context ({context_count} context signals) — "
            "client, constraints, and priorities declared"))
        score += 10
    elif context_count >= 2:
        warnings.append(Finding("warning", "context",
            f"Partial context ({context_count} signals) — Shapiro briefing includes: "
            "client business model, risk tolerance, counterparty history, acceptable deviations",
            suggestion="Add: what your agent needs to know about this specific task/domain "
                       "that isn't in the base model's training data"))
        score += 2
    else:
        errors.append(Finding("error", "context",
            "No task-specific context — the model only has what's in its training data. "
            "Your specific constraints, priorities, and judgment calls are invisible to it.",
            suggestion="Declare at minimum: purpose, constraints, what 'done' looks like, "
                       "what 'failure' looks like"))
        score -= 8

    # ── 5. Verification gate ──────────────────────────────────────────────────
    has_verification = any(
        sig in lower for sig in VERIFICATION_GATE_SIGNALS
    )

    if has_verification:
        strengths.append(Finding("strength", "verification",
            "Verification gate present — 'would this embarrass me' frame "
            "activates a deeper layer of care than checklists"))
        score += 8
    else:
        warnings.append(Finding("warning", "verification",
            "No verification gate — Shapiro: adding 'would this embarrass me' "
            "activates conscience-level review beyond itemized checklists",
            suggestion="Add at end: 'Before delivering, consider: if I hand this to [client/user] "
                       "as-is, is there anything here that would embarrass me?'"))
        score -= 3

    # ── 6. Ambiguous terms ────────────────────────────────────────────────────
    ambiguous_found = []
    for i, line in enumerate(lines, 1):
        line_lower = line.lower()
        for term in AMBIGUOUS_TERMS:
            if term in line_lower:
                ambiguous_found.append((term, i, line.strip()[:60]))

    if not ambiguous_found:
        strengths.append(Finding("strength", "precision",
            "No ambiguous scope terms detected — prompt builds a clear corridor"))
        score += 5
    elif len(ambiguous_found) <= 3:
        for term, lineno, ctx in ambiguous_found[:3]:
            warnings.append(Finding("warning", "precision",
                f"Ambiguous term: \"{term}\" (line {lineno}): {ctx}...",
                line_number=lineno,
                suggestion=f"Replace \"{term}\" with a specific enumeration or criterion"))
        score -= len(ambiguous_found) * 2
    else:
        errors.append(Finding("error", "precision",
            f"{len(ambiguous_found)} ambiguous scope terms found — "
            "each one is a gap where the model can interpret toward generic output"))
        for term, lineno, ctx in ambiguous_found[:5]:
            warnings.append(Finding("warning", "precision",
                f"\"{term}\" (line {lineno}): {ctx}...",
                line_number=lineno))
        score -= min(len(ambiguous_found) * 3, 20)
        recs.append("Audit each ambiguous term and replace with specific criteria or examples")

    # ── 7. Security integration ───────────────────────────────────────────────
    security_count = sum(1 for sig in SECURITY_SIGNALS if sig in lower)

    if security_count >= 3:
        strengths.append(Finding("strength", "security",
            "Aiglos security integration present — hard_bans and verification active"))
        score += 5
    elif security_count >= 1:
        warnings.append(Finding("warning", "security",
            "Partial security integration — consider adding Aiglos hard_bans",
            suggestion="Add to hard_bans: [\"fabricate_data\", \"skip_verification_steps\", "
                       "\"unauthorized_actions\"]"))
    else:
        recs.append(
            "Consider adding Aiglos hard_bans to make semantic constraints machine-enforceable: "
            "hard_bans=[\"fabricate_data\", \"unverified_claims\"]"
        )

    # ── 8. Role / identity definition ────────────────────────────────────────
    has_identity = any(kw in lower for kw in (
        "you are", "your role", "you act as", "identity", "you are a",
        "agent name", "soul", "purpose"
    ))
    if has_identity:
        strengths.append(Finding("strength", "identity",
            "Role/identity defined — pins the model to a specific operating context"))
        score += 5
    else:
        warnings.append(Finding("warning", "identity",
            "No role/identity declaration — the model has no operating context",
            suggestion="Add: 'You are [name]. [Description]. Your primary purpose is [X].'"))
        score -= 3

    # ── Build recommendations ─────────────────────────────────────────────────
    if len(errors) > 0:
        recs.insert(0,
            "Priority: address errors before warnings — errors represent gaps "
            "where the model can produce arbitrary output"
        )

    if word_count < 500 and not recs:
        recs.append(
            "Expand with context specific to your use case — the model's training "
            "data has the generic knowledge, your prompt needs the specific judgment"
        )

    if process_count == 0 and word_count > 200:
        recs.append(
            "Add process encoding: 'Step 1: [action]. Step 2: [action]. "
            "When [X], do [Y]. If [condition], escalate.' "
            "This is the moat that can't be reverse-engineered from outputs."
        )

    # ── Final score / grade ───────────────────────────────────────────────────
    score = max(0, min(100, score))

    if score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return ValidationResult(
        filepath     = filepath,
        word_count   = word_count,
        char_count   = char_count,
        score        = score,
        grade        = grade,
        strengths    = strengths,
        warnings     = warnings,
        errors       = errors,
        recommendations = recs,
    )


# ── Output formatting ─────────────────────────────────────────────────────────

def print_report(result: ValidationResult, verbose: bool = False) -> None:
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    RED    = "\033[31m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    grade_color = {
        "A": GREEN, "B": GREEN, "C": YELLOW, "D": YELLOW, "F": RED
    }.get(result.grade, YELLOW)

    print()
    print(f"  {BOLD}aiglos validate-prompt{RESET}  —  {result.filepath}")
    print(f"  {DIM}{'─' * 54}{RESET}")
    print()
    print(f"  Quality score: {grade_color}{BOLD}{result.score}/100  ({result.grade}){RESET}")
    print(f"  Words: {result.word_count:,}  |  "
          f"Strengths: {GREEN}{len(result.strengths)}{RESET}  |  "
          f"Warnings: {YELLOW}{len(result.warnings)}{RESET}  |  "
          f"Errors: {RED}{len(result.errors)}{RESET}")
    print()

    if result.strengths:
        print(f"  {GREEN}{BOLD}Strengths ({len(result.strengths)}):{RESET}")
        for f in result.strengths:
            print(f"    {GREEN}✓{RESET}  {f.message}")
        print()

    if result.errors:
        print(f"  {RED}{BOLD}Errors ({len(result.errors)}):{RESET}")
        for f in result.errors:
            print(f"    {RED}✗{RESET}  {f.message}")
            if f.suggestion and verbose:
                print(f"       {DIM}→ {f.suggestion}{RESET}")
        print()

    if result.warnings:
        print(f"  {YELLOW}{BOLD}Warnings ({len(result.warnings)}):{RESET}")
        for f in result.warnings:
            print(f"    {YELLOW}⚠{RESET}  {f.message}")
            if f.suggestion and verbose:
                print(f"       {DIM}→ {f.suggestion}{RESET}")
        print()

    if result.recommendations:
        print(f"  {BOLD}Recommendations:{RESET}")
        for rec in result.recommendations:
            print(f"    →  {rec}")
        print()

    # Shapiro benchmark comparison
    if result.word_count < 2000:
        gap = 2000 - result.word_count
        print(f"  {DIM}Shapiro benchmark: ~2,000 words. You're {gap:,} words short of that target.{RESET}")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────

def run(
    filepath:   Optional[str] = None,
    verbose:    bool = False,
    stdin:      bool = False,
    validate_all: bool = False,
    json_output:  bool = False,
) -> List[ValidationResult]:
    """
    Run prompt validation. Returns list of ValidationResults.
    """
    results = []

    if validate_all:
        aiglos_dir = Path(".aiglos")
        if aiglos_dir.exists():
            for md_file in aiglos_dir.glob("*.md"):
                content = md_file.read_text()
                result = validate(content, str(md_file))
                results.append(result)
        if not results:
            print("  No .aiglos/*.md files found. Run: aiglos launch")
            return results

    elif stdin or filepath == "-":
        content = sys.stdin.read()
        result = validate(content, "<stdin>")
        results.append(result)

    elif filepath:
        path = Path(filepath)
        if not path.exists():
            print(f"  File not found: {filepath}")
            return results
        content = path.read_text()
        result = validate(content, filepath)
        results.append(result)

    else:
        # Default: validate all .aiglos files if they exist
        for default_file in [".aiglos/soul.md", "soul.md"]:
            p = Path(default_file)
            if p.exists():
                content = p.read_text()
                result = validate(content, default_file)
                results.append(result)
                break
        if not results:
            print("  Usage: aiglos validate-prompt <file.md>")
            print("         aiglos validate-prompt --all")
            return results

    import json
    for result in results:
        if json_output:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print_report(result, verbose=verbose)

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="aiglos validate-prompt — analyze prompt/skill files for quality"
    )
    parser.add_argument("filepath", nargs="?", help="Prompt or skill file to validate")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show suggestions")
    parser.add_argument("--all",     action="store_true", dest="validate_all",
                        help="Validate all .aiglos/*.md files")
    parser.add_argument("--stdin",   action="store_true", help="Read from stdin")
    parser.add_argument("--json",    action="store_true", dest="json_output")
    args = parser.parse_args()

    results = run(
        filepath     = args.filepath,
        verbose      = args.verbose,
        validate_all = args.validate_all,
        stdin        = args.stdin,
        json_output  = args.json_output,
    )
    # Exit non-zero if any file has grade D or F
    sys.exit(1 if any(r.grade in ("D", "F") for r in results) else 0)
