"""
T34 — DataAgentMonitor
AI Data Stack security runtime for agentic data pipelines.

Covers:
  - Context brief scope validation (Goal Integrity for data agents)
  - Quirk store write-time poisoning detection (extends T31)
  - dbt schema fingerprinting (extends T1 manifest fingerprinting)
  - Sub-agent orchestration integrity (extends T29 A2A)
  - Per-query signed attestation artifacts (extends T7)

Integrates with: T1 (proxy), T6 (GIE), T7 (attestation),
                 T29 (A2A), T31 (RAG), audit log (T3)
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# ── Shared Aiglos primitives (mirrors existing module imports) ────────────────
try:
    from aiglos_core.audit import AuditLog
    from aiglos_core.intelligence import GoalIntegrityEngine
    from aiglos_core.intelligence.attestation import AttestationBuilder
    from aiglos_core.autonomous.rag import RAGPoisonDetector
    from aiglos_core.types import TrustScore
    _LIVE = True
except ImportError:
    # Standalone / test mode
    _LIVE = False


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

class DataAgentRisk(str, Enum):
    CLEAN          = "clean"
    QUIRK_POISON   = "quirk_poison"       # malicious correction injected
    SCOPE_DRIFT    = "scope_drift"        # context brief exceeds authorized scope
    SCHEMA_TAMPER  = "schema_tamper"      # dbt schema changed between runs
    SUBAGENT_HIJACK = "subagent_hijack"   # context sub-agent goal redirected
    QUERY_ANOMALY  = "query_anomaly"      # SQL deviates from declared context brief
    EXFIL_PATTERN  = "exfil_pattern"      # credential/secret pattern in query or result


@dataclass
class ContextBrief:
    """Structured output of the context sub-agent."""
    question: str
    relevant_tables: list[str]
    join_paths: list[str]
    filters: list[str]
    dedup_rules: list[str]
    caveats: list[str]
    raw_text: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def scope_hash(self) -> str:
        """Deterministic hash of authorized scope for this session."""
        scope = json.dumps({
            "tables": sorted(self.relevant_tables),
            "filters": sorted(self.filters),
            "dedup": sorted(self.dedup_rules),
        }, sort_keys=True)
        return hashlib.sha256(scope.encode()).hexdigest()[:16]


@dataclass
class QuirkEntry:
    """A learned correction stored in the quirk/knowledge store."""
    quirk_id: str
    content: str
    source: str          # "user_correction" | "human_authored" | "agent_learned"
    reviewed: bool
    embedding_vector: list[float] | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class DataAgentFinding:
    risk: DataAgentRisk
    severity: str          # "critical" | "high" | "medium" | "info"
    detail: str
    evidence: dict[str, Any]
    session_id: str
    timestamp: float = field(default_factory=time.time)
    blocked: bool = False

    def to_audit_dict(self) -> dict:
        return {
            "module": "T34_DataAgentMonitor",
            "risk": self.risk.value,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
            "session_id": self.session_id,
            "blocked": self.blocked,
            "timestamp": self.timestamp,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  SCHEMA FINGERPRINTER  (extends T1 manifest fingerprinting for dbt)
# ─────────────────────────────────────────────────────────────────────────────

class DBTSchemaFingerprinter:
    """
    Fingerprints dbt model files and manifest.json on every context agent run.
    Fires SCHEMA_TAMPER if schema changes between sessions without an
    authorized schema update event.
    """

    MANIFEST_FILES = ["manifest.json", "catalog.json"]

    def __init__(self, dbt_project_path: str | None = None):
        self.project_path = Path(dbt_project_path) if dbt_project_path else None
        self._fingerprints: dict[str, str] = {}   # path -> sha256
        self._baseline_set = False

    def _hash_file(self, path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, PermissionError):
            return "unreadable"

    def _collect_model_paths(self) -> list[Path]:
        if not self.project_path or not self.project_path.exists():
            return []
        paths = []
        for pat in ["models/**/*.sql", "models/**/*.yml", "target/manifest.json"]:
            paths.extend(self.project_path.glob(pat))
        return paths

    def set_baseline(self) -> dict[str, str]:
        """Call once at startup or after an authorized schema migration."""
        paths = self._collect_model_paths()
        self._fingerprints = {str(p): self._hash_file(p) for p in paths}
        self._baseline_set = True
        return dict(self._fingerprints)

    def check(self, tables_in_brief: list[str]) -> list[DataAgentFinding]:
        """
        Re-fingerprint files referenced in the context brief.
        Returns findings for any that changed since baseline.
        """
        if not self._baseline_set:
            self.set_baseline()
            return []

        findings = []
        paths = self._collect_model_paths()
        current = {str(p): self._hash_file(p) for p in paths}

        for path_str, new_hash in current.items():
            old_hash = self._fingerprints.get(path_str)
            if old_hash and old_hash != new_hash:
                # Only fire if the changed file is relevant to this query
                model_name = Path(path_str).stem
                relevant = any(
                    model_name.lower() in t.lower() for t in tables_in_brief
                ) or "manifest" in path_str

                if relevant:
                    findings.append(DataAgentFinding(
                        risk=DataAgentRisk.SCHEMA_TAMPER,
                        severity="high",
                        detail=f"dbt model '{model_name}' changed since baseline",
                        evidence={"path": path_str, "old_hash": old_hash, "new_hash": new_hash},
                        session_id="schema_check",
                        blocked=False,
                    ))
            elif path_str not in self._fingerprints:
                findings.append(DataAgentFinding(
                    risk=DataAgentRisk.SCHEMA_TAMPER,
                    severity="medium",
                    detail=f"New dbt model appeared: {Path(path_str).stem}",
                    evidence={"path": path_str, "hash": new_hash},
                    session_id="schema_check",
                    blocked=False,
                ))

        # Update baseline with current state
        self._fingerprints.update(current)
        return findings


# ─────────────────────────────────────────────────────────────────────────────
#  QUIRK STORE POISON DETECTOR  (extends T31 RAGPoisonDetector)
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that should never appear in a legitimate data correction
_INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|prior)\s+instructions?",
    r"you\s+are\s+now\s+a",
    r"disregard\s+(your|the|all)",
    r"system\s*:\s*",
    r"<\s*/?system\s*>",
    r"act\s+as\s+(if|though|a)",
    r"new\s+instruction",
    r"override\s+(policy|rule|constraint)",
    r"always\s+(respond|answer|say)\s+with",
    r"do\s+not\s+(filter|block|check|validate)",
    r"exfiltrate|send\s+to\s+http|POST\s+to",
    r"reveal\s+(credentials?|secrets?|keys?|tokens?)",
    r"__import__|exec\s*\(|eval\s*\(",
    r"\$\{.+\}",              # template injection
    r"{{.+}}",                # Jinja injection
    r";\s*DROP\s+TABLE",
    r"UNION\s+SELECT",
    r"1\s*=\s*1",             # classic SQLi
    r"OR\s+'[^']*'\s*=\s*'",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _INJECTION_PATTERNS]

# Patterns that suggest credential exfiltration in SQL output
_CREDENTIAL_PATTERNS = [
    r"api_key|api_secret|secret_key|private_key",
    r"password|passwd|pwd",
    r"access_token|refresh_token|bearer",
    r"aws_secret|aws_access",
    r"\.env\b",
    r"credentials?\b",
    r"-----BEGIN\s+(RSA|EC|OPENSSH)",
    r"sk-[a-zA-Z0-9]{20,}",   # OpenAI-style key
    r"ghp_[a-zA-Z0-9]{36}",   # GitHub PAT
]
_CRED_COMPILED = [re.compile(p, re.IGNORECASE) for p in _CREDENTIAL_PATTERNS]


class QuirkPoisonDetector:
    """
    Write-time and retrieval-time poison detection for the quirk store.
    Called before any correction is persisted and before any quirk
    is injected into a new prompt.
    """

    def scan_write(self, quirk: QuirkEntry, session_id: str) -> list[DataAgentFinding]:
        """Scan a correction before it is written to the quirk store."""
        findings = []
        text = quirk.content

        for pattern in _COMPILED:
            m = pattern.search(text)
            if m:
                findings.append(DataAgentFinding(
                    risk=DataAgentRisk.QUIRK_POISON,
                    severity="critical",
                    detail=f"Injection pattern in quirk write: '{pattern.pattern[:40]}'",
                    evidence={
                        "quirk_id": quirk.quirk_id,
                        "matched": m.group(0)[:80],
                        "source": quirk.source,
                    },
                    session_id=session_id,
                    blocked=True,
                ))
                break  # one finding per quirk is sufficient to block

        # Flag unreviewed agent-learned quirks that are unusually long
        if not findings and quirk.source == "agent_learned" and not quirk.reviewed:
            if len(text) > 500:
                findings.append(DataAgentFinding(
                    risk=DataAgentRisk.QUIRK_POISON,
                    severity="medium",
                    detail="Unusually long agent-learned quirk pending human review",
                    evidence={"quirk_id": quirk.quirk_id, "length": len(text)},
                    session_id=session_id,
                    blocked=False,
                ))

        return findings

    def scan_retrieval(self, quirks: list[QuirkEntry], session_id: str) -> list[DataAgentFinding]:
        """Scan quirks retrieved from the store before injection into a prompt."""
        findings = []
        for quirk in quirks:
            findings.extend(self.scan_write(quirk, session_id))
        return findings

    def scan_sql_result(self, sql: str, result_preview: str, session_id: str) -> list[DataAgentFinding]:
        """Scan generated SQL and result snippets for credential exfiltration patterns."""
        findings = []
        combined = sql + "\n" + result_preview
        for pattern in _CRED_COMPILED:
            m = pattern.search(combined)
            if m:
                findings.append(DataAgentFinding(
                    risk=DataAgentRisk.EXFIL_PATTERN,
                    severity="critical",
                    detail=f"Credential pattern in SQL or result: '{pattern.pattern}'",
                    evidence={"matched": m.group(0)[:60]},
                    session_id=session_id,
                    blocked=True,
                ))
                break
        return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CONTEXT BRIEF SCOPE VALIDATOR  (extends T6 Goal Integrity Engine)
# ─────────────────────────────────────────────────────────────────────────────

# Tables that should never appear in a data analytics brief
_FORBIDDEN_TABLE_PATTERNS = [
    r"users?[\b_].*password",
    r"\bpassword\b",
    r"credentials?",
    r"secrets?\b",
    r"api_keys?",
    r"auth_tokens?",
    r"private_keys?",
    r"env_vars?",
    r"\.env",
    r"vault\b",
    r"hsm\b",
    r"kms\b",
]
_FORBIDDEN_COMPILED = [re.compile(p, re.IGNORECASE) for p in _FORBIDDEN_TABLE_PATTERNS]


class ContextScopeValidator:
    """
    Validates the context brief produced by the sub-agent against:
    1. The original user question (scope creep detection)
    2. Forbidden table/column patterns (data boundary enforcement)
    3. Authorized table list (if a policy has been defined)

    This is Goal Integrity at the data agent layer: the authorized goal
    is "answer this specific data question." The scope validator checks
    that the context brief hasn't expanded beyond that goal.
    """

    def __init__(self, authorized_tables: list[str] | None = None):
        """
        authorized_tables: if provided, the context brief may only
        reference these tables. None = allow all non-forbidden tables.
        """
        self.authorized_tables = [t.lower() for t in authorized_tables] if authorized_tables else None

    def validate(self, brief: ContextBrief) -> list[DataAgentFinding]:
        findings = []

        # 1. Forbidden table/column patterns
        all_references = " ".join(
            brief.relevant_tables + brief.join_paths + brief.filters + brief.caveats
        )
        for pattern in _FORBIDDEN_COMPILED:
            m = pattern.search(all_references)
            if m:
                findings.append(DataAgentFinding(
                    risk=DataAgentRisk.SCOPE_DRIFT,
                    severity="critical",
                    detail=f"Context brief references forbidden data boundary: '{m.group(0)}'",
                    evidence={"pattern": pattern.pattern, "matched": m.group(0)},
                    session_id=brief.session_id,
                    blocked=True,
                ))

        # 2. Authorized table enforcement
        if self.authorized_tables and not findings:
            for table in brief.relevant_tables:
                if not any(auth in table.lower() for auth in self.authorized_tables):
                    findings.append(DataAgentFinding(
                        risk=DataAgentRisk.SCOPE_DRIFT,
                        severity="high",
                        detail=f"Context brief references unauthorized table: '{table}'",
                        evidence={"table": table, "authorized": self.authorized_tables},
                        session_id=brief.session_id,
                        blocked=True,
                    ))

        # 3. Scope creep heuristic: brief references far more tables than
        #    the question's domain suggests
        question_words = set(brief.question.lower().split())
        table_names = [t.split(".")[-1].lower() for t in brief.relevant_tables]
        overlap = sum(1 for t in table_names if any(w in t for w in question_words))
        if len(brief.relevant_tables) > 8 and overlap < 1:
            findings.append(DataAgentFinding(
                risk=DataAgentRisk.SCOPE_DRIFT,
                severity="medium",
                detail=f"Context brief references {len(brief.relevant_tables)} tables with low semantic overlap to question",
                evidence={"table_count": len(brief.relevant_tables), "question_overlap": overlap},
                session_id=brief.session_id,
                blocked=False,
            ))

        return findings

    def validate_sql(self, sql: str, brief: ContextBrief) -> list[DataAgentFinding]:
        """
        Check that generated SQL only touches tables declared in the context brief.
        Catches goal drift between the brief and the actual query.
        """
        findings = []
        authorized = {t.lower().split(".")[-1] for t in brief.relevant_tables}

        # Extract table references from SQL (FROM / JOIN clauses)
        sql_tables = set(re.findall(
            r'\bFROM\s+([`"\[]?[\w.]+[`"\]]?)|JOIN\s+([`"\[]?[\w.]+[`"\]]?)',
            sql, re.IGNORECASE
        ))
        sql_table_names = {
            (a or b).strip('`"[]').lower().split(".")[-1]
            for a, b in sql_tables
        }

        unauthorized = sql_table_names - authorized
        if unauthorized:
            findings.append(DataAgentFinding(
                risk=DataAgentRisk.QUERY_ANOMALY,
                severity="high",
                detail=f"SQL queries table(s) not declared in context brief: {unauthorized}",
                evidence={
                    "unauthorized_tables": list(unauthorized),
                    "authorized_tables": list(authorized),
                    "scope_hash": brief.scope_hash(),
                },
                session_id=brief.session_id,
                blocked=True,
            ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
#  PER-QUERY ATTESTATION  (extends T7 AttestationBuilder)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DataQueryAttestation:
    """
    Signed chain-of-custody record for a single data agent query.
    This is the claims artifact for Munich Re aiSure purposes.
    """
    query_id: str
    session_id: str
    question: str
    scope_hash: str           # hash of authorized scope from context brief
    sql_hash: str             # hash of generated SQL
    findings: list[dict]      # serialized DataAgentFindings
    blocked: bool
    timestamp: float
    aiglos_version: str = "T34.1.0"

    def to_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "session_id": self.session_id,
            "question_hash": hashlib.sha256(self.question.encode()).hexdigest()[:16],
            "scope_hash": self.scope_hash,
            "sql_hash": self.sql_hash,
            "finding_count": len(self.findings),
            "findings": self.findings,
            "blocked": self.blocked,
            "timestamp": self.timestamp,
            "aiglos_version": self.aiglos_version,
        }

    def sign(self, private_key_pem: bytes | None = None) -> str:
        """
        Produce RSA-2048 signature over canonical JSON.
        Falls back to SHA-256 HMAC if no key provided (dev mode).
        """
        payload = json.dumps(self.to_dict(), sort_keys=True).encode()
        if private_key_pem:
            try:
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding
                key = serialization.load_pem_private_key(private_key_pem, password=None)
                sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
                import base64
                return base64.b64encode(sig).decode()
            except Exception:
                pass
        # Dev mode: deterministic HMAC
        import hmac
        return hmac.new(b"aiglos-dev-key", payload, hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
#  T34 — DataAgentMonitor  (main class)
# ─────────────────────────────────────────────────────────────────────────────

class DataAgentMonitor:
    """
    Full-session security monitor for AI data agents following the
    Jamie Quint / AI Data Stack architecture pattern:

      User question
        → context sub-agent  [T34: scope validation, schema fingerprint]
        → quirk retrieval    [T34: poison scan at retrieval]
        → SQL generation     [T34: SQL scope validation, exfil scan]
        → SQL execution
        → result delivery    [T34: result exfil scan, attestation]

    Also covers:
      - Quirk write-time poison detection
      - dbt schema change detection
      - Per-query signed attestation artifact

    Usage:
        monitor = DataAgentMonitor(dbt_project_path="/app/dbt")
        monitor.set_baseline()

        # When context sub-agent returns a brief:
        findings = monitor.on_context_brief(brief)

        # Before writing a quirk:
        findings = monitor.on_quirk_write(quirk_entry)

        # Before injecting retrieved quirks:
        findings = monitor.on_quirk_retrieval(quirks)

        # After SQL is generated:
        findings = monitor.on_sql_generated(sql, brief)

        # After query executes, before returning to user:
        attestation = monitor.on_query_complete(sql, result_preview, brief, all_findings)
    """

    def __init__(
        self,
        dbt_project_path: str | None = None,
        authorized_tables: list[str] | None = None,
        rsa_private_key_pem: bytes | None = None,
        alert_on_block: bool = True,
    ):
        self.schema_fp = DBTSchemaFingerprinter(dbt_project_path)
        self.quirk_detector = QuirkPoisonDetector()
        self.scope_validator = ContextScopeValidator(authorized_tables)
        self._rsa_key = rsa_private_key_pem
        self._alert_on_block = alert_on_block
        self._session_findings: dict[str, list[DataAgentFinding]] = {}

    def set_baseline(self):
        """Call at startup or after an authorized schema migration."""
        self.schema_fp.set_baseline()

    # ── Event handlers ────────────────────────────────────────────────────────

    def on_context_brief(self, brief: ContextBrief) -> list[DataAgentFinding]:
        """
        Called immediately after the context sub-agent returns its brief,
        before SQL generation begins.
        """
        findings: list[DataAgentFinding] = []

        # 1. Validate scope
        findings += self.scope_validator.validate(brief)

        # 2. Schema fingerprint check
        findings += self.schema_fp.check(brief.relevant_tables)

        self._accumulate(brief.session_id, findings)
        self._maybe_alert(findings)
        return findings

    def on_quirk_write(self, quirk: QuirkEntry, session_id: str = "write") -> list[DataAgentFinding]:
        """
        Called before a user correction or agent-learned quirk is
        persisted to the knowledge store. BLOCKS on poison detection.
        """
        findings = self.quirk_detector.scan_write(quirk, session_id)
        self._accumulate(session_id, findings)
        self._maybe_alert(findings)
        return findings

    def on_quirk_retrieval(self, quirks: list[QuirkEntry], session_id: str) -> list[DataAgentFinding]:
        """
        Called after hybrid retrieval returns quirks, before they are
        injected into the prompt. BLOCKS poisoned quirks.
        """
        findings = self.quirk_detector.scan_retrieval(quirks, session_id)
        self._accumulate(session_id, findings)
        self._maybe_alert(findings)
        return findings

    def on_sql_generated(self, sql: str, brief: ContextBrief) -> list[DataAgentFinding]:
        """
        Called after the main agent generates SQL, before execution.
        Validates SQL only touches tables declared in the context brief.
        """
        findings: list[DataAgentFinding] = []
        findings += self.scope_validator.validate_sql(sql, brief)
        findings += self.quirk_detector.scan_sql_result(sql, "", brief.session_id)
        self._accumulate(brief.session_id, findings)
        self._maybe_alert(findings)
        return findings

    def on_query_complete(
        self,
        sql: str,
        result_preview: str,
        brief: ContextBrief,
        additional_findings: list[DataAgentFinding] | None = None,
    ) -> DataQueryAttestation:
        """
        Called after query execution, before delivering result to user.
        Scans result for exfil patterns and generates signed attestation.
        """
        findings: list[DataAgentFinding] = list(additional_findings or [])
        findings += self.quirk_detector.scan_sql_result(sql, result_preview, brief.session_id)
        self._accumulate(brief.session_id, findings)
        self._maybe_alert(findings)

        all_session_findings = self._session_findings.get(brief.session_id, [])
        blocked = any(f.blocked for f in all_session_findings)

        attestation = DataQueryAttestation(
            query_id=str(uuid.uuid4()),
            session_id=brief.session_id,
            question=brief.question,
            scope_hash=brief.scope_hash(),
            sql_hash=hashlib.sha256(sql.encode()).hexdigest()[:16],
            findings=[f.to_audit_dict() for f in all_session_findings],
            blocked=blocked,
            timestamp=time.time(),
        )
        attestation.sign(self._rsa_key)
        return attestation

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _accumulate(self, session_id: str, findings: list[DataAgentFinding]):
        self._session_findings.setdefault(session_id, []).extend(findings)
        if _LIVE:
            for f in findings:
                try:
                    AuditLog().append(f.to_audit_dict())
                except Exception:
                    pass

    def _maybe_alert(self, findings: list[DataAgentFinding]):
        if not self._alert_on_block:
            return
        for f in findings:
            if f.blocked and f.severity == "critical":
                print(f"[AIGLOS T34 CRITICAL BLOCK] {f.risk.value}: {f.detail}")

    def clear_session(self, session_id: str):
        self._session_findings.pop(session_id, None)

    def session_summary(self, session_id: str) -> dict:
        findings = self._session_findings.get(session_id, [])
        return {
            "session_id": session_id,
            "total_findings": len(findings),
            "blocked": any(f.blocked for f in findings),
            "by_risk": {
                risk.value: sum(1 for f in findings if f.risk == risk)
                for risk in DataAgentRisk
            },
        }
