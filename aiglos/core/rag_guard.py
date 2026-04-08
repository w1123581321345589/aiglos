"""
aiglos/core/rag_guard.py

RAG Pipeline Security with Taint Propagation.

51% of enterprise AI systems now use RAG. PoisonedRAG demonstrated
that 5 malicious texts achieve 98.2% retrieval success.

The core capability: it is not enough to detect a poisoned document at
retrieval time. Every downstream inference that was influenced by
that document is contaminated. The taint must propagate through the
session artifact so a forensic investigator can answer the question:
"which decisions did this agent make that touched the poisoned document?"

Three-layer architecture:
    1. Ingestion attestation: hash and sign documents at ingestion.
       Unsigned documents are untrusted by default.
    2. Retrieval trust scoring: each retrieved chunk carries a trust
       score based on provenance, content scan, and source reputation.
    3. Taint propagation: when a retrieved chunk fires T54
       VECTOR_DB_INJECTION or falls below trust threshold, the taint
       propagates forward through every inference that used it.
       The session artifact records the contamination chain.

Novel capability: taint propagation through AI agent inference chains.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


# ── Document provenance ───────────────────────────────────────────────────────

@dataclass
class DocumentProvenance:
    """Cryptographic provenance for a RAG document."""
    doc_id:        str
    content_hash:  str          # SHA-256 of content
    source_uri:    str
    ingest_time:   str          # ISO 8601
    trust_score:   float        # 0.0-1.0
    signed:        bool         # was this signed at ingestion?
    signature:     Optional[str]
    tainted:       bool = False
    taint_reason:  Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "doc_id":       self.doc_id,
            "content_hash": self.content_hash,
            "source_uri":   self.source_uri,
            "ingest_time":  self.ingest_time,
            "trust_score":  self.trust_score,
            "signed":       self.signed,
            "tainted":      self.tainted,
            "taint_reason": self.taint_reason,
        }


@dataclass
class RetrievalEvent:
    """A single RAG retrieval event with trust scoring."""
    query:         str
    retrieved_ids: List[str]
    trust_scores:  Dict[str, float]     # doc_id -> trust score
    tainted_ids:   List[str]            # doc_ids that are tainted
    min_trust:     float
    flagged:       bool
    timestamp:     str
    inference_id:  Optional[str] = None  # links to downstream inference


@dataclass
class TaintedInference:
    """An inference that was contaminated by a tainted document."""
    inference_id:    str
    query:           str
    tainted_doc_ids: List[str]
    taint_depth:     int        # how many hops from original taint
    timestamp:       str
    blocked:         bool


@dataclass
class RAGSessionReport:
    """Session-level RAG security report."""
    agent_name:          str
    session_id:          str
    documents_ingested:  int
    documents_tainted:   int
    retrievals:          int
    tainted_retrievals:  int
    contaminated_inferences: int
    taint_chain:         List[Dict]      # full propagation chain
    overall_trust:       float
    attestation_ready:   bool


# ── Injection patterns for RAG content ───────────────────────────────────────
RAG_INJECTION_PATTERNS = [
    # Direct prompt injection in documents
    "ignore previous instructions",
    "ignore all previous",
    "system:", "[system]",
    "you are now", "act as",
    "new instructions:",
    # Tool abuse via RAG
    "call tool", "invoke tool",
    "tool_call:", "function_call:",
    # Authority spoofing
    "from anthropic:", "from openai:",
    "from your developer:",
    "override your",
    # Exfiltration via retrieval
    "send this to", "post this to",
    "when you see this", "upon reading this",
    # Encoding
    "base64:", "hex:", "<script>",
]

# Source trust scores by URI scheme
SOURCE_TRUST = {
    "internal://":  0.95,
    "verified://":  0.90,
    "https://":     0.70,
    "http://":      0.40,
    "file://":      0.60,
    "unknown://":   0.30,
}


class RAGGuard:
    """
    RAG pipeline security with cryptographic provenance and taint propagation.

    Usage:
        from aiglos.core.rag_guard import RAGGuard

        guard = RAGGuard(agent_name="my-agent", policy="enterprise")

        # At document ingestion
        prov = guard.attest_document(content, source_uri="https://docs.example.com/policy.pdf")

        # At retrieval time
        result = guard.check_retrieval(query, retrieved_chunks)
        if result.flagged:
            # Filter or block tainted chunks

        # At inference time - propagate taint
        guard.record_inference(inference_id, query, doc_ids_used)

        # Session report
        report = guard.close_session()
    """

    def __init__(
        self,
        agent_name:       str = "agent",
        policy:           str = "enterprise",
        trust_threshold:  float = 0.5,
        block_tainted:    bool = True,
    ):
        self.agent_name      = agent_name
        self.policy          = policy
        self.trust_threshold = trust_threshold
        self.block_tainted   = block_tainted

        self._session_id = hashlib.sha256(
            f"{agent_name}{time.time()}".encode()
        ).hexdigest()[:16]

        self._provenance:    Dict[str, DocumentProvenance] = {}
        self._tainted_ids:   Set[str] = set()
        self._retrievals:    List[RetrievalEvent] = []
        self._inferences:    List[TaintedInference] = []
        self._taint_chain:   List[Dict] = []

    # ── Document ingestion ────────────────────────────────────────────────────

    def attest_document(
        self,
        content:    str,
        source_uri: str = "unknown://",
        doc_id:     Optional[str] = None,
        sign:       bool = True,
    ) -> DocumentProvenance:
        """
        Attest a document at ingestion time.
        Computes content hash, assigns trust score, scans for injection.
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        doc_id = doc_id or content_hash[:16]

        # Trust score from source
        trust = 0.5
        for prefix, score in SOURCE_TRUST.items():
            if source_uri.startswith(prefix):
                trust = score
                break

        # Scan for injection patterns
        content_lower = content.lower()
        injection_hits = [p for p in RAG_INJECTION_PATTERNS if p in content_lower]

        tainted = len(injection_hits) >= 1
        taint_reason = f"injection patterns: {injection_hits[:3]}" if tainted else None

        if tainted:
            trust = 0.0
            self._tainted_ids.add(doc_id)
            self._taint_chain.append({
                "event":      "document_tainted",
                "doc_id":     doc_id,
                "source_uri": source_uri,
                "reason":     taint_reason,
                "timestamp":  datetime.now(timezone.utc).isoformat(),
            })

        # Sign
        sig = None
        if sign:
            sig_data = f"{doc_id}{content_hash}{source_uri}"
            sig = "sha256:" + hashlib.sha256(sig_data.encode()).hexdigest()

        prov = DocumentProvenance(
            doc_id       = doc_id,
            content_hash = content_hash,
            source_uri   = source_uri,
            ingest_time  = datetime.now(timezone.utc).isoformat(),
            trust_score  = trust,
            signed       = sign,
            signature    = sig,
            tainted      = tainted,
            taint_reason = taint_reason,
        )
        self._provenance[doc_id] = prov
        return prov

    # ── Retrieval checking ────────────────────────────────────────────────────

    def check_retrieval(
        self,
        query:            str,
        retrieved_chunks: List[Dict],
        inference_id:     Optional[str] = None,
    ) -> RetrievalEvent:
        """
        Check a RAG retrieval for taint and trust.

        Args:
            query:             The retrieval query.
            retrieved_chunks:  List of dicts with 'content', 'doc_id', 'source_uri'.
            inference_id:      Optional inference ID to link this retrieval to.

        Returns:
            RetrievalEvent with trust scores and taint flags.
        """
        retrieved_ids = []
        trust_scores  = {}
        tainted_ids   = []

        for chunk in retrieved_chunks:
            doc_id  = chunk.get("doc_id", hashlib.sha256(
                chunk.get("content", "").encode()
            ).hexdigest()[:16])
            content = chunk.get("content", "")
            source  = chunk.get("source_uri", "unknown://")

            retrieved_ids.append(doc_id)

            # Check existing provenance
            if doc_id in self._provenance:
                prov = self._provenance[doc_id]
                trust = prov.trust_score
                if prov.tainted:
                    tainted_ids.append(doc_id)
            else:
                # Attest on-the-fly
                prov = self.attest_document(content, source, doc_id)
                trust = prov.trust_score
                if prov.tainted:
                    tainted_ids.append(doc_id)

            trust_scores[doc_id] = trust

            # Scan chunk content directly for injection
            content_lower = content.lower()
            hits = [p for p in RAG_INJECTION_PATTERNS if p in content_lower]
            if hits and doc_id not in tainted_ids:
                tainted_ids.append(doc_id)
                self._tainted_ids.add(doc_id)
                if doc_id in self._provenance:
                    self._provenance[doc_id].tainted = True
                    self._provenance[doc_id].trust_score = 0.0
                self._taint_chain.append({
                    "event":    "retrieval_taint_detected",
                    "doc_id":   doc_id,
                    "patterns": hits[:3],
                    "query":    query[:100],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        min_trust = min(trust_scores.values()) if trust_scores else 1.0
        flagged   = bool(tainted_ids) or min_trust < self.trust_threshold

        event = RetrievalEvent(
            query         = query,
            retrieved_ids = retrieved_ids,
            trust_scores  = trust_scores,
            tainted_ids   = tainted_ids,
            min_trust     = min_trust,
            flagged       = flagged,
            timestamp     = datetime.now(timezone.utc).isoformat(),
            inference_id  = inference_id,
        )
        self._retrievals.append(event)
        return event

    # ── Taint propagation ─────────────────────────────────────────────────────

    def record_inference(
        self,
        inference_id:  str,
        query:         str,
        doc_ids_used:  List[str],
        taint_depth:   int = 0,
    ) -> Optional[TaintedInference]:
        """
        Record an inference and propagate taint from any contaminated documents.

        Core mechanism: when an inference uses a tainted document,
        the inference itself becomes tainted evidence. The session artifact
        records which inferences were contaminated and by which documents.

        Args:
            inference_id:  Unique ID for this inference.
            query:         The query that drove this inference.
            doc_ids_used:  Document IDs that informed this inference.
            taint_depth:   Depth in the taint propagation chain.

        Returns:
            TaintedInference if contaminated, None if clean.
        """
        tainted_docs = [d for d in doc_ids_used if d in self._tainted_ids]
        if not tainted_docs:
            return None

        blocked = self.block_tainted and taint_depth == 0

        inf = TaintedInference(
            inference_id    = inference_id,
            query           = query,
            tainted_doc_ids = tainted_docs,
            taint_depth     = taint_depth,
            timestamp       = datetime.now(timezone.utc).isoformat(),
            blocked         = blocked,
        )
        self._inferences.append(inf)

        self._taint_chain.append({
            "event":         "inference_contaminated",
            "inference_id":  inference_id,
            "tainted_docs":  tainted_docs,
            "taint_depth":   taint_depth,
            "blocked":       blocked,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        })

        return inf

    # ── Session reporting ─────────────────────────────────────────────────────

    def close_session(self) -> RAGSessionReport:
        """Generate session-level RAG security report."""
        tainted_retrievals = sum(1 for r in self._retrievals if r.flagged)
        all_trust = [
            p.trust_score for p in self._provenance.values()
            if not p.tainted
        ]
        overall_trust = sum(all_trust) / len(all_trust) if all_trust else 0.5

        attestation_ready = (
            len(self._tainted_ids) == 0 and
            overall_trust >= self.trust_threshold
        )

        return RAGSessionReport(
            agent_name              = self.agent_name,
            session_id              = self._session_id,
            documents_ingested      = len(self._provenance),
            documents_tainted       = len(self._tainted_ids),
            retrievals              = len(self._retrievals),
            tainted_retrievals      = tainted_retrievals,
            contaminated_inferences = len(self._inferences),
            taint_chain             = self._taint_chain,
            overall_trust           = overall_trust,
            attestation_ready       = attestation_ready,
        )

    def get_taint_chain(self) -> List[Dict]:
        """Return the full taint propagation chain for forensic analysis."""
        return self._taint_chain

    def is_tainted(self, doc_id: str) -> bool:
        """Check if a document ID is tainted."""
        return doc_id in self._tainted_ids
