//! Session artifact -- the signed compliance record.

/// A cryptographically signed record of what an agent did in a session.
///
/// Mirrors the Python aiglos SessionArtifact exactly.
/// Corresponds to NDAA §1513 evidence requirements.
#[derive(Debug, Clone)]
pub struct SessionArtifact {
    /// Unique artifact identifier.
    pub artifact_id: String,
    /// Agent name.
    pub agent_name: String,
    /// Session identifier.
    pub session_id: String,
    /// Policy tier that was active.
    pub policy: String,
    /// ISO 8601 session start time.
    pub started_at: String,
    /// ISO 8601 session close time.
    pub closed_at: String,
    /// Total tool calls in session.
    pub total_calls: usize,
    /// Calls that were blocked.
    pub blocked_calls: usize,
    /// Calls that generated warnings.
    pub warned_calls: usize,
    /// Final trust score [0.0, 1.0].
    pub trust_score: f64,
    /// True when policy is Strict, Federal, or Lockdown.
    /// Required for NDAA §1513 compliance export.
    pub attestation_ready: bool,
    /// HMAC-SHA256 cryptographic signature of session data.
    pub signature: String,
}
