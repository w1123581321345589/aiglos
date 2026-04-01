//! Verdict types for tool call evaluation.

/// The verdict returned by `Guard::before_tool_call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Tool call is permitted to proceed.
    Allow,
    /// Tool call is suspicious -- log and proceed with caution.
    Warn,
    /// Tool call is blocked -- do not execute.
    Block,
}

/// The full result of a tool call evaluation.
#[derive(Debug, Clone)]
pub struct GuardResult {
    /// Whether the call is allowed, warned, or blocked.
    pub verdict: Verdict,
    /// Name of the tool being evaluated.
    pub tool_name: String,
    /// Matched threat rule ID (e.g. "T01"), if any.
    pub threat_class: Option<String>,
    /// Human-readable threat name (e.g. "EXFIL"), if any.
    pub threat_name: Option<String>,
    /// Composite threat score [0.0, 1.0].
    pub score: f64,
    /// Session ID this result belongs to.
    pub session_id: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

impl GuardResult {
    /// Returns true if the call is safe to execute.
    pub fn is_allowed(&self) -> bool {
        self.verdict == Verdict::Allow || self.verdict == Verdict::Warn
    }

    /// Returns true if the call is blocked.
    pub fn is_blocked(&self) -> bool {
        self.verdict == Verdict::Block
    }
}
