//! Policy tiers for the Aiglos guard.
//!
//! Each tier has a different block and warn threshold.
//! Thresholds match the Python aiglos library exactly.

/// Policy tier controlling block/warn thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Permissive: blocks at 0.90. Development and testing.
    Permissive,
    /// Enterprise: blocks at 0.75. Default for production.
    Enterprise,
    /// Strict: blocks at 0.50. Sensitive data environments.
    Strict,
    /// Federal: blocks at 0.40. DoD/NDAA §1513 compliance.
    Federal,
    /// Lockdown: blocks everything (threshold 0.0). Air-gapped.
    Lockdown,
}

impl Policy {
    /// Block threshold for this policy tier.
    pub fn block_threshold(&self) -> f64 {
        match self {
            Policy::Permissive => 0.90,
            Policy::Enterprise => 0.75,
            Policy::Strict     => 0.50,
            Policy::Federal    => 0.40,
            Policy::Lockdown   => 0.00,
        }
    }

    /// Warn threshold for this policy tier.
    pub fn warn_threshold(&self) -> f64 {
        match self {
            Policy::Permissive => 0.70,
            Policy::Enterprise => 0.55,
            Policy::Strict     => 0.35,
            Policy::Federal    => 0.25,
            Policy::Lockdown   => 0.00,
        }
    }

    /// Whether this policy tier produces NDAA §1513 attestation artifacts.
    pub fn attestation_ready(&self) -> bool {
        matches!(self, Policy::Strict | Policy::Federal | Policy::Lockdown)
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Policy::Permissive => "permissive",
            Policy::Enterprise => "enterprise",
            Policy::Strict     => "strict",
            Policy::Federal    => "federal",
            Policy::Lockdown   => "lockdown",
        };
        write!(f, "{}", s)
    }
}
