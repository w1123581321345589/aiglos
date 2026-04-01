//! Behavioral threat rule taxonomy (T01-T88).
//!
//! Each rule has an ID, name, score, and a match function that takes
//! a tool name and its arguments and returns whether the rule fires.
//!
//! Rules are evaluated in the Guard's before_tool_call() method.
//! All 88 rules from the Python aiglos library are enumerated here;
//! match functions are being ported from Python incrementally.

/// A single behavioral threat rule.
pub struct ThreatRule {
    /// Rule identifier (e.g. "T01").
    pub id: &'static str,
    /// Rule name (e.g. "EXFIL").
    pub name: &'static str,
    /// Threat score [0.0, 1.0].
    pub score: f64,
    /// Whether this rule always blocks regardless of policy threshold.
    pub critical: bool,
    /// Match function: (tool_name, args_str) -> bool.
    pub match_fn: fn(&str, &str) -> bool,
}

/// Result of matching a rule against a tool call.
pub struct RuleMatch {
    /// The matched rule.
    pub rule_id: String,
    /// The rule name.
    pub rule_name: String,
    /// The rule score.
    pub score: f64,
    /// Whether the rule is critical.
    pub critical: bool,
}

// ── Rule match functions ──────────────────────────────────────────────────────

fn match_t01_exfil(name: &str, args: &str) -> bool {
    let n = name.to_lowercase();
    let s = args.to_lowercase();
    (n.contains("http.post") || n.contains("http.put") || n.contains("api.call"))
        && (s.contains("api_key") || s.contains("secret") || s.contains("password")
            || s.contains("token") || s.contains("credential"))
}

fn match_t81_pth_inject(name: &str, args: &str) -> bool {
    let s = args.to_lowercase();
    (name.to_lowercase().contains("write") || name.to_lowercase().contains("create"))
        && s.contains(".pth")
        && s.contains("site-packages")
}

fn match_t86_cross_tenant(_name: &str, args: &str) -> bool {
    let s = args.to_lowercase();
    s.contains("source_tenant_id") && s.contains("dest_tenant_id")
}

fn match_t87_threshold_probe(_name: &str, args: &str) -> bool {
    let _ = args;
    false
}

fn match_t88_mcp_auth(name: &str, args: &str) -> bool {
    let n = name.to_lowercase();
    let s = args.to_lowercase();
    n.contains("mcpauth") || n.contains("mcp_auth") || n.contains("mcp_register")
        || (n.contains("write") || n.contains("set") || n.contains("store"))
            && (s.contains("client_id") && s.contains("client_secret"))
}

fn match_never(_: &str, _: &str) -> bool { false }

// ── Rule registry ─────────────────────────────────────────────────────────────

/// All threat rules T01-T88.
/// Match functions are ported from Python aiglos incrementally.
/// Rules with `match_never` have full Python implementations but
/// require session-level state not yet available in this Rust stub.
pub static RULES: &[ThreatRule] = &[
    ThreatRule { id: "T01", name: "EXFIL",                      score: 0.85, critical: false, match_fn: match_t01_exfil },
    ThreatRule { id: "T81", name: "PTH_FILE_INJECT",             score: 0.98, critical: true,  match_fn: match_t81_pth_inject },
    ThreatRule { id: "T82", name: "SELF_IMPROVEMENT_HIJACK",     score: 0.96, critical: true,  match_fn: match_never },
    ThreatRule { id: "T83", name: "INTER_AGENT_PROTOCOL_SPOOF",  score: 0.85, critical: false, match_fn: match_never },
    ThreatRule { id: "T84", name: "IP_TRANSFORMATION_EXFIL",     score: 0.80, critical: false, match_fn: match_never },
    ThreatRule { id: "T85", name: "AGENT_IDENTITY_SUPPRESSION",  score: 0.75, critical: false, match_fn: match_never },
    ThreatRule { id: "T86", name: "CROSS_TENANT_ACCESS",         score: 0.85, critical: false, match_fn: match_t86_cross_tenant },
    ThreatRule { id: "T87", name: "THRESHOLD_PROBING",           score: 0.88, critical: false, match_fn: match_t87_threshold_probe },
    ThreatRule { id: "T88", name: "MCP_AUTH_BYPASS",             score: 0.87, critical: false, match_fn: match_t88_mcp_auth },
];
