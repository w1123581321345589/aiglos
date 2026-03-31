import { useState, useEffect } from "react";

function useComplianceSeo() {
  useEffect(() => {
    document.title = "NDAA Section 1513 Compliance Mapping | Aiglos";
    const setMeta = (name, content, attr = "name") => {
      let el = document.querySelector(`meta[${attr}="${name}"]`);
      if (!el) { el = document.createElement("meta"); el.setAttribute(attr, name); document.head.appendChild(el); }
      el.setAttribute("content", content);
    };
    setMeta("description", "NDAA Section 1513 FY2026 compliance mapping for AI/ML security. Workforce risks, supply chain, adversarial tampering, security monitoring. Status report due June 16, 2026.");
    setMeta("og:title", "NDAA Section 1513 Compliance - Aiglos", "property");
    setMeta("og:description", "Full coverage of NDAA Section 1513 requirements. Automated attestation artifacts for 80,000 defense contractors. C3PAO-ready evidence packages.", "property");
  }, []);
}

// NDAA §1513 requirement → Aiglos capability mapping
// Source: King & Spalding client alert, Government Contracts Legal Forum, WilmerHale
const REQUIREMENTS = [
  {
    id: "1513-WF",
    clause: "§1513 — Workforce Risks",
    requirement: "Address human and workforce-related risks in AI/ML systems, including training, accountability, and operator error vectors.",
    aiglos_capabilities: [
      { feature: "AgentPhase progressive delegation", description: "5-phase unlock model with operator identity logged in signed artifact. Each phase expansion is timestamped with who authorized it.", rules: ["T38"], artifact_field: "phase_log" },
      { feature: "declare_subagent() scope enforcement", description: "Operator declares what each sub-agent is permitted to do. Out-of-scope actions fire T38 at elevated score.", rules: ["T38","T23"], artifact_field: "subagent_registry" },
      { feature: "GOVBENCH workforce governance score", description: "D5 Multi-Agent Cascading Failure dimension specifically scores sub-agent spawn control and delegation safety.", rules: [], artifact_field: "govbench_d5" },
    ],
    coverage: "FULL",
  },
  {
    id: "1513-SC",
    clause: "§1513 — Supply Chain Risks",
    requirement: "Identify and mitigate supply chain risks in AI/ML components, including dependency integrity and third-party model security.",
    aiglos_capabilities: [
      { feature: "T81 PTH_FILE_INJECT", description: "Fires when a .pth file is written to site-packages — the exact LiteLLM 1.82.8 attack mechanism. Score 0.98, critical.", rules: ["T81"], artifact_field: "blocked_calls" },
      { feature: "T30 SUPPLY_CHAIN", description: "Detects poisoned package installs, tool registration overrides, and skill installs bypassing security scan.", rules: ["T30"], artifact_field: "blocked_calls" },
      { feature: "aiglos scan-deps", description: "CLI command checks installed packages against COMPROMISED_PACKAGES registry, scans site-packages for .pth files, checks uv cache and persistence paths.", rules: [], artifact_field: "scan_result" },
      { feature: "PyPI release feed", description: "Continuous monitoring of 15 high-download AI packages for .pth files in releases. Wheel-level deep inspection every 24 hours.", rules: ["T81","T30"], artifact_field: "pypi_findings" },
      { feature: "REPO_TAKEOVER_CHAIN campaign", description: "Detects the full attacker-becomes-maintainer sequence: T30 install → T81 .pth → T04 harvest → T41 exfil → T30 again.", rules: ["T30","T81","T04","T41"], artifact_field: "campaign_detections" },
    ],
    coverage: "FULL",
  },
  {
    id: "1513-AT",
    clause: "§1513 — Adversarial Tampering",
    requirement: "Detect and prevent adversarial manipulation of AI/ML systems, including prompt injection, model poisoning, and behavioral manipulation.",
    aiglos_capabilities: [
      { feature: "T05 PROMPT_INJECT", description: "Pattern-matches adversarial instruction overrides in tool responses and memory reads.", rules: ["T05"], artifact_field: "blocked_calls" },
      { feature: "T31 MEMORY_POISON", description: "Detects in-session writes to agent memory with injection payloads.", rules: ["T31"], artifact_field: "blocked_calls" },
      { feature: "T79 PERSISTENT_MEMORY_INJECT", description: "Detects adversarial writes to cross-session memory backends (Gigabrain, ByteRover, Chroma, Pinecone, Qdrant, mem0, Letta, Zep). Survives session close.", rules: ["T79"], artifact_field: "blocked_calls" },
      { feature: "T82 SELF_IMPROVEMENT_HIJACK", description: "Detects writes to self-improvement pipeline infrastructure (DGM-Hyperagents, AI Scientist). One injection propagates to all future agent generations.", rules: ["T82"], artifact_field: "blocked_calls" },
      { feature: "T39 REWARD_POISON", description: "Detects manipulation of RL reward signals to influence trained behavior across future sessions.", rules: ["T39"], artifact_field: "blocked_calls" },
      { feature: "after_tool_call injection scanning", description: "InjectionScanner runs on every tool response before the agent processes it. Catches indirect injection via fetched documents, API responses, memory reads.", rules: ["T05"], artifact_field: "injection_summary" },
    ],
    coverage: "FULL",
  },
  {
    id: "1513-SM",
    clause: "§1513 — Security Monitoring",
    requirement: "Implement continuous security monitoring, audit trails, and attestation for AI/ML systems. Required to draw on NIST SP 800 series and augment CMMC.",
    aiglos_capabilities: [
      { feature: "Signed session artifact", description: "HMAC-SHA256 signed artifact produced at every session close. Contains total_calls, blocked_calls, warned_calls, threats list, policy, phase_log, agent_name, timestamps.", rules: [], artifact_field: "signature" },
      { feature: "attestation_ready field", description: "Set to true when policy is 'strict' or 'federal'. Maps directly to C3PAO audit evidence requirements.", rules: [], artifact_field: "attestation_ready" },
      { feature: "23 campaign pattern detections", description: "Multi-step attack sequence detection invisible to single-call rule engines. REPO_TAKEOVER_CHAIN, METACOGNITIVE_POISON_CHAIN, SUPERPOWERS_PLAN_HIJACK, etc.", rules: [], artifact_field: "campaign_detections" },
      { feature: "Behavioral baseline", description: "Per-agent fingerprint across event rates, surface mix, and rule frequency. Anomalous sessions flagged in artifact.", rules: [], artifact_field: "behavioral_baseline" },
      { feature: "GOVBENCH A–F governance grade", description: "Five-dimension benchmark: campaign detection, agent definition resistance, memory belief integrity, RL resistance, multi-agent failure modes.", rules: [], artifact_field: "govbench_score" },
    ],
    coverage: "FULL",
  },
];

const ARTIFACT_SAMPLE = {
  "schema": "aiglos/v1",
  "agent_name": "my-agent",
  "policy": "federal",
  "total_calls": 247,
  "blocked_calls": 4,
  "warned_calls": 2,
  "attestation_ready": true,
  "phase_log": [
    { "phase": 2, "operator": "will@agency.mil", "timestamp": 1743000000, "agent": "my-agent" }
  ],
  "campaign_detections": [],
  "threats": [],
  "govbench_score": { "grade": "A", "total": 94 },
  "behavioral_baseline": { "risk": "LOW", "composite": 0.07 },
  "signature": "sha256:a1b2c3d4e5f6..."
};

const COVERAGE_COLOR = { FULL: "#22c55e", PARTIAL: "#fbbf24", NONE: "#ef4444" };

function ReqCard({ req, expanded, onToggle }) {
  const color = COVERAGE_COLOR[req.coverage];
  return (
    <div style={{
      border: `1px solid ${color}25`,
      borderRadius: "6px", marginBottom: "12px",
      background: `${color}04`, overflow: "hidden",
    }}>
      <button onClick={onToggle} style={{
        width: "100%", padding: "16px 20px", background: "transparent",
        border: "none", cursor: "pointer", textAlign: "left",
        display: "flex", alignItems: "flex-start", gap: "14px",
        fontFamily: "'DM Mono', monospace",
      }}>
        <div style={{
          padding: "2px 8px", borderRadius: "3px", fontSize: "9px",
          fontWeight: 700, letterSpacing: "0.15em", flexShrink: 0,
          background: `${color}18`, border: `1px solid ${color}44`, color,
        }}>{req.coverage}</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: "10px", color: "#3b82f6", letterSpacing: "0.1em", marginBottom: "4px" }}>{req.clause}</div>
          <div style={{ fontSize: "11px", color: "#888", lineHeight: 1.5 }}>{req.requirement}</div>
        </div>
        <div style={{ color: "#444", fontSize: "14px", flexShrink: 0, marginTop: "2px" }}>
          {expanded ? "−" : "+"}
        </div>
      </button>

      {expanded && (
        <div style={{ borderTop: "1px solid #111", padding: "16px 20px" }}>
          {req.aiglos_capabilities.map((cap, i) => (
            <div key={i} style={{
              marginBottom: i < req.aiglos_capabilities.length - 1 ? "14px" : 0,
              paddingBottom: i < req.aiglos_capabilities.length - 1 ? "14px" : 0,
              borderBottom: i < req.aiglos_capabilities.length - 1 ? "1px solid #111" : "none",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px", flexWrap: "wrap" }}>
                <code style={{ fontSize: "11px", color: "#22c55e" }}>{cap.feature}</code>
                {cap.rules.map(r => (
                  <span key={r} style={{
                    background: "#111", border: "1px solid #222", color: "#555",
                    padding: "1px 6px", borderRadius: "2px", fontSize: "9px", letterSpacing: "0.1em",
                  }}>{r}</span>
                ))}
                {cap.artifact_field && (
                  <span style={{ marginLeft: "auto", fontSize: "9px", color: "#333" }}>
                    artifact: <code style={{ color: "#444" }}>{cap.artifact_field}</code>
                  </span>
                )}
              </div>
              <div style={{ fontSize: "11px", color: "#666", lineHeight: 1.6 }}>{cap.description}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AiglosCompliance() {
  useComplianceSeo();
  const [expanded, setExpanded] = useState({ "1513-SC": true });
  const [showArtifact, setShowArtifact] = useState(false);

  const toggle = (id) => setExpanded(p => ({ ...p, [id]: !p[id] }));

  return (
    <div style={{
      minHeight: "100vh", background: "#080808",
      fontFamily: "'DM Mono', 'Courier New', monospace", color: "#e2e8f0",
    }}>
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none",
        background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.025) 2px,rgba(0,0,0,0.025) 4px)",
      }} />

      {/* Status bar */}
      <div style={{
        borderBottom: "1px solid #1a1a1a", padding: "10px 32px",
        display: "flex", alignItems: "center", justifyContent: "flex-end",
        background: "rgba(8,8,8,0.96)",
      }}>
        <div style={{ fontSize: "10px", color: "#555" }}>NDAA Section 1513 · FY2026 · Status report due June 16, 2026</div>
      </div>

      <div style={{ maxWidth: "860px", margin: "0 auto", padding: "40px 32px", position: "relative", zIndex: 1 }}>

        {/* Hero */}
        <div style={{ marginBottom: "40px" }}>
          <div style={{ fontSize: "10px", letterSpacing: "0.3em", color: "#3b82f6", marginBottom: "12px" }}>
            DEFENSE CONTRACTOR COMPLIANCE
          </div>
          <h1 style={{ fontSize: "clamp(22px,3.5vw,34px)", fontWeight: 700, letterSpacing: "-0.03em", color: "#fff", marginBottom: "10px" }}>
            NDAA §1513 — AI/ML Security Framework
          </h1>
          <p style={{ fontSize: "12px", color: "#555", lineHeight: 1.7, maxWidth: "580px" }}>
            Section 1513 of the FY2026 NDAA requires DoD to develop a framework covering workforce risks,
            supply chain risks, adversarial tampering, and security monitoring for AI/ML systems.
            Status report to Congress due June 16, 2026. Aiglos maps to all four requirement areas.
          </p>
        </div>

        {/* Deadline bar */}
        <div style={{
          padding: "14px 20px", border: "1px solid rgba(239,68,68,0.3)",
          borderRadius: "6px", background: "rgba(239,68,68,0.04)",
          display: "flex", alignItems: "center", gap: "16px",
          marginBottom: "36px", flexWrap: "wrap",
        }}>
          <div style={{ width: "6px", height: "6px", background: "#ef4444", borderRadius: "50%", animation: "pulse 2s infinite" }} />
          <div>
            <div style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.15em", marginBottom: "2px" }}>CONGRESSIONAL DEADLINE</div>
            <div style={{ fontSize: "11px", color: "#888" }}>
              DoD must report implementation timelines to Congress by June 16, 2026.
              80,000 defense contractors need AI/ML security framework compliance artifacts.
            </div>
          </div>
          <div style={{ marginLeft: "auto", textAlign: "right" }}>
            <div style={{ fontSize: "9px", color: "#444", letterSpacing: "0.1em" }}>CMMC ANALOG</div>
            <div style={{ fontSize: "10px", color: "#666" }}>CMMC took years from FY2020 NDAA → enforcement</div>
          </div>
        </div>

        {/* Coverage summary */}
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1px",
          background: "#111", borderRadius: "6px", overflow: "hidden",
          marginBottom: "36px",
        }}>
          {REQUIREMENTS.map(req => (
            <div key={req.id} style={{ padding: "14px", background: "#0a0a0a", textAlign: "center" }}>
              <div style={{ fontSize: "10px", color: COVERAGE_COLOR[req.coverage], fontWeight: 700, marginBottom: "4px" }}>
                {req.coverage}
              </div>
              <div style={{ fontSize: "9px", color: "#444", lineHeight: 1.4 }}>
                {req.clause.split("—")[1]?.trim()}
              </div>
            </div>
          ))}
        </div>

        {/* Requirement cards */}
        <div style={{ marginBottom: "36px" }}>
          <div style={{ fontSize: "10px", color: "#555", letterSpacing: "0.2em", marginBottom: "16px" }}>
            §1513 REQUIREMENT → AIGLOS CAPABILITY MAPPING
          </div>
          {REQUIREMENTS.map(req => (
            <ReqCard
              key={req.id}
              req={req}
              expanded={!!expanded[req.id]}
              onToggle={() => toggle(req.id)}
            />
          ))}
        </div>

        {/* Artifact preview */}
        <div style={{ marginBottom: "36px" }}>
          <div style={{ fontSize: "10px", color: "#555", letterSpacing: "0.2em", marginBottom: "16px" }}>
            SESSION ARTIFACT (C3PAO EVIDENCE PACKAGE)
          </div>
          <div style={{ border: "1px solid #1a1a1a", borderRadius: "6px", overflow: "hidden" }}>
            <button onClick={() => setShowArtifact(!showArtifact)} style={{
              width: "100%", padding: "14px 20px", background: "#0a0a0a",
              border: "none", cursor: "pointer", fontFamily: "inherit",
              display: "flex", alignItems: "center", justifyContent: "space-between",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <code style={{ fontSize: "10px", color: "#22c55e" }}>aiglos.close_session()</code>
                <span style={{ fontSize: "10px", color: "#444" }}>→ signed artifact with attestation_ready: true</span>
              </div>
              <span style={{ color: "#444", fontSize: "11px" }}>{showArtifact ? "−" : "+"}</span>
            </button>
            {showArtifact && (
              <div style={{ borderTop: "1px solid #111", padding: "16px 20px", background: "#050505" }}>
                <pre style={{
                  fontSize: "10px", color: "#666", lineHeight: "1.8",
                  overflowX: "auto", fontFamily: "inherit", whiteSpace: "pre",
                }}>
                  {JSON.stringify(ARTIFACT_SAMPLE, null, 2)}
                </pre>
              </div>
            )}
          </div>
          <div style={{ marginTop: "8px", fontSize: "10px", color: "#444", lineHeight: 1.6 }}>
            Every session close produces this artifact automatically.
            <code style={{ color: "#555", marginLeft: "6px" }}>attestation_ready: true</code> requires
            <code style={{ color: "#555", marginLeft: "4px" }}>policy="strict"</code> or
            <code style={{ color: "#555", marginLeft: "4px" }}>policy="federal"</code>.
          </div>
        </div>

        {/* Standards table */}
        <div style={{ marginBottom: "40px" }}>
          <div style={{ fontSize: "10px", color: "#555", letterSpacing: "0.2em", marginBottom: "16px" }}>COMPLIANCE STANDARD COVERAGE</div>
          <div style={{ border: "1px solid #1a1a1a", borderRadius: "6px", overflow: "hidden" }}>
            {[
              ["NDAA §1513 FY2026",    "June 16, 2026",   "#22c55e", "attestation_ready auto-generated per session"],
              ["CMMC Level 2",         "Ongoing",         "#22c55e", "C3PAO-formatted evidence package"],
              ["NIST SP 800-171 Rev 2","Ongoing",         "#22c55e", "18 controls across AC, AU, IA, SC, SI"],
              ["EU AI Act",            "August 2026",     "#fbbf24", "Pro tier and above"],
              ["SOC 2 Type II",        "Ongoing",         "#22c55e", "CC6, CC7 coverage"],
            ].map(([std, deadline, color, note], i, arr) => (
              <div key={std} style={{
                padding: "12px 20px",
                borderBottom: i < arr.length - 1 ? "1px solid #111" : "none",
                display: "grid", gridTemplateColumns: "180px 100px 1fr",
                alignItems: "center", gap: "16px",
              }}>
                <div style={{ fontSize: "11px", color: "#888" }}>{std}</div>
                <div style={{ fontSize: "10px", color: color }}>{deadline}</div>
                <div style={{ fontSize: "10px", color: "#555" }}>{note}</div>
              </div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div style={{
          padding: "24px 28px", border: "1px solid #1a1a1a", borderRadius: "6px",
          background: "#0a0a0a", display: "flex", justifyContent: "space-between",
          alignItems: "center", gap: "24px", flexWrap: "wrap",
        }}>
          <div>
            <div style={{ fontSize: "11px", color: "#e2e8f0", marginBottom: "4px" }}>Start generating compliant artifacts today</div>
            <code style={{ fontSize: "11px", color: "#22c55e" }}>pip install aiglos && aiglos launch</code>
          </div>
          <div style={{ textAlign: "right", fontSize: "10px", color: "#444" }}>
            <div>80,000 defense contractors need this before June 2026</div>
            <div style={{ marginTop: "3px" }}>Nothing else auto-generates a NDAA §1513 attestation artifact</div>
          </div>
        </div>

        <div style={{ marginTop: "20px", textAlign: "center", fontSize: "9px", color: "#2a2a2a", letterSpacing: "0.1em" }}>
          aiglos.dev · Enterprise pricing for DoD contractors · MIT open core
        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap');
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:5px}
        ::-webkit-scrollbar-track{background:#0a0a0a}
        ::-webkit-scrollbar-thumb{background:#1e1e1e;border-radius:3px}
        button:hover{opacity:0.9}
      `}</style>
    </div>
  );
}
