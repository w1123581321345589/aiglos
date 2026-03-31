import { useState } from "react";
import { useSeo } from "@/hooks/use-seo";

interface Capability {
  feature: string;
  description: string;
  rules: string[];
  artifact_field: string;
}

interface Requirement {
  id: string;
  clause: string;
  requirement: string;
  aiglos_capabilities: Capability[];
  coverage: string;
}

const REQUIREMENTS: Requirement[] = [
  {
    id: "1513-WF",
    clause: "\u00A71513 \u2014 Workforce Risks",
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
    clause: "\u00A71513 \u2014 Supply Chain Risks",
    requirement: "Identify and mitigate supply chain risks in AI/ML components, including dependency integrity and third-party model security.",
    aiglos_capabilities: [
      { feature: "T81 PTH_FILE_INJECT", description: "Fires when a .pth file is written to site-packages \u2014 the exact LiteLLM 1.82.8 attack mechanism. Score 0.98, critical.", rules: ["T81"], artifact_field: "blocked_calls" },
      { feature: "T30 SUPPLY_CHAIN", description: "Detects poisoned package installs, tool registration overrides, and skill installs bypassing security scan.", rules: ["T30"], artifact_field: "blocked_calls" },
      { feature: "aiglos scan-deps", description: "CLI command checks installed packages against COMPROMISED_PACKAGES registry, scans site-packages for .pth files, checks uv cache and persistence paths.", rules: [], artifact_field: "scan_result" },
      { feature: "PyPI release feed", description: "Continuous monitoring of 15 high-download AI packages for .pth files in releases. Wheel-level deep inspection every 24 hours.", rules: ["T81","T30"], artifact_field: "pypi_findings" },
      { feature: "REPO_TAKEOVER_CHAIN campaign", description: "Detects the full attacker-becomes-maintainer sequence: T30 install \u2192 T81 .pth \u2192 T04 harvest \u2192 T41 exfil \u2192 T30 again.", rules: ["T30","T81","T04","T41"], artifact_field: "campaign_detections" },
    ],
    coverage: "FULL",
  },
  {
    id: "1513-AT",
    clause: "\u00A71513 \u2014 Adversarial Tampering",
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
    clause: "\u00A71513 \u2014 Security Monitoring",
    requirement: "Implement continuous security monitoring, audit trails, and attestation for AI/ML systems. Required to draw on NIST SP 800 series and augment CMMC.",
    aiglos_capabilities: [
      { feature: "Signed session artifact", description: "HMAC-SHA256 signed artifact produced at every session close. Contains total_calls, blocked_calls, warned_calls, threats list, policy, phase_log, agent_name, timestamps.", rules: [], artifact_field: "signature" },
      { feature: "attestation_ready field", description: "Set to true when policy is 'strict' or 'federal'. Maps directly to C3PAO audit evidence requirements.", rules: [], artifact_field: "attestation_ready" },
      { feature: "23 campaign pattern detections", description: "Multi-step attack sequence detection invisible to single-call rule engines. REPO_TAKEOVER_CHAIN, METACOGNITIVE_POISON_CHAIN, SUPERPOWERS_PLAN_HIJACK, etc.", rules: [], artifact_field: "campaign_detections" },
      { feature: "Behavioral baseline", description: "Per-agent fingerprint across event rates, surface mix, and rule frequency. Anomalous sessions flagged in artifact.", rules: [], artifact_field: "behavioral_baseline" },
      { feature: "GOVBENCH A-F governance grade", description: "Five-dimension benchmark: campaign detection, agent definition resistance, memory belief integrity, RL resistance, multi-agent failure modes.", rules: [], artifact_field: "govbench_score" },
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

const COVERAGE_COLOR: Record<string, string> = { FULL: "text-pub-green", PARTIAL: "text-yellow-400", NONE: "text-pub-red" };
const COVERAGE_BG: Record<string, string> = {
  FULL: "bg-pub-green/[0.08] border-pub-green/25",
  PARTIAL: "bg-yellow-400/[0.06] border-yellow-400/20",
  NONE: "bg-pub-red/[0.06] border-pub-red/20",
};

function ReqCard({ req, expanded, onToggle }: { req: Requirement; expanded: boolean; onToggle: () => void }) {
  return (
    <div className={`border rounded-md mb-3 overflow-hidden ${COVERAGE_BG[req.coverage]}`}>
      <button
        onClick={onToggle}
        className="w-full py-4 px-5 bg-transparent border-none cursor-pointer text-left flex items-start gap-3.5 font-pub-mono"
      >
        <span className={`py-0.5 px-2 rounded-[3px] text-[9px] font-bold tracking-[0.15em] flex-shrink-0 border ${COVERAGE_BG[req.coverage]} ${COVERAGE_COLOR[req.coverage]}`}>
          {req.coverage}
        </span>
        <div className="flex-1">
          <div className="text-[10px] text-pub-blue tracking-[0.1em] mb-1">{req.clause}</div>
          <div className="text-[11px] text-neutral-500 leading-[1.5]">{req.requirement}</div>
        </div>
        <span className="text-neutral-600 text-sm flex-shrink-0 mt-0.5">{expanded ? "\u2212" : "+"}</span>
      </button>

      {expanded && (
        <div className="border-t border-white/[0.06] py-4 px-5">
          {req.aiglos_capabilities.map((cap, i) => (
            <div
              key={i}
              className={`${
                i < req.aiglos_capabilities.length - 1
                  ? "mb-3.5 pb-3.5 border-b border-white/[0.06]"
                  : ""
              }`}
            >
              <div className="flex items-center gap-2.5 mb-1.5 flex-wrap">
                <code className="text-[11px] text-pub-green font-pub-mono">{cap.feature}</code>
                {cap.rules.map(r => (
                  <span key={r} className="bg-pub-card border border-white/[0.08] text-pub-dim py-px px-1.5 rounded-sm text-[9px] tracking-[0.1em] font-pub-mono">{r}</span>
                ))}
                {cap.artifact_field && (
                  <span className="ml-auto text-[9px] text-neutral-700">
                    artifact: <code className="text-neutral-600 font-pub-mono">{cap.artifact_field}</code>
                  </span>
                )}
              </div>
              <div className="text-[11px] text-neutral-500 leading-[1.6]">{cap.description}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AiglosCompliance() {
  useSeo({
    title: "NDAA Section 1513 Compliance Mapping | Aiglos",
    description: "NDAA Section 1513 FY2026 compliance mapping for AI/ML security. Workforce risks, supply chain, adversarial tampering, security monitoring. Status report due June 16, 2026.",
    ogTitle: "NDAA Section 1513 Compliance - Aiglos",
  });

  const [expanded, setExpanded] = useState<Record<string, boolean>>({ "1513-SC": true });
  const [showArtifact, setShowArtifact] = useState(false);

  const toggle = (id: string) => setExpanded(p => ({ ...p, [id]: !p[id] }));

  return (
    <div className="min-h-screen bg-[#080808] font-pub-mono text-slate-200">
      <div className="fixed inset-0 pointer-events-none bg-[repeating-linear-gradient(0deg,transparent,transparent_2px,rgba(0,0,0,0.025)_2px,rgba(0,0,0,0.025)_4px)]" />

      <div className="border-b border-white/[0.06] py-2.5 px-8 flex items-center justify-end bg-[#080808]/95">
        <div className="text-[10px] text-neutral-500">NDAA Section 1513 \u00B7 FY2026 \u00B7 Status report due June 16, 2026</div>
      </div>

      <div className="max-w-[860px] mx-auto py-10 px-8 relative z-[1]">
        <div className="mb-10">
          <div className="text-[10px] tracking-[0.3em] text-pub-blue mb-3">DEFENSE CONTRACTOR COMPLIANCE</div>
          <h1 className="text-[clamp(22px,3.5vw,34px)] font-bold tracking-tight text-white mb-2.5">
            NDAA \u00A71513 \u2014 AI/ML Security Framework
          </h1>
          <p className="text-xs text-neutral-500 leading-[1.7] max-w-[580px]">
            Section 1513 of the FY2026 NDAA requires DoD to develop a framework covering workforce risks,
            supply chain risks, adversarial tampering, and security monitoring for AI/ML systems.
            Status report to Congress due June 16, 2026. Aiglos maps to all four requirement areas.
          </p>
        </div>

        <div className="p-3.5 px-5 border border-pub-red/30 rounded-md bg-pub-red/[0.04] flex items-center gap-4 mb-9 flex-wrap">
          <div className="w-1.5 h-1.5 bg-pub-red rounded-full pub-pulse" />
          <div>
            <div className="text-[10px] text-pub-red tracking-[0.15em] mb-0.5">CONGRESSIONAL DEADLINE</div>
            <div className="text-[11px] text-neutral-500">
              DoD must report implementation timelines to Congress by June 16, 2026.
              80,000 defense contractors need AI/ML security framework compliance artifacts.
            </div>
          </div>
          <div className="ml-auto text-right">
            <div className="text-[9px] text-neutral-600 tracking-[0.1em]">CMMC ANALOG</div>
            <div className="text-[10px] text-neutral-500">CMMC took years from FY2020 NDAA \u2192 enforcement</div>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-px bg-white/[0.06] rounded-md overflow-hidden mb-9">
          {REQUIREMENTS.map(req => (
            <div key={req.id} className="py-3.5 bg-[#0a0a0a] text-center">
              <div className={`text-[10px] font-bold mb-1 ${COVERAGE_COLOR[req.coverage]}`}>{req.coverage}</div>
              <div className="text-[9px] text-neutral-600 leading-[1.4]">{req.clause.split("\u2014")[1]?.trim()}</div>
            </div>
          ))}
        </div>

        <div className="mb-9">
          <div className="text-[10px] text-neutral-500 tracking-[0.2em] mb-4">
            \u00A71513 REQUIREMENT \u2192 AIGLOS CAPABILITY MAPPING
          </div>
          {REQUIREMENTS.map(req => (
            <ReqCard key={req.id} req={req} expanded={!!expanded[req.id]} onToggle={() => toggle(req.id)} />
          ))}
        </div>

        <div className="mb-9">
          <div className="text-[10px] text-neutral-500 tracking-[0.2em] mb-4">SESSION ARTIFACT (C3PAO EVIDENCE PACKAGE)</div>
          <div className="border border-white/[0.06] rounded-md overflow-hidden">
            <button
              onClick={() => setShowArtifact(!showArtifact)}
              className="w-full py-3.5 px-5 bg-[#0a0a0a] border-none cursor-pointer font-pub-mono flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <code className="text-[10px] text-pub-green">aiglos.close_session()</code>
                <span className="text-[10px] text-neutral-600">\u2192 signed artifact with attestation_ready: true</span>
              </div>
              <span className="text-neutral-600 text-[11px]">{showArtifact ? "\u2212" : "+"}</span>
            </button>
            {showArtifact && (
              <div className="border-t border-white/[0.06] p-4 px-5 bg-[#050505]">
                <pre className="text-[10px] text-neutral-500 leading-[1.8] overflow-x-auto font-pub-mono whitespace-pre m-0">
                  {JSON.stringify(ARTIFACT_SAMPLE, null, 2)}
                </pre>
              </div>
            )}
          </div>
          <div className="mt-2 text-[10px] text-neutral-600 leading-[1.6]">
            Every session close produces this artifact automatically.
            <code className="text-neutral-500 ml-1.5 font-pub-mono">attestation_ready: true</code> requires
            <code className="text-neutral-500 ml-1 font-pub-mono">policy="strict"</code> or
            <code className="text-neutral-500 ml-1 font-pub-mono">policy="federal"</code>.
          </div>
        </div>

        <div className="mb-10">
          <div className="text-[10px] text-neutral-500 tracking-[0.2em] mb-4">COMPLIANCE STANDARD COVERAGE</div>
          <div className="border border-white/[0.06] rounded-md overflow-hidden">
            {([
              ["NDAA \u00A71513 FY2026", "June 16, 2026", "text-pub-green", "attestation_ready auto-generated per session"],
              ["CMMC Level 2", "Ongoing", "text-pub-green", "C3PAO-formatted evidence package"],
              ["NIST SP 800-171 Rev 2", "Ongoing", "text-pub-green", "18 controls across AC, AU, IA, SC, SI"],
              ["EU AI Act", "August 2026", "text-yellow-400", "Pro tier and above"],
              ["SOC 2 Type II", "Ongoing", "text-pub-green", "CC6, CC7 coverage"],
            ] as [string, string, string, string][]).map(([std, deadline, color, note], i, arr) => (
              <div
                key={std}
                className={`py-3 px-5 grid grid-cols-[180px_100px_1fr] gap-4 items-center ${
                  i < arr.length - 1 ? "border-b border-white/[0.06]" : ""
                }`}
              >
                <div className="text-[11px] text-neutral-500">{std}</div>
                <div className={`text-[10px] ${color}`}>{deadline}</div>
                <div className="text-[10px] text-neutral-500">{note}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="p-6 border border-white/[0.06] rounded-md bg-[#0a0a0a] flex justify-between items-center gap-6 flex-wrap">
          <div>
            <div className="text-[11px] text-slate-200 mb-1">Start generating compliant artifacts today</div>
            <code className="text-[11px] text-pub-green font-pub-mono">pip install aiglos && aiglos launch</code>
          </div>
          <div className="text-right text-[10px] text-neutral-600">
            <div>80,000 defense contractors need this before June 2026</div>
            <div className="mt-0.5">Nothing else auto-generates a NDAA \u00A71513 attestation artifact</div>
          </div>
        </div>
        <div className="mt-5 text-center text-[9px] text-neutral-800 tracking-[0.1em]">
          aiglos.dev \u00B7 Enterprise pricing for DoD contractors \u00B7 MIT open core
        </div>
      </div>
    </div>
  );
}
