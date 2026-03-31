import { useState } from "react";
import { useSeo } from "@/hooks/use-seo";
import SectionLabel from "@/components/public/section-label";
import CodeWindow from "@/components/public/code-window";

function RefSection({ title, id, children }: { title: string; id: string; children: React.ReactNode }) {
  return (
    <section id={id} className="mb-16">
      <h2 className="text-[clamp(22px,3vw,32px)] font-bold tracking-tight mb-6 pt-6 border-t border-pub">
        {title}
      </h2>
      {children}
    </section>
  );
}

function RuleTable({ rules }: { rules: { id: string; name: string; score: string; catches: string; source: string }[] }) {
  return (
    <div className="border border-pub rounded-md overflow-hidden mb-6">
      {rules.map((r, i) => (
        <div
          key={r.id}
          className={`py-3 px-5 grid grid-cols-[60px_200px_50px_1fr_180px] gap-4 items-start text-xs ${
            i < rules.length - 1 ? "border-b border-white/[0.04]" : ""
          }`}
        >
          <span className="font-pub-mono text-pub-ice">{r.id}</span>
          <span className="text-white font-medium">{r.name}</span>
          <span className="font-pub-mono text-pub-green">{r.score}</span>
          <span className="text-white/50 leading-[1.5]">{r.catches}</span>
          <span className="text-white/25 text-[10px]">{r.source}</span>
        </div>
      ))}
    </div>
  );
}

function CampaignTable({ campaigns }: { campaigns: { pattern: string; sequence: string; confidence: string; notes: string }[] }) {
  return (
    <div className="border border-pub rounded-md overflow-hidden mb-6">
      {campaigns.map((c, i) => (
        <div
          key={c.pattern}
          className={`py-3 px-5 grid grid-cols-[220px_160px_70px_1fr] gap-4 items-start text-xs ${
            i < campaigns.length - 1 ? "border-b border-white/[0.04]" : ""
          }`}
        >
          <span className="font-pub-mono text-pub-orange font-medium">{c.pattern}</span>
          <span className="font-pub-mono text-white/50">{c.sequence}</span>
          <span className="font-pub-mono text-pub-green">{c.confidence}</span>
          <span className="text-white/40 leading-[1.5]">{c.notes}</span>
        </div>
      ))}
    </div>
  );
}

export default function ReferencePage() {
  useSeo({
    title: "Complete Reference - 82 Rules, 23 Campaigns, CLI, Integrations | Aiglos",
    description: "The full Aiglos technical reference. 82 threat families, 23 campaign patterns, integrations, CLI commands, compliance mapping, and pricing. Ungated.",
    ogTitle: "Aiglos Complete Reference",
  });

  const [activeSection, setActiveSection] = useState("overview");

  const toc = [
    { id: "overview", label: "Overview" },
    { id: "architecture", label: "Architecture" },
    { id: "threat-families", label: "82 Threat Families" },
    { id: "campaigns", label: "23 Campaign Patterns" },
    { id: "integrations", label: "Integrations" },
    { id: "govbench", label: "GOVBENCH" },
    { id: "cli", label: "CLI Reference" },
    { id: "compliance", label: "Compliance" },
    { id: "intelligence", label: "Intelligence Layers" },
    { id: "pricing-ref", label: "Pricing" },
    { id: "build-history", label: "Build History" },
  ];

  return (
    <div className="flex max-w-[1200px] mx-auto py-20 px-6">
      <nav
        data-testid="nav-reference-toc"
        className="w-[200px] flex-shrink-0 sticky top-20 self-start pr-6 border-r border-pub max-h-[calc(100vh-100px)] overflow-y-auto"
      >
        <div className="font-pub-mono text-[10px] tracking-[0.2em] uppercase text-pub-dim mb-4">Reference</div>
        {toc.map((t) => (
          <a
            key={t.id}
            href={`#${t.id}`}
            onClick={() => setActiveSection(t.id)}
            className={`block py-1.5 text-xs no-underline transition-colors duration-150 ${
              activeSection === t.id ? "text-pub-ice" : "text-white/40 hover:text-white/60"
            }`}
          >
            {t.label}
          </a>
        ))}
      </nav>

      <div className="flex-1 pl-12 min-w-0">
        <SectionLabel>Complete Reference - v0.25.11</SectionLabel>
        <h1
          data-testid="text-reference-title"
          className="text-[clamp(28px,4vw,44px)] font-bold tracking-tight leading-[1.1] mb-4"
        >
          Aiglos: Complete Reference
        </h1>
        <p className="text-base text-pub-muted leading-[1.7] max-w-[640px] mb-12">
          The AI Agent Security Platform. Runtime security enforcement for every AI agent. One import
          intercepts every tool call before execution, classifies it against 82 threat families, and produces
          a signed audit artifact.
        </p>

        <RefSection title="What Aiglos Is" id="overview">
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            The dominant AI agent platform has a security policy that says: "Prompt injection attacks -- Out of Scope."
            OWASP published the Top 10 for Agentic Applications. Number one: Agent Goal Hijack. The most documented
            class of AI agent attacks is officially not the platform's problem.
          </p>
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            Three things nobody else can say:
          </p>
          <ul className="list-none p-0 m-0 mb-6 max-w-[640px]">
            {[
              "3/3 published OpenClaw GHSAs caught by existing rules before the advisories were disclosed. The rules came first. Every time.",
              "93% coverage of OpenClaw's own published MITRE ATLAS threat model.",
              "GOVBENCH: the first governance benchmark for AI agents. Published before any standard body required one.",
            ].map((item) => (
              <li key={item} className="py-2 text-[13px] text-white/60 leading-[1.6] border-b border-white/[0.04] flex gap-3">
                <span className="text-pub-green flex-shrink-0">&#10003;</span>
                {item}
              </li>
            ))}
          </ul>
        </RefSection>

        <RefSection title="Architecture" id="architecture">
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            Two front doors, same product. Security-first (GTM 1): Security engineers, DoD contractors, enterprise.
            Onboarding-first (GTM 2): Every new OpenClaw user. Both paths end with a signed session artifact and
            behavioral detection running on every tool call.
          </p>
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            Aiglos enforces outside the agent process. The agent cannot reason around a rule it doesn't know exists.
            Three interception surfaces operating simultaneously:
          </p>
          <CodeWindow filename="agent.py">{`aiglos.attach(
    agent_name            = "my-agent",
    policy                = "enterprise",
    intercept_http        = True,         # requests, httpx, urllib
    intercept_subprocess  = True,         # subprocess.run, os.system, Popen
    subprocess_tier3_mode = "pause",      # human confirmation on destructive ops
    guard_memory_writes   = True,         # T31/T79 memory protection
    guard_agent_defs      = True,         # T36 AgentDef protection
)`}</CodeWindow>
          <p className="text-[13px] text-white/40 mb-5">
            Under 1ms per call. Zero network dependency. No proxy. No sidecar. No port.
          </p>
        </RefSection>

        <RefSection title="82 Threat Families" id="threat-families">
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            Mapped to MITRE ATLAS techniques. Citation-verified. Every rule has a corresponding ATLAS technique ID.
          </p>
          {[
            { range: "T01-T10", title: "Exfiltration and Data Exposure", desc: "EXFIL, SSRF, SHADOW_WRITE, CRED_HARVEST, PROMPT_INJECT, CAMPAIGN, RECON, LATERAL, PERSISTENCE, PRIV_ESC" },
            { range: "T11-T20", title: "Infrastructure Abuse", desc: "ENV_LEAK, NET_SCAN, DNS_REBIND, CACHE_POISON, LOG_TAMPER, SHELL_INJECT, PATH_TRAV, SYM_LINK, CRED_HARVEST extended, DEST" },
            { range: "T21-T30", title: "Supply Chain and Agent Trust", desc: "PKG_CONFUSE, TYPOSQUAT, DEP_CONFUSION, TOOL_REDEF, AGENT_IMPERSONATE, TRUST_CHAIN, MEM_INJECT, RAG_POISON, CONTEXT_MANIP, SUPPLY_CHAIN" },
            { range: "T31-T43", title: "Agentic Threats", desc: "REWARD_HACK, GOAL_MISALIGN, SANDBOX_ESCAPE, DATA_PIPELINE, PERSONAL_AGENT, AGENTDEF, FIN_EXEC, AGENT_SPAWN, ORCHESTRATION, SHARED_CONTEXT_POISON, OUTBOUND_SECRET_LEAK, INSTRUCTION_REWRITE_POISON, HONEYPOT_ACCESS" },
            { range: "T44-T66", title: "Infrastructure-to-Agent and Campaign Threats", desc: "INFERENCE_ROUTER_HIJACK, TOKEN_BUDGET_EXHAUSTION, COMPUTE_RESOURCE_ABUSE, and 20 additional rules covering infrastructure-to-agent attacks, agent-to-agent attacks at scale, and vector store poisoning." },
          ].map((group) => (
            <div key={group.range} className="mb-6">
              <h3 className="text-base font-semibold mb-3">{group.range}: {group.title}</h3>
              <p className="text-xs text-white/40 leading-[1.6] mb-3">{group.desc}</p>
            </div>
          ))}

          <h3 className="text-base font-semibold mb-4">T67-T82: New Rules (v0.20.0-v0.25.11)</h3>
          <RuleTable
            rules={[
              { id: "T67", name: "HEARTBEAT_SILENCE", score: "0.88", catches: "Overnight job suppression", source: "Power user architecture" },
              { id: "T68", name: "INSECURE_DEFAULT_CONFIG", score: "0.95", catches: "Root cause of 40,214 exposed instances", source: "SecurityScorecard STRIKE" },
              { id: "T69", name: "PLAN_DRIFT", score: "0.95", catches: "Agent deviating from approved plan", source: "Superpowers integration" },
              { id: "T70", name: "ENV_PATH_HIJACK", score: "0.88", catches: "PATH/LD_PRELOAD/PYTHONPATH modification", source: "GHSA-mc68-q9jw-2h3v" },
              { id: "T71", name: "PAIRING_GRACE_ABUSE", score: "0.87", catches: "30-second pairing window exploit", source: "ATLAS T-ACCESS-001" },
              { id: "T72", name: "CHANNEL_IDENTITY_SPOOF", score: "0.89", catches: "AllowFrom header spoofing", source: "ATLAS T-ACCESS-002" },
              { id: "T73", name: "TOOL_ENUMERATION", score: "0.75", catches: "tools.list / empty-arg recon probes", source: "ATLAS T-DISC-001" },
              { id: "T74", name: "CONTENT_WRAPPER_ESCAPE", score: "0.84", catches: "XML wrapper termination, CDATA injection", source: "ATLAS T-EVADE-002" },
              { id: "T75", name: "SESSION_DATA_EXTRACT", score: "0.82", catches: "sessions.list / chat.history extraction", source: "ATLAS T-DISC-002" },
              { id: "T76", name: "NEMOCLAW_POLICY_BYPASS", score: "0.95", catches: "Agent writes to NemoClaw policy files", source: "NemoClaw GTC 2026" },
              { id: "T77", name: "OVERNIGHT_JOB_INJECTION", score: "0.87", catches: "Malicious writes to cron/scheduler config", source: "Vox AI company" },
              { id: "T78", name: "HALLUCINATION_CASCADE", score: "0.82", catches: "Cross-agent confidence amplification", source: "Vox AI case study" },
              { id: "T79", name: "PERSISTENT_MEMORY_INJECT", score: "0.92", catches: "Adversarial writes to cross-session memory", source: "WeeklyClaw #004" },
              { id: "T80", name: "UNCENSORED_MODEL_ROUTE", score: "0.90", catches: "Routing to uncensored/jailbroken models", source: "Inference router audit" },
              { id: "T81", name: "PTH_FILE_INJECT", score: "0.98", catches: ".pth file written to site-packages", source: "LiteLLM 1.82.8 incident" },
              { id: "T82", name: "SELF_IMPROVEMENT_HIJACK", score: "0.94", catches: "Writes to self-improvement pipeline", source: "DGM-Hyperagents" },
            ]}
          />
        </RefSection>

        <RefSection title="23 Campaign Patterns" id="campaigns">
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            Multi-step attack sequence detection invisible to single-call rule engines. Fires when
            individual tool calls form recognized attack sequences across time.
          </p>
          <CampaignTable
            campaigns={[
              { pattern: "RECON_SWEEP", sequence: "T07 -> T04", confidence: "0.88", notes: "Environment read then targeted credential access" },
              { pattern: "CREDENTIAL_ACCUMULATE", sequence: "T19 -> T12 -> T01", confidence: "0.91", notes: "Progressive credential gathering then exfil" },
              { pattern: "EXFIL_SETUP", sequence: "T07 -> T03 -> T01", confidence: "0.89", notes: "Recon then staging then exfiltration" },
              { pattern: "PERSISTENCE_CHAIN", sequence: "T09 -> T34", confidence: "0.87", notes: "Multi-step persistence installation" },
              { pattern: "LATERAL_PREP", sequence: "T08 -> T13", confidence: "0.85", notes: "Lateral movement preparation" },
              { pattern: "AGENTDEF_CHAIN", sequence: "T36 read -> T36 write", confidence: "0.94", notes: "Read-then-write on agent definitions" },
              { pattern: "MEMORY_PERSISTENCE_CHAIN", sequence: "T31 -> T27", confidence: "0.88", notes: "Cross-session memory persistence" },
              { pattern: "REWARD_MANIPULATION", sequence: "T31 -> T32", confidence: "0.86", notes: "RL reward signal manipulation" },
              { pattern: "REPEATED_INJECTION_ATTEMPT", sequence: "T05 x 3+", confidence: "0.84", notes: "Persistent injection retries" },
              { pattern: "EXTERNAL_INSTRUCTION_CHANNEL", sequence: "T13 -> T05", confidence: "0.87", notes: "External C2 channel establishment" },
              { pattern: "SKILL_CHAIN", sequence: "T30 -> T10", confidence: "0.89", notes: "Capability chaining for privilege escalation" },
              { pattern: "SANDBOX_ESCAPE_ATTEMPT", sequence: "T33 x 2+", confidence: "0.88", notes: "Multi-step sandbox boundary probing" },
              { pattern: "GAAS_TAKEOVER", sequence: "T25 -> T28", confidence: "0.86", notes: "GaaS hijack sequence" },
              { pattern: "INFERENCE_HIJACK_CHAIN", sequence: "T44 -> T01", confidence: "0.87", notes: "Model routing compromise then exfil" },
              { pattern: "RAG_POISON_CHAIN", sequence: "T54 -> T05", confidence: "0.91", notes: "Retrieval context poisoning" },
              { pattern: "MULTI_AGENT_IMPERSONATION", sequence: "T25 x 3+", confidence: "0.88", notes: "Agent identity substitution at scale" },
              { pattern: "CAPABILITY_EXPLOIT_CHAIN", sequence: "T38 -> T10", confidence: "0.86", notes: "Capability boundary exploitation" },
              { pattern: "SANDBOX_CONFIRMED_ESCAPE", sequence: "T33 -> T01", confidence: "0.96", notes: "Confirmed sandbox exit with evidence" },
              { pattern: "SUPERPOWERS_PLAN_HIJACK", sequence: "T69 -> T01", confidence: "0.97", notes: "Superpowers plan manipulation then exfil" },
              { pattern: "NEMOCLAW_POLICY_HIJACK", sequence: "T76 -> {T68,T12,T14}", confidence: "0.96", notes: "Policy bypass followed by insecure config or exfil" },
              { pattern: "GIGABRAIN_MEMORY_POISON", sequence: "T31 -> T79", confidence: "0.95", notes: "In-session probe then persistent memory commit" },
              { pattern: "REPO_TAKEOVER_CHAIN", sequence: "T30 -> T81 -> T04 -> T41", confidence: "0.97", notes: "Full attacker-becomes-maintainer sequence" },
              { pattern: "METACOGNITIVE_POISON_CHAIN", sequence: "T82 -> T31 -> T79", confidence: "0.96", notes: "Self-improvement then memory injection" },
            ]}
          />
        </RefSection>

        <RefSection title="Integrations" id="integrations">
          <h3 className="text-base font-semibold mb-3">OpenShell (v0.25.1)</h3>
          <p className="text-[13px] text-white/50 leading-[1.7] mb-4 max-w-[640px]">
            NVIDIA NemoClaw announced at GTC 2026. OpenShell is the sandbox layer. Aiglos is the behavioral
            detection layer above it. 9 known agents: Claude Code, Codex, Cursor, OpenClaw, Windsurf, Aider,
            Continue, Cody.
          </p>
          <CodeWindow filename="openShell integration">{`from aiglos.integrations.openShell import (
    openshell_detect,          # zero config
    attach_for_claude_code,
    attach_for_codex,
    attach_for_cursor,
    attach_for_openclaw,
    is_inside_openShell,
    openShell_context,
)

session = openshell_detect(guard)`}</CodeWindow>

          <h3 className="text-base font-semibold mb-3 mt-8">NemoClaw (v0.25.0)</h3>
          <CodeWindow>{`from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session, validate_policy

session = mark_as_nemoclaw_session(
    policy_path = "~/.nemoclaw/policy.yaml",
    guard       = guard,
)
# Allowed hosts/files/tools from YAML become T69/T76 enforcement boundary`}</CodeWindow>

          <h3 className="text-base font-semibold mb-3 mt-8">Superpowers (v0.24.0)</h3>
          <p className="text-[13px] text-white/50 leading-[1.7] mb-4 max-w-[640px]">
            The approved implementation plan becomes the T69 enforcement boundary. Plan deviation fires T69
            PLAN_DRIFT (confidence 0.95).
          </p>

          <h3 className="text-base font-semibold mb-3 mt-8">Sub-Agent Declaration (v0.25.2)</h3>
          <CodeWindow>{`guard.declare_subagent(
    "coding-agent",
    tools       = ["filesystem", "shell.execute", "web_search"],
    scope_files = ["src/", "tests/"],
    model       = "claude-sonnet",
    hard_bans   = ["fabricate_data", "unverified_claims"],
)`}</CodeWindow>

          <h3 className="text-base font-semibold mb-3 mt-8">Phase-Gated Delegation (v0.25.2)</h3>
          <CodeWindow>{`from aiglos.integrations.agent_phase import AgentPhase

guard.unlock_phase(AgentPhase.P1, operator="will@aiglos.dev")  # observe only
guard.unlock_phase(AgentPhase.P2, operator="will@aiglos.dev")  # low-risk auto-approve
guard.unlock_phase(AgentPhase.P3, operator="will@aiglos.dev")  # content autonomy
guard.unlock_phase(AgentPhase.P4, operator="will@aiglos.dev")  # site operations
guard.unlock_phase(AgentPhase.P5, operator="will@aiglos.dev")  # self-evolution`}</CodeWindow>

          <h3 className="text-base font-semibold mb-3 mt-8">Gigabrain + Persistent Memory (v0.25.3)</h3>
          <CodeWindow>{`from aiglos.integrations.gigabrain import gigabrain_autodetect, declare_memory_backend

session = gigabrain_autodetect(guard)  # scans ~/.gigabrain/, registers with T79

# Or explicit backend declaration
declare_memory_backend(guard, backend="chroma", db_path="./chroma.db")
# 8 backends: Gigabrain, MemoryOS, mem0, Letta, Zep, Chroma, Pinecone, Qdrant`}</CodeWindow>
        </RefSection>

        <RefSection title="GOVBENCH" id="govbench">
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            The first governance benchmark for AI agents. 5 dimensions, 20 scenarios, A-F grade, under 60 seconds.
          </p>
          <CodeWindow>{`aiglos benchmark run

# Grade: A (92/100)
# D1 Campaign detection:           19/20
# D2 Agent definition resistance:  20/20
# D3 Memory belief integrity:      18/20
# D4 RL feedback loop resistance:  18/20
# D5 Multi-agent cascading failure: 17/20`}</CodeWindow>
          <div className="grid grid-cols-5 pub-grid-5 gap-2 mb-6">
            {[
              { id: "D1", name: "Campaign Detection", max: 20 },
              { id: "D2", name: "Agent Definition Resistance", max: 20 },
              { id: "D3", name: "Memory Belief Integrity", max: 20 },
              { id: "D4", name: "RL Feedback Loop Resistance", max: 20 },
              { id: "D5", name: "Multi-Agent Cascading Failure", max: 20 },
            ].map((d) => (
              <div key={d.id} className="p-4 border border-pub rounded text-center">
                <div className="font-pub-mono text-sm text-pub-ice font-bold mb-1">{d.id}</div>
                <div className="text-[10px] text-white/40 leading-[1.3]">{d.name}</div>
                <div className="text-[10px] text-white/25 mt-1">/{d.max}</div>
              </div>
            ))}
          </div>
        </RefSection>

        <RefSection title="CLI Reference" id="cli">
          {[
            { group: "Onboarding", commands: [["aiglos launch", "OpenClaw production-ready in 5 minutes"], ['aiglos launch --from "description"', "Non-interactive, from description"], ["aiglos agents scaffold", "NL description to declare_subagent() calls"]] },
            { group: "Core", commands: [["aiglos attach", "Attach to running agent session"], ["aiglos check <tool> <args>", "Manual check against all 82 rules"], ["aiglos attest --session SESSION_ID", "Produce signed attestation"], ["aiglos verify SESSION_ID.aiglos", "Verify artifact integrity"]] },
            { group: "Policy", commands: [["aiglos policy list", "Pending proposals"], ["aiglos policy approve prp_abc123 user@co.com", "Approve policy proposal"], ["aiglos policy lockdown", "Deny-first mode"], ["aiglos policy recommend", "Min viable allowlist from session history"]] },
            { group: "Intelligence", commands: [["aiglos benchmark run", "GOVBENCH A-F grade"], ["aiglos forecast", "Current intent prediction state"], ["aiglos autoresearch watch-ghsa", "GHSA watcher"], ["aiglos autoresearch atlas-coverage", "ATLAS threat model coverage"], ["aiglos scan-deps", "Check installed packages for compromise"], ["aiglos scan-exposed", "CVE-2026-25253 exposure probe"], ["aiglos audit --hardening-check", "Compare against hardened baseline"]] },
            { group: "Memory and Sub-agents", commands: [["aiglos memory status", "Memory backend status"], ["aiglos memory scan --backend gigabrain", "Scan memory backend"], ["aiglos subagents list", "List declared sub-agents"], ["aiglos subagents declare --name scout --tools web_search,analytics", "Declare sub-agent"]] },
            { group: "Daemon", commands: [["aiglos daemon start", "Start background daemon"], ["aiglos daemon status", "Check daemon status"], ["aiglos daemon stop", "Stop daemon"]] },
          ].map((section) => (
            <div key={section.group} className="mb-6">
              <h3 className="text-sm font-semibold mb-3">{section.group}</h3>
              <div className="border border-pub rounded-md overflow-hidden">
                {section.commands.map(([cmd, desc], i) => (
                  <div key={cmd} className={`py-2.5 px-4 grid grid-cols-[360px_1fr] gap-4 items-center ${i < section.commands.length - 1 ? "border-b border-white/[0.04]" : ""}`}>
                    <code className="font-pub-mono text-xs text-pub-green">{cmd}</code>
                    <span className="text-xs text-white/40">{desc}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </RefSection>

        <RefSection title="Compliance and Attestation" id="compliance">
          <p className="text-sm text-white/60 leading-[1.8] mb-5 max-w-[640px]">
            Every session close produces a cryptographically signed audit record.
          </p>
          <CodeWindow filename="Session artifact">{`{
  "schema":             "aiglos/v1",
  "artifact_id":        "3f9a1c2d-...",
  "agent_name":         "my-agent",
  "policy":             "federal",
  "total_calls":        247,
  "blocked_calls":      4,
  "warned_calls":       2,
  "attestation_ready":  true,
  "phase_log":          [{"phase": 3, "operator": "will@aiglos.dev", "timestamp": 1742000000}],
  "memory_backends":    [{"backend": "gigabrain", "paths": ["~/.gigabrain/memory.db"]}],
  "subagent_registry":  [{"name": "coding-agent", "hard_bans": ["fabricate_data"]}],
  "signature":          "sha256:a1b2c3d4..."
}`}</CodeWindow>

          <h3 className="text-base font-semibold mb-4 mt-8">Compliance Standard Coverage</h3>
          <div className="border border-pub rounded-md overflow-hidden">
            {[
              ["NDAA Section 1513 FY2026", "June 16, 2026", "text-pub-green", "attestation_ready auto-generated per session"],
              ["CMMC Level 2", "Ongoing", "text-pub-green", "C3PAO-formatted evidence package"],
              ["NIST SP 800-171 Rev 2", "Ongoing", "text-pub-green", "18 controls across AC, AU, IA, SC, SI"],
              ["EU AI Act", "August 2026", "text-amber-400", "Pro tier and above"],
              ["SOC 2 Type II", "Ongoing", "text-pub-green", "CC6, CC7 coverage"],
            ].map(([std, deadline, color, note], i, arr) => (
              <div key={std} className={`py-3 px-5 grid grid-cols-[200px_120px_1fr] items-center gap-4 ${i < arr.length - 1 ? "border-b border-white/[0.04]" : ""}`}>
                <div className="text-[13px] text-white/70">{std}</div>
                <div className={`text-xs ${color}`}>{deadline}</div>
                <div className="text-xs text-white/40">{note}</div>
              </div>
            ))}
          </div>
        </RefSection>

        <RefSection title="Intelligence Layers" id="intelligence">
          {[
            { title: "Behavioral Baseline", desc: "Per-agent statistical fingerprinting across three independent feature spaces: event rate (z-score), surface mix (chi-squared), and rule frequency (KL-divergence). BEHAVIORAL_ANOMALY trigger fires when composite deviation exceeds threshold." },
            { title: "Predictive Intent Modeling", desc: "Deployment-specific Markov chain trained on local call history. No external ML dependency. SessionForecaster pre-tightens effective_tier() when predicted next action is Tier 2 or Tier 3. THREAT_FORECAST_ALERT fires before the threat executes." },
            { title: "Federated Threat Intelligence", desc: "Privacy-preserving global threat intelligence. Differential privacy with Laplace mechanism (epsilon=0.1). Only noisy unigram transition counts leave a deployment. New deployments start pre-warmed from collective intelligence." },
            { title: "Policy Proposals", desc: "Evidence-weighted policy decisions. LOWER_TIER (5+ blocks, 60%), RAISE_THRESHOLD (8+ blocks, 70%), ALLOW_LIST (10+ blocks, 80%), SUPPRESS_PATTERN (15+ blocks, 90%)." },
            { title: "Causal Attribution", desc: "Traces the causal chain from a block event back to the originating injection point. Answers 'what caused this agent to make this call?' rather than just logging that it was blocked." },
            { title: "Source Reputation", desc: "Inbound data sources scored against a reputation index. Sources that previously triggered injection rules receive elevated inspection in future sessions across deployments when federation is enabled." },
          ].map((layer) => (
            <div key={layer.title} className="mb-5 p-5 border border-pub rounded-md">
              <div className="text-sm font-semibold mb-2">{layer.title}</div>
              <p className="text-[13px] text-white/50 leading-[1.6]">{layer.desc}</p>
            </div>
          ))}
        </RefSection>

        <RefSection title="Pricing" id="pricing-ref">
          <div className="border border-pub rounded-md overflow-hidden">
            {[
              ["Community", "$0 / MIT", "Full T01-T82 detection, 3 surfaces, 23 campaign patterns, GOVBENCH, GHSA watcher, ATLAS coverage, OpenShell, NemoClaw, Superpowers, Gigabrain, declare_subagent(), hard_bans, AgentPhase, aiglos launch, GitHub Actions CI"],
              ["Pro", "$49/dev/mo", "Community + federated intelligence, behavioral baseline, RSA-2048 signed artifacts, NDAA Section 1513 + EU AI Act compliance export, policy proposals, cloud dashboard"],
              ["Teams", "$399/mo (15 devs)", "Pro + centralized policy, aggregated threat view, Tier 3 approval workflows, audit exports"],
              ["Enterprise", "Custom, annual", "Teams + private federation server, air-gap deployment, C3PAO packages, dedicated engineering, NET-30"],
            ].map(([tier, price, features], i, arr) => (
              <div key={tier} className={`py-4 px-5 grid grid-cols-[120px_160px_1fr] gap-4 items-start ${i < arr.length - 1 ? "border-b border-white/[0.04]" : ""}`}>
                <div className="font-pub-mono text-[13px] font-semibold text-pub-ice">{tier}</div>
                <div className="font-pub-mono text-[13px] text-white">{price}</div>
                <div className="text-xs text-white/50 leading-[1.6]">{features}</div>
              </div>
            ))}
          </div>
          <p className="mt-4 text-[13px] text-white/40 leading-[1.6]">
            Conversion mechanic: first call to aiglos.attest() or cloud telemetry connection auto-starts a
            30-day Pro trial. No feature blocked. By day 30, the developer has built their workflow around
            signed artifacts. The decision is already made.
          </p>
        </RefSection>

        <RefSection title="Build History" id="build-history">
          <div className="border border-pub rounded-md overflow-hidden">
            {[
              ["v0.1.0", "335", "36", "5", "Initial release"],
              ["v0.10.0", "688", "39", "10", "Intent prediction"],
              ["v0.11.0", "753", "39", "12", "Behavioral baseline"],
              ["v0.13.0", "882", "39", "15", "Federated intelligence"],
              ["v0.19.0", "1,300", "66", "19", "Campaign patterns, new threat families"],
              ["v0.24.0", "1,514", "75", "19", "GOVBENCH, ATLAS coverage, T71-T75, NemoClaw"],
              ["v0.25.0", "1,582", "76", "20", "T76 NEMOCLAW_POLICY_BYPASS"],
              ["v0.25.1", "1,636", "76", "20", "OpenShell agent-agnostic (9 agents)"],
              ["v0.25.2", "1,690", "77", "21", "declare_subagent(), hard_bans, AgentPhase"],
              ["v0.25.3", "1,747", "79", "21", "T78, T79, Gigabrain, aiglos launch"],
              ["v0.25.11", "1,830", "82", "23", "T80-T82, REPO_TAKEOVER_CHAIN, METACOGNITIVE_POISON_CHAIN"],
            ].map(([ver, tests, rules, campaigns, notes], i, arr) => (
              <div key={ver} className={`py-2.5 px-5 grid grid-cols-[80px_80px_60px_70px_1fr] gap-3 items-center text-xs ${i < arr.length - 1 ? "border-b border-white/[0.04]" : ""}`}>
                <span className="font-pub-mono text-pub-ice">{ver}</span>
                <span className="text-white/50">{tests} tests</span>
                <span className="text-white/50">{rules}</span>
                <span className="text-white/50">{campaigns}</span>
                <span className="text-white/40">{notes}</span>
              </div>
            ))}
          </div>
          <p className="mt-4 text-[11px] text-white/25 font-pub-mono">
            Generated from v0.25.11 codebase. 1,830 tests passing. github.com/w1123581321345589/aiglos
          </p>
        </RefSection>
      </div>
    </div>
  );
}
