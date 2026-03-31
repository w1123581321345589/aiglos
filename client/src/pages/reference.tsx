import { useState } from "react";
import { useSeo } from "@/hooks/use-seo";

function Section({
  title,
  id,
  children,
}: {
  title: string;
  id: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} style={{ marginBottom: "64px" }}>
      <h2
        style={{
          fontSize: "clamp(22px, 3vw, 32px)",
          fontWeight: 700,
          letterSpacing: "-0.03em",
          marginBottom: "24px",
          paddingTop: "24px",
          borderTop: "1px solid rgba(255,255,255,0.06)",
        }}
      >
        {title}
      </h2>
      {children}
    </section>
  );
}

function RuleTable({
  rules,
}: {
  rules: { id: string; name: string; score: string; catches: string; source: string }[];
}) {
  return (
    <div
      style={{
        border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: "6px",
        overflow: "hidden",
        marginBottom: "24px",
      }}
    >
      {rules.map((r, i) => (
        <div
          key={r.id}
          style={{
            padding: "12px 20px",
            borderBottom: i < rules.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
            display: "grid",
            gridTemplateColumns: "60px 200px 50px 1fr 180px",
            gap: "16px",
            alignItems: "start",
            fontSize: "12px",
          }}
        >
          <span style={{ fontFamily: "'DM Mono', monospace", color: "#60a5fa" }}>{r.id}</span>
          <span style={{ color: "#fff", fontWeight: 500 }}>{r.name}</span>
          <span style={{ fontFamily: "'DM Mono', monospace", color: "#4ade80" }}>{r.score}</span>
          <span style={{ color: "rgba(255,255,255,0.5)", lineHeight: 1.5 }}>{r.catches}</span>
          <span style={{ color: "rgba(255,255,255,0.25)", fontSize: "10px" }}>{r.source}</span>
        </div>
      ))}
    </div>
  );
}

function CampaignTable({
  campaigns,
}: {
  campaigns: { pattern: string; sequence: string; confidence: string; notes: string }[];
}) {
  return (
    <div
      style={{
        border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: "6px",
        overflow: "hidden",
        marginBottom: "24px",
      }}
    >
      {campaigns.map((c, i) => (
        <div
          key={c.pattern}
          style={{
            padding: "12px 20px",
            borderBottom: i < campaigns.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
            display: "grid",
            gridTemplateColumns: "220px 160px 70px 1fr",
            gap: "16px",
            alignItems: "start",
            fontSize: "12px",
          }}
        >
          <span style={{ fontFamily: "'DM Mono', monospace", color: "#f97316", fontWeight: 500 }}>
            {c.pattern}
          </span>
          <span style={{ fontFamily: "'DM Mono', monospace", color: "rgba(255,255,255,0.5)" }}>
            {c.sequence}
          </span>
          <span style={{ fontFamily: "'DM Mono', monospace", color: "#4ade80" }}>
            {c.confidence}
          </span>
          <span style={{ color: "rgba(255,255,255,0.4)", lineHeight: 1.5 }}>{c.notes}</span>
        </div>
      ))}
    </div>
  );
}

function CodeBlock({ code, filename }: { code: string; filename?: string }) {
  return (
    <div
      style={{
        background: "#0d1117",
        border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: "6px",
        overflow: "hidden",
        marginBottom: "20px",
        maxWidth: "720px",
      }}
    >
      {filename && (
        <div
          style={{
            background: "#161b22",
            padding: "8px 16px",
            borderBottom: "1px solid rgba(255,255,255,0.06)",
            fontFamily: "'DM Mono', monospace",
            fontSize: "11px",
            color: "rgba(255,255,255,0.35)",
          }}
        >
          {filename}
        </div>
      )}
      <pre
        style={{
          padding: "16px 20px",
          fontFamily: "'DM Mono', monospace",
          fontSize: "12px",
          lineHeight: 1.7,
          color: "#e6edf3",
          overflowX: "auto",
          margin: 0,
        }}
      >
        {code}
      </pre>
    </div>
  );
}

export default function ReferencePage() {
  useSeo({
    title: "Complete Reference - 82 Rules, 23 Campaigns, CLI, Integrations | Aiglos",
    description:
      "The full Aiglos technical reference. 82 threat families, 23 campaign patterns, integrations, CLI commands, compliance mapping, and pricing. Ungated.",
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
    <div style={{ display: "flex", maxWidth: "1200px", margin: "0 auto", padding: "80px 24px 80px 24px" }}>
      {/* Sidebar TOC */}
      <nav
        data-testid="nav-reference-toc"
        style={{
          width: "200px",
          flexShrink: 0,
          position: "sticky",
          top: "80px",
          alignSelf: "flex-start",
          paddingRight: "24px",
          borderRight: "1px solid rgba(255,255,255,0.06)",
          maxHeight: "calc(100vh - 100px)",
          overflowY: "auto",
        }}
      >
        <div
          style={{
            fontFamily: "'DM Mono', monospace",
            fontSize: "10px",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            color: "rgba(255,255,255,0.35)",
            marginBottom: "16px",
          }}
        >
          Reference
        </div>
        {toc.map((t) => (
          <a
            key={t.id}
            href={`#${t.id}`}
            onClick={() => setActiveSection(t.id)}
            style={{
              display: "block",
              padding: "6px 0",
              fontSize: "12px",
              color: activeSection === t.id ? "#60a5fa" : "rgba(255,255,255,0.4)",
              textDecoration: "none",
              transition: "color 0.15s",
            }}
          >
            {t.label}
          </a>
        ))}
      </nav>

      {/* Content */}
      <div style={{ flex: 1, paddingLeft: "48px", minWidth: 0 }}>
        <div
          style={{
            fontFamily: "'DM Mono', monospace",
            fontSize: "10px",
            letterSpacing: "0.25em",
            textTransform: "uppercase",
            color: "#60a5fa",
            marginBottom: "16px",
          }}
        >
          Complete Reference - v0.25.3
        </div>
        <h1
          data-testid="text-reference-title"
          style={{
            fontSize: "clamp(28px, 4vw, 44px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            lineHeight: 1.1,
            marginBottom: "16px",
          }}
        >
          Aiglos: Complete Reference
        </h1>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            lineHeight: 1.7,
            maxWidth: "640px",
            marginBottom: "48px",
          }}
        >
          The AI Agent Security Platform. Runtime security enforcement for every AI agent. One import
          intercepts every tool call before execution, classifies it against 82 threat families, and produces
          a signed audit artifact.
        </p>

        {/* OVERVIEW */}
        <Section title="What Aiglos Is" id="overview">
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
            The dominant AI agent platform has a security policy that says: "Prompt injection attacks -- Out of Scope."
            OWASP published the Top 10 for Agentic Applications. Number one: Agent Goal Hijack. The most documented
            class of AI agent attacks is officially not the platform's problem.
          </p>
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
            Three things nobody else can say:
          </p>
          <ul style={{ listStyle: "none", padding: 0, margin: "0 0 24px 0", maxWidth: "640px" }}>
            {[
              "3/3 published OpenClaw GHSAs caught by existing rules before the advisories were disclosed. The rules came first. Every time.",
              "93% coverage of OpenClaw's own published MITRE ATLAS threat model.",
              "GOVBENCH: the first governance benchmark for AI agents. Published before any standard body required one.",
            ].map((item) => (
              <li
                key={item}
                style={{
                  padding: "8px 0",
                  fontSize: "13px",
                  color: "rgba(255,255,255,0.6)",
                  lineHeight: 1.6,
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  display: "flex",
                  gap: "12px",
                }}
              >
                <span style={{ color: "#4ade80", flexShrink: 0 }}>&#10003;</span>
                {item}
              </li>
            ))}
          </ul>
        </Section>

        {/* ARCHITECTURE */}
        <Section title="Architecture" id="architecture">
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
            Two front doors, same product. Security-first (GTM 1): Security engineers, DoD contractors, enterprise.
            Onboarding-first (GTM 2): Every new OpenClaw user. Both paths end with a signed session artifact and
            behavioral detection running on every tool call.
          </p>
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
            Aiglos enforces outside the agent process. The agent cannot reason around a rule it doesn't know exists.
            Three interception surfaces operating simultaneously:
          </p>
          <CodeBlock
            filename="agent.py"
            code={`aiglos.attach(
    agent_name            = "my-agent",
    policy                = "enterprise",
    intercept_http        = True,         # requests, httpx, urllib
    intercept_subprocess  = True,         # subprocess.run, os.system, Popen
    subprocess_tier3_mode = "pause",      # human confirmation on destructive ops
    guard_memory_writes   = True,         # T31/T79 memory protection
    guard_agent_defs      = True,         # T36 AgentDef protection
)`}
          />
          <p style={{ fontSize: "13px", color: "rgba(255,255,255,0.4)", marginBottom: "20px" }}>
            Under 1ms per call. Zero network dependency. No proxy. No sidecar. No port.
          </p>
        </Section>

        {/* THREAT FAMILIES */}
        <Section title="82 Threat Families" id="threat-families">
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
            Mapped to MITRE ATLAS techniques. Citation-verified. Every rule has a corresponding ATLAS technique ID.
          </p>

          <div style={{ marginBottom: "24px" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px" }}>T01-T10: Exfiltration and Data Exposure</h3>
            <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.4)", lineHeight: 1.6, marginBottom: "12px" }}>
              EXFIL, SSRF, SHADOW_WRITE, CRED_HARVEST, PROMPT_INJECT, CAMPAIGN, RECON, LATERAL, PERSISTENCE, PRIV_ESC
            </p>
          </div>

          <div style={{ marginBottom: "24px" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px" }}>T11-T20: Infrastructure Abuse</h3>
            <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.4)", lineHeight: 1.6, marginBottom: "12px" }}>
              ENV_LEAK, NET_SCAN, DNS_REBIND, CACHE_POISON, LOG_TAMPER, SHELL_INJECT, PATH_TRAV, SYM_LINK, CRED_HARVEST extended, DEST
            </p>
          </div>

          <div style={{ marginBottom: "24px" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px" }}>T21-T30: Supply Chain and Agent Trust</h3>
            <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.4)", lineHeight: 1.6, marginBottom: "12px" }}>
              PKG_CONFUSE, TYPOSQUAT, DEP_CONFUSION, TOOL_REDEF, AGENT_IMPERSONATE, TRUST_CHAIN, MEM_INJECT, RAG_POISON, CONTEXT_MANIP, SUPPLY_CHAIN
            </p>
          </div>

          <div style={{ marginBottom: "24px" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px" }}>T31-T43: Agentic Threats</h3>
            <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.4)", lineHeight: 1.6, marginBottom: "12px" }}>
              REWARD_HACK, GOAL_MISALIGN, SANDBOX_ESCAPE, DATA_PIPELINE, PERSONAL_AGENT, AGENTDEF, FIN_EXEC, AGENT_SPAWN, ORCHESTRATION, SHARED_CONTEXT_POISON, OUTBOUND_SECRET_LEAK, INSTRUCTION_REWRITE_POISON, HONEYPOT_ACCESS
            </p>
          </div>

          <div style={{ marginBottom: "24px" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px" }}>T44-T66: Infrastructure-to-Agent and Campaign Threats</h3>
            <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.4)", lineHeight: 1.6, marginBottom: "12px" }}>
              INFERENCE_ROUTER_HIJACK, TOKEN_BUDGET_EXHAUSTION, COMPUTE_RESOURCE_ABUSE, and 20 additional rules covering infrastructure-to-agent attacks, agent-to-agent attacks at scale, and vector store poisoning.
            </p>
          </div>

          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "16px" }}>T67-T82: New Rules (v0.20.0-v0.25.8)</h3>
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
        </Section>

        {/* CAMPAIGNS */}
        <Section title="23 Campaign Patterns" id="campaigns">
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
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
        </Section>

        {/* INTEGRATIONS */}
        <Section title="Integrations" id="integrations">
          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px" }}>OpenShell (v0.25.1)</h3>
          <p style={{ fontSize: "13px", color: "rgba(255,255,255,0.5)", lineHeight: 1.7, marginBottom: "16px", maxWidth: "640px" }}>
            NVIDIA NemoClaw announced at GTC 2026. OpenShell is the sandbox layer. Aiglos is the behavioral
            detection layer above it. 9 known agents: Claude Code, Codex, Cursor, OpenClaw, Windsurf, Aider,
            Continue, Cody.
          </p>
          <CodeBlock
            filename="openShell integration"
            code={`from aiglos.integrations.openShell import (
    openshell_detect,          # zero config
    attach_for_claude_code,
    attach_for_codex,
    attach_for_cursor,
    attach_for_openclaw,
    is_inside_openShell,
    openShell_context,
)

session = openshell_detect(guard)`}
          />

          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px", marginTop: "32px" }}>NemoClaw (v0.25.0)</h3>
          <CodeBlock
            code={`from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session, validate_policy

session = mark_as_nemoclaw_session(
    policy_path = "~/.nemoclaw/policy.yaml",
    guard       = guard,
)
# Allowed hosts/files/tools from YAML become T69/T76 enforcement boundary`}
          />

          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px", marginTop: "32px" }}>Superpowers (v0.24.0)</h3>
          <p style={{ fontSize: "13px", color: "rgba(255,255,255,0.5)", lineHeight: 1.7, marginBottom: "16px", maxWidth: "640px" }}>
            The approved implementation plan becomes the T69 enforcement boundary. Plan deviation fires T69
            PLAN_DRIFT (confidence 0.95).
          </p>

          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px", marginTop: "32px" }}>Sub-Agent Declaration (v0.25.2)</h3>
          <CodeBlock
            code={`guard.declare_subagent(
    "coding-agent",
    tools       = ["filesystem", "shell.execute", "web_search"],
    scope_files = ["src/", "tests/"],
    model       = "claude-sonnet",
    hard_bans   = ["fabricate_data", "unverified_claims"],
)`}
          />

          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px", marginTop: "32px" }}>Phase-Gated Delegation (v0.25.2)</h3>
          <CodeBlock
            code={`from aiglos.integrations.agent_phase import AgentPhase

guard.unlock_phase(AgentPhase.P1, operator="will@aiglos.dev")  # observe only
guard.unlock_phase(AgentPhase.P2, operator="will@aiglos.dev")  # low-risk auto-approve
guard.unlock_phase(AgentPhase.P3, operator="will@aiglos.dev")  # content autonomy
guard.unlock_phase(AgentPhase.P4, operator="will@aiglos.dev")  # site operations
guard.unlock_phase(AgentPhase.P5, operator="will@aiglos.dev")  # self-evolution`}
          />

          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "12px", marginTop: "32px" }}>Gigabrain + Persistent Memory (v0.25.3)</h3>
          <CodeBlock
            code={`from aiglos.integrations.gigabrain import gigabrain_autodetect, declare_memory_backend

session = gigabrain_autodetect(guard)  # scans ~/.gigabrain/, registers with T79

# Or explicit backend declaration
declare_memory_backend(guard, backend="chroma", db_path="./chroma.db")
# 8 backends: Gigabrain, MemoryOS, mem0, Letta, Zep, Chroma, Pinecone, Qdrant`}
          />
        </Section>

        {/* GOVBENCH */}
        <Section title="GOVBENCH" id="govbench">
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
            The first governance benchmark for AI agents. 5 dimensions, 20 scenarios, A-F grade, under 60 seconds.
          </p>
          <CodeBlock
            code={`aiglos benchmark run

# Grade: A (92/100)
# D1 Campaign detection:           19/20
# D2 Agent definition resistance:  20/20
# D3 Memory belief integrity:      18/20
# D4 RL feedback loop resistance:  18/20
# D5 Multi-agent cascading failure: 17/20`}
          />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "8px", marginBottom: "24px" }}>
            {[
              { id: "D1", name: "Campaign Detection", max: 20 },
              { id: "D2", name: "Agent Definition Resistance", max: 20 },
              { id: "D3", name: "Memory Belief Integrity", max: 20 },
              { id: "D4", name: "RL Feedback Loop Resistance", max: 20 },
              { id: "D5", name: "Multi-Agent Cascading Failure", max: 20 },
            ].map((d) => (
              <div
                key={d.id}
                style={{
                  padding: "16px",
                  border: "1px solid rgba(255,255,255,0.06)",
                  borderRadius: "4px",
                  textAlign: "center",
                }}
              >
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "14px", color: "#60a5fa", fontWeight: 700, marginBottom: "4px" }}>{d.id}</div>
                <div style={{ fontSize: "10px", color: "rgba(255,255,255,0.4)", lineHeight: 1.3 }}>{d.name}</div>
                <div style={{ fontSize: "10px", color: "rgba(255,255,255,0.25)", marginTop: "4px" }}>/{d.max}</div>
              </div>
            ))}
          </div>
        </Section>

        {/* CLI REFERENCE */}
        <Section title="CLI Reference" id="cli">
          {[
            {
              group: "Onboarding",
              commands: [
                ["aiglos launch", "OpenClaw production-ready in 5 minutes"],
                ['aiglos launch --from "description"', "Non-interactive, from description"],
                ["aiglos agents scaffold", "NL description to declare_subagent() calls"],
              ],
            },
            {
              group: "Core",
              commands: [
                ["aiglos attach", "Attach to running agent session"],
                ["aiglos check <tool> <args>", "Manual check against all 82 rules"],
                ["aiglos attest --session SESSION_ID", "Produce signed attestation"],
                ["aiglos verify SESSION_ID.aiglos", "Verify artifact integrity"],
              ],
            },
            {
              group: "Policy",
              commands: [
                ["aiglos policy list", "Pending proposals"],
                ["aiglos policy approve prp_abc123 user@co.com", "Approve policy proposal"],
                ["aiglos policy lockdown", "Deny-first mode"],
                ["aiglos policy recommend", "Min viable allowlist from session history"],
              ],
            },
            {
              group: "Intelligence",
              commands: [
                ["aiglos benchmark run", "GOVBENCH A-F grade"],
                ["aiglos forecast", "Current intent prediction state"],
                ["aiglos autoresearch watch-ghsa", "GHSA watcher"],
                ["aiglos autoresearch atlas-coverage", "ATLAS threat model coverage"],
                ["aiglos scan-deps", "Check installed packages for compromise"],
                ["aiglos scan-exposed", "CVE-2026-25253 exposure probe"],
                ["aiglos audit --hardening-check", "Compare against hardened baseline"],
              ],
            },
            {
              group: "Memory and Sub-agents",
              commands: [
                ["aiglos memory status", "Memory backend status"],
                ["aiglos memory scan --backend gigabrain", "Scan memory backend"],
                ["aiglos subagents list", "List declared sub-agents"],
                ["aiglos subagents declare --name scout --tools web_search,analytics", "Declare sub-agent"],
              ],
            },
            {
              group: "Daemon",
              commands: [
                ["aiglos daemon start", "Start background daemon"],
                ["aiglos daemon status", "Check daemon status"],
                ["aiglos daemon stop", "Stop daemon"],
              ],
            },
          ].map((section) => (
            <div key={section.group} style={{ marginBottom: "24px" }}>
              <h3 style={{ fontSize: "14px", fontWeight: 600, marginBottom: "12px" }}>{section.group}</h3>
              <div
                style={{
                  border: "1px solid rgba(255,255,255,0.06)",
                  borderRadius: "6px",
                  overflow: "hidden",
                }}
              >
                {section.commands.map(([cmd, desc], i) => (
                  <div
                    key={cmd}
                    style={{
                      padding: "10px 16px",
                      borderBottom: i < section.commands.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
                      display: "grid",
                      gridTemplateColumns: "360px 1fr",
                      gap: "16px",
                      alignItems: "center",
                    }}
                  >
                    <code style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: "#4ade80" }}>{cmd}</code>
                    <span style={{ fontSize: "12px", color: "rgba(255,255,255,0.4)" }}>{desc}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </Section>

        {/* COMPLIANCE */}
        <Section title="Compliance and Attestation" id="compliance">
          <p style={{ fontSize: "14px", color: "rgba(255,255,255,0.6)", lineHeight: 1.8, marginBottom: "20px", maxWidth: "640px" }}>
            Every session close produces a cryptographically signed audit record.
          </p>
          <CodeBlock
            filename="Session artifact"
            code={`{
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
}`}
          />

          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "16px", marginTop: "32px" }}>Compliance Standard Coverage</h3>
          <div style={{ border: "1px solid rgba(255,255,255,0.06)", borderRadius: "6px", overflow: "hidden" }}>
            {[
              ["NDAA Section 1513 FY2026", "June 16, 2026", "#4ade80", "attestation_ready auto-generated per session"],
              ["CMMC Level 2", "Ongoing", "#4ade80", "C3PAO-formatted evidence package"],
              ["NIST SP 800-171 Rev 2", "Ongoing", "#4ade80", "18 controls across AC, AU, IA, SC, SI"],
              ["EU AI Act", "August 2026", "#fbbf24", "Pro tier and above"],
              ["SOC 2 Type II", "Ongoing", "#4ade80", "CC6, CC7 coverage"],
            ].map(([std, deadline, color, note], i, arr) => (
              <div
                key={std}
                style={{
                  padding: "12px 20px",
                  borderBottom: i < arr.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
                  display: "grid",
                  gridTemplateColumns: "200px 120px 1fr",
                  alignItems: "center",
                  gap: "16px",
                }}
              >
                <div style={{ fontSize: "13px", color: "rgba(255,255,255,0.7)" }}>{std}</div>
                <div style={{ fontSize: "12px", color }}>{deadline}</div>
                <div style={{ fontSize: "12px", color: "rgba(255,255,255,0.4)" }}>{note}</div>
              </div>
            ))}
          </div>
        </Section>

        {/* INTELLIGENCE */}
        <Section title="Intelligence Layers" id="intelligence">
          {[
            {
              title: "Behavioral Baseline",
              desc: "Per-agent statistical fingerprinting across three independent feature spaces: event rate (z-score), surface mix (chi-squared), and rule frequency (KL-divergence). BEHAVIORAL_ANOMALY trigger fires when composite deviation exceeds threshold.",
            },
            {
              title: "Predictive Intent Modeling",
              desc: "Deployment-specific Markov chain trained on local call history. No external ML dependency. SessionForecaster pre-tightens effective_tier() when predicted next action is Tier 2 or Tier 3. THREAT_FORECAST_ALERT fires before the threat executes.",
            },
            {
              title: "Federated Threat Intelligence",
              desc: "Privacy-preserving global threat intelligence. Differential privacy with Laplace mechanism (epsilon=0.1). Only noisy unigram transition counts leave a deployment. New deployments start pre-warmed from collective intelligence.",
            },
            {
              title: "Policy Proposals",
              desc: "Evidence-weighted policy decisions. LOWER_TIER (5+ blocks, 60%), RAISE_THRESHOLD (8+ blocks, 70%), ALLOW_LIST (10+ blocks, 80%), SUPPRESS_PATTERN (15+ blocks, 90%).",
            },
            {
              title: "Causal Attribution",
              desc: "Traces the causal chain from a block event back to the originating injection point. Answers 'what caused this agent to make this call?' rather than just logging that it was blocked.",
            },
            {
              title: "Source Reputation",
              desc: "Inbound data sources scored against a reputation index. Sources that previously triggered injection rules receive elevated inspection in future sessions across deployments when federation is enabled.",
            },
          ].map((layer) => (
            <div
              key={layer.title}
              style={{
                marginBottom: "20px",
                padding: "20px",
                border: "1px solid rgba(255,255,255,0.06)",
                borderRadius: "6px",
              }}
            >
              <div style={{ fontSize: "14px", fontWeight: 600, marginBottom: "8px" }}>{layer.title}</div>
              <p style={{ fontSize: "13px", color: "rgba(255,255,255,0.5)", lineHeight: 1.6 }}>{layer.desc}</p>
            </div>
          ))}
        </Section>

        {/* PRICING */}
        <Section title="Pricing" id="pricing-ref">
          <div style={{ border: "1px solid rgba(255,255,255,0.06)", borderRadius: "6px", overflow: "hidden" }}>
            {[
              ["Community", "$0 / MIT", "Full T01-T82 detection, 3 surfaces, 23 campaign patterns, GOVBENCH, GHSA watcher, ATLAS coverage, OpenShell, NemoClaw, Superpowers, Gigabrain, declare_subagent(), hard_bans, AgentPhase, aiglos launch, GitHub Actions CI"],
              ["Pro", "$49/dev/mo", "Community + federated intelligence, behavioral baseline, RSA-2048 signed artifacts, NDAA Section 1513 + EU AI Act compliance export, policy proposals, cloud dashboard"],
              ["Teams", "$399/mo (15 devs)", "Pro + centralized policy, aggregated threat view, Tier 3 approval workflows, audit exports"],
              ["Enterprise", "Custom, annual", "Teams + private federation server, air-gap deployment, C3PAO packages, dedicated engineering, NET-30"],
            ].map(([tier, price, features], i, arr) => (
              <div
                key={tier}
                style={{
                  padding: "16px 20px",
                  borderBottom: i < arr.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
                  display: "grid",
                  gridTemplateColumns: "120px 160px 1fr",
                  gap: "16px",
                  alignItems: "start",
                }}
              >
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", fontWeight: 600, color: "#60a5fa" }}>{tier}</div>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: "#fff" }}>{price}</div>
                <div style={{ fontSize: "12px", color: "rgba(255,255,255,0.5)", lineHeight: 1.6 }}>{features}</div>
              </div>
            ))}
          </div>
          <p style={{ marginTop: "16px", fontSize: "13px", color: "rgba(255,255,255,0.4)", lineHeight: 1.6 }}>
            Conversion mechanic: first call to aiglos.attest() or cloud telemetry connection auto-starts a
            30-day Pro trial. No feature blocked. By day 30, the developer has built their workflow around
            signed artifacts. The decision is already made.
          </p>
        </Section>

        {/* BUILD HISTORY */}
        <Section title="Build History" id="build-history">
          <div style={{ border: "1px solid rgba(255,255,255,0.06)", borderRadius: "6px", overflow: "hidden" }}>
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
              ["v0.25.8", "1,842", "82", "23", "T80-T82, REPO_TAKEOVER_CHAIN, METACOGNITIVE_POISON_CHAIN"],
            ].map(([ver, tests, rules, campaigns, notes], i, arr) => (
              <div
                key={ver}
                style={{
                  padding: "10px 20px",
                  borderBottom: i < arr.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
                  display: "grid",
                  gridTemplateColumns: "80px 80px 60px 70px 1fr",
                  gap: "12px",
                  alignItems: "center",
                  fontSize: "12px",
                }}
              >
                <span style={{ fontFamily: "'DM Mono', monospace", color: "#60a5fa" }}>{ver}</span>
                <span style={{ color: "rgba(255,255,255,0.5)" }}>{tests} tests</span>
                <span style={{ color: "rgba(255,255,255,0.5)" }}>{rules}</span>
                <span style={{ color: "rgba(255,255,255,0.5)" }}>{campaigns}</span>
                <span style={{ color: "rgba(255,255,255,0.4)" }}>{notes}</span>
              </div>
            ))}
          </div>
          <p style={{ marginTop: "16px", fontSize: "11px", color: "rgba(255,255,255,0.25)", fontFamily: "'DM Mono', monospace" }}>
            Generated from v0.25.8 codebase. 1,842 tests passing. github.com/aiglos/aiglos
          </p>
        </Section>
      </div>
    </div>
  );
}
