import { useSeo } from "@/hooks/use-seo";
import SectionLabel from "@/components/public/section-label";
import RevealSection from "@/components/public/reveal-section";

const featureMatrix = [
  { feature: "What it protects", aiglos: "Agents (runtime behavior)", hiddenlayer: "Models (pre-deployment + inference)", snyk: "Dependencies (static scanning)", openshell: "Containers (kernel-level sandbox)" },
  { feature: "Interception surface", aiglos: "MCP + HTTP + subprocess", hiddenlayer: "API gateway + model inference", snyk: "Package manifest only", openshell: "Syscall + network boundary" },
  { feature: "Multi-step attack detection", aiglos: "23 campaign patterns across sessions", hiddenlayer: "Cascading chains (single session)", snyk: "None", openshell: "None" },
  { feature: "Signed audit artifact", aiglos: "HMAC-SHA256 / RSA-2048 per session", hiddenlayer: "Audit-ready logs (unsigned)", snyk: "None", openshell: "None" },
  { feature: "Agent definition monitoring", aiglos: "T36 monitors .cursorrules, AGENTS.md, claude.md, YAML configs", hiddenlayer: "Not covered", snyk: "Not covered", openshell: "Not covered" },
  { feature: "Persistent memory protection", aiglos: "T79 guards Gigabrain, Chroma, Pinecone, Qdrant, mem0, Letta, Zep", hiddenlayer: "Partial (RAG poisoning only)", snyk: "None", openshell: "None" },
  { feature: "Self-improvement pipeline", aiglos: "T82 monitors auto-fine-tuning, recursive self-mod", hiddenlayer: "Not covered", snyk: "None", openshell: "None" },
  { feature: "Coding agent integrations", aiglos: "Claude Code, Cursor, Codex, Windsurf, Aider, smolagents, Cline, Augment, OpenClaw", hiddenlayer: "0 (discovers vulns in Cursor/Windsurf, does not protect them)", snyk: "CI/CD integration only", openshell: "Claude Code, Codex, Cursor, OpenClaw, Windsurf, Aider, Continue, Cody" },
  { feature: "Governance benchmark", aiglos: "GOVBENCH: 5 dimensions, A-F grade, README badge", hiddenlayer: "None", snyk: "None", openshell: "None" },
  { feature: "NDAA Section 1513 compliance", aiglos: "Automated attestation artifact per session", hiddenlayer: "DoD contracts exist, no automated artifact", snyk: "None", openshell: "None" },
  { feature: "Federated threat intelligence", aiglos: "Differential privacy, collective intelligence across deployments", hiddenlayer: "SAI team research (centralized)", snyk: "Centralized vuln database", openshell: "None" },
  { feature: "Onboarding time", aiglos: "30 seconds (pip install aiglos && aiglos launch)", hiddenlayer: "Enterprise sales cycle (weeks to months)", snyk: "Minutes (CLI install)", openshell: "Minutes (container config)" },
  { feature: "Pricing", aiglos: "Free tier with full detection. Pro $49/dev/mo", hiddenlayer: "Enterprise custom (~$500/mo minimum)", snyk: "Free tier + paid plans", openshell: "Open source" },
];

const competitors = [
  { name: "HiddenLayer", layer: "Model layer", desc: "Scans model files before deployment. Detects adversarial inputs at inference time. Discovers shadow AI across cloud environments.", strength: "Model supply chain security", highlight: false },
  { name: "Snyk mcp-scan", layer: "Package layer", desc: "Static analysis of MCP server configurations. Identifies known-vulnerable dependencies in package manifests.", strength: "Dependency vulnerability database", highlight: false },
  { name: "NVIDIA OpenShell", layer: "Container layer", desc: "Kernel-level sandboxing. Controls what the agent can access at the OS level. Same YAML policy for all agents.", strength: "Agent-agnostic sandbox", highlight: false },
  { name: "Aiglos", layer: "Agent runtime layer", desc: "Wraps the agent execution environment. Intercepts every MCP tool call, HTTP request, and subprocess before execution. Sees behavior, not just inputs.", strength: "Behavioral sequence detection", highlight: true },
];

export default function ComparePage() {
  useSeo({
    title: "Aiglos vs HiddenLayer, Snyk, OpenShell - AI Security Comparison | Aiglos",
    description: "Honest feature comparison: Aiglos vs HiddenLayer, Snyk mcp-scan, and NVIDIA OpenShell. Different architectures, different layers, complementary but distinct.",
    ogTitle: "AI Security Tool Comparison | Aiglos",
  });

  return (
    <div>
      <section className="pt-28 pb-20 px-12 max-w-[1200px] mx-auto">
        <SectionLabel>Competitive landscape</SectionLabel>
        <h1
          data-testid="text-compare-title"
          className="text-[clamp(28px,4vw,48px)] font-bold tracking-tight leading-[1.1] mb-4"
        >
          Different architectures.
          <br />
          Different layers.
        </h1>
        <p className="text-base text-pub-muted leading-[1.7] max-w-[620px] mb-12">
          HiddenLayer protects models. Snyk scans packages. OpenShell sandboxes containers. Aiglos
          protects agents at runtime. These products are complementary, not interchangeable. Here is what
          each one does, honestly.
        </p>

        <div className="grid grid-cols-4 pub-grid-4 gap-px bg-white/[0.06] rounded-lg overflow-hidden mb-16">
          {competitors.map((p) => (
            <div key={p.name} className={`p-8 ${p.highlight ? "bg-pub-blue/[0.06]" : "bg-pub-card"}`}>
              <div className={`font-pub-mono text-xs font-semibold mb-1 ${p.highlight ? "text-pub-ice" : "text-white"}`}>
                {p.name}
              </div>
              <div className={`font-pub-mono text-[10px] tracking-[0.15em] uppercase mb-4 ${p.highlight ? "text-pub-ice" : "text-pub-dim"}`}>
                {p.layer}
              </div>
              <div className="text-[13px] text-white/50 leading-[1.6] mb-4">{p.desc}</div>
              <div className="text-[11px] text-white/25">{p.strength}</div>
            </div>
          ))}
        </div>
      </section>

      <RevealSection className="pb-20 px-12 max-w-[1200px] mx-auto">
        <h2 className="text-[clamp(24px,3vw,36px)] font-bold tracking-tight mb-10">
          Feature-by-feature comparison
        </h2>

        <div data-testid="table-compare" className="w-full overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr>
                {["Capability", "Aiglos", "HiddenLayer", "Snyk mcp-scan", "OpenShell"].map((h) => (
                  <th key={h} className="font-pub-mono text-[10px] tracking-[0.15em] uppercase text-pub-dim py-3 px-4 text-left border-b-2 border-white/10">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {featureMatrix.map((row) => (
                <tr key={row.feature}>
                  <td className="py-3.5 px-4 border-b border-white/[0.06] font-medium text-white align-top min-w-[160px]">{row.feature}</td>
                  <td className="py-3.5 px-4 border-b border-white/[0.06] bg-pub-blue/[0.04] text-white align-top min-w-[200px]">{row.aiglos}</td>
                  <td className="py-3.5 px-4 border-b border-white/[0.06] text-white/60 align-top min-w-[200px]">{row.hiddenlayer}</td>
                  <td className="py-3.5 px-4 border-b border-white/[0.06] text-white/60 align-top min-w-[160px]">{row.snyk}</td>
                  <td className="py-3.5 px-4 border-b border-white/[0.06] text-white/60 align-top min-w-[160px]">{row.openshell}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </RevealSection>

      <RevealSection className="py-20 px-12 max-w-[1100px] mx-auto border-t border-pub">
        <h2 className="text-[clamp(24px,3vw,36px)] font-bold tracking-tight mb-6">
          The architectural gap
        </h2>

        <div className="grid grid-cols-2 pub-grid-2 gap-6">
          <div className="bg-pub-card border border-pub rounded-lg p-8">
            <div className="font-pub-mono text-[10px] tracking-[0.2em] uppercase text-pub-dim mb-4">HiddenLayer sees</div>
            <ul className="list-none p-0 m-0 text-[13px] text-white/60 leading-[2]">
              <li>What goes into the model</li>
              <li>What comes out of the model</li>
              <li>Malware embedded in model files</li>
              <li>Adversarial inputs at inference time</li>
            </ul>
          </div>

          <div className="bg-pub-blue/[0.06] border border-pub-blue/20 rounded-lg p-8">
            <div className="font-pub-mono text-[10px] tracking-[0.2em] uppercase text-pub-ice mb-4">Aiglos sees</div>
            <ul className="list-none p-0 m-0 text-[13px] text-white/80 leading-[2]">
              <li>Every tool call the agent makes</li>
              <li>Every HTTP request it sends</li>
              <li>Every subprocess it spawns</li>
              <li>Multi-step sequences across sessions</li>
              <li>Agent definition file tampering</li>
              <li>Cross-session memory poisoning</li>
              <li>Self-improvement pipeline exploitation</li>
            </ul>
          </div>
        </div>

        <p className="mt-8 text-sm text-white/50 leading-[1.7] max-w-[680px]">
          HiddenLayer operates between the application and the model. Aiglos wraps the agent itself. This
          means Aiglos sees attacks that never touch the model layer: agent definition file tampering,
          memory poisoning across sessions, self-improvement pipeline exploitation, and multi-step
          campaigns that unfold over days rather than single sessions. For organizations deploying
          autonomous agents with tool access, persistent memory, and self-improvement capabilities, these
          are the threat vectors that matter.
        </p>
      </RevealSection>
    </div>
  );
}
