import { useSeo } from "@/hooks/use-seo";

export default function ComparePage() {
  useSeo({
    title: "Aiglos vs HiddenLayer, Snyk, OpenShell - AI Security Comparison | Aiglos",
    description:
      "Honest feature comparison: Aiglos vs HiddenLayer, Snyk mcp-scan, and NVIDIA OpenShell. Different architectures, different layers, complementary but distinct.",
    ogTitle: "AI Security Tool Comparison | Aiglos",
  });

  const featureMatrix = [
    {
      feature: "What it protects",
      aiglos: "Agents (runtime behavior)",
      hiddenlayer: "Models (pre-deployment + inference)",
      snyk: "Dependencies (static scanning)",
      openshell: "Containers (kernel-level sandbox)",
    },
    {
      feature: "Interception surface",
      aiglos: "MCP + HTTP + subprocess",
      hiddenlayer: "API gateway + model inference",
      snyk: "Package manifest only",
      openshell: "Syscall + network boundary",
    },
    {
      feature: "Multi-step attack detection",
      aiglos: "23 campaign patterns across sessions",
      hiddenlayer: "Cascading chains (single session)",
      snyk: "None",
      openshell: "None",
    },
    {
      feature: "Signed audit artifact",
      aiglos: "HMAC-SHA256 / RSA-2048 per session",
      hiddenlayer: "Audit-ready logs (unsigned)",
      snyk: "None",
      openshell: "None",
    },
    {
      feature: "Agent definition monitoring",
      aiglos: "T36 monitors .cursorrules, AGENTS.md, claude.md, YAML configs",
      hiddenlayer: "Not covered",
      snyk: "Not covered",
      openshell: "Not covered",
    },
    {
      feature: "Persistent memory protection",
      aiglos: "T79 guards Gigabrain, Chroma, Pinecone, Qdrant, mem0, Letta, Zep",
      hiddenlayer: "Partial (RAG poisoning only)",
      snyk: "None",
      openshell: "None",
    },
    {
      feature: "Self-improvement pipeline",
      aiglos: "T82 monitors auto-fine-tuning, recursive self-mod",
      hiddenlayer: "Not covered",
      snyk: "None",
      openshell: "None",
    },
    {
      feature: "Coding agent integrations",
      aiglos: "Claude Code, Cursor, Codex, Windsurf, Aider, smolagents, Cline, Augment, OpenClaw",
      hiddenlayer: "0 (discovers vulns in Cursor/Windsurf, does not protect them)",
      snyk: "CI/CD integration only",
      openshell: "Claude Code, Codex, Cursor, OpenClaw, Windsurf, Aider, Continue, Cody",
    },
    {
      feature: "Governance benchmark",
      aiglos: "GOVBENCH: 5 dimensions, A-F grade, README badge",
      hiddenlayer: "None",
      snyk: "None",
      openshell: "None",
    },
    {
      feature: "NDAA Section 1513 compliance",
      aiglos: "Automated attestation artifact per session",
      hiddenlayer: "DoD contracts exist, no automated artifact",
      snyk: "None",
      openshell: "None",
    },
    {
      feature: "Federated threat intelligence",
      aiglos: "Differential privacy, collective intelligence across deployments",
      hiddenlayer: "SAI team research (centralized)",
      snyk: "Centralized vuln database",
      openshell: "None",
    },
    {
      feature: "Onboarding time",
      aiglos: "30 seconds (pip install aiglos && aiglos launch)",
      hiddenlayer: "Enterprise sales cycle (weeks to months)",
      snyk: "Minutes (CLI install)",
      openshell: "Minutes (container config)",
    },
    {
      feature: "Pricing",
      aiglos: "Free tier with full detection. Pro $49/dev/mo",
      hiddenlayer: "Enterprise custom (~$500/mo minimum)",
      snyk: "Free tier + paid plans",
      openshell: "Open source",
    },
  ];

  return (
    <div>
      {/* Hero */}
      <section
        style={{
          padding: "120px 48px 80px",
          maxWidth: "1200px",
          margin: "0 auto",
        }}
      >
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
          Competitive landscape
        </div>
        <h1
          data-testid="text-compare-title"
          style={{
            fontSize: "clamp(28px, 4vw, 48px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            lineHeight: 1.1,
            marginBottom: "16px",
          }}
        >
          Different architectures.
          <br />
          Different layers.
        </h1>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            lineHeight: 1.7,
            maxWidth: "620px",
            marginBottom: "48px",
          }}
        >
          HiddenLayer protects models. Snyk scans packages. OpenShell sandboxes containers. Aiglos
          protects agents at runtime. These products are complementary, not interchangeable. Here is what
          each one does, honestly.
        </p>

        {/* Architecture Position Diagram */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "1px",
            background: "rgba(255,255,255,0.06)",
            borderRadius: "8px",
            overflow: "hidden",
            marginBottom: "64px",
          }}
        >
          {[
            {
              name: "HiddenLayer",
              layer: "Model layer",
              desc: "Scans model files before deployment. Detects adversarial inputs at inference time. Discovers shadow AI across cloud environments.",
              funding: "$56M raised",
              strength: "Model supply chain security",
            },
            {
              name: "Snyk mcp-scan",
              layer: "Package layer",
              desc: "Static analysis of MCP server configurations. Identifies known-vulnerable dependencies in package manifests.",
              funding: "Public (Snyk)",
              strength: "Dependency vulnerability database",
            },
            {
              name: "NVIDIA OpenShell",
              layer: "Container layer",
              desc: "Kernel-level sandboxing. Controls what the agent can access at the OS level. Same YAML policy for all agents.",
              funding: "NVIDIA",
              strength: "Agent-agnostic sandbox",
            },
            {
              name: "Aiglos",
              layer: "Agent runtime layer",
              desc: "Wraps the agent execution environment. Intercepts every MCP tool call, HTTP request, and subprocess before execution. Sees behavior, not just inputs.",
              funding: "Open source",
              strength: "Behavioral sequence detection",
              highlight: true,
            },
          ].map((p) => (
            <div
              key={p.name}
              style={{
                background: p.highlight ? "rgba(37,99,235,0.06)" : "#111116",
                padding: "32px 24px",
              }}
            >
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "12px",
                  color: p.highlight ? "#60a5fa" : "#fff",
                  fontWeight: 600,
                  marginBottom: "4px",
                }}
              >
                {p.name}
              </div>
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "10px",
                  letterSpacing: "0.15em",
                  textTransform: "uppercase",
                  color: p.highlight ? "#60a5fa" : "rgba(255,255,255,0.35)",
                  marginBottom: "16px",
                }}
              >
                {p.layer}
              </div>
              <div
                style={{
                  fontSize: "13px",
                  color: "rgba(255,255,255,0.5)",
                  lineHeight: 1.6,
                  marginBottom: "16px",
                }}
              >
                {p.desc}
              </div>
              <div
                style={{
                  fontSize: "11px",
                  color: "rgba(255,255,255,0.25)",
                }}
              >
                {p.strength}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Feature Matrix */}
      <section
        style={{
          padding: "0 48px 80px",
          maxWidth: "1200px",
          margin: "0 auto",
        }}
      >
        <h2
          style={{
            fontSize: "clamp(24px, 3vw, 36px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            marginBottom: "40px",
          }}
        >
          Feature-by-feature comparison
        </h2>

        <div
          data-testid="table-compare"
          style={{
            width: "100%",
            overflowX: "auto",
          }}
        >
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              fontSize: "13px",
            }}
          >
            <thead>
              <tr>
                {["Capability", "Aiglos", "HiddenLayer", "Snyk mcp-scan", "OpenShell"].map(
                  (h) => (
                    <th
                      key={h}
                      style={{
                        fontFamily: "'DM Mono', monospace",
                        fontSize: "10px",
                        letterSpacing: "0.15em",
                        textTransform: "uppercase",
                        color: "rgba(255,255,255,0.35)",
                        padding: "12px 16px",
                        textAlign: "left",
                        borderBottom: "2px solid rgba(255,255,255,0.1)",
                      }}
                    >
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {featureMatrix.map((row) => (
                <tr key={row.feature}>
                  <td
                    style={{
                      padding: "14px 16px",
                      borderBottom: "1px solid rgba(255,255,255,0.06)",
                      fontWeight: 500,
                      color: "#fff",
                      verticalAlign: "top",
                      minWidth: "160px",
                    }}
                  >
                    {row.feature}
                  </td>
                  <td
                    style={{
                      padding: "14px 16px",
                      borderBottom: "1px solid rgba(255,255,255,0.06)",
                      background: "rgba(37,99,235,0.04)",
                      color: "#fff",
                      verticalAlign: "top",
                      minWidth: "200px",
                    }}
                  >
                    {row.aiglos}
                  </td>
                  <td
                    style={{
                      padding: "14px 16px",
                      borderBottom: "1px solid rgba(255,255,255,0.06)",
                      color: "rgba(255,255,255,0.6)",
                      verticalAlign: "top",
                      minWidth: "200px",
                    }}
                  >
                    {row.hiddenlayer}
                  </td>
                  <td
                    style={{
                      padding: "14px 16px",
                      borderBottom: "1px solid rgba(255,255,255,0.06)",
                      color: "rgba(255,255,255,0.6)",
                      verticalAlign: "top",
                      minWidth: "160px",
                    }}
                  >
                    {row.snyk}
                  </td>
                  <td
                    style={{
                      padding: "14px 16px",
                      borderBottom: "1px solid rgba(255,255,255,0.06)",
                      color: "rgba(255,255,255,0.6)",
                      verticalAlign: "top",
                      minWidth: "160px",
                    }}
                  >
                    {row.openshell}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Key Insight */}
      <section
        style={{
          padding: "80px 48px",
          maxWidth: "1100px",
          margin: "0 auto",
          borderTop: "1px solid rgba(255,255,255,0.06)",
        }}
      >
        <h2
          style={{
            fontSize: "clamp(24px, 3vw, 36px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            marginBottom: "24px",
          }}
        >
          The architectural gap
        </h2>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "24px",
          }}
        >
          <div
            style={{
              background: "#111116",
              border: "1px solid rgba(255,255,255,0.06)",
              borderRadius: "8px",
              padding: "32px",
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
              HiddenLayer sees
            </div>
            <ul
              style={{
                listStyle: "none",
                padding: 0,
                margin: 0,
                fontSize: "13px",
                color: "rgba(255,255,255,0.6)",
                lineHeight: 2,
              }}
            >
              <li>What goes into the model</li>
              <li>What comes out of the model</li>
              <li>Malware embedded in model files</li>
              <li>Adversarial inputs at inference time</li>
            </ul>
          </div>

          <div
            style={{
              background: "rgba(37,99,235,0.06)",
              border: "1px solid rgba(37,99,235,0.2)",
              borderRadius: "8px",
              padding: "32px",
            }}
          >
            <div
              style={{
                fontFamily: "'DM Mono', monospace",
                fontSize: "10px",
                letterSpacing: "0.2em",
                textTransform: "uppercase",
                color: "#60a5fa",
                marginBottom: "16px",
              }}
            >
              Aiglos sees
            </div>
            <ul
              style={{
                listStyle: "none",
                padding: 0,
                margin: 0,
                fontSize: "13px",
                color: "rgba(255,255,255,0.8)",
                lineHeight: 2,
              }}
            >
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

        <p
          style={{
            marginTop: "32px",
            fontSize: "14px",
            color: "rgba(255,255,255,0.5)",
            lineHeight: 1.7,
            maxWidth: "680px",
          }}
        >
          HiddenLayer operates between the application and the model. Aiglos wraps the agent itself. This
          means Aiglos sees attacks that never touch the model layer: agent definition file tampering,
          memory poisoning across sessions, self-improvement pipeline exploitation, and multi-step
          campaigns that unfold over days rather than single sessions. For organizations deploying
          autonomous agents with tool access, persistent memory, and self-improvement capabilities, these
          are the threat vectors that matter.
        </p>
      </section>
    </div>
  );
}
