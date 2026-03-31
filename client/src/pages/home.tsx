import { useState } from "react";
import { Link } from "wouter";
import { useSeo } from "@/hooks/use-seo";

export default function HomePage() {
  const [copied, setCopied] = useState(false);

  useSeo({
    title: "Aiglos - Runtime Security for AI Agents",
    description:
      "The runtime security layer for AI agents. 82 threat families. One import. Under 1ms. 3/3 published OpenClaw GHSAs caught by existing rules.",
    ogTitle: "Aiglos - Runtime Security for AI Agents",
  });

  const handleCopy = () => {
    navigator.clipboard.writeText("pip install aiglos && aiglos launch");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div>
      {/* HERO - LiteLLM Incident First */}
      <section
        style={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          textAlign: "center",
          padding: "80px 48px 64px",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            position: "absolute",
            inset: 0,
            background:
              "radial-gradient(ellipse 80% 60% at 50% 20%, rgba(37,99,235,0.08) 0%, transparent 70%)",
            pointerEvents: "none",
          }}
        />

        {/* Incident Badge */}
        <div
          className="fade-up"
          data-testid="badge-incident"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            background: "rgba(239,68,68,0.1)",
            border: "1px solid rgba(239,68,68,0.25)",
            borderRadius: "100px",
            padding: "5px 14px",
            marginBottom: "32px",
            fontFamily: "'DM Mono', monospace",
            fontSize: "11px",
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color: "#ef4444",
            position: "relative",
            zIndex: 1,
          }}
        >
          <span
            style={{
              width: "6px",
              height: "6px",
              borderRadius: "50%",
              background: "#ef4444",
              animation: "pulse 2s infinite",
            }}
          />
          March 24, 2026 - Supply chain attack confirmed
        </div>

        <h1
          className="fade-up delay-1"
          data-testid="text-hero-title"
          style={{
            fontSize: "clamp(32px, 5vw, 64px)",
            fontWeight: 700,
            lineHeight: 1.05,
            letterSpacing: "-0.03em",
            maxWidth: "900px",
            marginBottom: "24px",
            position: "relative",
            zIndex: 1,
          }}
        >
          LiteLLM 1.82.8 exfiltrated every credential on every machine that installed it.{" "}
          <span style={{ color: "#60a5fa" }}>T81 caught it.</span>
        </h1>

        <p
          className="fade-up delay-2"
          style={{
            fontSize: "18px",
            fontWeight: 300,
            color: "rgba(255,255,255,0.6)",
            maxWidth: "600px",
            lineHeight: 1.65,
            marginBottom: "48px",
            position: "relative",
            zIndex: 1,
          }}
        >
          97 million monthly downloads. SSH keys, AWS credentials, database passwords, crypto wallets
          sent to models.litellm.cloud. One .pth file. Aiglos rule T81 PTH_FILE_INJECT existed before anyone
          knew the attack happened.
        </p>

        {/* Dual CTAs */}
        <div
          className="fade-up delay-2"
          style={{
            display: "flex",
            gap: "16px",
            alignItems: "stretch",
            flexWrap: "wrap",
            justifyContent: "center",
            marginBottom: "48px",
            position: "relative",
            zIndex: 1,
          }}
        >
          {/* Developer CTA */}
          <div
            data-testid="cta-developer"
            style={{
              background: "#111116",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: "6px",
              padding: "16px 24px",
              display: "flex",
              alignItems: "center",
              gap: "16px",
            }}
          >
            <div style={{ textAlign: "left" }}>
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "10px",
                  letterSpacing: "0.15em",
                  textTransform: "uppercase",
                  color: "rgba(255,255,255,0.35)",
                  marginBottom: "4px",
                }}
              >
                For developers
              </div>
              <code
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "13px",
                  color: "#fff",
                }}
              >
                pip install aiglos && aiglos launch
              </code>
            </div>
            <button
              data-testid="button-copy-install"
              onClick={handleCopy}
              style={{
                background: "none",
                border: "1px solid rgba(255,255,255,0.06)",
                borderRadius: "3px",
                padding: "4px 10px",
                fontFamily: "'DM Mono', monospace",
                fontSize: "10px",
                color: copied ? "#4ade80" : "rgba(255,255,255,0.35)",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>

          {/* Enterprise CTA */}
          <Link href="/compliance">
            <div
              data-testid="cta-enterprise"
              style={{
                background: "#fff",
                color: "#09090b",
                borderRadius: "6px",
                padding: "16px 24px",
                display: "flex",
                flexDirection: "column",
                justifyContent: "center",
                cursor: "pointer",
                transition: "opacity 0.15s",
              }}
            >
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "10px",
                  letterSpacing: "0.15em",
                  textTransform: "uppercase",
                  color: "rgba(0,0,0,0.4)",
                  marginBottom: "4px",
                }}
              >
                For enterprise
              </div>
              <span
                style={{
                  fontSize: "13px",
                  fontWeight: 600,
                }}
              >
                See compliance coverage
              </span>
            </div>
          </Link>
        </div>

        {/* 3/3 GHSA Proof Banner */}
        <div
          className="fade-up delay-3"
          data-testid="banner-ghsa-proof"
          style={{
            display: "flex",
            gap: "48px",
            flexWrap: "wrap",
            justifyContent: "center",
            position: "relative",
            zIndex: 1,
          }}
        >
          {[
            ["3/3", "GHSAs caught"],
            ["82", "Threat families"],
            ["23", "Campaign patterns"],
            ["<1ms", "Per call"],
            ["0", "Dependencies"],
          ].map(([n, l]) => (
            <div key={l} style={{ textAlign: "center" }}>
              <span
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "28px",
                  fontWeight: 500,
                  color: "#fff",
                  display: "block",
                  lineHeight: 1,
                }}
              >
                {n}
              </span>
              <span
                style={{
                  fontSize: "11px",
                  letterSpacing: "0.1em",
                  textTransform: "uppercase",
                  color: "rgba(255,255,255,0.35)",
                  marginTop: "4px",
                  display: "block",
                }}
              >
                {l}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* PROOF SECTION */}
      <div
        style={{
          padding: "80px 48px",
          textAlign: "center",
          borderTop: "1px solid rgba(255,255,255,0.06)",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}
      >
        <span
          data-testid="text-proof-number"
          style={{
            fontFamily: "'DM Mono', monospace",
            fontSize: "clamp(48px, 8vw, 96px)",
            fontWeight: 500,
            color: "#fff",
            lineHeight: 1,
            display: "block",
            letterSpacing: "-0.02em",
          }}
        >
          3 / 3
        </span>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            maxWidth: "560px",
            margin: "20px auto 0",
            lineHeight: 1.6,
          }}
        >
          Every published OpenClaw GHSA caught by Aiglos rules that{" "}
          <strong style={{ color: "#fff" }}>existed before the advisories were disclosed</strong>.
          The rules came first. Every time.
        </p>
      </div>

      {/* ARCHITECTURE POSITION DIAGRAM */}
      <section
        style={{
          padding: "80px 48px",
          maxWidth: "1100px",
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
          Architecture
        </div>
        <h2
          data-testid="text-architecture-title"
          style={{
            fontSize: "clamp(28px, 4vw, 44px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            lineHeight: 1.1,
            marginBottom: "16px",
          }}
        >
          Where each product sits in the stack
        </h2>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            lineHeight: 1.7,
            maxWidth: "560px",
            marginBottom: "48px",
          }}
        >
          Every competitor operates at the API gateway or model inference layer. Aiglos operates at the
          agent runtime layer. Three surfaces. One position no one else occupies.
        </p>

        {/* Architecture Diagram */}
        <div
          data-testid="diagram-architecture"
          style={{
            border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: "8px",
            overflow: "hidden",
            background: "#111116",
          }}
        >
          {[
            {
              layer: "Package Registry",
              product: "Snyk",
              desc: "Static dependency scanning",
              color: "rgba(255,255,255,0.2)",
              isAiglos: false,
            },
            {
              layer: "Container / Sandbox Boundary",
              product: "NVIDIA OpenShell",
              desc: "Kernel-level agent sandboxing",
              color: "rgba(255,255,255,0.2)",
              isAiglos: false,
            },
            {
              layer: "API Gateway / Model Inference",
              product: "HiddenLayer",
              desc: "Model file scanning, inference-time detection",
              color: "rgba(255,255,255,0.2)",
              isAiglos: false,
            },
            {
              layer: "Agent Runtime (MCP + HTTP + Subprocess)",
              product: "Aiglos",
              desc: "Every tool call, HTTP request, and subprocess intercepted before execution",
              color: "#2563eb",
              isAiglos: true,
            },
          ].map((item) => (
            <div
              key={item.layer}
              style={{
                padding: "24px 32px",
                borderBottom: "1px solid rgba(255,255,255,0.04)",
                display: "grid",
                gridTemplateColumns: "260px 140px 1fr",
                gap: "24px",
                alignItems: "center",
                background: item.isAiglos ? "rgba(37,99,235,0.05)" : "transparent",
              }}
            >
              <div
                style={{
                  fontSize: "13px",
                  fontWeight: item.isAiglos ? 600 : 400,
                  color: item.isAiglos ? "#60a5fa" : "rgba(255,255,255,0.6)",
                }}
              >
                {item.layer}
              </div>
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "12px",
                  color: item.isAiglos ? "#fff" : "rgba(255,255,255,0.35)",
                }}
              >
                {item.product}
              </div>
              <div
                style={{
                  fontSize: "13px",
                  color: item.isAiglos ? "rgba(255,255,255,0.8)" : "rgba(255,255,255,0.35)",
                }}
              >
                {item.desc}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section
        style={{
          padding: "80px 48px",
          maxWidth: "1100px",
          margin: "0 auto",
          borderTop: "1px solid rgba(255,255,255,0.06)",
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
          How it works
        </div>
        <h2
          style={{
            fontSize: "clamp(28px, 4vw, 44px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            lineHeight: 1.1,
            marginBottom: "16px",
          }}
        >
          One line. Nothing else changes.
        </h2>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            lineHeight: 1.7,
            maxWidth: "560px",
            marginBottom: "48px",
          }}
        >
          Aiglos intercepts every tool call, HTTP request, and shell command before execution. The agent
          never knows it's running.
        </p>

        <div
          style={{
            background: "#0d1117",
            border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: "8px",
            overflow: "hidden",
            maxWidth: "680px",
          }}
        >
          <div
            style={{
              background: "#161b22",
              padding: "10px 16px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              borderBottom: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f57" }} />
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#febc2e" }} />
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#28c840" }} />
            <span
              style={{
                fontFamily: "'DM Mono', monospace",
                fontSize: "11px",
                color: "rgba(255,255,255,0.35)",
                marginLeft: "8px",
              }}
            >
              agent.py
            </span>
          </div>
          <div style={{ padding: "24px", overflowX: "auto" }}>
            <pre
              style={{
                fontFamily: "'DM Mono', monospace",
                fontSize: "13.5px",
                lineHeight: 1.75,
                color: "#e6edf3",
                margin: 0,
              }}
            >
              <span style={{ color: "#ff7b72" }}>import</span> aiglos{"\n\n"}
              aiglos.<span style={{ color: "#d2a8ff" }}>attach</span>(
              {"\n    "}
              <span style={{ color: "#79c0ff" }}>agent_name</span>=
              <span style={{ color: "#a5d6ff" }}>"my-agent"</span>,{"\n    "}
              <span style={{ color: "#79c0ff" }}>policy</span>=
              <span style={{ color: "#a5d6ff" }}>"enterprise"</span>,{"\n"}){"\n\n"}
              <span style={{ color: "#6e7681" }}>
                {"# The agent keeps running. Nothing else changes.\n"}
                {"# Until something tries to exfiltrate credentials.\n"}
                {"# Then it stops."}
              </span>
            </pre>
          </div>
        </div>
      </section>

      {/* FEATURE GRID */}
      <section
        style={{
          padding: "80px 48px",
          maxWidth: "1100px",
          margin: "0 auto",
          borderTop: "1px solid rgba(255,255,255,0.06)",
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
          Capabilities
        </div>
        <h2
          style={{
            fontSize: "clamp(28px, 4vw, 44px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            lineHeight: 1.1,
            marginBottom: "48px",
          }}
        >
          Built for the way agents actually work.
        </h2>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: "1px",
            background: "rgba(255,255,255,0.06)",
            border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: "8px",
            overflow: "hidden",
          }}
        >
          {[
            {
              title: "82 Threat Families",
              body: "T01-T82 covering MCP tool calls, HTTP/API requests, subprocess execution, session data extraction, .pth supply chain persistence, self-improvement pipeline hijacking, and every attack class in the OpenClaw ATLAS threat model.",
            },
            {
              title: "Campaign Detection",
              body: "23 multi-step attack patterns. A git log followed by a .env read followed by an outbound POST is a credential exfiltration campaign. Each call looks clean. The sequence is the attack.",
            },
            {
              title: "Behavioral Baseline",
              body: "After 20 sessions, Aiglos builds a per-agent statistical fingerprint. The DevOps agent that reads .aws/credentials scores LOW. The code review agent that suddenly does scores HIGH.",
            },
            {
              title: "Signed Audit Artifact",
              body: "Every session closes with a cryptographically signed record. HMAC-SHA256 minimum. RSA-2048 for regulatory submission. The artifact NDAA Section 1513 requires.",
            },
            {
              title: "Federation Intelligence",
              body: "Every contributing deployment shares anonymized threat patterns via differential privacy. New deployment, day one: pre-warmed from collective intelligence.",
            },
            {
              title: "GOVBENCH",
              body: "The first governance benchmark for AI agents. Five dimensions. A-F grade. Published before any standard body required one. The company that defines the benchmark owns the compliance category.",
            },
          ].map((f) => (
            <div
              key={f.title}
              style={{
                background: "#09090b",
                padding: "32px",
                transition: "background 0.2s",
              }}
            >
              <div style={{ fontSize: "15px", fontWeight: 600, marginBottom: "8px" }}>{f.title}</div>
              <div
                style={{
                  fontSize: "13px",
                  color: "rgba(255,255,255,0.35)",
                  lineHeight: 1.65,
                }}
              >
                {f.body}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* GHSA VALIDATION */}
      <section
        style={{
          padding: "80px 48px",
          maxWidth: "1100px",
          margin: "0 auto",
          borderTop: "1px solid rgba(255,255,255,0.06)",
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
          Empirical validation
        </div>
        <h2
          style={{
            fontSize: "clamp(28px, 4vw, 44px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            lineHeight: 1.1,
            marginBottom: "16px",
          }}
        >
          Every published OpenClaw vulnerability.
          <br />
          Caught by existing rules.
        </h2>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            lineHeight: 1.7,
            maxWidth: "560px",
            marginBottom: "40px",
          }}
        >
          Three published advisories. All three covered by Aiglos rules before the advisories were
          disclosed, before any patch existed.
        </p>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "1px",
            background: "rgba(255,255,255,0.06)",
            border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: "8px",
            overflow: "hidden",
          }}
        >
          {[
            {
              ghsa: "GHSA-g8p2-7wf7-98mq",
              cvss: "8.8",
              title: "1-Click RCE via Authentication Token Exfiltration",
              rules: "T03 T12 T19 T68",
            },
            {
              ghsa: "GHSA-q284-4pvr-m585",
              cvss: "8.6",
              title: "OS Command Injection via Project Root Path",
              rules: "T03 T04 T70",
            },
            {
              ghsa: "GHSA-mc68-q9jw-2h3v",
              cvss: "8.4",
              title: "Command Injection via PATH Environment Variable",
              rules: "T03 T70",
            },
          ].map((a) => (
            <div
              key={a.ghsa}
              data-testid={`row-ghsa-${a.ghsa}`}
              style={{
                background: "#111116",
                display: "grid",
                gridTemplateColumns: "180px 1fr auto",
                gap: "24px",
                padding: "20px 24px",
                alignItems: "center",
              }}
            >
              <div>
                <div
                  style={{
                    fontFamily: "'DM Mono', monospace",
                    fontSize: "11px",
                    color: "#60a5fa",
                  }}
                >
                  {a.ghsa}
                </div>
                <div
                  style={{
                    fontSize: "10px",
                    color: "rgba(255,255,255,0.35)",
                    marginTop: "2px",
                  }}
                >
                  CVSS {a.cvss}
                </div>
              </div>
              <div
                style={{
                  fontSize: "13px",
                  color: "rgba(255,255,255,0.6)",
                }}
              >
                {a.title}
              </div>
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "11px",
                  color: "#4ade80",
                  whiteSpace: "nowrap",
                }}
              >
                {a.rules} ✓
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section
        style={{
          padding: "80px 48px",
          maxWidth: "1100px",
          margin: "0 auto",
          borderTop: "1px solid rgba(255,255,255,0.06)",
          textAlign: "center",
        }}
      >
        <h2
          style={{
            fontSize: "clamp(28px, 4vw, 44px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            marginBottom: "16px",
          }}
        >
          Start in 30 seconds.
        </h2>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            marginBottom: "32px",
          }}
        >
          The free tier runs the full detection engine. Every rule. Every campaign pattern.
        </p>
        <div style={{ display: "flex", gap: "16px", justifyContent: "center", flexWrap: "wrap" }}>
          <Link href="/scan">
            <span
              data-testid="link-try-scan"
              style={{
                fontFamily: "'DM Mono', monospace",
                fontSize: "11px",
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                color: "rgba(255,255,255,0.35)",
                textDecoration: "none",
                padding: "12px 24px",
                border: "1px solid rgba(255,255,255,0.1)",
                borderRadius: "4px",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
            >
              Try the scanner
            </span>
          </Link>
          <Link href="/pricing">
            <span
              data-testid="link-view-pricing"
              style={{
                fontFamily: "'DM Mono', monospace",
                fontSize: "11px",
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                background: "#fff",
                color: "#09090b",
                padding: "12px 24px",
                borderRadius: "4px",
                cursor: "pointer",
                textDecoration: "none",
                transition: "opacity 0.15s",
              }}
            >
              View pricing
            </span>
          </Link>
        </div>
      </section>
    </div>
  );
}
