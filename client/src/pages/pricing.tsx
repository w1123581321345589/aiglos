import { useSeo } from "@/hooks/use-seo";
import { Link } from "wouter";

export default function PricingPage() {
  useSeo({
    title: "Pricing - Community, Pro, Teams, Enterprise | Aiglos",
    description:
      "Free to detect. Pro to prove. Full T01-T82 detection engine free. Signed artifacts, federated intelligence, and compliance exports on Pro.",
    ogTitle: "Aiglos Pricing",
  });

  const tiers = [
    {
      name: "Community",
      price: "$0",
      period: "forever",
      description: "Full detection engine. Every rule. Every campaign pattern.",
      features: [
        "Full T01-T82 detection (82 rules)",
        "All 23 campaign patterns",
        "3 interception surfaces (MCP + HTTP + subprocess)",
        "GOVBENCH governance benchmark",
        "GHSA watcher",
        "ATLAS coverage reports",
        "OpenShell + NemoClaw integration",
        "Superpowers plan-as-policy",
        "Gigabrain persistent memory guard",
        "declare_subagent() + hard_bans",
        "AgentPhase progressive delegation",
        "aiglos launch (5-minute setup)",
        "aiglos agents scaffold",
        "GitHub Actions CI integration",
        "HMAC-SHA256 session artifacts",
      ],
      cta: "pip install aiglos",
      ctaStyle: "ghost" as const,
      highlight: false,
    },
    {
      name: "Pro",
      price: "$49",
      period: "/dev/mo",
      description: "Everything in Community, plus the proof that turns detection into compliance.",
      features: [
        "Everything in Community",
        "Federated threat intelligence",
        "Behavioral baseline per agent",
        "RSA-2048 signed artifacts",
        "NDAA Section 1513 compliance export",
        "EU AI Act compliance export",
        "CMMC Level 2 evidence package",
        "NIST SP 800-171 mapping",
        "SOC 2 Type II coverage",
        "Policy proposals (evidence-weighted)",
        "Cloud dashboard",
        "Intent prediction (Markov chain)",
        "Source reputation scoring",
        "Causal attribution tracing",
      ],
      cta: "Start 30-day trial",
      ctaStyle: "primary" as const,
      highlight: true,
    },
    {
      name: "Teams",
      price: "$399",
      period: "/mo (15 devs)",
      description: "Pro for the whole team. Centralized policy. Aggregated threat view.",
      features: [
        "Everything in Pro",
        "Up to 15 developer seats",
        "Centralized policy management",
        "Aggregated threat view across agents",
        "Tier 3 approval workflows",
        "Audit exports (JSON, PDF)",
        "Team-wide behavioral baselines",
        "Shared allowlists and suppressions",
        "Priority support",
      ],
      cta: "Contact sales",
      ctaStyle: "ghost" as const,
      highlight: false,
    },
    {
      name: "Enterprise",
      price: "Custom",
      period: "annual",
      description: "For defense contractors and regulated industries. Air-gapped. C3PAO-ready.",
      features: [
        "Everything in Teams",
        "Private federation server",
        "Air-gap deployment",
        "C3PAO evidence packages",
        "Dedicated engineering support",
        "NET-30 payment terms",
        "Custom policy templates",
        "On-premise installation support",
        "SLA with guaranteed response times",
      ],
      cta: "Contact sales",
      ctaStyle: "ghost" as const,
      highlight: false,
    },
  ];

  return (
    <div>
      {/* Hero */}
      <section
        style={{
          padding: "120px 48px 40px",
          maxWidth: "1200px",
          margin: "0 auto",
          textAlign: "center",
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
          Pricing
        </div>
        <h1
          data-testid="text-pricing-title"
          style={{
            fontSize: "clamp(28px, 4vw, 48px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            lineHeight: 1.1,
            marginBottom: "16px",
          }}
        >
          Free to detect. Pro to prove.
        </h1>
        <p
          style={{
            fontSize: "16px",
            color: "rgba(255,255,255,0.6)",
            lineHeight: 1.7,
            maxWidth: "560px",
            margin: "0 auto 48px",
          }}
        >
          The free tier runs the full detection engine. Pro adds the federation intelligence and the signed
          compliance artifact -- the document that turns a security tool into a regulatory submission.
        </p>
      </section>

      {/* Pricing Grid */}
      <section
        style={{
          padding: "0 48px 80px",
          maxWidth: "1200px",
          margin: "0 auto",
        }}
      >
        <div
          data-testid="grid-pricing"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "1px",
            background: "rgba(255,255,255,0.06)",
            border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: "8px",
            overflow: "hidden",
          }}
        >
          {tiers.map((tier) => (
            <div
              key={tier.name}
              data-testid={`card-pricing-${tier.name.toLowerCase()}`}
              style={{
                background: tier.highlight ? "#fff" : "#09090b",
                color: tier.highlight ? "#09090b" : "#fff",
                padding: "36px 28px",
              }}
            >
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "10px",
                  letterSpacing: "0.2em",
                  textTransform: "uppercase",
                  color: tier.highlight ? "rgba(0,0,0,0.4)" : "rgba(255,255,255,0.35)",
                  marginBottom: "16px",
                }}
              >
                {tier.name}
              </div>

              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "40px",
                  fontWeight: 500,
                  lineHeight: 1,
                  marginBottom: "4px",
                }}
              >
                {tier.price}
                <span
                  style={{
                    fontSize: "14px",
                    fontWeight: 400,
                    color: tier.highlight ? "rgba(0,0,0,0.4)" : "rgba(255,255,255,0.35)",
                    marginLeft: "4px",
                  }}
                >
                  {tier.period}
                </span>
              </div>

              <p
                style={{
                  fontSize: "12px",
                  color: tier.highlight ? "rgba(0,0,0,0.5)" : "rgba(255,255,255,0.4)",
                  lineHeight: 1.5,
                  marginBottom: "24px",
                  minHeight: "36px",
                }}
              >
                {tier.description}
              </p>

              <ul
                style={{
                  listStyle: "none",
                  padding: 0,
                  margin: "0 0 24px 0",
                  fontSize: "13px",
                  lineHeight: 1.6,
                }}
              >
                {tier.features.map((f) => (
                  <li
                    key={f}
                    style={{
                      padding: "6px 0",
                      borderBottom: tier.highlight
                        ? "1px solid rgba(0,0,0,0.06)"
                        : "1px solid rgba(255,255,255,0.06)",
                      color: tier.highlight ? "rgba(0,0,0,0.7)" : "rgba(255,255,255,0.6)",
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'DM Mono', monospace",
                        color: tier.highlight ? "#2563eb" : "#60a5fa",
                        marginRight: "8px",
                      }}
                    >
                      --
                    </span>
                    {f}
                  </li>
                ))}
              </ul>

              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "11px",
                  letterSpacing: "0.1em",
                  textTransform: "uppercase",
                  textAlign: "center",
                  padding: "10px 16px",
                  borderRadius: "4px",
                  cursor: "pointer",
                  transition: "all 0.15s",
                  ...(tier.ctaStyle === "primary"
                    ? {
                        background: "#09090b",
                        color: "#fff",
                      }
                    : tier.highlight
                    ? {
                        background: "transparent",
                        border: "1px solid rgba(0,0,0,0.15)",
                        color: "#09090b",
                      }
                    : {
                        background: "transparent",
                        border: "1px solid rgba(255,255,255,0.1)",
                        color: "rgba(255,255,255,0.5)",
                      }),
                }}
              >
                {tier.cta}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Conversion Mechanic */}
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
          The conversion happens automatically.
        </h2>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr 1fr",
            gap: "1px",
            background: "rgba(255,255,255,0.06)",
            borderRadius: "8px",
            overflow: "hidden",
            marginBottom: "32px",
          }}
        >
          {[
            {
              step: "01",
              title: "Install",
              desc: "pip install aiglos && aiglos launch. Full T01-T82 detection running in 30 seconds. Every rule active. No feature gates.",
            },
            {
              step: "02",
              title: "First attest() call",
              desc: "The first call to aiglos.attest() or cloud telemetry connection auto-starts a 30-day Pro trial. No credit card. No feature blocked.",
            },
            {
              step: "03",
              title: "Day 30",
              desc: "By day 30, the developer has built their workflow around signed artifacts. The compliance team has seen the NDAA mapping. The decision is already made.",
            },
          ].map((s) => (
            <div
              key={s.step}
              style={{
                background: "#111116",
                padding: "32px 24px",
              }}
            >
              <div
                style={{
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "28px",
                  fontWeight: 500,
                  color: "#60a5fa",
                  marginBottom: "12px",
                }}
              >
                {s.step}
              </div>
              <div
                style={{
                  fontSize: "15px",
                  fontWeight: 600,
                  marginBottom: "8px",
                }}
              >
                {s.title}
              </div>
              <div
                style={{
                  fontSize: "13px",
                  color: "rgba(255,255,255,0.5)",
                  lineHeight: 1.6,
                }}
              >
                {s.desc}
              </div>
            </div>
          ))}
        </div>

        <div style={{ textAlign: "center" }}>
          <Link href="/scan">
            <span
              data-testid="link-try-scan-pricing"
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
              }}
            >
              Try the free scanner now
            </span>
          </Link>
        </div>
      </section>
    </div>
  );
}
