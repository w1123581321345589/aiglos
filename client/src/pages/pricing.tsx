import { useSeo } from "@/hooks/use-seo";
import { Link } from "wouter";
import SectionLabel from "@/components/public/section-label";
import RevealSection from "@/components/public/reveal-section";

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
    primary: false,
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
    primary: true,
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
    primary: false,
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
    primary: false,
    highlight: false,
  },
];

export default function PricingPage() {
  useSeo({
    title: "Pricing - Community, Pro, Teams, Enterprise | Aiglos",
    description: "Free to detect. Pro to prove. Full T01-T82 detection engine free. Signed artifacts, federated intelligence, and compliance exports on Pro.",
    ogTitle: "Aiglos Pricing",
  });

  return (
    <div>
      <section className="pt-28 pb-10 px-12 max-w-[1200px] mx-auto text-center">
        <SectionLabel>Pricing</SectionLabel>
        <h1
          data-testid="text-pricing-title"
          className="text-[clamp(28px,4vw,48px)] font-bold tracking-tight leading-[1.1] mb-4"
        >
          Free to detect. Pro to prove.
        </h1>
        <p className="text-base text-pub-muted leading-[1.7] max-w-[560px] mx-auto mb-12">
          The free tier runs the full detection engine. Pro adds the federation intelligence and the signed
          compliance artifact -- the document that turns a security tool into a regulatory submission.
        </p>
      </section>

      <section className="pb-20 px-12 max-w-[1200px] mx-auto">
        <div
          data-testid="grid-pricing"
          className="grid grid-cols-4 pub-grid-4 gap-px bg-white/[0.06] border border-pub rounded-lg overflow-hidden"
        >
          {tiers.map((tier) => (
            <div
              key={tier.name}
              data-testid={`card-pricing-${tier.name.toLowerCase()}`}
              className={`p-9 ${tier.highlight ? "bg-white text-pub-dark" : "bg-pub-dark text-white"}`}
            >
              <div className={`font-pub-mono text-[10px] tracking-[0.2em] uppercase mb-4 ${tier.highlight ? "text-black/40" : "text-pub-dim"}`}>
                {tier.name}
              </div>
              <div className="font-pub-mono text-[40px] font-medium leading-none mb-1">
                {tier.price}
                <span className={`text-sm font-normal ml-1 ${tier.highlight ? "text-black/40" : "text-pub-dim"}`}>
                  {tier.period}
                </span>
              </div>
              <p className={`text-xs leading-[1.5] mb-6 min-h-[36px] ${tier.highlight ? "text-black/50" : "text-white/40"}`}>
                {tier.description}
              </p>
              <ul className="list-none p-0 m-0 mb-6 text-[13px] leading-[1.6]">
                {tier.features.map((f) => (
                  <li key={f} className={`py-1.5 border-b ${tier.highlight ? "border-black/[0.06] text-black/70" : "border-white/[0.06] text-white/60"}`}>
                    <span className={`font-pub-mono mr-2 ${tier.highlight ? "text-pub-blue" : "text-pub-ice"}`}>--</span>
                    {f}
                  </li>
                ))}
              </ul>
              <div
                className={`font-pub-mono text-[11px] tracking-[0.1em] uppercase text-center py-2.5 px-4 rounded cursor-pointer transition-all duration-150 ${
                  tier.primary
                    ? "bg-pub-dark text-white"
                    : tier.highlight
                    ? "bg-transparent border border-black/15 text-pub-dark"
                    : "bg-transparent border border-pub text-pub-dim"
                }`}
              >
                {tier.cta}
              </div>
            </div>
          ))}
        </div>
      </section>

      <RevealSection className="py-20 px-12 max-w-[1100px] mx-auto border-t border-pub">
        <h2 className="text-[clamp(24px,3vw,36px)] font-bold tracking-tight mb-6">
          The conversion happens automatically.
        </h2>

        <div className="grid grid-cols-3 pub-grid-3 gap-px bg-white/[0.06] rounded-lg overflow-hidden mb-8">
          {[
            { step: "01", title: "Install", desc: "pip install aiglos && aiglos launch. Full T01-T82 detection running in 30 seconds. Every rule active. No feature gates." },
            { step: "02", title: "First attest() call", desc: "The first call to aiglos.attest() or cloud telemetry connection auto-starts a 30-day Pro trial. No credit card. No feature blocked." },
            { step: "03", title: "Day 30", desc: "By day 30, the developer has built their workflow around signed artifacts. The compliance team has seen the NDAA mapping. The decision is already made." },
          ].map((s) => (
            <div key={s.step} className="bg-pub-card p-8">
              <div className="font-pub-mono text-[28px] font-medium text-pub-ice mb-3">{s.step}</div>
              <div className="text-[15px] font-semibold mb-2">{s.title}</div>
              <div className="text-[13px] text-white/50 leading-[1.6]">{s.desc}</div>
            </div>
          ))}
        </div>

        <div className="text-center">
          <Link href="/scan">
            <span
              data-testid="link-try-scan-pricing"
              className="font-pub-mono text-[11px] tracking-[0.1em] uppercase text-pub-dim no-underline py-3 px-6 border border-pub rounded cursor-pointer transition-all duration-150 hover:text-pub-muted hover:border-white/20 inline-block"
            >
              Try the free scanner now
            </span>
          </Link>
        </div>
      </RevealSection>
    </div>
  );
}
