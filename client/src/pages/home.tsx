import { useState } from "react";
import { Link } from "wouter";
import { useSeo } from "@/hooks/use-seo";
import SectionLabel from "@/components/public/section-label";
import CodeWindow from "@/components/public/code-window";
import RevealSection from "@/components/public/reveal-section";

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
      <section className="min-h-screen flex flex-col justify-center items-center text-center py-20 px-12 relative overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_50%_20%,rgba(37,99,235,0.08)_0%,transparent_70%)] pointer-events-none" />

        <div
          className="pub-fade-up inline-flex items-center gap-2 bg-pub-red/10 border border-pub-red/25 rounded-full py-1 px-3.5 mb-8 font-pub-mono text-[11px] tracking-[0.12em] uppercase text-pub-red relative z-[1]"
          data-testid="badge-incident"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-pub-red pub-pulse" />
          March 24, 2026 - Supply chain attack confirmed
        </div>

        <h1
          className="pub-fade-up pub-delay-1 text-[clamp(32px,5vw,64px)] font-bold leading-[1.05] tracking-tight max-w-[900px] mb-6 relative z-[1]"
          data-testid="text-hero-title"
        >
          LiteLLM 1.82.8 exfiltrated every credential on every machine that installed it.{" "}
          <span className="text-pub-ice">T81 caught it.</span>
        </h1>

        <p className="pub-fade-up pub-delay-2 text-lg font-light text-pub-muted max-w-[600px] leading-[1.65] mb-12 relative z-[1]">
          97 million monthly downloads. SSH keys, AWS credentials, database passwords, crypto wallets
          sent to models.litellm.cloud. One .pth file. Aiglos rule T81 PTH_FILE_INJECT existed before anyone
          knew the attack happened.
        </p>

        <div className="pub-fade-up pub-delay-2 flex gap-4 items-stretch flex-wrap justify-center mb-12 relative z-[1]">
          <div
            data-testid="cta-developer"
            className="bg-pub-card border border-pub-strong rounded-md py-4 px-6 flex items-center gap-4"
          >
            <div className="text-left">
              <div className="font-pub-mono text-[10px] tracking-[0.15em] uppercase text-pub-dim mb-1">
                For developers
              </div>
              <code className="font-pub-mono text-[13px] text-white">
                pip install aiglos && aiglos launch
              </code>
            </div>
            <button
              data-testid="button-copy-install"
              onClick={handleCopy}
              className={`bg-transparent border border-pub rounded-[3px] py-1 px-2.5 font-pub-mono text-[10px] cursor-pointer transition-all duration-150 ${
                copied ? "text-pub-green" : "text-pub-dim"
              }`}
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>

          <Link href="/compliance">
            <div
              data-testid="cta-enterprise"
              className="bg-white text-pub-dark rounded-md py-4 px-6 flex flex-col justify-center cursor-pointer transition-opacity duration-150 hover:opacity-90"
            >
              <div className="font-pub-mono text-[10px] tracking-[0.15em] uppercase text-black/40 mb-1">
                For enterprise
              </div>
              <span className="text-[13px] font-semibold">See compliance coverage</span>
            </div>
          </Link>
        </div>

        <div
          className="pub-fade-up pub-delay-3 flex gap-12 flex-wrap justify-center relative z-[1]"
          data-testid="banner-ghsa-proof"
        >
          {[
            ["3/3", "GHSAs caught"],
            ["82", "Threat families"],
            ["23", "Campaign patterns"],
            ["<1ms", "Per call"],
            ["0", "Dependencies"],
          ].map(([n, l]) => (
            <div key={l} className="text-center">
              <span className="font-pub-mono text-[28px] font-medium text-white block leading-none">
                {n}
              </span>
              <span className="text-[11px] tracking-[0.1em] uppercase text-pub-dim mt-1 block">
                {l}
              </span>
            </div>
          ))}
        </div>
      </section>

      <RevealSection className="py-20 px-12 text-center border-t border-b border-pub">
        <span
          data-testid="text-proof-number"
          className="font-pub-mono text-[clamp(48px,8vw,96px)] font-medium text-white leading-none block tracking-tight"
        >
          3 / 3
        </span>
        <p className="text-base text-pub-muted max-w-[560px] mx-auto mt-5 leading-relaxed">
          Every published OpenClaw GHSA caught by Aiglos rules that{" "}
          <strong className="text-white">existed before the advisories were disclosed</strong>.
          The rules came first. Every time.
        </p>
      </RevealSection>

      <RevealSection className="py-20 px-12 max-w-[1100px] mx-auto">
        <SectionLabel>Architecture</SectionLabel>
        <h2
          data-testid="text-architecture-title"
          className="text-[clamp(28px,4vw,44px)] font-bold tracking-tight leading-[1.1] mb-4"
        >
          Where each product sits in the stack
        </h2>
        <p className="text-base text-pub-muted leading-[1.7] max-w-[560px] mb-12">
          Every competitor operates at the API gateway or model inference layer. Aiglos operates at the
          agent runtime layer. Three surfaces. One position no one else occupies.
        </p>

        <div
          data-testid="diagram-architecture"
          className="border border-pub rounded-lg overflow-hidden bg-pub-card"
        >
          {[
            { layer: "Package Registry", product: "Snyk", desc: "Static dependency scanning", isAiglos: false },
            { layer: "Container / Sandbox Boundary", product: "NVIDIA OpenShell", desc: "Kernel-level agent sandboxing", isAiglos: false },
            { layer: "API Gateway / Model Inference", product: "HiddenLayer", desc: "Model file scanning, inference-time detection", isAiglos: false },
            { layer: "Agent Runtime (MCP + HTTP + Subprocess)", product: "Aiglos", desc: "Every tool call, HTTP request, and subprocess intercepted before execution", isAiglos: true },
          ].map((item) => (
            <div
              key={item.layer}
              className={`py-6 px-8 border-b border-white/[0.04] grid grid-cols-[260px_140px_1fr] gap-6 items-center ${
                item.isAiglos ? "bg-pub-blue/5" : ""
              }`}
            >
              <div className={`text-[13px] ${item.isAiglos ? "font-semibold text-pub-ice" : "text-pub-muted"}`}>
                {item.layer}
              </div>
              <div className={`font-pub-mono text-xs ${item.isAiglos ? "text-white" : "text-pub-dim"}`}>
                {item.product}
              </div>
              <div className={`text-[13px] ${item.isAiglos ? "text-white/80" : "text-pub-dim"}`}>
                {item.desc}
              </div>
            </div>
          ))}
        </div>
      </RevealSection>

      <RevealSection className="py-20 px-12 max-w-[1100px] mx-auto border-t border-pub">
        <SectionLabel>How it works</SectionLabel>
        <h2 className="text-[clamp(28px,4vw,44px)] font-bold tracking-tight leading-[1.1] mb-4">
          One line. Nothing else changes.
        </h2>
        <p className="text-base text-pub-muted leading-[1.7] max-w-[560px] mb-12">
          Aiglos intercepts every tool call, HTTP request, and shell command before execution. The agent
          never knows it's running.
        </p>

        <CodeWindow filename="agent.py">
          <span className="text-[#ff7b72]">import</span> aiglos{"\n\n"}
          aiglos.<span className="text-[#d2a8ff]">attach</span>(
          {"\n    "}
          <span className="text-[#79c0ff]">agent_name</span>=
          <span className="text-[#a5d6ff]">"my-agent"</span>,{"\n    "}
          <span className="text-[#79c0ff]">policy</span>=
          <span className="text-[#a5d6ff]">"enterprise"</span>,{"\n"}){"\n\n"}
          <span className="text-[#6e7681]">
            {"# The agent keeps running. Nothing else changes.\n"}
            {"# Until something tries to exfiltrate credentials.\n"}
            {"# Then it stops."}
          </span>
        </CodeWindow>
      </RevealSection>

      <RevealSection className="py-20 px-12 max-w-[1100px] mx-auto border-t border-pub">
        <SectionLabel>Capabilities</SectionLabel>
        <h2 className="text-[clamp(28px,4vw,44px)] font-bold tracking-tight leading-[1.1] mb-12">
          Built for the way agents actually work.
        </h2>

        <div className="grid grid-cols-3 pub-grid-3 gap-px bg-white/[0.06] border border-pub rounded-lg overflow-hidden">
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
            <div key={f.title} className="bg-pub-dark p-8 transition-colors duration-200">
              <div className="text-[15px] font-semibold mb-2">{f.title}</div>
              <div className="text-[13px] text-pub-dim leading-[1.65]">{f.body}</div>
            </div>
          ))}
        </div>
      </RevealSection>

      <RevealSection className="py-20 px-12 max-w-[1100px] mx-auto border-t border-pub">
        <SectionLabel>Empirical validation</SectionLabel>
        <h2 className="text-[clamp(28px,4vw,44px)] font-bold tracking-tight leading-[1.1] mb-4">
          Every published OpenClaw vulnerability.
          <br />
          Caught by existing rules.
        </h2>
        <p className="text-base text-pub-muted leading-[1.7] max-w-[560px] mb-10">
          Three published advisories. All three covered by Aiglos rules before the advisories were
          disclosed, before any patch existed.
        </p>

        <div className="flex flex-col gap-px bg-white/[0.06] border border-pub rounded-lg overflow-hidden">
          {[
            { ghsa: "GHSA-g8p2-7wf7-98mq", cvss: "8.8", title: "1-Click RCE via Authentication Token Exfiltration", rules: "T03 T12 T19 T68" },
            { ghsa: "GHSA-q284-4pvr-m585", cvss: "8.6", title: "OS Command Injection via PATH Manipulation", rules: "T03 T04 T70" },
            { ghsa: "GHSA-mc68-q9jw-2h3v", cvss: "8.4", title: "Remote Code Execution via Command Injection", rules: "T03 T70" },
          ].map((g) => (
            <div key={g.ghsa} className="bg-pub-dark py-5 px-8 grid grid-cols-[160px_50px_1fr_auto] gap-6 items-center">
              <div className="font-pub-mono text-xs text-pub-ice">{g.ghsa}</div>
              <div className="font-pub-mono text-xs text-pub-red">{g.cvss}</div>
              <div className="text-[13px] text-pub-muted">{g.title}</div>
              <div className="flex gap-1.5">
                {g.rules.split(" ").map((r) => (
                  <span key={r} className="bg-pub-card border border-white/[0.08] text-pub-dim py-0.5 px-2 rounded-sm text-[10px] font-pub-mono tracking-[0.1em]">
                    {r}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </RevealSection>

      <RevealSection className="py-20 px-12 max-w-[1100px] mx-auto border-t border-pub">
        <SectionLabel>Get started</SectionLabel>
        <h2 className="text-[clamp(28px,4vw,44px)] font-bold tracking-tight leading-[1.1] mb-4">
          30 seconds to full coverage.
        </h2>
        <p className="text-base text-pub-muted leading-[1.7] max-w-[560px] mb-12">
          Install. Attach. Every tool call protected. No configuration. No network dependency. No proxy.
        </p>

        <div className="grid grid-cols-3 pub-grid-3 gap-px bg-white/[0.06] rounded-lg overflow-hidden mb-8">
          {[
            { step: "01", title: "Install", desc: "pip install aiglos. Zero dependencies. Under 2MB." },
            { step: "02", title: "Attach", desc: "import aiglos; aiglos.attach(). One line in your agent entrypoint." },
            { step: "03", title: "Ship", desc: "Every tool call intercepted. Signed artifact on session close. CI integration in 2 minutes." },
          ].map((s) => (
            <div key={s.step} className="bg-pub-card p-8">
              <div className="font-pub-mono text-[28px] font-medium text-pub-ice mb-3">{s.step}</div>
              <div className="text-[15px] font-semibold mb-2">{s.title}</div>
              <div className="text-[13px] text-pub-muted leading-relaxed">{s.desc}</div>
            </div>
          ))}
        </div>

        <div className="text-center">
          <Link href="/scan">
            <span
              data-testid="link-try-scan"
              className="font-pub-mono text-[11px] tracking-[0.1em] uppercase text-pub-dim no-underline py-3 px-6 border border-pub-strong rounded cursor-pointer transition-all duration-150 hover:text-pub-muted hover:border-white/20 inline-block"
            >
              Try the free scanner now
            </span>
          </Link>
        </div>
      </RevealSection>
    </div>
  );
}
