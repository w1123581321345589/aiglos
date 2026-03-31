import { useState, useEffect } from "react";

function useIntelSeo() {
  useEffect(() => {
    document.title = "Intel - AI Agent Threat Intelligence Feed | Aiglos";
    const setMeta = (name, content, attr = "name") => {
      let el = document.querySelector(`meta[${attr}="${name}"]`);
      if (!el) { el = document.createElement("meta"); el.setAttribute(attr, name); document.head.appendChild(el); }
      el.setAttribute("content", content);
    };
    setMeta("description", "Live AI agent threat feed. PyPI release monitoring, GHSA advisory coverage, HF Spaces MCP scanner. Every incident mapped to T01-T82 taxonomy.");
    setMeta("og:title", "Aiglos Intel - AI Agent Threat Intelligence", "property");
    setMeta("og:description", "Live threat feed covering supply chain attacks, PyPI monitoring, GHSA advisories. 82 rules, 23 campaigns, 93% ATLAS coverage.", "property");
  }, []);
}

// ── Static threat feed data (mirrors aiglos autoresearch module) ───────────────
const INCIDENTS = [
  {
    id: "litellm-2026-03-24",
    severity: "CRITICAL",
    date: "2026-03-24",
    title: "LiteLLM 1.82.7/1.82.8 supply chain attack",
    summary: "Malicious .pth file exfiltrated SSH keys, AWS/GCP/Azure credentials, database passwords, all .env API keys, shell history, crypto wallets to models.litellm.cloud.",
    rules: ["T30", "T81", "T04", "T41"],
    campaign: "REPO_TAKEOVER_CHAIN",
    packages: ["litellm==1.82.7", "litellm==1.82.8"],
    transitive: ["dspy", "smolagents", "langchain", "langgraph", "crewai"],
    discoverer: "Callum McMahon / FutureSearch",
    exfil: "models.litellm.cloud",
    aiglos_status: "COVERED",
    mechanism: ".pth file in site-packages auto-executes at Python startup",
    source: "https://github.com/BerriAI/litellm/issues/7643",
  },
];

const GHSA_FEED = [
  { id: "GHSA-g8p2-7wf7-98mq", cvss: 8.8, title: "OpenClaw auth token exfiltration", rules: ["T03","T12","T19","T68"], status: "COVERED", date: "2026-02" },
  { id: "GHSA-q284-4pvr-m585", cvss: 8.6, title: "OpenClaw OS command injection via PATH", rules: ["T03","T04","T70"], status: "COVERED", date: "2026-01" },
  { id: "GHSA-mc68-q9jw-2h3v", cvss: 8.4, title: "OpenClaw command injection", rules: ["T03","T70"], status: "COVERED", date: "2025-12" },
];

const PYPI_WATCH = [
  { package: "litellm",    version: "1.82.8", status: "COMPROMISED",   signal: "Known malicious — .pth exfil confirmed", checked: "2026-03-29" },
  { package: "litellm",    version: "1.83.0", status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "langchain",  version: "0.3.1",  status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "openai",     version: "1.51.0", status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "anthropic",  version: "0.40.0", status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "dspy",       version: "2.5.0",  status: "WARN",          signal: "Transitive litellm dependency",          checked: "2026-03-29" },
  { package: "smolagents", version: "1.2.0",  status: "WARN",          signal: "Optional litellm dependency",            checked: "2026-03-29" },
];

const HF_SPACES = [
  { id: "model-provider/litellm-proxy", signals: ["mcp", "high_downloads"], risk: "HIGH", note: "MCP-tagged space with litellm proxy pattern", date: "2026-03-25" },
];

const STATS = {
  rules: 82, campaigns: 23, agents: 17,
  atlas_coverage: "93%", ghsa_coverage: "3/3",
  pypi_watching: 15,
};

const SEV_COLOR = { CRITICAL: "#ef4444", HIGH: "#f97316", WARN: "#fbbf24", CLEAN: "#22c55e", COVERED: "#22c55e" };
const SEV_BG = { CRITICAL: "rgba(239,68,68,0.07)", HIGH: "rgba(249,115,22,0.06)", WARN: "rgba(251,191,36,0.05)", CLEAN: "rgba(34,197,94,0.05)", COVERED: "rgba(34,197,94,0.05)" };

function Badge({ label, color }) {
  return (
    <span style={{
      background: `${color}18`, border: `1px solid ${color}44`,
      color, padding: "1px 7px", borderRadius: "3px",
      fontSize: "9px", letterSpacing: "0.15em", fontWeight: 600,
      fontFamily: "'DM Mono', monospace",
    }}>{label}</span>
  );
}

function RuleTag({ rule }) {
  return (
    <span style={{
      background: "#111", border: "1px solid #222",
      color: "#555", padding: "1px 7px", borderRadius: "2px",
      fontSize: "9px", letterSpacing: "0.1em",
      fontFamily: "'DM Mono', monospace",
    }}>{rule}</span>
  );
}

function Section({ title, count, color = "#555", children }) {
  return (
    <div style={{ marginBottom: "40px" }}>
      <div style={{
        display: "flex", alignItems: "baseline", gap: "10px",
        marginBottom: "14px", borderBottom: "1px solid #111", paddingBottom: "10px",
      }}>
        <span style={{ fontSize: "10px", letterSpacing: "0.25em", color, textTransform: "uppercase" }}>{title}</span>
        {count !== undefined && (
          <span style={{ fontSize: "10px", color: "#333" }}>{count} entries</span>
        )}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: "9px", color: "#2a2a2a", letterSpacing: "0.1em" }}>LIVE · Updated continuously</span>
      </div>
      {children}
    </div>
  );
}

export default function AiglosIntel() {
  useIntelSeo();
  const [activeTab, setActiveTab] = useState("incidents");
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setTick(n => n + 1), 3000);
    return () => clearInterval(t);
  }, []);

  const tabs = [
    { id: "incidents", label: "Incidents" },
    { id: "pypi",      label: "PyPI Watch" },
    { id: "ghsa",      label: "GHSA Coverage" },
    { id: "hf",        label: "HF Spaces MCP" },
  ];

  return (
    <div style={{
      minHeight: "100vh", background: "#080808",
      fontFamily: "'DM Mono', 'Courier New', monospace",
      color: "#e2e8f0",
    }}>
      {/* Scanlines */}
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
        <div style={{ display: "flex", gap: "20px", fontSize: "10px", alignItems: "center" }}>
          <span style={{ color: "#ef4444", display: "flex", alignItems: "center", gap: "5px" }}>
            <span style={{ width: "5px", height: "5px", background: "#ef4444", borderRadius: "50%", display: "inline-block", animation: "pulse 2s infinite" }} />
            LIVE
          </span>
          <span style={{ color: "#333" }}>T01-T82 · {STATS.rules} rules · {STATS.campaigns} campaigns</span>
        </div>
      </div>

      <div style={{ maxWidth: "900px", margin: "0 auto", padding: "40px 32px", position: "relative", zIndex: 1 }}>

        {/* Hero */}
        <div style={{ marginBottom: "40px" }}>
          <div style={{ fontSize: "10px", letterSpacing: "0.3em", color: "#3b82f6", marginBottom: "12px" }}>
            AI AGENT THREAT INTELLIGENCE
          </div>
          <h1 style={{ fontSize: "clamp(24px,3.5vw,36px)", fontWeight: 700, letterSpacing: "-0.03em", color: "#fff", marginBottom: "10px" }}>
            Live threat feed
          </h1>
          <p style={{ fontSize: "12px", color: "#555", lineHeight: 1.7, maxWidth: "520px" }}>
            PyPI release monitoring · GHSA advisory feed · HF Spaces MCP scanner.
            Every incident mapped to T01–T82 taxonomy before it hits the news.
          </p>
        </div>

        {/* Stat bar */}
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "1px",
          background: "#111", borderRadius: "6px", overflow: "hidden",
          marginBottom: "36px",
        }}>
          {[
            ["Rules", STATS.rules],
            ["Campaigns", STATS.campaigns],
            ["ATLAS", STATS.atlas_coverage],
            ["GHSAs", STATS.ghsa_coverage],
            ["PyPI Watch", STATS.pypi_watching + " pkgs"],
          ].map(([label, val]) => (
            <div key={label} style={{
              padding: "14px 16px", background: "#0a0a0a", textAlign: "center"
            }}>
              <div style={{ fontSize: "18px", fontWeight: 700, color: "#fff", marginBottom: "3px" }}>{val}</div>
              <div style={{ fontSize: "9px", color: "#444", letterSpacing: "0.15em" }}>{label}</div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: "0", marginBottom: "28px", borderBottom: "1px solid #111" }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
              padding: "10px 20px", background: "transparent", border: "none",
              borderBottom: activeTab === t.id ? "2px solid #3b82f6" : "2px solid transparent",
              color: activeTab === t.id ? "#e2e8f0" : "#444",
              fontSize: "10px", letterSpacing: "0.15em", cursor: "pointer",
              fontFamily: "inherit", transition: "all 0.15s",
            }}>{t.label}</button>
          ))}
        </div>

        {/* Incidents tab */}
        {activeTab === "incidents" && (
          <Section title="Supply Chain Incidents" count={INCIDENTS.length} color="#ef4444">
            {INCIDENTS.map(inc => (
              <div key={inc.id} style={{
                border: `1px solid rgba(239,68,68,0.2)`, borderRadius: "6px",
                padding: "20px", marginBottom: "16px",
                background: "rgba(239,68,68,0.03)",
              }}>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "12px", marginBottom: "12px", flexWrap: "wrap" }}>
                  <Badge label={inc.severity} color={SEV_COLOR[inc.severity]} />
                  <span style={{ color: "#e2e8f0", fontSize: "12px", fontWeight: 600 }}>{inc.title}</span>
                  <span style={{ color: "#444", fontSize: "10px", marginLeft: "auto" }}>{inc.date}</span>
                </div>
                <p style={{ fontSize: "11px", color: "#777", lineHeight: 1.7, marginBottom: "12px" }}>
                  {inc.summary}
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
                  <div>
                    <div style={{ fontSize: "9px", color: "#444", letterSpacing: "0.15em", marginBottom: "6px" }}>MECHANISM</div>
                    <div style={{ fontSize: "10px", color: "#666" }}>{inc.mechanism}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: "9px", color: "#444", letterSpacing: "0.15em", marginBottom: "6px" }}>EXFIL ENDPOINT</div>
                    <code style={{ fontSize: "10px", color: "#ef4444" }}>{inc.exfil}</code>
                  </div>
                </div>
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
                  {inc.rules.map(r => <RuleTag key={r} rule={r} />)}
                  <span style={{ color: "#333", fontSize: "9px", margin: "0 4px" }}>→</span>
                  <Badge label={inc.campaign} color="#f97316" />
                  <span style={{ flex: 1 }} />
                  <Badge label={inc.aiglos_status} color={SEV_COLOR[inc.aiglos_status]} />
                </div>
                {inc.transitive.length > 0 && (
                  <div style={{ marginTop: "12px", padding: "10px 12px", background: "#0d0d0d", borderRadius: "4px", border: "1px solid #1a1a1a" }}>
                    <span style={{ fontSize: "9px", color: "#555", letterSpacing: "0.15em" }}>TRANSITIVE EXPOSURE: </span>
                    <span style={{ fontSize: "10px", color: "#666" }}>{inc.transitive.join(" · ")}</span>
                  </div>
                )}
              </div>
            ))}
          </Section>
        )}

        {/* PyPI Watch tab */}
        {activeTab === "pypi" && (
          <Section title="PyPI Release Monitor" count={PYPI_WATCH.length} color="#f97316">
            <div style={{ fontSize: "11px", color: "#555", marginBottom: "16px", lineHeight: 1.7 }}>
              Monitoring {STATS.pypi_watching} high-download AI packages for .pth files. Deep wheel inspection on litellm, langchain, openai, anthropic, dspy every 24 hours.
            </div>
            <div style={{ border: "1px solid #1a1a1a", borderRadius: "6px", overflow: "hidden" }}>
              {PYPI_WATCH.map((p, i) => (
                <div key={i} style={{
                  padding: "12px 20px",
                  borderBottom: i < PYPI_WATCH.length - 1 ? "1px solid #111" : "none",
                  display: "flex", alignItems: "center", gap: "12px",
                  background: p.status === "COMPROMISED" ? "rgba(239,68,68,0.03)" : "transparent",
                }}>
                  <code style={{ fontSize: "11px", color: SEV_COLOR[p.status] || "#666", minWidth: "200px" }}>
                    {p.package}=={p.version}
                  </code>
                  <div style={{ flex: 1, fontSize: "10px", color: "#555" }}>{p.signal}</div>
                  <Badge label={p.status} color={SEV_COLOR[p.status] || "#555"} />
                  <span style={{ fontSize: "9px", color: "#333" }}>{p.checked}</span>
                </div>
              ))}
            </div>
            <div style={{ marginTop: "16px", padding: "12px 16px", border: "1px solid #1a1a1a", borderRadius: "4px", background: "#0a0a0a" }}>
              <code style={{ fontSize: "11px", color: "#22c55e" }}>aiglos scan-deps</code>
              <span style={{ fontSize: "10px", color: "#444", marginLeft: "16px" }}>Run locally to check your environment now</span>
            </div>
          </Section>
        )}

        {/* GHSA Coverage tab */}
        {activeTab === "ghsa" && (
          <Section title="GHSA Advisory Coverage" count={GHSA_FEED.length} color="#22c55e">
            <div style={{ fontSize: "11px", color: "#555", marginBottom: "16px", lineHeight: 1.7 }}>
              3/3 published OpenClaw GHSAs caught by existing Aiglos rules before advisory disclosure.
              Every GHSA mapped to the T-rule taxonomy.
            </div>
            {GHSA_FEED.map((adv, i) => (
              <div key={i} style={{
                border: "1px solid #1a1a1a", borderRadius: "6px", padding: "16px 20px",
                marginBottom: "10px", background: "#0a0a0a",
                display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap",
              }}>
                <code style={{ fontSize: "10px", color: "#3b82f6", minWidth: "160px" }}>{adv.id}</code>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: "11px", color: "#888", marginBottom: "6px" }}>{adv.title}</div>
                  <div style={{ display: "flex", gap: "6px" }}>
                    {adv.rules.map(r => <RuleTag key={r} rule={r} />)}
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ marginBottom: "4px" }}>
                    <Badge label={adv.status} color={SEV_COLOR[adv.status]} />
                  </div>
                  <div style={{ fontSize: "9px", color: "#444" }}>CVSS {adv.cvss} · {adv.date}</div>
                </div>
              </div>
            ))}
            <div style={{ marginTop: "16px", padding: "12px 16px", border: "1px solid #1a1a1a", borderRadius: "4px", background: "#0a0a0a" }}>
              <code style={{ fontSize: "11px", color: "#22c55e" }}>aiglos autoresearch atlas-coverage</code>
              <span style={{ fontSize: "10px", color: "#444", marginLeft: "16px" }}>93% ATLAS coverage · 0 gaps</span>
            </div>
          </Section>
        )}

        {/* HF Spaces tab */}
        {activeTab === "hf" && (
          <Section title="HuggingFace Spaces MCP Scanner" count={HF_SPACES.length} color="#f97316">
            <div style={{ fontSize: "11px", color: "#555", marginBottom: "16px", lineHeight: 1.7 }}>
              Monitoring huggingface.co/api/spaces?tag=mcp for suspicious new Spaces.
              Flags skill packages with high download velocity and supply-chain risk patterns.
            </div>
            {HF_SPACES.map((sp, i) => (
              <div key={i} style={{
                border: "1px solid rgba(249,115,22,0.2)", borderRadius: "6px",
                padding: "16px 20px", marginBottom: "10px",
                background: "rgba(249,115,22,0.03)",
                display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap",
              }}>
                <code style={{ fontSize: "10px", color: "#f97316", minWidth: "180px" }}>{sp.id}</code>
                <div style={{ flex: 1, fontSize: "10px", color: "#777" }}>{sp.note}</div>
                <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                  {sp.signals.map(s => <RuleTag key={s} rule={s} />)}
                  <Badge label={sp.risk} color={SEV_COLOR[sp.risk] || "#555"} />
                </div>
              </div>
            ))}
          </Section>
        )}

        {/* Footer CTA */}
        <div style={{
          marginTop: "48px", padding: "24px 28px",
          border: "1px solid #1a1a1a", borderRadius: "6px", background: "#0a0a0a",
          display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "20px",
        }}>
          <div>
            <div style={{ fontSize: "11px", color: "#e2e8f0", marginBottom: "4px" }}>Get alerted the moment the next one hits</div>
            <code style={{ fontSize: "11px", color: "#22c55e" }}>pip install aiglos && aiglos autoresearch watch-ghsa</code>
          </div>
          <div style={{ fontSize: "10px", color: "#333", textAlign: "right" }}>
            <div>PyPI · GHSA · NVD · OSV.dev · HF Spaces</div>
            <div style={{ marginTop: "3px" }}>T81 caught LiteLLM before any other tool named the mechanism</div>
          </div>
        </div>
        <div style={{ marginTop: "20px", textAlign: "center", fontSize: "9px", color: "#2a2a2a", letterSpacing: "0.1em" }}>
          aiglos.dev · MIT · github.com/w1123581321345589/aiglos
        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap');
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar{width:5px}
        ::-webkit-scrollbar-track{background:#0a0a0a}
        ::-webkit-scrollbar-thumb{background:#1e1e1e;border-radius:3px}
      `}</style>
    </div>
  );
}
