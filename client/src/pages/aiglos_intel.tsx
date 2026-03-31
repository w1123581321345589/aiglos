import { useState } from "react";
import { useSeo } from "@/hooks/use-seo";

interface Incident {
  id: string;
  severity: string;
  date: string;
  title: string;
  summary: string;
  rules: string[];
  campaign: string;
  packages: string[];
  transitive: string[];
  discoverer: string;
  exfil: string;
  aiglos_status: string;
  mechanism: string;
  source: string;
}

const INCIDENTS: Incident[] = [
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

interface GhsaEntry {
  id: string;
  cvss: number;
  title: string;
  rules: string[];
  status: string;
  date: string;
}

const GHSA_FEED: GhsaEntry[] = [
  { id: "GHSA-g8p2-7wf7-98mq", cvss: 8.8, title: "OpenClaw auth token exfiltration", rules: ["T03","T12","T19","T68"], status: "COVERED", date: "2026-02" },
  { id: "GHSA-q284-4pvr-m585", cvss: 8.6, title: "OpenClaw OS command injection via PATH", rules: ["T03","T04","T70"], status: "COVERED", date: "2026-01" },
  { id: "GHSA-mc68-q9jw-2h3v", cvss: 8.4, title: "OpenClaw command injection", rules: ["T03","T70"], status: "COVERED", date: "2025-12" },
];

interface PypiEntry {
  package: string;
  version: string;
  status: string;
  signal: string;
  checked: string;
}

const PYPI_WATCH: PypiEntry[] = [
  { package: "litellm",    version: "1.82.8", status: "COMPROMISED",   signal: "Known malicious \u2014 .pth exfil confirmed", checked: "2026-03-29" },
  { package: "litellm",    version: "1.83.0", status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "langchain",  version: "0.3.1",  status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "openai",     version: "1.51.0", status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "anthropic",  version: "0.40.0", status: "CLEAN",         signal: "No .pth files detected",                 checked: "2026-03-29" },
  { package: "dspy",       version: "2.5.0",  status: "WARN",          signal: "Transitive litellm dependency",          checked: "2026-03-29" },
  { package: "smolagents", version: "1.2.0",  status: "WARN",          signal: "Optional litellm dependency",            checked: "2026-03-29" },
];

interface HfEntry {
  id: string;
  signals: string[];
  risk: string;
  note: string;
  date: string;
}

const HF_SPACES: HfEntry[] = [
  { id: "model-provider/litellm-proxy", signals: ["mcp", "high_downloads"], risk: "HIGH", note: "MCP-tagged space with litellm proxy pattern", date: "2026-03-25" },
];

const STATS = { rules: 82, campaigns: 23, agents: 17, atlas_coverage: "93%", ghsa_coverage: "3/3", pypi_watching: 15 };

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "text-pub-red", HIGH: "text-pub-orange", WARN: "text-yellow-400", CLEAN: "text-pub-green", COVERED: "text-pub-green",
};
const SEV_BG: Record<string, string> = {
  CRITICAL: "bg-pub-red/[0.08] border-pub-red/30", HIGH: "bg-pub-orange/[0.06] border-pub-orange/30",
  WARN: "bg-yellow-400/[0.06] border-yellow-400/20", CLEAN: "bg-pub-green/[0.06] border-pub-green/20",
  COVERED: "bg-pub-green/[0.06] border-pub-green/20",
};

function Badge({ label, className }: { label: string; className: string }) {
  return (
    <span className={`py-px px-[7px] rounded-[3px] text-[9px] tracking-[0.15em] font-semibold font-pub-mono border ${className}`}>
      {label}
    </span>
  );
}

function RuleTag({ rule }: { rule: string }) {
  return (
    <span className="bg-pub-card border border-white/[0.08] text-pub-dim py-px px-[7px] rounded-sm text-[9px] tracking-[0.1em] font-pub-mono">
      {rule}
    </span>
  );
}

function FeedSection({ title, count, color, children }: { title: string; count?: number; color: string; children: React.ReactNode }) {
  return (
    <div className="mb-10">
      <div className="flex items-baseline gap-2.5 mb-3.5 border-b border-white/[0.06] pb-2.5">
        <span className={`text-[10px] tracking-[0.25em] uppercase ${color}`}>{title}</span>
        {count !== undefined && <span className="text-[10px] text-neutral-700">{count} entries</span>}
        <div className="flex-1" />
        <span className="text-[9px] text-neutral-800 tracking-[0.1em]">LIVE \u00B7 Updated continuously</span>
      </div>
      {children}
    </div>
  );
}

export default function AiglosIntel() {
  useSeo({
    title: "Intel - AI Agent Threat Intelligence Feed | Aiglos",
    description: "Live AI agent threat feed. PyPI release monitoring, GHSA advisory coverage, HF Spaces MCP scanner. Every incident mapped to T01-T82 taxonomy.",
    ogTitle: "Aiglos Intel - AI Agent Threat Intelligence",
  });

  const [activeTab, setActiveTab] = useState("incidents");

  const tabs = [
    { id: "incidents", label: "Incidents" },
    { id: "pypi",      label: "PyPI Watch" },
    { id: "ghsa",      label: "GHSA Coverage" },
    { id: "hf",        label: "HF Spaces MCP" },
  ];

  return (
    <div className="min-h-screen bg-[#080808] font-pub-mono text-slate-200">
      <div className="fixed inset-0 pointer-events-none bg-[repeating-linear-gradient(0deg,transparent,transparent_2px,rgba(0,0,0,0.025)_2px,rgba(0,0,0,0.025)_4px)]" />

      <div className="border-b border-white/[0.06] py-2.5 px-8 flex items-center justify-end bg-[#080808]/95">
        <div className="flex gap-5 text-[10px] items-center">
          <span className="text-pub-red flex items-center gap-1.5">
            <span className="w-[5px] h-[5px] bg-pub-red rounded-full inline-block pub-pulse" />
            LIVE
          </span>
          <span className="text-neutral-700">T01-T82 \u00B7 {STATS.rules} rules \u00B7 {STATS.campaigns} campaigns</span>
        </div>
      </div>

      <div className="max-w-[900px] mx-auto py-10 px-8 relative z-[1]">
        <div className="mb-10">
          <div className="text-[10px] tracking-[0.3em] text-pub-blue mb-3">AI AGENT THREAT INTELLIGENCE</div>
          <h1 className="text-[clamp(24px,3.5vw,36px)] font-bold tracking-tight text-white mb-2.5">
            Live threat feed
          </h1>
          <p className="text-xs text-neutral-500 leading-[1.7] max-w-[520px]">
            PyPI release monitoring \u00B7 GHSA advisory feed \u00B7 HF Spaces MCP scanner.
            Every incident mapped to T01-T82 taxonomy before it hits the news.
          </p>
        </div>

        <div className="grid grid-cols-5 gap-px bg-white/[0.06] rounded-md overflow-hidden mb-9">
          {([
            ["Rules", STATS.rules],
            ["Campaigns", STATS.campaigns],
            ["ATLAS", STATS.atlas_coverage],
            ["GHSAs", STATS.ghsa_coverage],
            ["PyPI Watch", STATS.pypi_watching + " pkgs"],
          ] as [string, string | number][]).map(([label, val]) => (
            <div key={label} className="py-3.5 px-4 bg-[#0a0a0a] text-center">
              <div className="text-lg font-bold text-white mb-0.5">{val}</div>
              <div className="text-[9px] text-neutral-600 tracking-[0.15em]">{label}</div>
            </div>
          ))}
        </div>

        <div className="flex gap-0 mb-7 border-b border-white/[0.06]">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`py-2.5 px-5 bg-transparent border-none cursor-pointer text-[10px] tracking-[0.15em] font-pub-mono transition-all duration-150 ${
                activeTab === t.id
                  ? "border-b-2 border-b-pub-blue text-slate-200"
                  : "border-b-2 border-b-transparent text-neutral-600"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {activeTab === "incidents" && (
          <FeedSection title="Supply Chain Incidents" count={INCIDENTS.length} color="text-pub-red">
            {INCIDENTS.map(inc => (
              <div key={inc.id} className="border border-pub-red/20 rounded-md p-5 mb-4 bg-pub-red/[0.03]">
                <div className="flex items-start gap-3 mb-3 flex-wrap">
                  <Badge label={inc.severity} className={`${SEV_BG[inc.severity]} ${SEV_COLOR[inc.severity]}`} />
                  <span className="text-slate-200 text-xs font-semibold">{inc.title}</span>
                  <span className="text-neutral-600 text-[10px] ml-auto">{inc.date}</span>
                </div>
                <p className="text-[11px] text-neutral-500 leading-[1.7] mb-3">{inc.summary}</p>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div>
                    <div className="text-[9px] text-neutral-600 tracking-[0.15em] mb-1.5">MECHANISM</div>
                    <div className="text-[10px] text-neutral-500">{inc.mechanism}</div>
                  </div>
                  <div>
                    <div className="text-[9px] text-neutral-600 tracking-[0.15em] mb-1.5">EXFIL ENDPOINT</div>
                    <code className="text-[10px] text-pub-red font-pub-mono">{inc.exfil}</code>
                  </div>
                </div>
                <div className="flex gap-1.5 flex-wrap items-center">
                  {inc.rules.map(r => <RuleTag key={r} rule={r} />)}
                  <span className="text-neutral-700 text-[9px] mx-1">\u2192</span>
                  <Badge label={inc.campaign} className="bg-pub-orange/[0.08] border-pub-orange/30 text-pub-orange" />
                  <span className="flex-1" />
                  <Badge label={inc.aiglos_status} className={`${SEV_BG[inc.aiglos_status]} ${SEV_COLOR[inc.aiglos_status]}`} />
                </div>
                {inc.transitive.length > 0 && (
                  <div className="mt-3 p-2.5 px-3 bg-[#0d0d0d] rounded border border-white/[0.06]">
                    <span className="text-[9px] text-neutral-500 tracking-[0.15em]">TRANSITIVE EXPOSURE: </span>
                    <span className="text-[10px] text-neutral-500">{inc.transitive.join(" \u00B7 ")}</span>
                  </div>
                )}
              </div>
            ))}
          </FeedSection>
        )}

        {activeTab === "pypi" && (
          <FeedSection title="PyPI Release Monitor" count={PYPI_WATCH.length} color="text-pub-orange">
            <div className="text-[11px] text-neutral-500 mb-4 leading-[1.7]">
              Monitoring {STATS.pypi_watching} high-download AI packages for .pth files. Deep wheel inspection on litellm, langchain, openai, anthropic, dspy every 24 hours.
            </div>
            <div className="border border-white/[0.06] rounded-md overflow-hidden">
              {PYPI_WATCH.map((p, i) => (
                <div
                  key={i}
                  className={`py-3 px-5 flex items-center gap-3 ${
                    i < PYPI_WATCH.length - 1 ? "border-b border-white/[0.06]" : ""
                  } ${p.status === "COMPROMISED" ? "bg-pub-red/[0.03]" : ""}`}
                >
                  <code className={`text-[11px] min-w-[200px] font-pub-mono ${SEV_COLOR[p.status] || "text-neutral-500"}`}>
                    {p.package}=={p.version}
                  </code>
                  <div className="flex-1 text-[10px] text-neutral-500">{p.signal}</div>
                  <Badge label={p.status} className={`${SEV_BG[p.status] || ""} ${SEV_COLOR[p.status] || "text-neutral-500"}`} />
                  <span className="text-[9px] text-neutral-700">{p.checked}</span>
                </div>
              ))}
            </div>
            <div className="mt-4 p-3 px-4 border border-white/[0.06] rounded bg-[#0a0a0a]">
              <code className="text-[11px] text-pub-green font-pub-mono">aiglos scan-deps</code>
              <span className="text-[10px] text-neutral-600 ml-4">Run locally to check your environment now</span>
            </div>
          </FeedSection>
        )}

        {activeTab === "ghsa" && (
          <FeedSection title="GHSA Advisory Coverage" count={GHSA_FEED.length} color="text-pub-green">
            <div className="text-[11px] text-neutral-500 mb-4 leading-[1.7]">
              3/3 published OpenClaw GHSAs caught by existing Aiglos rules before advisory disclosure.
              Every GHSA mapped to the T-rule taxonomy.
            </div>
            {GHSA_FEED.map((adv, i) => (
              <div key={i} className="border border-white/[0.06] rounded-md py-4 px-5 mb-2.5 bg-[#0a0a0a] flex items-center gap-4 flex-wrap">
                <code className="text-[10px] text-pub-blue min-w-[160px] font-pub-mono">{adv.id}</code>
                <div className="flex-1">
                  <div className="text-[11px] text-neutral-500 mb-1.5">{adv.title}</div>
                  <div className="flex gap-1.5">{adv.rules.map(r => <RuleTag key={r} rule={r} />)}</div>
                </div>
                <div className="text-right">
                  <div className="mb-1">
                    <Badge label={adv.status} className={`${SEV_BG[adv.status]} ${SEV_COLOR[adv.status]}`} />
                  </div>
                  <div className="text-[9px] text-neutral-600">CVSS {adv.cvss} \u00B7 {adv.date}</div>
                </div>
              </div>
            ))}
            <div className="mt-4 p-3 px-4 border border-white/[0.06] rounded bg-[#0a0a0a]">
              <code className="text-[11px] text-pub-green font-pub-mono">aiglos autoresearch atlas-coverage</code>
              <span className="text-[10px] text-neutral-600 ml-4">93% ATLAS coverage \u00B7 0 gaps</span>
            </div>
          </FeedSection>
        )}

        {activeTab === "hf" && (
          <FeedSection title="HuggingFace Spaces MCP Scanner" count={HF_SPACES.length} color="text-pub-orange">
            <div className="text-[11px] text-neutral-500 mb-4 leading-[1.7]">
              Monitoring huggingface.co/api/spaces?tag=mcp for suspicious new Spaces.
              Flags skill packages with high download velocity and supply-chain risk patterns.
            </div>
            {HF_SPACES.map((sp, i) => (
              <div key={i} className="border border-pub-orange/20 rounded-md py-4 px-5 mb-2.5 bg-pub-orange/[0.03] flex items-center gap-4 flex-wrap">
                <code className="text-[10px] text-pub-orange min-w-[180px] font-pub-mono">{sp.id}</code>
                <div className="flex-1 text-[10px] text-neutral-500">{sp.note}</div>
                <div className="flex gap-1.5 items-center">
                  {sp.signals.map(s => <RuleTag key={s} rule={s} />)}
                  <Badge label={sp.risk} className={`${SEV_BG[sp.risk] || ""} ${SEV_COLOR[sp.risk] || "text-neutral-500"}`} />
                </div>
              </div>
            ))}
          </FeedSection>
        )}

        <div className="mt-12 p-6 border border-white/[0.06] rounded-md bg-[#0a0a0a] flex items-center justify-between flex-wrap gap-5">
          <div>
            <div className="text-[11px] text-slate-200 mb-1">Get alerted the moment the next one hits</div>
            <code className="text-[11px] text-pub-green font-pub-mono">pip install aiglos && aiglos autoresearch watch-ghsa</code>
          </div>
          <div className="text-[10px] text-neutral-700 text-right">
            <div>PyPI \u00B7 GHSA \u00B7 NVD \u00B7 OSV.dev \u00B7 HF Spaces</div>
            <div className="mt-0.5">T81 caught LiteLLM before any other tool named the mechanism</div>
          </div>
        </div>
        <div className="mt-5 text-center text-[9px] text-neutral-800 tracking-[0.1em]">
          aiglos.dev \u00B7 MIT \u00B7 github.com/w1123581321345589/aiglos
        </div>
      </div>
    </div>
  );
}
