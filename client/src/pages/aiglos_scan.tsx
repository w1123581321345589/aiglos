import { useState, useEffect, useRef } from "react";
import { useSeo } from "@/hooks/use-seo";

interface CompromisedInfo {
  severity: string;
  description: string;
  discovered: string;
  discoverer: string;
  exfil: string;
  rules: string[];
}

const COMPROMISED: Record<string, Record<string, CompromisedInfo>> = {
  "litellm": {
    "1.82.7": {
      severity: "CRITICAL",
      description: "Contains litellm_init.pth \u2014 exfiltrates SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, database passwords, all .env API keys, shell history, crypto wallets to models.litellm.cloud",
      discovered: "2026-03-24",
      discoverer: "Callum McMahon / FutureSearch",
      exfil: "models.litellm.cloud",
      rules: ["T30", "T81", "T04", "T41"],
    },
    "1.82.8": {
      severity: "CRITICAL",
      description: "Same payload as 1.82.7. Fork bomb bug (exponential Python process spawn) caused by .pth re-triggering on child processes. The bug is why it was discovered.",
      discovered: "2026-03-24",
      discoverer: "Callum McMahon / FutureSearch",
      exfil: "models.litellm.cloud",
      rules: ["T30", "T81", "T04", "T41"],
    }
  }
};

const TRANSITIVE: Record<string, { via: string; risk: string }> = {
  "dspy": { via: "litellm>=1.64.0", risk: "HIGH" },
  "smolagents": { via: "litellm (optional)", risk: "MEDIUM" },
  "langchain": { via: "litellm (optional)", risk: "MEDIUM" },
  "langchain-core": { via: "langchain", risk: "MEDIUM" },
  "langgraph": { via: "langchain", risk: "MEDIUM" },
  "crewai": { via: "litellm (optional)", risk: "MEDIUM" },
  "autogen": { via: "litellm (optional)", risk: "MEDIUM" },
  "litellm-proxy": { via: "litellm (direct)", risk: "CRITICAL" },
};

function parsePackages(text: string) {
  const packages: Record<string, string> = {};
  const lines = text.trim().split("\n");
  for (const line of lines) {
    const clean = line.trim();
    if (!clean || clean.startsWith("#")) continue;
    const eqMatch = clean.match(/^([a-zA-Z0-9_\-\.]+)==([^\s;]+)/);
    if (eqMatch) {
      packages[eqMatch[1].toLowerCase()] = eqMatch[2];
      continue;
    }
    const reqMatch = clean.match(/^([a-zA-Z0-9_\-\.]+)/);
    if (reqMatch) {
      packages[reqMatch[1].toLowerCase()] = "unspecified";
    }
  }
  return packages;
}

interface Finding {
  package: string;
  version: string;
  severity: string;
  description: string;
  discovered: string;
  discoverer: string;
  exfil: string;
  rules: string[];
}

interface TransitiveFinding {
  package: string;
  version: string;
  via: string;
  risk: string;
}

interface ScanResult {
  compromised: Finding[];
  transitive: TransitiveFinding[];
  total: number;
  shared?: { c: number; t: number; total: number; pkgs: string[] };
}

function runScan(text: string): ScanResult {
  const packages = parsePackages(text);
  const findings: ScanResult = { compromised: [], transitive: [], total: Object.keys(packages).length };

  for (const [pkg, versions] of Object.entries(COMPROMISED)) {
    const installedVer = packages[pkg.toLowerCase()];
    if (installedVer && versions[installedVer]) {
      findings.compromised.push({
        package: pkg,
        version: installedVer,
        ...versions[installedVer],
      });
    }
  }

  for (const [pkg, info] of Object.entries(TRANSITIVE)) {
    const installed = packages[pkg.toLowerCase()];
    if (installed) {
      const hasLitellmCompromised = findings.compromised.some(f => f.package === "litellm");
      if (hasLitellmCompromised) {
        findings.transitive.push({ package: pkg, version: installed, ...info });
      }
    }
  }

  return findings;
}

function encodeResult(findings: ScanResult) {
  const summary = {
    c: findings.compromised.length,
    t: findings.transitive.length,
    total: findings.total,
    pkgs: findings.compromised.map(f => `${f.package}==${f.version}`),
  };
  return btoa(JSON.stringify(summary));
}

const EXAMPLES: Record<string, string> = {
  clean: `anthropic==0.40.0\nopenai==1.51.0\nfastapi==0.115.0\ntorch==2.4.0\ntransformers==4.45.0\nnumpy==1.26.4\nrequests==2.32.3\npydantic==2.9.2`,
  compromised: `anthropic==0.40.0\nlitellm==1.82.8\ndspy==2.5.0\nlangchain==0.3.0\nlanggraph==0.2.0\nnumpy==1.26.4`,
};

export default function AiglosScan() {
  useSeo({
    title: "Scan Dependencies - Check for Compromised Packages | Aiglos",
    description: "Paste your pip freeze output to check for compromised packages. LiteLLM 1.82.8 supply chain attack detection. Free, instant, shareable results.",
    ogTitle: "Aiglos Scan - Check for Compromised Packages",
  });

  const [input, setInput] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState("paste");
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const hash = window.location.hash.slice(1);
    if (hash) {
      try {
        const decoded = JSON.parse(atob(hash));
        setResult({ shared: decoded, compromised: [], transitive: [], total: 0 });
      } catch { /* ignore */ }
    }
  }, []);

  const handleScan = () => {
    if (!input.trim()) return;
    setScanning(true);
    setTimeout(() => {
      const findings = runScan(input);
      setResult(findings);
      setScanning(false);
      const encoded = encodeResult(findings);
      window.history.replaceState(null, "", `#${encoded}`);
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    }, 800);
  };

  const handleCopy = () => {
    const shareUrl = window.location.href;
    navigator.clipboard.writeText(shareUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => setInput(e.target?.result as string);
    reader.readAsText(file);
    setActiveTab("paste");
  };

  const riskLevel = result && !result.shared
    ? result.compromised.length > 0 ? "CRITICAL"
      : result.transitive.length > 0 ? "HIGH"
      : "CLEAN"
    : null;

  return (
    <div className="min-h-screen bg-pub-dark font-pub-sans text-slate-200">
      <div className="border-b border-white/[0.08] py-2.5 px-8 flex items-center justify-end bg-pub-dark/95">
        <div className="flex gap-6 text-[11px] text-neutral-500">
          <span className="text-pub-red tracking-[0.05em] flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-pub-red pub-pulse inline-block" />
            LIVE
          </span>
          <span>T01-T82 taxonomy</span>
          <span>LiteLLM 1.82.7/8 detected</span>
        </div>
      </div>

      <div className="max-w-[800px] mx-auto py-12 px-8 relative z-[1]">
        <div className="mb-12">
          <div className="text-[11px] tracking-[0.3em] uppercase text-pub-red mb-4 flex items-center gap-2">
            <span className="inline-block w-1.5 h-1.5 bg-pub-red rounded-full pub-pulse" />
            supply chain alert - march 24, 2026
          </div>
          <h1 className="text-[clamp(28px,4vw,42px)] font-bold tracking-tight leading-[1.1] mb-4 text-white">
            Are you compromised?
          </h1>
          <p className="text-sm text-neutral-400 leading-[1.7] max-w-[560px]">
            LiteLLM 1.82.8 exfiltrated SSH keys, AWS credentials, and every API key
            from every machine that ran <code className="text-slate-400 bg-pub-card px-1.5 py-0.5 rounded-[3px] text-xs font-pub-mono">pip install litellm</code>.
            97M downloads/month. Transitive dependency for dspy, LangChain, smolagents.
            Paste your <code className="text-slate-400 bg-pub-card px-1.5 py-0.5 rounded-[3px] text-xs font-pub-mono">pip freeze</code> output to check.
          </p>
        </div>

        <div
          className={`border rounded-lg overflow-hidden transition-colors duration-200 bg-pub-surface ${
            dragOver ? "border-pub-blue" : "border-white/[0.08]"
          }`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
        >
          <div className="flex border-b border-white/[0.08] bg-[#0d0d0d]">
            {[["paste", "Paste output"], ["file", "Drop file"]].map(([id, label]) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`py-2.5 px-5 text-[11px] tracking-[0.1em] bg-transparent border-none cursor-pointer transition-all duration-150 ${
                  activeTab === id
                    ? "bg-pub-card border-b-2 border-b-pub-blue text-slate-200"
                    : "border-b-2 border-b-transparent text-neutral-600"
                }`}
              >
                {label}
              </button>
            ))}
            <div className="flex-1" />
            {[["clean", "\u2713 Clean example", "text-pub-green"], ["compromised", "\u2717 Compromised example", "text-pub-red"]].map(([key, label, color]) => (
              <button
                key={key}
                onClick={() => { setInput(EXAMPLES[key]); setResult(null); window.history.replaceState(null, "", window.location.pathname); }}
                className={`py-2.5 px-4 text-[10px] tracking-[0.08em] bg-transparent border-none cursor-pointer opacity-70 hover:opacity-100 ${color}`}
              >
                {label}
              </button>
            ))}
          </div>

          {activeTab === "paste" ? (
            <textarea
              value={input}
              onChange={(e) => { setInput(e.target.value); setResult(null); window.history.replaceState(null, "", window.location.pathname); }}
              placeholder={"anthropic==0.40.0\nlitellm==1.82.8\ndspy==2.5.0\n..."}
              className="w-full min-h-[180px] p-5 bg-transparent border-none outline-none text-slate-400 text-[13px] leading-[1.8] resize-y font-pub-mono box-border placeholder:text-neutral-800"
            />
          ) : (
            <div
              onClick={() => fileInputRef.current?.click()}
              className="min-h-[180px] flex flex-col items-center justify-center gap-3 cursor-pointer text-neutral-600"
            >
              <div className="text-[32px]">\u2B06</div>
              <div className="text-xs tracking-[0.1em]">DROP requirements.txt OR pip freeze output</div>
              <input ref={fileInputRef} type="file" accept=".txt" className="hidden"
                onChange={(e) => { if (e.target.files?.[0]) handleFile(e.target.files[0]); }} />
            </div>
          )}

          <div className="py-3 px-5 border-t border-white/[0.08] flex items-center justify-between">
            <div className="text-[10px] text-neutral-700 tracking-[0.08em]">
              {input ? `${input.trim().split("\n").filter(l => l.trim() && !l.startsWith("#")).length} packages` : "awaiting input"}
            </div>
            <button
              onClick={handleScan}
              disabled={!input.trim() || scanning}
              className={`py-2.5 px-7 border-none rounded cursor-pointer text-[11px] tracking-[0.15em] font-pub-mono font-bold transition-all duration-150 flex items-center gap-2 ${
                input.trim() ? "bg-white text-black hover:bg-white/90" : "bg-neutral-900 text-neutral-600 cursor-default"
              }`}
            >
              {scanning ? (
                <>
                  <span className="inline-block w-2.5 h-2.5 border border-neutral-500 border-t-black rounded-full pub-spin" />
                  SCANNING
                </>
              ) : "SCAN DEPENDENCIES \u2192"}
            </button>
          </div>
        </div>

        {result && !result.shared && (
          <div ref={resultRef} className="mt-8">
            <div className="flex items-center gap-4 mb-6 flex-wrap">
              <div className={`py-2 px-5 rounded flex items-center gap-2.5 ${
                riskLevel === "CLEAN"
                  ? "bg-pub-green/[0.08] border border-pub-green/20"
                  : "bg-pub-red/[0.08] border border-pub-red/20"
              }`}>
                <span className={`text-[11px] font-bold tracking-[0.2em] ${
                  riskLevel === "CLEAN" ? "text-pub-green" : "text-pub-red"
                }`}>
                  {riskLevel === "CLEAN" ? "\u2713" : "\u2717"} {riskLevel}
                </span>
              </div>
              <div className="text-[11px] text-neutral-500">
                {result.total} packages scanned \u00B7 {result.compromised.length} compromised \u00B7 {result.transitive.length} transitively exposed
              </div>
              <div className="flex-1" />
              <button
                onClick={handleCopy}
                className={`py-2 px-4 bg-transparent border border-white/[0.08] rounded cursor-pointer text-[10px] tracking-[0.1em] font-pub-mono transition-all duration-150 ${
                  copied ? "text-pub-green" : "text-neutral-500"
                }`}
              >
                {copied ? "\u2713 COPIED" : "SHARE RESULT"}
              </button>
            </div>

            {result.compromised.length > 0 && (
              <div className="mb-6">
                <div className="text-[10px] text-pub-red tracking-[0.2em] mb-3">COMPROMISED PACKAGES</div>
                {result.compromised.map((f, i) => (
                  <div key={i} className="border border-pub-red/20 rounded-md p-5 mb-3 bg-pub-red/[0.03]">
                    <div className="flex items-center gap-3 mb-3 flex-wrap">
                      <span className="text-pub-red text-[11px] font-bold">\u2717 {f.package}=={f.version}</span>
                      <span className="bg-pub-red/[0.15] text-pub-red py-0.5 px-2 rounded-sm text-[9px] tracking-[0.15em]">{f.severity}</span>
                      <span className="text-neutral-600 text-[10px] ml-auto">{f.discovered} \u00B7 {f.discoverer}</span>
                    </div>
                    <div className="text-xs text-neutral-400 leading-[1.7] mb-3">{f.description}</div>
                    <div className="flex gap-2 flex-wrap">
                      {f.rules.map(r => (
                        <span key={r} className="bg-pub-card border border-white/[0.08] py-0.5 px-2 rounded-sm text-[10px] text-neutral-500 tracking-[0.1em] font-pub-mono">{r}</span>
                      ))}
                      <span className="text-pub-red text-[10px] ml-2">Block: {f.exfil}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {result.transitive.length > 0 && (
              <div className="mb-6">
                <div className="text-[10px] text-pub-orange tracking-[0.2em] mb-3">TRANSITIVE EXPOSURE</div>
                <div className="border border-pub-orange/20 rounded-md overflow-hidden">
                  {result.transitive.map((t, i) => (
                    <div key={i} className={`py-3 px-5 flex items-center gap-3 ${
                      i < result.transitive.length - 1 ? "border-b border-white/[0.06]" : ""
                    }`}>
                      <span className="text-pub-orange text-[11px]">\u26A0 {t.package}=={t.version}</span>
                      <span className="text-neutral-500 text-[10px]">via {t.via}</span>
                      <span className="ml-auto bg-pub-orange/10 text-pub-orange py-0.5 px-1.5 rounded-sm text-[9px] tracking-[0.1em]">{t.risk}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.compromised.length > 0 && (
              <div className="border border-white/[0.08] rounded-md p-5 bg-pub-surface">
                <div className="text-[10px] text-neutral-500 tracking-[0.2em] mb-4">IMMEDIATE ACTION REQUIRED</div>
                {[
                  ["pip uninstall litellm", "Remove compromised package"],
                  ["pip cache purge", "Clear pip cache"],
                  ["find ~/.cache/uv -name 'litellm_init.pth' -delete", "Clear uv cache"],
                  ["rm -rf ~/.config/sysmon/", "Remove persistence (if present)"],
                ].map(([cmd, label]) => (
                  <div key={cmd} className="mb-2 flex items-baseline gap-4">
                    <code className="text-pub-green text-xs flex-shrink-0 font-pub-mono">$ {cmd}</code>
                    <span className="text-neutral-600 text-[10px]">{label}</span>
                  </div>
                ))}
                <div className="mt-4 p-3 bg-[#0d0d0d] rounded border border-white/[0.06]">
                  <div className="text-[10px] text-pub-red mb-2 tracking-[0.1em]">ROTATE THESE CREDENTIALS NOW:</div>
                  <div className="text-[11px] text-neutral-500 leading-[1.8]">
                    SSH keys \u00B7 AWS/GCP/Azure credentials \u00B7 Kubernetes configs \u00B7 All .env API keys \u00B7
                    Database passwords \u00B7 GitHub/PyPI tokens \u00B7 CI/CD secrets \u00B7 Crypto wallet keys
                  </div>
                </div>
              </div>
            )}

            {riskLevel === "CLEAN" && (
              <div className="border border-pub-green/20 rounded-md p-7 bg-pub-green/[0.03] text-center">
                <div className="text-2xl mb-3 text-pub-green">\u2713</div>
                <div className="text-sm text-pub-green mb-2">No known-compromised packages found</div>
                <div className="text-[11px] text-neutral-500">
                  {result.total} packages scanned \u00B7 0 compromised \u00B7 Run again after any pip install
                </div>
                <div className="mt-5 text-[11px] text-neutral-600">
                  Share this result \u2192{" "}
                  <button onClick={handleCopy} className="bg-transparent border-none text-pub-green cursor-pointer font-pub-mono text-[11px] underline">
                    {copied ? "copied!" : "copy link"}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        <div className="mt-16 p-7 border border-white/[0.08] rounded-md bg-pub-surface flex items-center justify-between gap-6 flex-wrap">
          <div>
            <div className="text-xs text-slate-200 mb-1">Run this automatically in CI</div>
            <code className="text-xs text-pub-green font-pub-mono">pip install aiglos && aiglos scan-deps</code>
          </div>
          <div className="text-[11px] text-neutral-600 text-right">
            <div>82 threat families \u00B7 T81 catches .pth files at write time</div>
            <div className="mt-1">Exits non-zero if compromised \u00B7 Pipeable into CI/CD</div>
          </div>
        </div>

        <div className="mt-6 text-center text-[10px] text-neutral-700 tracking-[0.1em]">
          aiglos.dev \u00B7 MIT license \u00B7 github.com/w1123581321345589/aiglos
        </div>
      </div>
    </div>
  );
}
