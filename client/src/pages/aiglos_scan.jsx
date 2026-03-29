import { useState, useEffect, useRef } from "react";

// ── Threat database (mirrors aiglos/cli/scan_deps.py) ──────────────────────
const COMPROMISED = {
  "litellm": {
    "1.82.7": {
      severity: "CRITICAL",
      description: "Contains litellm_init.pth — exfiltrates SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, database passwords, all .env API keys, shell history, crypto wallets to models.litellm.cloud",
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

const TRANSITIVE = {
  "dspy": { via: "litellm>=1.64.0", risk: "HIGH" },
  "smolagents": { via: "litellm (optional)", risk: "MEDIUM" },
  "langchain": { via: "litellm (optional)", risk: "MEDIUM" },
  "langchain-core": { via: "langchain", risk: "MEDIUM" },
  "langgraph": { via: "langchain", risk: "MEDIUM" },
  "crewai": { via: "litellm (optional)", risk: "MEDIUM" },
  "autogen": { via: "litellm (optional)", risk: "MEDIUM" },
  "litellm-proxy": { via: "litellm (direct)", risk: "CRITICAL" },
};

const PERSISTENCE_INDICATORS = [
  "~/.config/sysmon/sysmon.py",
  "~/.config/systemd/user/sysmon.service",
];

// ── Parser ─────────────────────────────────────────────────────────────────
function parsePackages(text) {
  const packages = {};
  const lines = text.trim().split("\n");
  for (const line of lines) {
    const clean = line.trim();
    if (!clean || clean.startsWith("#")) continue;
    // pip freeze format: package==version
    const eqMatch = clean.match(/^([a-zA-Z0-9_\-\.]+)==([^\s;]+)/);
    if (eqMatch) {
      packages[eqMatch[1].toLowerCase()] = eqMatch[2];
      continue;
    }
    // requirements.txt format: package>=version or just package
    const reqMatch = clean.match(/^([a-zA-Z0-9_\-\.]+)/);
    if (reqMatch) {
      packages[reqMatch[1].toLowerCase()] = "unspecified";
    }
  }
  return packages;
}

function runScan(text) {
  const packages = parsePackages(text);
  const findings = { compromised: [], transitive: [], total: Object.keys(packages).length };

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

// ── Share URL via hash ─────────────────────────────────────────────────────
function encodeResult(findings) {
  const summary = {
    c: findings.compromised.length,
    t: findings.transitive.length,
    total: findings.total,
    pkgs: findings.compromised.map(f => `${f.package}==${f.version}`),
  };
  return btoa(JSON.stringify(summary));
}

// ── Components ─────────────────────────────────────────────────────────────
const EXAMPLES = {
  clean: `anthropic==0.40.0\nopenai==1.51.0\nfastapi==0.115.0\ntorch==2.4.0\ntransformers==4.45.0\nnumpy==1.26.4\nrequests==2.32.3\npydantic==2.9.2`,
  compromised: `anthropic==0.40.0\nlitellm==1.82.8\ndspy==2.5.0\nlangchain==0.3.0\nlanggraph==0.2.0\nnumpy==1.26.4`,
};

export default function AiglosScan() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState("paste");
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);
  const resultRef = useRef(null);

  useEffect(() => {
    // Check URL hash for shared results
    const hash = window.location.hash.slice(1);
    if (hash) {
      try {
        const decoded = JSON.parse(atob(hash));
        setResult({ shared: decoded });
      } catch {}
    }
  }, []);

  const handleScan = () => {
    if (!input.trim()) return;
    setScanning(true);
    setTimeout(() => {
      const findings = runScan(input);
      setResult(findings);
      setScanning(false);
      // Update URL hash
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

  const handleFile = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => setInput(e.target.result);
    reader.readAsText(file);
    setActiveTab("paste");
  };

  const riskLevel = result && !result.shared
    ? result.compromised.length > 0 ? "CRITICAL"
      : result.transitive.length > 0 ? "HIGH"
      : "CLEAN"
    : null;

  const riskColor = { CRITICAL: "#ef4444", HIGH: "#f97316", CLEAN: "#22c55e" };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#080808",
      fontFamily: "'DM Mono', 'Courier New', monospace",
      color: "#e2e8f0",
      padding: "0",
    }}>
      {/* Scanline overlay */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)",
      }} />

      {/* Header */}
      <div style={{
        borderBottom: "1px solid #1e1e1e",
        padding: "16px 32px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: "rgba(8,8,8,0.95)", backdropFilter: "blur(8px)",
        position: "sticky", top: 0, zIndex: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{
            fontFamily: "'DM Mono', monospace", fontSize: "15px", fontWeight: 600,
            letterSpacing: "0.05em", color: "#fff",
          }}>
            ▲ aiglos
          </div>
          <div style={{ color: "#444", fontSize: "11px" }}>/</div>
          <div style={{ color: "#888", fontSize: "11px", letterSpacing: "0.1em" }}>SCAN</div>
        </div>
        <div style={{ display: "flex", gap: "24px", fontSize: "11px", color: "#555" }}>
          <span style={{ color: "#ef4444", letterSpacing: "0.05em" }}>● LIVE</span>
          <span>T01–T82 taxonomy</span>
          <span>LiteLLM 1.82.7/8 detected</span>
        </div>
      </div>

      <div style={{ maxWidth: "800px", margin: "0 auto", padding: "48px 32px", position: "relative", zIndex: 1 }}>

        {/* Hero */}
        <div style={{ marginBottom: "48px" }}>
          <div style={{
            fontSize: "11px", letterSpacing: "0.3em", textTransform: "uppercase",
            color: "#ef4444", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px"
          }}>
            <span style={{ display: "inline-block", width: "6px", height: "6px", background: "#ef4444", borderRadius: "50%", animation: "pulse 2s infinite" }} />
            supply chain alert — march 24, 2026
          </div>
          <h1 style={{
            fontSize: "clamp(28px, 4vw, 42px)", fontWeight: 700,
            letterSpacing: "-0.03em", lineHeight: 1.1, marginBottom: "16px",
            color: "#fff",
          }}>
            Are you compromised?
          </h1>
          <p style={{ fontSize: "14px", color: "#666", lineHeight: 1.7, maxWidth: "560px" }}>
            LiteLLM 1.82.8 exfiltrated SSH keys, AWS credentials, and every API key
            from every machine that ran <code style={{ color: "#94a3b8", background: "#111", padding: "2px 6px", borderRadius: "3px" }}>pip install litellm</code>.
            97M downloads/month. Transitive dependency for dspy, LangChain, smolagents.
            Paste your <code style={{ color: "#94a3b8", background: "#111", padding: "2px 6px", borderRadius: "3px" }}>pip freeze</code> output to check.
          </p>
        </div>

        {/* Input area */}
        <div style={{
          border: `1px solid ${dragOver ? "#3b82f6" : "#1e1e1e"}`,
          borderRadius: "8px", overflow: "hidden",
          transition: "border-color 0.2s",
          background: "#0a0a0a",
        }}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
        >
          {/* Tab bar */}
          <div style={{
            display: "flex", borderBottom: "1px solid #1e1e1e",
            background: "#0d0d0d",
          }}>
            {[["paste", "Paste output"], ["file", "Drop file"]].map(([id, label]) => (
              <button key={id} onClick={() => setActiveTab(id)} style={{
                padding: "10px 20px", fontSize: "11px", letterSpacing: "0.1em",
                background: activeTab === id ? "#111" : "transparent",
                border: "none", borderBottom: activeTab === id ? "1px solid #3b82f6" : "1px solid transparent",
                color: activeTab === id ? "#e2e8f0" : "#444", cursor: "pointer",
                transition: "all 0.15s",
              }}>{label}</button>
            ))}
            <div style={{ flex: 1 }} />
            {[["clean", "✓ Clean example"], ["compromised", "✗ Compromised example"]].map(([key, label]) => (
              <button key={key} onClick={() => { setInput(EXAMPLES[key]); setResult(null); window.history.replaceState(null, "", window.location.pathname); }} style={{
                padding: "10px 16px", fontSize: "10px", letterSpacing: "0.08em",
                background: "transparent", border: "none",
                color: key === "compromised" ? "#ef4444" : "#22c55e",
                cursor: "pointer", opacity: 0.7,
              }}>{label}</button>
            ))}
          </div>

          {activeTab === "paste" ? (
            <textarea
              value={input}
              onChange={(e) => { setInput(e.target.value); setResult(null); window.history.replaceState(null, "", window.location.pathname); }}
              placeholder={"anthropic==0.40.0\nlitellm==1.82.8\ndspy==2.5.0\n..."}
              style={{
                width: "100%", minHeight: "180px", padding: "20px",
                background: "transparent", border: "none", outline: "none",
                color: "#94a3b8", fontSize: "13px", lineHeight: "1.8",
                resize: "vertical", fontFamily: "inherit",
                boxSizing: "border-box",
              }}
            />
          ) : (
            <div
              onClick={() => fileInputRef.current?.click()}
              style={{
                minHeight: "180px", display: "flex", flexDirection: "column",
                alignItems: "center", justifyContent: "center", gap: "12px",
                cursor: "pointer", color: "#444",
              }}>
              <div style={{ fontSize: "32px" }}>⬆</div>
              <div style={{ fontSize: "12px", letterSpacing: "0.1em" }}>DROP requirements.txt OR pip freeze output</div>
              <input ref={fileInputRef} type="file" accept=".txt" style={{ display: "none" }}
                onChange={(e) => { if (e.target.files[0]) handleFile(e.target.files[0]); }} />
            </div>
          )}

          {/* Scan button */}
          <div style={{ padding: "12px 20px", borderTop: "1px solid #1e1e1e", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ fontSize: "10px", color: "#333", letterSpacing: "0.08em" }}>
              {input ? `${input.trim().split("\n").filter(l => l.trim() && !l.startsWith("#")).length} packages` : "awaiting input"}
            </div>
            <button
              onClick={handleScan}
              disabled={!input.trim() || scanning}
              style={{
                padding: "10px 28px", background: input.trim() ? "#fff" : "#1a1a1a",
                color: input.trim() ? "#000" : "#333",
                border: "none", borderRadius: "4px", cursor: input.trim() ? "pointer" : "default",
                fontSize: "11px", letterSpacing: "0.15em", fontFamily: "inherit",
                fontWeight: 700, transition: "all 0.15s",
                display: "flex", alignItems: "center", gap: "8px",
              }}>
              {scanning ? (
                <>
                  <span style={{ display: "inline-block", width: "10px", height: "10px", border: "1px solid #666", borderTop: "1px solid #000", borderRadius: "50%", animation: "spin 0.6s linear infinite" }} />
                  SCANNING
                </>
              ) : "SCAN DEPENDENCIES →"}
            </button>
          </div>
        </div>

        {/* Results */}
        {result && !result.shared && (
          <div ref={resultRef} style={{ marginTop: "32px" }}>
            {/* Risk badge */}
            <div style={{
              display: "flex", alignItems: "center", gap: "16px",
              marginBottom: "24px",
            }}>
              <div style={{
                padding: "8px 20px",
                background: riskLevel === "CLEAN" ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)",
                border: `1px solid ${riskColor[riskLevel]}33`,
                borderRadius: "4px", display: "flex", alignItems: "center", gap: "10px",
              }}>
                <span style={{ color: riskColor[riskLevel], fontSize: "11px", fontWeight: 700, letterSpacing: "0.2em" }}>
                  {riskLevel === "CLEAN" ? "✓" : "✗"} {riskLevel}
                </span>
              </div>
              <div style={{ fontSize: "11px", color: "#555" }}>
                {result.total} packages scanned · {result.compromised.length} compromised · {result.transitive.length} transitively exposed
              </div>
              <div style={{ flex: 1 }} />
              <button onClick={handleCopy} style={{
                padding: "8px 16px", background: "transparent",
                border: "1px solid #1e1e1e", borderRadius: "4px",
                color: copied ? "#22c55e" : "#555", cursor: "pointer",
                fontSize: "10px", letterSpacing: "0.1em", fontFamily: "inherit",
                transition: "all 0.15s",
              }}>
                {copied ? "✓ COPIED" : "SHARE RESULT"}
              </button>
            </div>

            {/* Compromised packages */}
            {result.compromised.length > 0 && (
              <div style={{ marginBottom: "24px" }}>
                <div style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.2em", marginBottom: "12px" }}>COMPROMISED PACKAGES</div>
                {result.compromised.map((f, i) => (
                  <div key={i} style={{
                    border: "1px solid rgba(239,68,68,0.2)",
                    borderRadius: "6px", padding: "20px", marginBottom: "12px",
                    background: "rgba(239,68,68,0.03)",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "12px" }}>
                      <span style={{ color: "#ef4444", fontSize: "11px", fontWeight: 700 }}>✗ {f.package}=={f.version}</span>
                      <span style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444", padding: "2px 8px", borderRadius: "2px", fontSize: "9px", letterSpacing: "0.15em" }}>{f.severity}</span>
                      <span style={{ color: "#444", fontSize: "10px", marginLeft: "auto" }}>{f.discovered} · {f.discoverer}</span>
                    </div>
                    <div style={{ fontSize: "12px", color: "#888", lineHeight: 1.7, marginBottom: "12px" }}>{f.description}</div>
                    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                      {f.rules.map(r => (
                        <span key={r} style={{ background: "#111", border: "1px solid #222", padding: "2px 8px", borderRadius: "2px", fontSize: "10px", color: "#666", letterSpacing: "0.1em" }}>{r}</span>
                      ))}
                      <span style={{ color: "#ef4444", fontSize: "10px", marginLeft: "8px" }}>Block: {f.exfil}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Transitive exposure */}
            {result.transitive.length > 0 && (
              <div style={{ marginBottom: "24px" }}>
                <div style={{ fontSize: "10px", color: "#f97316", letterSpacing: "0.2em", marginBottom: "12px" }}>TRANSITIVE EXPOSURE</div>
                <div style={{ border: "1px solid rgba(249,115,22,0.2)", borderRadius: "6px", overflow: "hidden" }}>
                  {result.transitive.map((t, i) => (
                    <div key={i} style={{
                      padding: "12px 20px", borderBottom: i < result.transitive.length - 1 ? "1px solid #1a1a1a" : "none",
                      display: "flex", alignItems: "center", gap: "12px",
                    }}>
                      <span style={{ color: "#f97316", fontSize: "11px" }}>⚠ {t.package}=={t.version}</span>
                      <span style={{ color: "#555", fontSize: "10px" }}>via {t.via}</span>
                      <span style={{ marginLeft: "auto", background: "rgba(249,115,22,0.1)", color: "#f97316", padding: "1px 6px", borderRadius: "2px", fontSize: "9px", letterSpacing: "0.1em" }}>{t.risk}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation */}
            {result.compromised.length > 0 && (
              <div style={{
                border: "1px solid #1e1e1e", borderRadius: "6px", padding: "20px",
                background: "#0a0a0a",
              }}>
                <div style={{ fontSize: "10px", color: "#555", letterSpacing: "0.2em", marginBottom: "16px" }}>IMMEDIATE ACTION REQUIRED</div>
                {[
                  ["pip uninstall litellm", "Remove compromised package"],
                  ["pip cache purge", "Clear pip cache"],
                  ["find ~/.cache/uv -name 'litellm_init.pth' -delete", "Clear uv cache"],
                  ["rm -rf ~/.config/sysmon/", "Remove persistence (if present)"],
                ].map(([cmd, label]) => (
                  <div key={cmd} style={{ marginBottom: "8px", display: "flex", alignItems: "baseline", gap: "16px" }}>
                    <code style={{ color: "#22c55e", fontSize: "12px", flex: "0 0 auto" }}>$ {cmd}</code>
                    <span style={{ color: "#444", fontSize: "10px" }}>{label}</span>
                  </div>
                ))}
                <div style={{ marginTop: "16px", padding: "12px", background: "#0d0d0d", borderRadius: "4px", border: "1px solid #1a1a1a" }}>
                  <div style={{ fontSize: "10px", color: "#ef4444", marginBottom: "8px", letterSpacing: "0.1em" }}>ROTATE THESE CREDENTIALS NOW:</div>
                  <div style={{ fontSize: "11px", color: "#666", lineHeight: "1.8" }}>
                    SSH keys · AWS/GCP/Azure credentials · Kubernetes configs · All .env API keys ·
                    Database passwords · GitHub/PyPI tokens · CI/CD secrets · Crypto wallet keys
                  </div>
                </div>
              </div>
            )}

            {/* Clean result */}
            {riskLevel === "CLEAN" && (
              <div style={{
                border: "1px solid rgba(34,197,94,0.2)", borderRadius: "6px", padding: "28px",
                background: "rgba(34,197,94,0.03)", textAlign: "center",
              }}>
                <div style={{ fontSize: "24px", marginBottom: "12px", color: "#22c55e" }}>✓</div>
                <div style={{ fontSize: "14px", color: "#22c55e", marginBottom: "8px" }}>No known-compromised packages found</div>
                <div style={{ fontSize: "11px", color: "#555" }}>
                  {result.total} packages scanned · 0 compromised · Run again after any pip install
                </div>
                <div style={{ marginTop: "20px", fontSize: "11px", color: "#444" }}>
                  Share this result → <button onClick={handleCopy} style={{ background: "none", border: "none", color: "#22c55e", cursor: "pointer", fontFamily: "inherit", fontSize: "11px", textDecoration: "underline" }}>
                    {copied ? "copied!" : "copy link"}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* CTA footer */}
        <div style={{
          marginTop: "64px", padding: "28px", border: "1px solid #1e1e1e",
          borderRadius: "6px", background: "#0a0a0a",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          gap: "24px", flexWrap: "wrap",
        }}>
          <div>
            <div style={{ fontSize: "12px", color: "#e2e8f0", marginBottom: "4px" }}>Run this automatically in CI</div>
            <code style={{ fontSize: "12px", color: "#22c55e" }}>pip install aiglos && aiglos scan-deps</code>
          </div>
          <div style={{ fontSize: "11px", color: "#444", textAlign: "right" }}>
            <div>82 threat families · T81 catches .pth files at write time</div>
            <div style={{ marginTop: "4px" }}>Exits non-zero if compromised · Pipeable into CI/CD</div>
          </div>
        </div>

        <div style={{ marginTop: "24px", textAlign: "center", fontSize: "10px", color: "#333", letterSpacing: "0.1em" }}>
          aiglos.dev · MIT license · github.com/aiglos/aiglos
        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap');
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        @keyframes spin { to { transform: rotate(360deg); } }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0a0a0a; }
        ::-webkit-scrollbar-thumb { background: #222; border-radius: 3px; }
        textarea::placeholder { color: #2a2a2a; }
      `}</style>
    </div>
  );
}
