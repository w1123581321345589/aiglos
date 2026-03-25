import React, { useState } from 'react';

export function DarkCurrent() {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText('pip install aiglos && aiglos launch');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="dark-landing">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap');

        .dark-landing {
          --bg: #09090b;
          --bg2: #111116;
          --bg3: #18181e;
          --ln: rgba(255, 255, 255, 0.06);
          --ln2: rgba(255, 255, 255, 0.1);
          --dim: rgba(255, 255, 255, 0.35);
          --mid: rgba(255, 255, 255, 0.6);
          --hi: #fff;
          --blue: #2563eb;
          --ice: #60a5fa;
          --paper: #fafaf9;
          --gold: #b8860b;

          background: var(--bg);
          color: var(--hi);
          font-family: 'Plus Jakarta Sans', sans-serif;
          -webkit-font-smoothing: antialiased;
          overflow-x: hidden;
          min-height: 100vh;
          width: 100%;
          text-align: left;
        }

        .dark-landing * {
          box-sizing: border-box;
        }

        .dark-landing a {
          color: inherit;
          text-decoration: none;
        }

        /* NAV */
        .dark-landing-nav {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 100;
          background: rgba(9, 9, 11, 0.85);
          backdrop-filter: blur(12px);
          border-bottom: 1px solid var(--ln);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 48px;
          height: 56px;
        }
        .nav-logo {
          display: flex;
          align-items: center;
          gap: 10px;
          text-decoration: none;
        }
        .nav-mark {
          width: 20px;
          height: 24px;
        }
        .nav-name {
          font-family: 'DM Mono', monospace;
          font-size: 13px;
          font-weight: 500;
          letter-spacing: 0.04em;
          color: var(--hi);
        }
        .nav-links {
          display: flex;
          gap: 28px;
          list-style: none;
          margin: 0;
          padding: 0;
        }
        .nav-links a {
          font-size: 13px;
          color: var(--dim);
          text-decoration: none;
          transition: color .15s;
        }
        .nav-links a:hover {
          color: var(--hi);
        }
        .nav-cta {
          display: flex;
          gap: 10px;
          align-items: center;
        }
        .btn-ghost {
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          letter-spacing: 0.1em;
          text-transform: uppercase;
          color: var(--dim);
          text-decoration: none;
          padding: 7px 14px;
          border: 1px solid var(--ln2);
          border-radius: 4px;
          transition: all .15s;
        }
        .btn-ghost:hover {
          color: var(--hi);
          border-color: rgba(255, 255, 255, 0.3);
        }
        .btn-primary {
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          letter-spacing: 0.1em;
          text-transform: uppercase;
          background: var(--hi);
          color: var(--bg);
          padding: 7px 16px;
          border-radius: 4px;
          text-decoration: none;
          transition: opacity .15s;
        }
        .btn-primary:hover {
          opacity: 0.85;
        }

        /* HERO */
        .hero {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          text-align: center;
          padding: 80px 48px 64px;
          position: relative;
          overflow: hidden;
        }
        .hero::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: radial-gradient(ellipse 80% 60% at 50% 20%, rgba(37, 99, 235, 0.08) 0%, transparent 70%);
          pointer-events: none;
        }
        .hero-badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          background: rgba(37, 99, 235, 0.1);
          border: 1px solid rgba(37, 99, 235, 0.25);
          border-radius: 100px;
          padding: 5px 14px;
          margin-bottom: 32px;
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          letter-spacing: 0.12em;
          text-transform: uppercase;
          color: var(--ice);
        }
        .hero-badge-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: var(--ice);
          animation: pulse 2s infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1 }
          50% { opacity: 0.4 }
        }
        .hero h1 {
          font-size: clamp(40px, 6vw, 80px);
          font-weight: 700;
          line-height: 1.05;
          letter-spacing: -0.03em;
          max-width: 800px;
          margin-bottom: 24px;
          margin-top: 0;
        }
        .hero h1 span {
          color: var(--ice);
        }
        .hero-sub {
          font-size: 18px;
          font-weight: 300;
          color: var(--mid);
          max-width: 520px;
          line-height: 1.65;
          margin-bottom: 48px;
        }
        .hero-actions {
          display: flex;
          gap: 12px;
          align-items: center;
          flex-wrap: wrap;
          justify-content: center;
          margin-bottom: 72px;
        }
        .hero-install {
          background: var(--bg2);
          border: 1px solid var(--ln2);
          border-radius: 6px;
          padding: 14px 20px;
          display: flex;
          align-items: center;
          gap: 12px;
          text-align: left;
        }
        .hero-install code {
          font-family: 'DM Mono', monospace;
          font-size: 13px;
          color: var(--hi);
        }
        .hero-install-label {
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: var(--dim);
          margin-bottom: 2px;
        }
        .copy-btn {
          background: none;
          border: 1px solid var(--ln);
          border-radius: 3px;
          padding: 4px 10px;
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          color: var(--dim);
          cursor: pointer;
          transition: all .15s;
        }
        .copy-btn:hover {
          border-color: var(--ln2);
          color: var(--hi);
        }
        .hero-stats {
          display: flex;
          gap: 48px;
          flex-wrap: wrap;
          justify-content: center;
        }
        .hero-stat {
          text-align: center;
        }
        .hero-stat-n {
          font-family: 'DM Mono', monospace;
          font-size: 28px;
          font-weight: 500;
          color: var(--hi);
          display: block;
          line-height: 1;
        }
        .hero-stat-l {
          font-size: 11px;
          letter-spacing: 0.1em;
          text-transform: uppercase;
          color: var(--dim);
          margin-top: 4px;
          display: block;
        }

        /* THE NUMBER */
        .number-section {
          padding: 80px 48px;
          text-align: center;
          border-top: 1px solid var(--ln);
          border-bottom: 1px solid var(--ln);
        }
        .number-big {
          font-family: 'DM Mono', monospace;
          font-size: clamp(64px, 10vw, 128px);
          font-weight: 500;
          color: var(--hi);
          line-height: 1;
          display: block;
          letter-spacing: -0.02em;
        }
        .number-label {
          font-size: 16px;
          color: var(--mid);
          max-width: 480px;
          margin: 20px auto 0;
          line-height: 1.6;
        }
        .number-label strong {
          color: var(--hi);
        }

        /* SECTIONS */
        .section {
          padding: 80px 48px;
          max-width: 1100px;
          margin: 0 auto;
        }
        .section-kicker {
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.25em;
          text-transform: uppercase;
          color: var(--ice);
          margin-bottom: 16px;
        }
        .section h2 {
          font-size: clamp(28px, 4vw, 44px);
          font-weight: 700;
          letter-spacing: -0.03em;
          line-height: 1.1;
          margin-bottom: 16px;
          margin-top: 0;
        }
        .section-sub {
          font-size: 16px;
          color: var(--mid);
          line-height: 1.7;
          max-width: 560px;
          margin-bottom: 48px;
        }

        /* CODE BLOCK */
        .code-window {
          background: #0d1117;
          border: 1px solid var(--ln2);
          border-radius: 8px;
          overflow: hidden;
          max-width: 680px;
        }
        .code-topbar {
          background: #161b22;
          padding: 10px 16px;
          display: flex;
          align-items: center;
          gap: 8px;
          border-bottom: 1px solid var(--ln);
        }
        .code-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
        }
        .code-dot.red { background: #ff5f57; }
        .code-dot.yellow { background: #febc2e; }
        .code-dot.green { background: #28c840; }
        .code-filename {
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          color: var(--dim);
          margin-left: 8px;
        }
        .code-body {
          padding: 24px;
          overflow-x: auto;
        }
        .code-body pre {
          font-family: 'DM Mono', monospace;
          font-size: 13.5px;
          line-height: 1.75;
          color: #e6edf3;
          margin: 0;
        }
        .tok-kw { color: #ff7b72; }
        .tok-str { color: #a5d6ff; }
        .tok-fn { color: #d2a8ff; }
        .tok-comment { color: #6e7681; }
        .tok-param { color: #79c0ff; }
        .tok-num { color: #79c0ff; }

        /* FEATURE GRID */
        .feature-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 1px;
          background: var(--ln);
          border: 1px solid var(--ln);
          border-radius: 8px;
          overflow: hidden;
          margin-top: 48px;
        }
        .feature-cell {
          background: var(--bg);
          padding: 32px;
          transition: background .2s;
        }
        .feature-cell:hover {
          background: var(--bg2);
        }
        .feature-icon {
          width: 36px;
          height: 36px;
          margin-bottom: 16px;
          opacity: 0.7;
        }
        .feature-title {
          font-size: 15px;
          font-weight: 600;
          margin-bottom: 8px;
        }
        .feature-body {
          font-size: 13px;
          color: var(--dim);
          line-height: 1.65;
        }

        /* STAT ROW */
        .stat-row {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 1px;
          background: var(--ln);
          border: 1px solid var(--ln);
          border-radius: 8px;
          overflow: hidden;
          margin: 48px 0;
        }
        .stat-cell {
          background: var(--bg2);
          padding: 32px 24px;
          text-align: center;
        }
        .stat-n {
          font-family: 'DM Mono', monospace;
          font-size: 36px;
          font-weight: 500;
          color: var(--hi);
          display: block;
          line-height: 1;
          margin-bottom: 8px;
        }
        .stat-l {
          font-size: 12px;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: var(--dim);
        }

        /* COMPARE */
        .compare-table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 40px;
          font-size: 13px;
        }
        .compare-table th {
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: var(--dim);
          padding: 12px 16px;
          text-align: left;
          border-bottom: 2px solid var(--ln2);
        }
        .compare-table th:first-child {
          padding-left: 0;
        }
        .compare-table td {
          padding: 14px 16px;
          border-bottom: 1px solid var(--ln);
          color: var(--mid);
          vertical-align: top;
        }
        .compare-table td:first-child {
          padding-left: 0;
          font-weight: 500;
          color: var(--hi);
        }
        .compare-table tr.aiglos-row td {
          background: rgba(37, 99, 235, 0.05);
          color: var(--hi);
        }
        .compare-table tr.aiglos-row td:first-child {
          color: var(--ice);
          font-family: 'DM Mono', monospace;
          font-size: 12px;
        }
        .check { color: #4ade80; font-weight: 600; }
        .cross { color: rgba(255, 255, 255, 0.2); }

        /* PRICING */
        .pricing-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 1px;
          background: var(--ln);
          border: 1px solid var(--ln);
          border-radius: 8px;
          overflow: hidden;
          margin-top: 48px;
        }
        .price-col {
          background: var(--bg);
          padding: 36px 32px;
        }
        .price-col.featured {
          background: var(--hi);
          color: var(--bg);
        }
        .price-tier {
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          color: var(--dim);
          margin-bottom: 16px;
        }
        .price-col.featured .price-tier {
          color: rgba(0, 0, 0, 0.4);
        }
        .price-amount {
          font-family: 'DM Mono', monospace;
          font-size: 40px;
          font-weight: 500;
          line-height: 1;
          margin-bottom: 24px;
        }
        .price-col.featured .price-amount {
          color: var(--bg);
        }
        .price-mo {
          font-size: 14px;
          font-weight: 400;
          color: var(--dim);
          margin-left: 4px;
        }
        .price-col.featured .price-mo {
          color: rgba(0, 0, 0, 0.4);
        }
        .price-features {
          list-style: none;
          font-size: 13px;
          line-height: 1.6;
          margin: 0;
          padding: 0;
        }
        .price-features li {
          padding: 8px 0;
          border-bottom: 1px solid var(--ln);
          color: var(--mid);
        }
        .price-col.featured .price-features li {
          border-bottom-color: rgba(0, 0, 0, 0.08);
          color: rgba(0, 0, 0, 0.7);
        }
        .price-features li:last-child {
          border-bottom: none;
        }
        .price-features li::before {
          content: '— ';
          color: var(--ice);
          font-family: 'DM Mono', monospace;
        }
        .price-col.featured .price-features li::before {
          color: var(--blue);
        }

        /* GHSA VALIDATION */
        .validation-grid {
          display: flex;
          flex-direction: column;
          gap: 1px;
          background: var(--ln);
          border: 1px solid var(--ln);
          border-radius: 8px;
          overflow: hidden;
          margin-top: 40px;
        }
        .validation-row {
          background: var(--bg2);
          display: grid;
          grid-template-columns: 140px 1fr auto;
          gap: 24px;
          padding: 20px 24px;
          align-items: center;
        }
        .validation-ghsa {
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          color: var(--ice);
        }
        .validation-title {
          font-size: 13px;
          color: var(--mid);
        }
        .validation-rules {
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          color: #4ade80;
          white-space: nowrap;
        }

        /* ATLAS */
        .atlas-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 16px;
          margin-top: 40px;
        }
        .atlas-cell {
          background: var(--bg2);
          border: 1px solid var(--ln);
          border-radius: 6px;
          padding: 20px;
          display: flex;
          gap: 14px;
        }
        .atlas-icon {
          font-size: 20px;
          flex-shrink: 0;
          margin-top: 2px;
        }
        .atlas-id {
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          color: var(--ice);
          letter-spacing: 0.1em;
          display: block;
          margin-bottom: 4px;
        }
        .atlas-title {
          font-size: 13px;
          font-weight: 500;
          margin-bottom: 4px;
        }
        .atlas-rules {
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          color: var(--dim);
        }

        /* FOOTER */
        .dark-landing-footer {
          border-top: 1px solid var(--ln);
          padding: 40px 48px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          flex-wrap: wrap;
          gap: 16px;
        }
        .footer-logo {
          font-family: 'DM Mono', monospace;
          font-size: 13px;
          color: var(--dim);
        }
        .footer-links {
          display: flex;
          gap: 24px;
        }
        .footer-links a {
          font-size: 12px;
          color: var(--dim);
          text-decoration: none;
        }
        .footer-links a:hover {
          color: var(--hi);
        }
        .footer-copy {
          font-size: 12px;
          color: rgba(255, 255, 255, 0.2);
        }

        /* RESPONSIVE */
        @media (max-width: 768px) {
          .dark-landing-nav { padding: 0 20px; }
          .nav-links { display: none; }
          .hero { padding: 80px 20px 48px; }
          .hero-stats { gap: 24px; }
          .section { padding: 56px 20px; }
          .feature-grid, .stat-row, .pricing-grid { grid-template-columns: 1fr; }
          .atlas-grid { grid-template-columns: 1fr; }
          .validation-row { grid-template-columns: 1fr; gap: 8px; }
          .dark-landing-footer { padding: 32px 20px; flex-direction: column; text-align: center; }
        }

        /* ANIMATIONS */
        .fade-up {
          opacity: 0;
          transform: translateY(20px);
          animation: fadeUp 0.6s ease forwards;
        }
        @keyframes fadeUp {
          to { opacity: 1; transform: translateY(0); }
        }
        .delay-1 { animation-delay: .1s; }
        .delay-2 { animation-delay: .2s; }
        .delay-3 { animation-delay: .3s; }
        .delay-4 { animation-delay: .4s; }
      `}</style>

      {/* NAV */}
      <nav className="dark-landing-nav">
        <a href="#home" className="nav-logo">
          <svg className="nav-mark" viewBox="0 0 44 50" fill="none">
            <polygon points="22,2 2,44 22,44" fill="white" />
            <polygon points="22,2 42,44 22,44" fill="rgba(255,255,255,0.42)" />
            <rect x="14" y="44" width="16" height="6" fill="white" />
          </svg>
          <span className="nav-name">aiglos</span>
        </a>
        <ul className="nav-links">
          <li><a href="#intel">Intel</a></li>
          <li><a href="#compare">Compare</a></li>
          <li><a href="#pricing">Pricing</a></li>
          <li><a href="#docs">Docs</a></li>
          <li><a href="#github">GitHub</a></li>
        </ul>
        <div className="nav-cta">
          <a href="#docs" className="btn-ghost">Docs</a>
          <a href="#install" className="btn-primary">pip install</a>
        </div>
      </nav>

      {/* HERO */}
      <section className="hero" id="home">
        <div className="hero-badge">
          <span className="hero-badge-dot"></span>
          v0.25.3 — 81 threat families — 1,747 tests passing
        </div>
        <h1 className="fade-up">Runtime security for<br /><span>AI agents.</span></h1>
        <p className="hero-sub fade-up delay-1">
          One import. Every tool call inspected before execution. Under 1ms. The security layer the OpenClaw ecosystem doesn't ship.
        </p>
        <div className="hero-actions fade-up delay-2">
          <div className="hero-install">
            <div>
              <div className="hero-install-label">Install</div>
              <code>pip install aiglos &amp;&amp; aiglos launch</code>
            </div>
            <button className="copy-btn" onClick={handleCopy}>
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <a href="#github" className="btn-ghost">GitHub →</a>
        </div>
        <div className="hero-stats fade-up delay-3">
          <div className="hero-stat">
            <span className="hero-stat-n">81</span>
            <span className="hero-stat-l">Threat families</span>
          </div>
          <div className="hero-stat">
            <span className="hero-stat-n">22</span>
            <span className="hero-stat-l">Campaign patterns</span>
          </div>
          <div className="hero-stat">
            <span className="hero-stat-n">&lt;1ms</span>
            <span className="hero-stat-l">Per call</span>
          </div>
          <div className="hero-stat">
            <span className="hero-stat-n">0</span>
            <span className="hero-stat-l">Dependencies</span>
          </div>
        </div>
      </section>

      {/* THE NUMBER */}
      <div className="number-section">
        <span className="number-big">233 / 247</span>
        <p className="number-label">
          IBM found that shadow AI breaches take <strong>247 days</strong> to detect. SWE-CI ran agents for <strong>233 days</strong>. The agent operates inside its own undetected breach window. Every production deployment running right now.
        </p>
      </div>

      {/* HOW IT WORKS */}
      <section className="section">
        <div className="section-kicker">How it works</div>
        <h2>One line. Nothing else changes.</h2>
        <p className="section-sub">
          Aiglos intercepts every tool call, HTTP request, and shell command before execution. The agent never knows it's running.
        </p>
        <div className="code-window">
          <div className="code-topbar">
            <span className="code-dot red"></span>
            <span className="code-dot yellow"></span>
            <span className="code-dot green"></span>
            <span className="code-filename">agent.py</span>
          </div>
          <div className="code-body">
            <pre>
              <span className="tok-kw">import</span> aiglos<br />
              <br />
              aiglos.<span className="tok-fn">attach</span>(<br />
              {'    '}<span className="tok-param">agent_name</span>=<span className="tok-str">"my-agent"</span>,<br />
              {'    '}<span className="tok-param">policy</span>=<span className="tok-str">"enterprise"</span>,<br />
              )<br />
              <br />
              <span className="tok-comment"># The agent keeps running. Nothing else changes.</span><br />
              <span className="tok-comment"># Until something tries to exfiltrate credentials.</span><br />
              <span className="tok-comment"># Then it stops.</span>
            </pre>
          </div>
        </div>
        
        <div className="feature-grid">
          <div className="feature-cell">
            <div className="feature-title">81 Threat Families</div>
            <div className="feature-body">T01-T81 covering MCP tool calls, HTTP/API requests, subprocess execution, session data extraction, content wrapper escapes, environment hijacking, .pth supply chain persistence, uncensored model routing, and every attack class in the OpenClaw ATLAS threat model.</div>
          </div>
          <div className="feature-cell">
            <div className="feature-title">Campaign Detection</div>
            <div className="feature-body">22 multi-step attack patterns. A git log followed by a .env read followed by an outbound POST is a credential exfiltration campaign. Each call looks clean. The sequence is the attack. Aiglos sees sequences.</div>
          </div>
          <div className="feature-cell">
            <div className="feature-title">Behavioral Baseline</div>
            <div className="feature-body">After 20 sessions, Aiglos builds a per-agent statistical fingerprint. The DevOps agent that reads .aws/credentials scores LOW. The code review agent that never has — and suddenly does — scores HIGH.</div>
          </div>
          <div className="feature-cell">
            <div className="feature-title">Signed Audit Artifact</div>
            <div className="feature-body">Every session closes with a cryptographically signed record of everything the agent did. HMAC-SHA256 minimum. RSA-2048 for regulatory submission. The artifact NDAA §1513 requires. Nothing else produces it.</div>
          </div>
          <div className="feature-cell">
            <div className="feature-title">Federation Intelligence</div>
            <div className="feature-body">Every contributing deployment shares anonymized threat patterns via differential privacy (ε=0.1). New deployment, day one: pre-warmed from collective intelligence. The moat that compounds with every install.</div>
          </div>
          <div className="feature-cell">
            <div className="feature-title">GOVBENCH</div>
            <div className="feature-body">The first governance benchmark for AI agents. Five dimensions. A-F grade. Published before any standard body required one. The company that defines the benchmark owns the compliance category. Run it: <code>aiglos benchmark run</code></div>
          </div>
        </div>
      </section>

      {/* STATS */}
      <section className="section" style={{ borderTop: '1px solid var(--ln)' }}>
        <div className="section-kicker">By the numbers</div>
        <h2>Built for the way agents actually work.</h2>
        <div className="stat-row">
          <div className="stat-cell">
            <span className="stat-n">81</span>
            <span className="stat-l">Threat families T01–T81</span>
          </div>
          <div className="stat-cell">
            <span className="stat-n">93%</span>
            <span className="stat-l">OpenClaw ATLAS coverage</span>
          </div>
          <div className="stat-cell">
            <span className="stat-n">3/3</span>
            <span className="stat-l">Published GHSAs caught</span>
          </div>
          <div className="stat-cell">
            <span className="stat-n">1,747</span>
            <span className="stat-l">Tests passing</span>
          </div>
        </div>
      </section>

      {/* GHSA VALIDATION */}
      <section className="section" style={{ borderTop: '1px solid var(--ln)' }}>
        <div className="section-kicker">Empirical validation</div>
        <h2>Every published OpenClaw vulnerability.<br />Caught by existing rules.</h2>
        <p className="section-sub">
          The OpenClaw security page has received 288 vulnerability reports. Three have been published. All three are covered by Aiglos rules — before the advisories were disclosed, before any patch existed.
        </p>
        <div className="validation-grid">
          <div className="validation-row">
            <div className="validation-ghsa">GHSA-g8p2-7wf7-98mq<br /><span style={{ color: 'var(--dim)', fontSize: '10px' }}>CVSS 8.8 · High</span></div>
            <div className="validation-title">1-Click RCE via Authentication Token Exfiltration from gatewayUrl</div>
            <div className="validation-rules">T03 T12 T19 T68 ✓</div>
          </div>
          <div className="validation-row">
            <div className="validation-ghsa">GHSA-q284-4pvr-m585<br /><span style={{ color: 'var(--dim)', fontSize: '10px' }}>CVSS 8.6 · High</span></div>
            <div className="validation-title">OS Command Injection via Project Root Path in sshNodeCommand</div>
            <div className="validation-rules">T03 T04 T70 ✓</div>
          </div>
          <div className="validation-row">
            <div className="validation-ghsa">GHSA-mc68-q9jw-2h3v<br /><span style={{ color: 'var(--dim)', fontSize: '10px' }}>CVSS 8.4 · High</span></div>
            <div className="validation-title">Command Injection in Clawdbot Docker via PATH Environment Variable</div>
            <div className="validation-rules">T03 T70 ✓</div>
          </div>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--dim)', marginTop: '16px' }}>
          The 285 advisories that haven't published yet are what Aiglos is already watching for. <a href="#intel" style={{ color: 'var(--ice)' }}>aiglos.dev/intel →</a>
        </p>
      </section>

      {/* COMPARE */}
      <section className="section" id="compare" style={{ borderTop: '1px solid var(--ln)' }}>
        <div className="section-kicker">Competition</div>
        <h2>Everyone watches calls.<br />Nobody watches sessions.</h2>
        <p className="section-sub">
          The gap is not a feature gap. It is architectural. You cannot retrofit sequence detection onto a system built for single-call inspection.
        </p>
        <table className="compare-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>What they watch</th>
              <th>Sessions</th>
              <th>Signed audit</th>
              <th>Fed intel</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Azure / Lakera</td><td>Inbound prompt text</td><td className="cross">✗</td><td className="cross">✗</td><td className="cross">✗</td></tr>
            <tr><td>Kong / Apigee AI</td><td>HTTP traffic only</td><td className="cross">✗</td><td className="cross">✗</td><td className="cross">✗</td></tr>
            <tr><td>CrowdStrike / Splunk</td><td>Host logs, after the fact</td><td className="cross">✗</td><td className="cross">✗</td><td className="cross">✗</td></tr>
            <tr><td>Snyk mcp-scan</td><td>Static skill scanning</td><td className="cross">✗</td><td className="cross">✗</td><td className="cross">✗</td></tr>
            <tr><td>ClawKeeper</td><td>Host configuration</td><td className="cross">✗</td><td className="cross">✗</td><td className="cross">✗</td></tr>
            <tr className="aiglos-row"><td>Aiglos</td><td>MCP + HTTP + subprocess</td><td className="check">✓</td><td className="check">✓</td><td className="check">✓</td></tr>
          </tbody>
        </table>
      </section>

      {/* ATLAS COVERAGE */}
      <section className="section" style={{ borderTop: '1px solid var(--ln)' }}>
        <div className="section-kicker">OpenClaw ATLAS Threat Model</div>
        <h2>93% coverage of the platform's<br />own documented threat model.</h2>
        <p className="section-sub">
          OpenClaw published a formal MITRE ATLAS threat model in February 2026. 22 threats across 8 tactic categories. Aiglos covers 19 fully, 3 partially, 0 gaps.
        </p>
        <div className="atlas-grid">
          <div className="atlas-cell">
            <div>
              <span className="atlas-id">T-EXEC-001 · T-EXEC-002</span>
              <div className="atlas-title">Direct + Indirect Prompt Injection</div>
              <div className="atlas-rules">T05 T01 T54 T60 T74 — FULL</div>
            </div>
          </div>
          <div className="atlas-cell">
            <div>
              <span className="atlas-id">T-PERSIST-001/002/003</span>
              <div className="atlas-title">Skill Installation, Update Poisoning, Config Tampering</div>
              <div className="atlas-rules">T30 T34 T36 T37 — FULL</div>
            </div>
          </div>
          <div className="atlas-cell">
            <div>
              <span className="atlas-id">T-EXFIL-001/002/003</span>
              <div className="atlas-title">Data Theft, Unauthorized Messaging, Credential Harvesting</div>
              <div className="atlas-rules">T09 T12 T14 T19 T37 — FULL</div>
            </div>
          </div>
          <div className="atlas-cell">
            <div>
              <span className="atlas-id">T-DISC-001 · T-DISC-002</span>
              <div className="atlas-title">Tool Enumeration + Session Data Extraction</div>
              <div className="atlas-rules">T73 T56 T75 — FULL</div>
            </div>
          </div>
        </div>
      </section>

      {/* PRICING */}
      <section className="section" id="pricing" style={{ borderTop: '1px solid var(--ln)' }}>
        <div className="section-kicker">Pricing</div>
        <h2>Free to detect. Pro to prove.</h2>
        <p className="section-sub">
          The free tier runs the full detection engine. Pro adds the federation intelligence and the signed compliance artifact — the document that turns a security tool into a regulatory submission.
        </p>
        <div className="pricing-grid">
          <div className="price-col">
            <div className="price-tier">Free</div>
            <div className="price-amount">$0<span className="price-mo">/mo</span></div>
            <ul className="price-features">
              <li>81 Threat Families</li>
              <li>Campaign Detection</li>
              <li>Under 1ms Overhead</li>
              <li>Community Support</li>
            </ul>
          </div>
          <div className="price-col featured">
            <div className="price-tier">Pro</div>
            <div className="price-amount">$49<span className="price-mo">/mo</span></div>
            <ul className="price-features">
              <li>Everything in Free</li>
              <li>Federation Intelligence</li>
              <li>Signed Audit Artifacts</li>
              <li>Behavioral Baselines</li>
              <li>Priority Support</li>
            </ul>
          </div>
          <div className="price-col">
            <div className="price-tier">Enterprise</div>
            <div className="price-amount">Custom</div>
            <ul className="price-features">
              <li>Everything in Pro</li>
              <li>On-Premise Deployment</li>
              <li>Custom Policy Rules</li>
              <li>SLA & Dedicated Rep</li>
            </ul>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="section" style={{ borderTop: '1px solid var(--ln)', textAlign: 'center', padding: '120px 48px' }}>
        <h2>The window is measured in months, not years.</h2>
        <p className="section-sub" style={{ margin: '0 auto 40px' }}>
          Secure your agents today before the breach window closes.
        </p>
        <a href="#install" className="btn-primary" style={{ padding: '12px 24px', fontSize: '13px' }}>
          pip install aiglos
        </a>
      </section>

      {/* FOOTER */}
      <footer className="dark-landing-footer">
        <div className="footer-logo">aiglos</div>
        <div className="footer-links">
          <a href="#intel">Intel</a>
          <a href="#compare">Compare</a>
          <a href="#pricing">Pricing</a>
          <a href="#docs">Docs</a>
          <a href="#github">GitHub</a>
        </div>
        <div className="footer-copy">© {new Date().getFullYear()} Aiglos. All rights reserved.</div>
      </footer>
    </div>
  );
}
