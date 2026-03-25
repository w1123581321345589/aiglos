import React from 'react';

export function LightVariant() {
  const scope = "light-variant-aiglos";
  
  return (
    <div className={scope}>
      <style dangerouslySetInnerHTML={{__html: `
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap');
        
        .${scope} {
          --bg: #F7F7F4;
          --bg-card: #FFFFFF;
          --text-dark: #1a1a1a;
          --text-sec: #6b6b6b;
          --text-dim: #999999;
          --blue-prim: #2563eb;
          --blue-sec: #1e40af;
          --line: rgba(0,0,0,0.08);
          --line-hover: rgba(0,0,0,0.15);
          --nav-bg: rgba(247,247,244,0.9);
          --code-bg: #0d1117;
          
          background: var(--bg);
          color: var(--text-dark);
          font-family: 'Plus Jakarta Sans', sans-serif;
          -webkit-font-smoothing: antialiased;
          overflow-x: hidden;
          min-height: 100vh;
          width: 100%;
        }

        .${scope} a {
          text-decoration: none;
        }
        
        .${scope} .nav {
          position: sticky; top: 0; left: 0; right: 0; z-index: 100;
          background: var(--nav-bg); backdrop-filter: blur(12px);
          border-bottom: 1px solid var(--line);
          display: flex; align-items: center; justify-content: space-between;
          padding: 0 48px; height: 64px;
        }
        
        .${scope} .nav-logo {
          display: flex; align-items: center; gap: 10px;
        }
        
        .${scope} .nav-mark { width: 20px; height: 24px; }
        
        .${scope} .nav-name {
          font-family: 'DM Mono', monospace; font-size: 14px; font-weight: 500;
          letter-spacing: 0.04em; color: var(--text-dark);
        }
        
        .${scope} .nav-links {
          display: flex; gap: 32px; list-style: none; margin: 0; padding: 0;
        }
        
        .${scope} .nav-links a {
          font-size: 14px; font-weight: 500; color: var(--text-sec);
          transition: color .15s;
        }
        
        .${scope} .nav-links a:hover { color: var(--text-dark); }
        
        .${scope} .nav-cta { display: flex; gap: 12px; align-items: center; }
        
        .${scope} .btn-ghost {
          font-family: 'DM Mono', monospace; font-size: 12px; letter-spacing: 0.05em;
          text-transform: uppercase; color: var(--text-dark);
          padding: 8px 16px; border: 1px solid var(--line); border-radius: 6px;
          transition: all .15s; background: transparent; cursor: pointer;
        }
        
        .${scope} .btn-ghost:hover {
          border-color: var(--line-hover); background: rgba(0,0,0,0.02);
        }
        
        .${scope} .btn-primary {
          font-family: 'DM Mono', monospace; font-size: 12px; letter-spacing: 0.05em;
          text-transform: uppercase; background: var(--text-dark); color: #fff;
          padding: 8px 18px; border-radius: 6px; border: none; cursor: pointer;
          transition: opacity .15s;
        }
        
        .${scope} .btn-primary:hover { opacity: 0.85; }

        .${scope} .hero {
          min-height: 90vh; display: flex; flex-direction: column; justify-content: center;
          align-items: center; text-align: center; padding: 120px 48px 80px;
        }
        
        .${scope} .hero-badge {
          display: inline-flex; align-items: center; gap: 8px;
          background: rgba(37,99,235,0.1); border: 1px solid rgba(37,99,235,0.2);
          border-radius: 100px; padding: 6px 16px; margin-bottom: 32px;
          font-family: 'DM Mono', monospace; font-size: 12px;
          color: var(--blue-prim);
        }
        
        .${scope} .hero-badge-dot {
          width: 8px; height: 8px; border-radius: 50%; background: var(--blue-prim);
          animation: pulse 2s infinite;
        }
        
        @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }
        
        .${scope} .hero h1 {
          font-size: clamp(48px, 7vw, 88px); font-weight: 700; line-height: 1.05;
          letter-spacing: -0.04em; max-width: 900px; margin: 0 0 24px; color: var(--text-dark);
        }
        
        .${scope} .hero h1 span { color: var(--blue-prim); }
        
        .${scope} .hero-sub {
          font-size: 20px; font-weight: 400; color: var(--text-sec); max-width: 600px;
          line-height: 1.6; margin: 0 0 48px;
        }
        
        .${scope} .hero-actions {
          display: flex; gap: 16px; align-items: stretch; flex-wrap: wrap;
          justify-content: center; margin-bottom: 80px;
        }
        
        .${scope} .hero-install {
          background: var(--bg-card); border: 1px solid var(--line);
          border-radius: 8px; padding: 12px 20px; display: flex; align-items: center; gap: 16px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.02);
        }
        
        .${scope} .hero-install code {
          font-family: 'DM Mono', monospace; font-size: 14px; color: var(--text-dark);
        }
        
        .${scope} .hero-stats {
          display: flex; gap: 64px; flex-wrap: wrap; justify-content: center;
        }
        
        .${scope} .hero-stat { text-align: center; }
        
        .${scope} .hero-stat-n {
          font-family: 'DM Mono', monospace; font-size: 32px; font-weight: 500;
          color: var(--text-dark); display: block; line-height: 1;
        }
        
        .${scope} .hero-stat-l {
          font-size: 12px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;
          color: var(--text-dim); margin-top: 8px; display: block;
        }

        .${scope} .number-section {
          padding: 100px 48px; text-align: center;
          border-top: 1px solid var(--line); border-bottom: 1px solid var(--line);
          background: var(--bg-card);
        }
        
        .${scope} .number-big {
          font-family: 'DM Mono', monospace; font-size: clamp(80px, 12vw, 160px);
          font-weight: 500; color: var(--text-dark); line-height: 1; display: block;
          letter-spacing: -0.04em;
        }
        
        .${scope} .number-label {
          font-size: 18px; color: var(--text-sec); max-width: 600px; margin: 32px auto 0;
          line-height: 1.6;
        }
        
        .${scope} .number-label strong { color: var(--text-dark); font-weight: 600; }

        .${scope} .section {
          padding: 120px 48px; max-width: 1200px; margin: 0 auto;
        }
        
        .${scope} .section-kicker {
          font-family: 'DM Mono', monospace; font-size: 12px; font-weight: 500; letter-spacing: 0.1em;
          text-transform: uppercase; color: var(--blue-prim); margin-bottom: 20px;
        }
        
        .${scope} .section h2 {
          font-size: clamp(36px, 5vw, 56px); font-weight: 700; letter-spacing: -0.03em;
          line-height: 1.1; margin: 0 0 24px; color: var(--text-dark);
        }
        
        .${scope} .section-sub {
          font-size: 18px; color: var(--text-sec); line-height: 1.7; max-width: 640px;
          margin: 0 0 56px;
        }

        .${scope} .code-window {
          background: var(--code-bg); border-radius: 12px;
          overflow: hidden; max-width: 720px; box-shadow: 0 12px 32px rgba(0,0,0,0.1);
        }
        
        .${scope} .code-topbar {
          background: rgba(255,255,255,0.05); padding: 12px 20px; display: flex;
          align-items: center; gap: 8px; border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .${scope} .code-dot { width: 12px; height: 12px; border-radius: 50%; }
        .${scope} .code-dot.red { background: #ff5f57; }
        .${scope} .code-dot.yellow { background: #febc2e; }
        .${scope} .code-dot.green { background: #28c840; }
        
        .${scope} .code-filename {
          font-family: 'DM Mono', monospace; font-size: 12px; color: rgba(255,255,255,0.5);
          margin-left: 12px;
        }
        
        .${scope} .code-body { padding: 32px; overflow-x: auto; text-align: left; }
        
        .${scope} .code-body pre {
          font-family: 'DM Mono', monospace; font-size: 14px; line-height: 1.8;
          color: #e6edf3; margin: 0;
        }

        .${scope} .feature-grid {
          display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px;
          margin-top: 64px;
        }
        
        .${scope} .feature-cell {
          background: var(--bg-card); padding: 40px; border: 1px solid var(--line);
          border-radius: 12px; transition: all .2s; box-shadow: 0 4px 12px rgba(0,0,0,0.02);
        }
        
        .${scope} .feature-cell:hover {
          background: #fafafa;
          border-color: var(--line-hover); transform: translateY(-2px);
          box-shadow: 0 8px 24px rgba(0,0,0,0.04);
        }
        
        .${scope} .feature-title {
          font-size: 18px; font-weight: 600; margin-bottom: 12px; color: var(--text-dark);
        }
        
        .${scope} .feature-body {
          font-size: 15px; color: var(--text-sec); line-height: 1.6;
        }

        .${scope} .stat-row {
          display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px;
          margin: 64px 0;
        }
        
        .${scope} .stat-cell {
          background: var(--bg-card); padding: 48px 32px; text-align: center;
          border: 1px solid var(--line); border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.02);
        }
        
        .${scope} .stat-n {
          font-family: 'DM Mono', monospace; font-size: 48px; font-weight: 500;
          color: var(--text-dark); display: block; line-height: 1; margin-bottom: 12px;
          letter-spacing: -0.02em;
        }
        
        .${scope} .stat-l {
          font-size: 13px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;
          color: var(--text-dim);
        }

        .${scope} .compare-table {
          width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 56px; font-size: 15px;
          border: 1px solid var(--line); border-radius: 12px; overflow: hidden; background: var(--bg-card);
        }
        
        .${scope} .compare-table th {
          font-family: 'DM Mono', monospace; font-size: 12px; letter-spacing: 0.1em;
          text-transform: uppercase; color: var(--text-sec); padding: 20px 24px; text-align: left;
          border-bottom: 1px solid var(--line); background: rgba(0,0,0,0.02);
        }
        
        .${scope} .compare-table td {
          padding: 20px 24px; border-bottom: 1px solid var(--line);
          color: var(--text-sec); vertical-align: middle;
        }
        
        .${scope} .compare-table tr:last-child td { border-bottom: none; }
        
        .${scope} .compare-table td:first-child {
          font-weight: 600; color: var(--text-dark);
        }
        
        .${scope} .compare-table tr.aiglos-row td {
          background: rgba(37,99,235,0.06); color: var(--text-dark);
        }
        
        .${scope} .compare-table tr.aiglos-row td:first-child {
          color: var(--blue-prim); font-family: 'DM Mono', monospace; font-size: 14px;
        }
        
        .${scope} .check { color: #16a34a; font-weight: 600; font-size: 18px; }
        .${scope} .cross { color: rgba(0,0,0,0.15); font-size: 18px; }

        .${scope} .pricing-grid {
          display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px;
          margin-top: 64px; align-items: stretch;
        }
        
        .${scope} .price-col {
          background: var(--bg-card); padding: 48px; border: 1px solid var(--line);
          border-radius: 16px; display: flex; flex-direction: column;
        }
        
        .${scope} .price-col.featured {
          background: var(--text-dark); color: #fff; border-color: var(--text-dark);
          transform: scale(1.02); box-shadow: 0 24px 48px rgba(0,0,0,0.1);
        }
        
        .${scope} .price-tier {
          font-family: 'DM Mono', monospace; font-size: 13px; font-weight: 500; letter-spacing: 0.1em;
          text-transform: uppercase; color: var(--text-sec); margin-bottom: 20px;
        }
        
        .${scope} .price-col.featured .price-tier { color: rgba(255,255,255,0.6); }
        
        .${scope} .price-amount {
          font-family: 'DM Mono', monospace; font-size: 56px; font-weight: 500;
          line-height: 1; margin-bottom: 32px; color: var(--text-dark);
        }
        
        .${scope} .price-col.featured .price-amount { color: #fff; }
        
        .${scope} .price-mo {
          font-size: 16px; font-weight: 400; color: var(--text-dim); margin-left: 8px;
          font-family: 'Plus Jakarta Sans', sans-serif;
        }
        
        .${scope} .price-col.featured .price-mo { color: rgba(255,255,255,0.4); }
        
        .${scope} .price-features {
          list-style: none; font-size: 15px; line-height: 1.6; margin: 0; padding: 0; flex-grow: 1;
        }
        
        .${scope} .price-features li {
          padding: 12px 0; border-bottom: 1px solid var(--line); color: var(--text-sec);
        }
        
        .${scope} .price-col.featured .price-features li {
          border-bottom-color: rgba(255,255,255,0.1); color: rgba(255,255,255,0.8);
        }
        
        .${scope} .price-features li:last-child { border-bottom: none; }
        
        .${scope} .price-features li::before {
          content: '— '; color: var(--blue-prim); font-family: 'DM Mono', monospace; font-weight: bold;
        }
        
        .${scope} .price-col.featured .price-features li::before { color: #60a5fa; }

        .${scope} .validation-grid {
          display: flex; flex-direction: column; gap: 16px; margin-top: 56px;
        }
        
        .${scope} .validation-row {
          background: var(--bg-card); display: grid; grid-template-columns: 200px 1fr auto;
          gap: 32px; padding: 24px 32px; align-items: center; border: 1px solid var(--line);
          border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.02);
        }
        
        .${scope} .validation-ghsa { font-family: 'DM Mono', monospace; font-size: 13px; color: var(--blue-prim); }
        .${scope} .validation-title { font-size: 15px; font-weight: 500; color: var(--text-dark); }
        .${scope} .validation-rules { font-family: 'DM Mono', monospace; font-size: 13px; color: #16a34a; white-space: nowrap; font-weight: 500; }

        .${scope} .atlas-grid {
          display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; margin-top: 56px;
        }
        
        .${scope} .atlas-cell {
          background: var(--bg-card); border: 1px solid var(--line); border-radius: 12px;
          padding: 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.02);
        }
        
        .${scope} .atlas-id {
          font-family: 'DM Mono', monospace; font-size: 12px; color: var(--blue-prim);
          letter-spacing: 0.05em; display: block; margin-bottom: 12px;
        }
        
        .${scope} .atlas-title { font-size: 18px; font-weight: 600; margin-bottom: 12px; color: var(--text-dark); }
        .${scope} .atlas-rules { font-family: 'DM Mono', monospace; font-size: 12px; color: var(--text-dim); }

        .${scope} .cta-section {
          padding: 120px 48px; text-align: center; border-top: 1px solid var(--line);
        }
        
        .${scope} .cta-section h2 {
          font-size: clamp(32px, 4vw, 48px); font-weight: 700; color: var(--text-dark);
          margin-bottom: 40px; letter-spacing: -0.02em;
        }

        .${scope} footer {
          border-top: 1px solid var(--line); padding: 48px 48px; display: flex;
          justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 24px;
        }
        
        .${scope} .footer-logo { font-family: 'DM Mono', monospace; font-size: 14px; color: var(--text-sec); font-weight: 500; }
        .${scope} .footer-links { display: flex; gap: 32px; }
        .${scope} .footer-links a { font-size: 14px; color: var(--text-sec); }
        .${scope} .footer-links a:hover { color: var(--text-dark); }
        .${scope} .footer-copy { font-size: 14px; color: var(--text-dim); }

        @media(max-width: 900px) {
          .${scope} .feature-grid, .${scope} .stat-row, .${scope} .pricing-grid, .${scope} .atlas-grid { grid-template-columns: 1fr; }
          .${scope} .validation-row { grid-template-columns: 1fr; gap: 16px; }
          .${scope} .price-col.featured { transform: none; }
        }
        @media(max-width: 768px) {
          .${scope} .nav { padding: 0 24px; }
          .${scope} .nav-links { display: none; }
          .${scope} .hero, .${scope} .section, .${scope} .number-section, .${scope} .cta-section { padding-left: 24px; padding-right: 24px; }
          .${scope} footer { flex-direction: column; text-align: center; padding: 48px 24px; }
        }
      `}} />

      <nav className="nav">
        <a href="#home" className="nav-logo">
          <svg className="nav-mark" viewBox="0 0 44 50" fill="none">
            <polygon points="22,2 2,44 22,44" fill="#1a1a1a"/>
            <polygon points="22,2 42,44 22,44" fill="rgba(26,26,26,0.42)"/>
            <rect x="14" y="44" width="16" height="6" fill="#1a1a1a"/>
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
          <button className="btn-ghost">Docs</button>
          <button className="btn-primary">pip install</button>
        </div>
      </nav>

      <section className="hero" id="home">
        <div className="hero-badge">
          <span className="hero-badge-dot"></span>
          v0.25.3 — 81 threat families — 1,747 tests passing
        </div>
        <h1>Runtime security for<br/><span>AI agents.</span></h1>
        <p className="hero-sub">One import. Every tool call inspected before execution. Under 1ms. The security layer the OpenClaw ecosystem doesn't ship.</p>
        <div className="hero-actions">
          <div className="hero-install">
            <div>
              <code style={{display:'block', marginBottom: '4px', fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em'}}>Install</code>
              <code>pip install aiglos && aiglos launch</code>
            </div>
            <button className="btn-ghost" style={{padding: '6px 12px', fontSize: '10px'}} onClick={(e) => { e.currentTarget.textContent = 'Copied'; setTimeout(() => e.currentTarget.textContent = 'Copy', 2000); }}>Copy</button>
          </div>
          <button className="btn-ghost" style={{padding: '16px 24px', fontSize: '12px', display: 'flex', alignItems: 'center'}}>GitHub →</button>
        </div>
        <div className="hero-stats">
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

      <div className="number-section">
        <span className="number-big">233 / 247</span>
        <p className="number-label">IBM found that shadow AI breaches take <strong>247 days</strong> to detect. SWE-CI ran agents for <strong>233 days</strong>. The agent operates inside its own undetected breach window. Every production deployment running right now.</p>
      </div>

      <section className="section" id="how-it-works">
        <div className="section-kicker">How it works</div>
        <h2>One line. Nothing else changes.</h2>
        <p className="section-sub">Aiglos intercepts every tool call, HTTP request, and shell command before execution. The agent never knows it's running.</p>
        <div className="code-window">
          <div className="code-topbar">
            <span className="code-dot red"></span>
            <span className="code-dot yellow"></span>
            <span className="code-dot green"></span>
            <span className="code-filename">agent.py</span>
          </div>
          <div className="code-body">
            <pre>
<span style={{color: '#ff7b72'}}>import</span> aiglos{'\n\n'}
aiglos.<span style={{color: '#d2a8ff'}}>attach</span>({'\n'}
{'    '}<span style={{color: '#79c0ff'}}>agent_name</span>=<span style={{color: '#a5d6ff'}}>"my-agent"</span>,{'\n'}
{'    '}<span style={{color: '#79c0ff'}}>policy</span>=<span style={{color: '#a5d6ff'}}>"enterprise"</span>,{'\n'}
){'\n\n'}
<span style={{color: '#6e7681'}}># The agent keeps running. Nothing else changes.</span>{'\n'}
<span style={{color: '#6e7681'}}># Until something tries to exfiltrate credentials.</span>{'\n'}
<span style={{color: '#6e7681'}}># Then it stops.</span>
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
            <div className="feature-body">The first governance benchmark for AI agents. Five dimensions. A-F grade. Published before any standard body required one. The company that defines the benchmark owns the compliance category.</div>
          </div>
        </div>
      </section>

      <section className="section" style={{borderTop: '1px solid var(--line)'}}>
        <div className="section-kicker">By the numbers</div>
        <h2>Built for the way agents actually work.</h2>
        <div className="stat-row">
          <div className="stat-cell">
            <span className="stat-n">79</span>
            <span className="stat-l">Threat families T01–T79</span>
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

      <section className="section" id="intel" style={{borderTop: '1px solid var(--line)'}}>
        <div className="section-kicker">Empirical validation</div>
        <h2>Every published OpenClaw vulnerability.<br/>Caught by existing rules.</h2>
        <p className="section-sub">The OpenClaw security page has received 288 vulnerability reports. Three have been published. All three are covered by Aiglos rules — before the advisories were disclosed, before any patch existed.</p>
        <div className="validation-grid">
          <div className="validation-row">
            <div className="validation-ghsa">GHSA-g8p2-7wf7-98mq<br/><span style={{color:'var(--text-dim)', fontSize:'11px', marginTop: '4px', display: 'inline-block'}}>CVSS 8.8 · High</span></div>
            <div className="validation-title">1-Click RCE via Authentication Token Exfiltration from gatewayUrl</div>
            <div className="validation-rules">T03 T12 T19 T68 ✓</div>
          </div>
          <div className="validation-row">
            <div className="validation-ghsa">GHSA-q284-4pvr-m585<br/><span style={{color:'var(--text-dim)', fontSize:'11px', marginTop: '4px', display: 'inline-block'}}>CVSS 8.6 · High</span></div>
            <div className="validation-title">OS Command Injection via Project Root Path in sshNodeCommand</div>
            <div className="validation-rules">T03 T04 T70 ✓</div>
          </div>
          <div className="validation-row">
            <div className="validation-ghsa">GHSA-mc68-q9jw-2h3v<br/><span style={{color:'var(--text-dim)', fontSize:'11px', marginTop: '4px', display: 'inline-block'}}>CVSS 8.4 · High</span></div>
            <div className="validation-title">Command Injection in Clawdbot Docker via PATH Environment Variable</div>
            <div className="validation-rules">T03 T70 ✓</div>
          </div>
        </div>
        <p style={{fontSize: '15px', color: 'var(--text-sec)', marginTop: '24px'}}>The 285 advisories that haven't published yet are what Aiglos is already watching for.</p>
      </section>

      <section className="section" id="compare" style={{borderTop: '1px solid var(--line)'}}>
        <div className="section-kicker">Competition</div>
        <h2>Everyone watches calls.<br/>Nobody watches sessions.</h2>
        <p className="section-sub">The gap is not a feature gap. It is architectural. You cannot retrofit sequence detection onto a system built for single-call inspection.</p>
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

      <section className="section" style={{borderTop: '1px solid var(--line)'}}>
        <div className="section-kicker">OpenClaw ATLAS Threat Model</div>
        <h2>93% coverage of the platform's<br/>own documented threat model.</h2>
        <p className="section-sub">OpenClaw published a formal MITRE ATLAS threat model in February 2026. 22 threats across 8 tactic categories. Aiglos covers 19 fully, 3 partially, 0 gaps.</p>
        <div className="atlas-grid">
          <div className="atlas-cell">
            <span className="atlas-id">T-EXEC-001 · T-EXEC-002</span>
            <div className="atlas-title">Direct + Indirect Prompt Injection</div>
            <div className="atlas-rules">T05 T01 T54 T60 T74 — FULL</div>
          </div>
          <div className="atlas-cell">
            <span className="atlas-id">T-PERSIST-001/002/003</span>
            <div className="atlas-title">Skill Installation, Update Poisoning, Config Tampering</div>
            <div className="atlas-rules">T30 T34 T36 T37 — FULL</div>
          </div>
          <div className="atlas-cell">
            <span className="atlas-id">T-EXFIL-001/002/003</span>
            <div className="atlas-title">Data Theft, Unauthorized Messaging, Credential Harvesting</div>
            <div className="atlas-rules">T09 T12 T14 T19 T37 — FULL</div>
          </div>
          <div className="atlas-cell">
            <span className="atlas-id">T-DISC-001 · T-DISC-002</span>
            <div className="atlas-title">Tool Enumeration + Session Data Extraction</div>
            <div className="atlas-rules">T73 T56 T75 — FULL</div>
          </div>
        </div>
      </section>

      <section className="section" id="pricing" style={{borderTop: '1px solid var(--line)'}}>
        <div className="section-kicker">Pricing</div>
        <h2>Free to detect. Pro to prove.</h2>
        <p className="section-sub">The free tier runs the full detection engine. Pro adds the federation intelligence and the signed compliance artifact — the document that turns a security tool into a regulatory submission.</p>
        <div className="pricing-grid">
          <div className="price-col">
            <div className="price-tier">Free</div>
            <div className="price-amount">$0<span className="price-mo">/mo</span></div>
            <ul className="price-features">
              <li>Full threat engine</li>
              <li>81 threat families</li>
              <li>Local logging</li>
              <li>Community support</li>
            </ul>
          </div>
          <div className="price-col featured">
            <div className="price-tier">Pro</div>
            <div className="price-amount">$49<span className="price-mo">/mo</span></div>
            <ul className="price-features">
              <li>Everything in Free</li>
              <li>Signed compliance artifacts</li>
              <li>Federation intelligence</li>
              <li>Campaign pattern updates</li>
              <li>Priority support</li>
            </ul>
          </div>
          <div className="price-col">
            <div className="price-tier">Enterprise</div>
            <div className="price-amount">Custom</div>
            <ul className="price-features">
              <li>Everything in Pro</li>
              <li>Custom behavioral baselines</li>
              <li>Air-gapped deployment</li>
              <li>Dedicated success engineer</li>
              <li>SLA guarantees</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="cta-section">
        <h2>The window is measured in months, not years.</h2>
        <button className="btn-primary" style={{fontSize: '14px', padding: '16px 32px'}}>pip install aiglos</button>
      </section>

      <footer>
        <div className="footer-logo">aiglos</div>
        <div className="footer-links">
          <a href="#intel">Intel</a>
          <a href="#compare">Compare</a>
          <a href="#pricing">Pricing</a>
          <a href="#docs">Docs</a>
          <a href="#github">GitHub</a>
        </div>
        <div className="footer-copy">© 2026 Aiglos Security. All rights reserved.</div>
      </footer>
    </div>
  );
}
