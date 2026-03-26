import { useState } from 'react';

export function Supernova() {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText('pip install aiglos && aiglos launch');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="sn">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

        .sn {
          --bg: #fafafa;
          --surface: #ffffff;
          --surface-raised: #ffffff;
          --border: rgba(0, 0, 0, 0.06);
          --border-hover: rgba(0, 0, 0, 0.12);
          --text-primary: #0a0a0a;
          --text-secondary: #525252;
          --text-tertiary: #a3a3a3;
          --accent: #0a0a0a;
          --accent-soft: #171717;
          --blue: #2563eb;
          --blue-soft: rgba(37, 99, 235, 0.08);
          --green: #16a34a;
          --green-soft: rgba(22, 163, 74, 0.08);

          background: var(--bg);
          color: var(--text-primary);
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
          -webkit-font-smoothing: antialiased;
          -moz-osx-font-smoothing: grayscale;
          overflow-x: hidden;
          min-height: 100vh;
          width: 100%;
          text-rendering: optimizeLegibility;
        }

        .sn * { box-sizing: border-box; }
        .sn a { color: inherit; text-decoration: none; }

        /* NAV */
        .sn-nav {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 100;
          background: rgba(250, 250, 250, 0.8);
          backdrop-filter: saturate(180%) blur(20px);
          -webkit-backdrop-filter: saturate(180%) blur(20px);
          border-bottom: 1px solid var(--border);
          height: 56px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 32px;
        }
        .sn-logo {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .sn-logo-name {
          font-family: 'JetBrains Mono', monospace;
          font-size: 15px;
          font-weight: 600;
          letter-spacing: -0.01em;
          color: var(--text-primary);
        }
        .sn-nav-center {
          display: flex;
          gap: 8px;
          list-style: none;
          margin: 0;
          padding: 0;
        }
        .sn-nav-center a {
          font-size: 13px;
          font-weight: 500;
          color: var(--text-secondary);
          padding: 6px 12px;
          border-radius: 6px;
          transition: all 0.15s ease;
        }
        .sn-nav-center a:hover {
          color: var(--text-primary);
          background: rgba(0,0,0,0.04);
        }
        .sn-nav-right {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .sn-btn-secondary {
          font-size: 13px;
          font-weight: 500;
          color: var(--text-secondary);
          padding: 7px 14px;
          border-radius: 8px;
          border: 1px solid var(--border);
          background: var(--surface);
          transition: all 0.15s ease;
          cursor: pointer;
        }
        .sn-btn-secondary:hover {
          border-color: var(--border-hover);
          background: #f5f5f5;
        }
        .sn-btn-primary {
          font-size: 13px;
          font-weight: 600;
          color: #fff;
          padding: 7px 16px;
          border-radius: 8px;
          background: var(--accent);
          border: none;
          transition: all 0.15s ease;
          cursor: pointer;
        }
        .sn-btn-primary:hover {
          background: var(--accent-soft);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        /* HERO */
        .sn-hero {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          text-align: center;
          padding: 140px 32px 100px;
          position: relative;
          overflow: hidden;
        }
        .sn-hero-bg {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background:
            radial-gradient(ellipse 80% 50% at 50% -20%, rgba(37, 99, 235, 0.06), transparent),
            radial-gradient(ellipse 60% 40% at 80% 60%, rgba(147, 51, 234, 0.04), transparent);
          pointer-events: none;
        }
        .sn-hero-content {
          position: relative;
          z-index: 1;
          max-width: 800px;
        }
        .sn-pill {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 100px;
          padding: 6px 16px 6px 8px;
          margin-bottom: 40px;
          font-size: 13px;
          font-weight: 500;
          color: var(--text-secondary);
          box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }
        .sn-pill-badge {
          background: var(--accent);
          color: #fff;
          font-size: 11px;
          font-weight: 600;
          padding: 2px 8px;
          border-radius: 100px;
          letter-spacing: 0.02em;
        }
        .sn-hero h1 {
          font-size: clamp(44px, 7vw, 76px);
          font-weight: 800;
          line-height: 1.05;
          letter-spacing: -0.04em;
          margin: 0 0 28px;
          color: var(--text-primary);
        }
        .sn-hero h1 .sn-gradient {
          background: linear-gradient(135deg, #2563eb 0%, #7c3aed 50%, #2563eb 100%);
          background-size: 200% 200%;
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
        .sn-hero-sub {
          font-size: 19px;
          font-weight: 400;
          color: var(--text-secondary);
          line-height: 1.65;
          max-width: 560px;
          margin: 0 auto 48px;
        }

        .sn-install-row {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 12px;
          margin-bottom: 64px;
        }
        .sn-install-box {
          display: flex;
          align-items: center;
          gap: 12px;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 10px;
          padding: 12px 20px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 4px 16px rgba(0,0,0,0.03);
        }
        .sn-install-prompt {
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          color: var(--text-tertiary);
          user-select: none;
        }
        .sn-install-cmd {
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          color: var(--text-primary);
          font-weight: 500;
        }
        .sn-copy-btn {
          background: none;
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 6px 10px;
          cursor: pointer;
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          color: var(--text-tertiary);
          transition: all 0.15s ease;
        }
        .sn-copy-btn:hover {
          border-color: var(--border-hover);
          color: var(--text-primary);
          background: #f5f5f5;
        }

        .sn-hero-stats {
          display: flex;
          gap: 48px;
          justify-content: center;
        }
        .sn-stat {
          text-align: center;
        }
        .sn-stat-n {
          font-family: 'JetBrains Mono', monospace;
          font-size: 28px;
          font-weight: 600;
          color: var(--text-primary);
          display: block;
          line-height: 1;
        }
        .sn-stat-l {
          font-size: 12px;
          font-weight: 500;
          color: var(--text-tertiary);
          margin-top: 6px;
          display: block;
          letter-spacing: 0.04em;
          text-transform: uppercase;
        }

        /* SECTIONS */
        .sn-section {
          padding: 100px 32px;
          max-width: 1100px;
          margin: 0 auto;
        }
        .sn-divider {
          height: 1px;
          background: var(--border);
          margin: 0 32px;
          max-width: 1100px;
          margin-left: auto;
          margin-right: auto;
        }
        .sn-kicker {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          font-weight: 500;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: var(--blue);
          margin-bottom: 16px;
        }
        .sn-h2 {
          font-size: clamp(28px, 4vw, 42px);
          font-weight: 800;
          letter-spacing: -0.035em;
          line-height: 1.1;
          margin: 0 0 16px;
          color: var(--text-primary);
        }
        .sn-lead {
          font-size: 17px;
          color: var(--text-secondary);
          line-height: 1.65;
          max-width: 540px;
          margin-bottom: 56px;
        }

        /* BIG NUMBER */
        .sn-big-sec {
          padding: 100px 32px;
          text-align: center;
        }
        .sn-big-n {
          font-family: 'JetBrains Mono', monospace;
          font-size: clamp(64px, 10vw, 120px);
          font-weight: 700;
          color: var(--text-primary);
          line-height: 1;
          letter-spacing: -0.04em;
        }
        .sn-big-label {
          font-size: 17px;
          color: var(--text-secondary);
          max-width: 480px;
          margin: 24px auto 0;
          line-height: 1.65;
        }
        .sn-big-label strong {
          color: var(--text-primary);
          font-weight: 600;
        }

        /* GRIDS */
        .sn-g3 {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
        }
        .sn-g4 {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
        }
        .sn-g2 {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 16px;
        }

        /* CARD */
        .sn-card {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 12px;
          padding: 32px;
          transition: all 0.2s ease;
        }
        .sn-card:hover {
          border-color: var(--border-hover);
          box-shadow: 0 4px 20px rgba(0,0,0,0.06);
          transform: translateY(-2px);
        }
        .sn-card-icon {
          width: 36px;
          height: 36px;
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 20px;
          font-size: 16px;
        }
        .sn-card-icon.blue { background: var(--blue-soft); color: var(--blue); }
        .sn-card-icon.green { background: var(--green-soft); color: var(--green); }
        .sn-card-icon.dark { background: rgba(0,0,0,0.04); color: var(--text-primary); }
        .sn-feat-title {
          font-size: 15px;
          font-weight: 600;
          margin-bottom: 8px;
          color: var(--text-primary);
        }
        .sn-feat-body {
          font-size: 14px;
          color: var(--text-secondary);
          line-height: 1.6;
        }

        /* CODE WINDOW */
        .sn-code {
          background: #1a1a2e;
          border-radius: 12px;
          overflow: hidden;
          max-width: 680px;
          box-shadow: 0 20px 60px -10px rgba(0,0,0,0.2), 0 0 0 1px rgba(255,255,255,0.05);
          margin-bottom: 56px;
        }
        .sn-code-bar {
          background: rgba(255,255,255,0.04);
          padding: 14px 18px;
          display: flex;
          align-items: center;
          gap: 8px;
          border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .sn-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
        }
        .sn-dot.r { background: #ff5f57; }
        .sn-dot.y { background: #febc2e; }
        .sn-dot.g { background: #28c840; }
        .sn-code-name {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: rgba(255,255,255,0.35);
          margin-left: 10px;
        }
        .sn-code-body {
          padding: 20px;
          display: flex;
          overflow-x: auto;
        }
        .sn-code-ln {
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          line-height: 1.8;
          color: rgba(255,255,255,0.18);
          padding-right: 20px;
          text-align: right;
          user-select: none;
        }
        .sn-code-pre {
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          line-height: 1.8;
          color: #e1e4e8;
          margin: 0;
        }

        /* TABLE */
        .sn-tbl-wrap {
          border: 1px solid var(--border);
          border-radius: 12px;
          overflow: hidden;
          background: var(--surface);
        }
        .sn-tbl {
          width: 100%;
          border-collapse: collapse;
          font-size: 14px;
        }
        .sn-tbl th {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          font-weight: 500;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          color: var(--text-tertiary);
          padding: 16px 20px;
          text-align: left;
          background: #fafafa;
          border-bottom: 1px solid var(--border);
        }
        .sn-tbl td {
          padding: 16px 20px;
          border-bottom: 1px solid rgba(0,0,0,0.03);
          color: var(--text-secondary);
        }
        .sn-tbl tr:last-child td { border-bottom: none; }
        .sn-tbl td:first-child {
          font-weight: 500;
          color: var(--text-primary);
        }
        .sn-tbl tr.sn-highlight td {
          background: var(--blue-soft);
          color: var(--text-primary);
        }
        .sn-tbl tr.sn-highlight td:first-child {
          color: var(--blue);
          font-weight: 600;
          position: relative;
        }
        .sn-tbl tr.sn-highlight td:first-child::before {
          content: '';
          position: absolute;
          left: 0;
          top: 0;
          bottom: 0;
          width: 3px;
          background: var(--blue);
          border-radius: 0 2px 2px 0;
        }
        .sn-check { color: var(--green); font-weight: 600; }
        .sn-x { color: var(--text-tertiary); }

        /* GHSA */
        .sn-val-item {
          display: grid;
          grid-template-columns: 160px 1fr auto;
          gap: 24px;
          align-items: center;
          padding: 20px 0;
          border-bottom: 1px solid var(--border);
        }
        .sn-val-item:last-child { border-bottom: none; }
        .sn-val-ghsa {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: var(--blue);
          font-weight: 500;
        }
        .sn-val-cvss {
          font-size: 11px;
          color: var(--text-tertiary);
          display: block;
          margin-top: 2px;
        }
        .sn-val-title {
          font-size: 14px;
          color: var(--text-primary);
          font-weight: 500;
        }
        .sn-val-rules {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: var(--green);
          background: var(--green-soft);
          padding: 4px 10px;
          border-radius: 6px;
          font-weight: 500;
        }

        /* ATLAS */
        .sn-atlas-id {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          color: var(--blue);
          font-weight: 500;
          display: block;
          margin-bottom: 6px;
        }
        .sn-atlas-title {
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 6px;
          color: var(--text-primary);
        }
        .sn-atlas-rules {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: var(--text-tertiary);
        }

        /* PRICING */
        .sn-price-col {
          padding: 36px 32px;
          display: flex;
          flex-direction: column;
        }
        .sn-price-featured {
          border: 2px solid var(--accent);
          box-shadow: 0 8px 32px rgba(0,0,0,0.08);
          position: relative;
        }
        .sn-price-badge {
          position: absolute;
          top: -11px;
          left: 50%;
          transform: translateX(-50%);
          background: var(--accent);
          color: #fff;
          font-size: 11px;
          font-weight: 600;
          padding: 3px 14px;
          border-radius: 100px;
          letter-spacing: 0.02em;
        }
        .sn-tier {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          font-weight: 500;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: var(--text-tertiary);
          margin-bottom: 20px;
        }
        .sn-amount {
          font-family: 'JetBrains Mono', monospace;
          font-size: 40px;
          font-weight: 700;
          line-height: 1;
          margin-bottom: 28px;
          color: var(--text-primary);
        }
        .sn-mo {
          font-size: 14px;
          font-weight: 400;
          color: var(--text-tertiary);
          margin-left: 4px;
        }
        .sn-features {
          list-style: none;
          padding: 0;
          margin: 0;
          flex-grow: 1;
        }
        .sn-features li {
          padding: 10px 0;
          border-bottom: 1px solid var(--border);
          color: var(--text-secondary);
          font-size: 14px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .sn-features li:last-child { border-bottom: none; }
        .sn-features li::before {
          content: '';
          width: 5px;
          height: 5px;
          border-radius: 50%;
          background: var(--text-tertiary);
          flex-shrink: 0;
        }

        /* CTA */
        .sn-cta {
          padding: 120px 32px;
          text-align: center;
          position: relative;
        }
        .sn-cta-bg {
          position: absolute;
          inset: 0;
          background: radial-gradient(ellipse at center, rgba(37,99,235,0.04), transparent 70%);
          pointer-events: none;
        }
        .sn-cta h2 {
          font-size: clamp(28px, 4vw, 48px);
          font-weight: 800;
          letter-spacing: -0.03em;
          margin: 0 0 40px;
          position: relative;
          z-index: 1;
          color: var(--text-primary);
        }

        /* FOOTER */
        .sn-footer {
          padding: 48px 32px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          flex-wrap: wrap;
          gap: 16px;
          max-width: 1100px;
          margin: 0 auto;
        }
        .sn-footer-links {
          display: flex;
          gap: 24px;
        }
        .sn-footer-links a {
          font-size: 13px;
          color: var(--text-tertiary);
          transition: color 0.15s ease;
        }
        .sn-footer-links a:hover { color: var(--text-primary); }

        @media (max-width: 1024px) {
          .sn-g3, .sn-g4 { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 768px) {
          .sn-nav { padding: 0 16px; }
          .sn-nav-center { display: none; }
          .sn-hero { padding: 100px 16px 64px; }
          .sn-section, .sn-big-sec, .sn-cta { padding: 64px 16px; }
          .sn-g2, .sn-g3, .sn-g4 { grid-template-columns: 1fr; }
          .sn-val-item { grid-template-columns: 1fr; gap: 8px; }
          .sn-hero-stats { gap: 24px; }
          .sn-install-row { flex-direction: column; }
        }

        .tk-kw { color: #ff7b72; }
        .tk-str { color: #a5d6ff; }
        .tk-fn { color: #d2a8ff; }
        .tk-cm { color: #8b949e; }
        .tk-p { color: #79c0ff; }
      `}</style>

      {/* NAV */}
      <nav className="sn-nav">
        <a href="#" className="sn-logo">
          <svg width="20" height="24" viewBox="0 0 44 50" fill="none">
            <polygon points="22,2 2,44 22,44" fill="#0a0a0a" />
            <polygon points="22,2 42,44 22,44" fill="rgba(0,0,0,0.3)" />
            <rect x="14" y="44" width="16" height="6" fill="#0a0a0a" />
          </svg>
          <span className="sn-logo-name">aiglos</span>
        </a>
        <ul className="sn-nav-center">
          <li><a href="#intel">Intel</a></li>
          <li><a href="#compare">Compare</a></li>
          <li><a href="#pricing">Pricing</a></li>
          <li><a href="#docs">Docs</a></li>
          <li><a href="#github">GitHub</a></li>
        </ul>
        <div className="sn-nav-right">
          <a href="#docs" className="sn-btn-secondary">Docs</a>
          <a href="#install" className="sn-btn-primary">Get started</a>
        </div>
      </nav>

      {/* HERO */}
      <section className="sn-hero">
        <div className="sn-hero-bg" />
        <div className="sn-hero-content">
          <div className="sn-pill">
            <span className="sn-pill-badge">New</span>
            v0.25.7 -- T82 Self-Improvement Hijack + DGM-Hyperagents
          </div>

          <h1>
            The security runtime<br/>
            <span className="sn-gradient">your AI agents need</span>
          </h1>

          <p className="sn-hero-sub">
            One import. Zero dependencies. 82 threat rules that stop prompt injection,
            supply-chain hijacks, and memory poisoning before they reach production.
          </p>

          <div className="sn-install-row">
            <div className="sn-install-box">
              <span className="sn-install-prompt">$</span>
              <span className="sn-install-cmd">pip install aiglos && aiglos launch</span>
              <button className="sn-copy-btn" onClick={handleCopy}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>

          <div className="sn-hero-stats">
            <div className="sn-stat">
              <span className="sn-stat-n">82</span>
              <span className="sn-stat-l">Threat rules</span>
            </div>
            <div className="sn-stat">
              <span className="sn-stat-n">23</span>
              <span className="sn-stat-l">Attack campaigns</span>
            </div>
            <div className="sn-stat">
              <span className="sn-stat-n">0</span>
              <span className="sn-stat-l">Dependencies</span>
            </div>
            <div className="sn-stat">
              <span className="sn-stat-n">1</span>
              <span className="sn-stat-l">Import</span>
            </div>
          </div>
        </div>
      </section>

      <div className="sn-divider" />

      {/* QUICK START */}
      <section className="sn-section">
        <div className="sn-kicker">Quick start</div>
        <h2 className="sn-h2">Two lines. Full coverage.</h2>
        <p className="sn-lead">
          Import aiglos, call launch. Every outbound HTTP request, subprocess,
          and LLM call is monitored in real time.
        </p>
        <div className="sn-code">
          <div className="sn-code-bar">
            <span className="sn-dot r" />
            <span className="sn-dot y" />
            <span className="sn-dot g" />
            <span className="sn-code-name">main.py</span>
          </div>
          <div className="sn-code-body">
            <div className="sn-code-ln">{'1\n2\n3\n4\n5\n6\n7\n8\n9'}</div>
            <pre className="sn-code-pre">
{`\x1b[0m`}<span className="tk-kw">import</span> aiglos{'\n'}
{'\n'}
aiglos.<span className="tk-fn">launch</span>(){'\n'}
{'\n'}
<span className="tk-cm"># That's it. Every outbound call is now</span>{'\n'}
<span className="tk-cm"># validated against 82 threat rules,</span>{'\n'}
<span className="tk-cm"># 23 known attack campaigns, and</span>{'\n'}
<span className="tk-cm"># real-time supply-chain analysis.</span>{'\n'}
<span className="tk-cm"># Zero dependencies. stdlib only.</span>
            </pre>
          </div>
        </div>

        <div className="sn-g3">
          <div className="sn-card">
            <div className="sn-card-icon blue">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1L1 5v6l7 4 7-4V5L8 1z" stroke="currentColor" strokeWidth="1.5" fill="none"/><path d="M1 5l7 4 7-4M8 9v6" stroke="currentColor" strokeWidth="1.5"/></svg>
            </div>
            <div className="sn-feat-title">HTTP interception</div>
            <div className="sn-feat-body">Every outbound request checked against known C2 servers, exfiltration endpoints, and malicious domains.</div>
          </div>
          <div className="sn-card">
            <div className="sn-card-icon green">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1v14M1 8h14" stroke="currentColor" strokeWidth="1.5"/><circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" fill="none"/></svg>
            </div>
            <div className="sn-feat-title">Subprocess guard</div>
            <div className="sn-feat-body">Blocks shell injections, reverse shells, and encoded payloads before the OS ever sees them.</div>
          </div>
          <div className="sn-card">
            <div className="sn-card-icon dark">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="12" height="12" rx="2" stroke="currentColor" strokeWidth="1.5" fill="none"/><path d="M5 8l2 2 4-4" stroke="currentColor" strokeWidth="1.5"/></svg>
            </div>
            <div className="sn-feat-title">Prompt validation</div>
            <div className="sn-feat-body">Score system prompts with the Shapiro framework. Catch vague instructions before they become attack surface.</div>
          </div>
        </div>
      </section>

      <div className="sn-divider" />

      {/* BIG NUMBER */}
      <div className="sn-big-sec">
        <div className="sn-big-n">82</div>
        <div className="sn-big-label">
          Detection rules. Each one maps to a <strong>real CVE, GHSA, or documented attack campaign</strong> from the last 18 months. Not theoretical. Not hypothetical.
        </div>
      </div>

      <div className="sn-divider" />

      {/* THREAT INTEL */}
      <section className="sn-section">
        <div className="sn-kicker">Threat intelligence</div>
        <h2 className="sn-h2">Built on real incident data</h2>
        <p className="sn-lead">
          Every rule traces to a GHSA advisory, a CVE, or a supply-chain attack
          discovered in the wild. Three recent validations:
        </p>

        <div style={{display:'flex',flexDirection:'column',gap:'0'}}>
          <div className="sn-val-item">
            <div>
              <span className="sn-val-ghsa">GHSA-cr6f-gf23</span>
              <span className="sn-val-cvss">CVSS 9.1</span>
            </div>
            <span className="sn-val-title">Ultralytics supply-chain compromise via GitHub Actions</span>
            <span className="sn-val-rules">T44, T45</span>
          </div>
          <div className="sn-val-item">
            <div>
              <span className="sn-val-ghsa">CVE-2024-3094</span>
              <span className="sn-val-cvss">CVSS 10.0</span>
            </div>
            <span className="sn-val-title">XZ Utils backdoor via build system injection</span>
            <span className="sn-val-rules">T64, T67</span>
          </div>
          <div className="sn-val-item">
            <div>
              <span className="sn-val-ghsa">GHSA-7x48-qmm2</span>
              <span className="sn-val-cvss">CVSS 9.8</span>
            </div>
            <span className="sn-val-title">tj-actions/changed-files REPO_TAKEOVER_CHAIN</span>
            <span className="sn-val-rules">T80, T81, T82</span>
          </div>
        </div>
      </section>

      <div className="sn-divider" />

      {/* ATLAS */}
      <section className="sn-section">
        <div className="sn-kicker">Coverage</div>
        <h2 className="sn-h2">22 attack campaigns mapped</h2>
        <p className="sn-lead">
          From MCP tool poisoning to ByteRover autodetect abuse, each campaign
          is decomposed into the rules that detect it.
        </p>
        <div className="sn-g4">
          {[
            { id: 'C01', title: 'Prompt injection (direct)', rules: 'T01-T04' },
            { id: 'C02', title: 'Prompt injection (indirect)', rules: 'T05-T08' },
            { id: 'C03', title: 'Tool-use smuggling', rules: 'T09-T12' },
            { id: 'C04', title: 'Memory poisoning', rules: 'T13-T15' },
            { id: 'C05', title: 'Credential harvesting', rules: 'T16-T18' },
            { id: 'C06', title: 'Data exfiltration', rules: 'T19-T22' },
            { id: 'C07', title: 'Supply-chain hijack', rules: 'T23-T26' },
            { id: 'C08', title: 'Dependency confusion', rules: 'T27-T29' },
            { id: 'C09', title: 'Build system injection', rules: 'T30-T33' },
            { id: 'C10', title: 'CI/CD token theft', rules: 'T34-T37' },
            { id: 'C11', title: 'MCP tool poisoning', rules: 'T38-T40' },
            { id: 'C12', title: 'Agent identity spoof', rules: 'T41-T43' },
            { id: 'C13', title: 'Ultralytics-class CI attack', rules: 'T44-T46' },
            { id: 'C14', title: 'Typosquat + starjack', rules: 'T47-T50' },
            { id: 'C15', title: 'Phantom dependency', rules: 'T51-T54' },
            { id: 'C16', title: 'Model weight backdoor', rules: 'T55-T58' },
            { id: 'C17', title: 'Telemetry hijack', rules: 'T59-T62' },
            { id: 'C18', title: 'XZ-class build trojan', rules: 'T63-T67' },
            { id: 'C19', title: 'NeMoClaw session escape', rules: 'T68-T71' },
            { id: 'C20', title: 'OpenShell sandbox breakout', rules: 'T72-T75' },
            { id: 'C21', title: 'Gigabrain session hijack', rules: 'T76-T79' },
            { id: 'C23', title: 'METACOGNITIVE_POISON_CHAIN', rules: 'T82' },
          ].map(c => (
            <div className="sn-card" key={c.id} style={{padding: '24px'}}>
              <span className="sn-atlas-id">{c.id}</span>
              <div className="sn-atlas-title">{c.title}</div>
              <span className="sn-atlas-rules">{c.rules}</span>
            </div>
          ))}
        </div>
      </section>

      <div className="sn-divider" />

      {/* COMPARE */}
      <section className="sn-section">
        <div className="sn-kicker">Compare</div>
        <h2 className="sn-h2">Measure what matters</h2>
        <p className="sn-lead">
          Side-by-side against the tools teams actually evaluate.
        </p>
        <div className="sn-tbl-wrap">
          <table className="sn-tbl">
            <thead>
              <tr>
                <th>Capability</th>
                <th>Aiglos</th>
                <th>Guardrails AI</th>
                <th>Lakera</th>
                <th>Rebuff</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['Threat rules', '82', '12', '8', '4'],
                ['Supply-chain scan', <span className="sn-check" key="a1">Yes</span>, <span className="sn-x" key="b1">No</span>, <span className="sn-x" key="c1">No</span>, <span className="sn-x" key="d1">No</span>],
                ['Zero dependencies', <span className="sn-check" key="a2">Yes</span>, <span className="sn-x" key="b2">No</span>, <span className="sn-x" key="c2">No</span>, <span className="sn-x" key="d2">No</span>],
                ['Prompt validation', <span className="sn-check" key="a3">Yes</span>, <span className="sn-x" key="b3">No</span>, <span className="sn-x" key="c3">No</span>, <span className="sn-x" key="d3">No</span>],
                ['Multi-agent registry', <span className="sn-check" key="a4">Yes</span>, <span className="sn-x" key="b4">No</span>, <span className="sn-x" key="c4">No</span>, <span className="sn-x" key="d4">No</span>],
                ['Real CVE mapping', <span className="sn-check" key="a5">Yes</span>, <span className="sn-x" key="b5">Partial</span>, <span className="sn-x" key="c5">No</span>, <span className="sn-x" key="d5">No</span>],
                ['Self-hosted', <span className="sn-check" key="a6">Yes</span>, <span className="sn-check" key="b6">Yes</span>, <span className="sn-x" key="c6">No</span>, <span className="sn-check" key="d6">Yes</span>],
                ['Open source', <span className="sn-check" key="a7">Yes</span>, <span className="sn-check" key="b7">Yes</span>, <span className="sn-x" key="c7">No</span>, <span className="sn-check" key="d7">Yes</span>],
                ['Price', 'Free', '$$$', '$$$', 'Free'],
              ].map(([cap, ...vals], i) => (
                <tr key={i} className={i < 5 ? 'sn-highlight' : ''}>
                  <td>{cap}</td>
                  {vals.map((v, j) => <td key={j}>{v}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="sn-divider" />

      {/* PRICING */}
      <section className="sn-section">
        <div className="sn-kicker">Pricing</div>
        <h2 className="sn-h2">Start free. Scale when ready.</h2>
        <p className="sn-lead">
          The core runtime is open source. Commercial tiers add team features and priority support.
        </p>
        <div className="sn-g3">
          <div className="sn-card sn-price-col">
            <div className="sn-tier">Open source</div>
            <div className="sn-amount">$0</div>
            <ul className="sn-features">
              <li>82 threat rules (T01-T82)</li>
              <li>23 campaign detections</li>
              <li>HTTP + subprocess interception</li>
              <li>Prompt validation (validate-prompt)</li>
              <li>Supply-chain scanner (scan-deps)</li>
              <li>Multi-agent registry</li>
              <li>Community support</li>
            </ul>
          </div>
          <div className="sn-card sn-price-col sn-price-featured">
            <div className="sn-price-badge">Recommended</div>
            <div className="sn-tier">Pro</div>
            <div className="sn-amount">$49<span className="sn-mo">/mo</span></div>
            <ul className="sn-features">
              <li>Everything in Open Source</li>
              <li>Real-time telemetry dashboard</li>
              <li>Slack/PagerDuty alerts</li>
              <li>Custom policy engine</li>
              <li>Team management (up to 25)</li>
              <li>48h email support SLA</li>
              <li>Private rule authoring</li>
            </ul>
          </div>
          <div className="sn-card sn-price-col">
            <div className="sn-tier">Enterprise</div>
            <div className="sn-amount">Custom</div>
            <ul className="sn-features">
              <li>Everything in Pro</li>
              <li>Custom policy engineering</li>
              <li>On-premise telemetry</li>
              <li>SSO + RBAC</li>
              <li>Dedicated CSM</li>
              <li>SLA & uptime guarantee</li>
              <li>Audit log + compliance</li>
            </ul>
          </div>
        </div>
      </section>

      <div className="sn-divider" />

      {/* CTA */}
      <div className="sn-cta">
        <div className="sn-cta-bg" />
        <h2>The window is measured<br/>in months, not years.</h2>
        <a href="#install" className="sn-btn-primary" style={{position:'relative',zIndex:1,fontSize:'14px',padding:'12px 28px',borderRadius:'10px'}}>Install aiglos</a>
      </div>

      <div className="sn-divider" />

      {/* FOOTER */}
      <footer className="sn-footer">
        <span className="sn-logo-name" style={{color: 'var(--text-tertiary)'}}>aiglos</span>
        <div className="sn-footer-links">
          <a href="#intel">Intel</a>
          <a href="#compare">Compare</a>
          <a href="#pricing">Pricing</a>
          <a href="#docs">Docs</a>
          <a href="#github">GitHub</a>
        </div>
        <span style={{fontSize:'12px',color:'var(--text-tertiary)'}}>
          &copy; {new Date().getFullYear()} Aiglos
        </span>
      </footer>
    </div>
  );
}
