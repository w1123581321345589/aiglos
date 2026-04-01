import React, { useState } from 'react';

export function DarkPolished() {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText('pip install aiglos && aiglos launch');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="dark-polished">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap');

        .dark-polished {
          --bg: #09090b;
          --card-bg-start: rgba(255, 255, 255, 0.02);
          --card-bg-end: rgba(255, 255, 255, 0.04);
          --card-border: rgba(255, 255, 255, 0.06);
          --card-hover: rgba(96, 165, 250, 0.2);
          --text-hi: #fff;
          --text-mid: rgba(255, 255, 255, 0.6);
          --text-dim: rgba(255, 255, 255, 0.35);
          --blue: #2563eb;
          --ice: #60a5fa;
          --glow-blue: #3b82f6;
          --glow-purple: #7c3aed;

          background: var(--bg);
          color: var(--text-hi);
          font-family: 'Plus Jakarta Sans', sans-serif;
          -webkit-font-smoothing: antialiased;
          overflow-x: hidden;
          min-height: 100vh;
          width: 100%;
          text-align: left;
        }

        .dark-polished * {
          box-sizing: border-box;
        }

        .dark-polished a {
          color: inherit;
          text-decoration: none;
        }

        /* DIVIDERS */
        .gradient-divider {
          height: 1px;
          width: 100%;
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.06) 50%, transparent);
          border: none;
          margin: 0;
        }

        /* NAV */
        .dp-nav {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 100;
          background: rgba(9, 9, 11, 0.5);
          backdrop-filter: blur(24px);
          -webkit-backdrop-filter: blur(24px);
          border-bottom: 1px solid rgba(255, 255, 255, 0.04);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 48px;
          height: 64px;
        }
        .dp-logo {
          display: flex;
          align-items: center;
          gap: 12px;
          text-decoration: none;
        }
        .dp-mark {
          width: 22px;
          height: 26px;
        }
        .dp-name {
          font-family: 'DM Mono', monospace;
          font-size: 14px;
          font-weight: 500;
          letter-spacing: 0.04em;
          color: var(--text-hi);
        }
        .dp-nav-links {
          display: flex;
          gap: 32px;
          list-style: none;
          margin: 0;
          padding: 0;
        }
        .dp-nav-links a {
          font-size: 14px;
          font-weight: 500;
          color: var(--text-dim);
          transition: color .2s ease;
        }
        .dp-nav-links a:hover {
          color: var(--text-hi);
        }
        .dp-nav-cta {
          display: flex;
          gap: 12px;
          align-items: center;
        }
        .dp-btn-ghost {
          font-family: 'DM Mono', monospace;
          font-size: 12px;
          letter-spacing: 0.1em;
          text-transform: uppercase;
          color: var(--text-dim);
          padding: 8px 16px;
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 6px;
          transition: all .2s ease;
        }
        .dp-btn-ghost:hover {
          color: var(--text-hi);
          border-color: rgba(255,255,255,0.2);
          background: rgba(255,255,255,0.02);
        }
        .dp-btn-primary {
          font-family: 'DM Mono', monospace;
          font-size: 12px;
          letter-spacing: 0.1em;
          text-transform: uppercase;
          background: var(--text-hi);
          color: var(--bg);
          padding: 9px 18px;
          border-radius: 6px;
          font-weight: 600;
          transition: opacity .2s ease, transform .2s ease;
        }
        .dp-btn-primary:hover {
          opacity: 0.9;
          transform: translateY(-1px);
        }

        /* HERO */
        .dp-hero {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          text-align: center;
          padding: 160px 48px 120px;
          position: relative;
        }
        .dp-hero-glow {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          width: 800px;
          height: 600px;
          background: radial-gradient(circle at 50% 50%, rgba(37,99,235,0.15) 0%, rgba(124,58,237,0.1) 30%, transparent 70%);
          filter: blur(60px);
          pointer-events: none;
          z-index: 0;
        }
        .dp-hero-content {
          position: relative;
          z-index: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
        }
        .dp-badge {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid rgba(255, 255, 255, 0.08);
          box-shadow: 0 4px 24px -4px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.1);
          backdrop-filter: blur(12px);
          border-radius: 100px;
          padding: 8px 20px;
          margin-bottom: 40px;
          font-family: 'DM Mono', monospace;
          font-size: 12px;
          letter-spacing: 0.12em;
          text-transform: uppercase;
          color: var(--text-mid);
        }
        .dp-badge-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: var(--ice);
          box-shadow: 0 0 12px var(--ice);
          animation: dpPulse 2s ease-in-out infinite;
        }
        @keyframes dpPulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(0.8); }
        }
        .dp-hero h1 {
          font-size: clamp(48px, 8vw, 100px);
          font-weight: 700;
          line-height: 1;
          letter-spacing: -0.04em;
          max-width: 900px;
          margin: 0 0 32px;
        }
        .dp-hero h1 span {
          background: linear-gradient(135deg, #fff 0%, rgba(255,255,255,0.7) 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        .dp-hero-sub {
          font-size: 20px;
          font-weight: 400;
          color: var(--text-mid);
          max-width: 580px;
          line-height: 1.7;
          margin-bottom: 56px;
        }
        
        .dp-hero-install {
          background: rgba(255, 255, 255, 0.03);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 8px;
          padding: 16px 24px;
          display: flex;
          align-items: center;
          gap: 16px;
          text-align: left;
          box-shadow: 0 8px 32px rgba(0,0,0,0.4);
          margin-bottom: 80px;
        }
        .dp-install-text {
          display: flex;
          flex-direction: column;
        }
        .dp-install-label {
          font-family: 'DM Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: var(--text-dim);
          margin-bottom: 4px;
        }
        .dp-install-code {
          font-family: 'DM Mono', monospace;
          font-size: 14px;
          color: var(--text-hi);
        }
        .dp-copy-btn {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 6px;
          padding: 8px 12px;
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          color: var(--text-mid);
          cursor: pointer;
          transition: all .2s ease;
        }
        .dp-copy-btn:hover {
          border-color: rgba(255,255,255,0.2);
          color: var(--text-hi);
          background: rgba(255,255,255,0.1);
        }

        .dp-hero-stats {
          display: flex;
          gap: 64px;
          flex-wrap: wrap;
          justify-content: center;
        }
        .dp-hstat {
          text-align: center;
        }
        .dp-hstat-n {
          font-family: 'DM Mono', monospace;
          font-size: 32px;
          font-weight: 500;
          color: var(--text-hi);
          display: block;
          line-height: 1;
          text-shadow: 0 2px 12px rgba(255,255,255,0.15);
        }
        .dp-hstat-l {
          font-size: 12px;
          font-weight: 500;
          letter-spacing: 0.1em;
          text-transform: uppercase;
          color: var(--text-dim);
          margin-top: 8px;
          display: block;
        }

        /* SECTION COMMON */
        .dp-section {
          padding: 120px 48px;
          max-width: 1200px;
          margin: 0 auto;
          position: relative;
        }
        .dp-kicker {
          font-family: 'DM Mono', monospace;
          font-size: 12px;
          letter-spacing: 0.25em;
          text-transform: uppercase;
          color: var(--ice);
          margin-bottom: 20px;
        }
        .dp-h2 {
          font-size: clamp(32px, 5vw, 48px);
          font-weight: 700;
          letter-spacing: -0.04em;
          line-height: 1.1;
          margin: 0 0 24px;
          background: linear-gradient(135deg, #fff 0%, rgba(255,255,255,0.7) 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        .dp-sub {
          font-size: 18px;
          color: var(--text-mid);
          line-height: 1.7;
          max-width: 600px;
          margin-bottom: 64px;
        }

        /* BIG NUMBER */
        .dp-number-sec {
          padding: 120px 48px;
          text-align: center;
          position: relative;
        }
        .dp-big-num {
          font-family: 'DM Mono', monospace;
          font-size: clamp(80px, 12vw, 160px);
          font-weight: 500;
          color: var(--text-hi);
          line-height: 1;
          display: block;
          letter-spacing: -0.03em;
          text-shadow: 0 0 40px rgba(255,255,255,0.1);
        }
        .dp-num-label {
          font-size: 18px;
          color: var(--text-mid);
          max-width: 540px;
          margin: 32px auto 0;
          line-height: 1.7;
        }
        .dp-num-label strong {
          color: var(--text-hi);
          font-weight: 600;
        }

        /* CARDS & GRID */
        .dp-grid-3 {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 24px;
        }
        .dp-grid-4 {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 24px;
        }
        .dp-grid-2 {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 24px;
        }
        
        .dp-card {
          background: linear-gradient(180deg, var(--card-bg-start), var(--card-bg-end));
          border: 1px solid var(--card-border);
          border-radius: 12px;
          padding: 40px;
          transition: all 0.3s ease;
          position: relative;
          overflow: hidden;
        }
        .dp-card:hover {
          border-color: var(--card-hover);
          transform: translateY(-2px);
          box-shadow: 0 12px 40px -12px rgba(0,0,0,0.5), 0 0 20px rgba(96,165,250,0.05);
        }

        /* CODE BLOCK */
        .dp-code-window {
          background: #0d1117;
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 12px;
          overflow: hidden;
          max-width: 720px;
          box-shadow: 0 20px 60px -10px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.02);
          margin-bottom: 64px;
        }
        .dp-code-top {
          background: rgba(255,255,255,0.02);
          padding: 16px 20px;
          display: flex;
          align-items: center;
          gap: 10px;
          border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .dp-code-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
        }
        .dp-code-dot.red { background: #ff5f57; }
        .dp-code-dot.yellow { background: #febc2e; }
        .dp-code-dot.green { background: #28c840; }
        .dp-code-filename {
          font-family: 'DM Mono', monospace;
          font-size: 12px;
          color: var(--text-dim);
          margin-left: 12px;
        }
        .dp-code-body {
          padding: 24px;
          overflow-x: auto;
          display: flex;
        }
        .dp-code-lines {
          font-family: 'DM Mono', monospace;
          font-size: 14px;
          line-height: 1.75;
          color: rgba(255,255,255,0.2);
          padding-right: 24px;
          text-align: right;
          user-select: none;
        }
        .dp-code-pre {
          font-family: 'DM Mono', monospace;
          font-size: 14px;
          line-height: 1.75;
          color: #e6edf3;
          margin: 0;
        }

        /* FEATURE CARD */
        .dp-feat-title {
          font-size: 18px;
          font-weight: 600;
          margin-bottom: 12px;
          color: var(--text-hi);
        }
        .dp-feat-body {
          font-size: 15px;
          color: var(--text-mid);
          line-height: 1.6;
        }

        /* COMPARE TABLE */
        .dp-table-wrap {
          border: 1px solid var(--card-border);
          border-radius: 12px;
          overflow: hidden;
          background: rgba(255,255,255,0.01);
        }
        .dp-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 15px;
        }
        .dp-table th {
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: var(--text-dim);
          padding: 20px 24px;
          text-align: left;
          background: rgba(255,255,255,0.02);
          border-bottom: 1px solid var(--card-border);
        }
        .dp-table td {
          padding: 20px 24px;
          border-bottom: 1px solid rgba(255,255,255,0.03);
          color: var(--text-mid);
        }
        .dp-table tr:nth-child(even) td {
          background: rgba(255,255,255,0.01);
        }
        .dp-table td:first-child {
          font-weight: 500;
          color: var(--text-hi);
        }
        .dp-table tr.dp-aiglos-row td {
          background: rgba(37, 99, 235, 0.08);
          color: var(--text-hi);
        }
        .dp-table tr.dp-aiglos-row td:first-child {
          color: var(--ice);
          font-family: 'Plus Jakarta Sans', sans-serif;
          font-weight: 600;
          position: relative;
        }
        .dp-table tr.dp-aiglos-row td:first-child::before {
          content: '';
          position: absolute;
          left: 0;
          top: 0;
          bottom: 0;
          width: 3px;
          background: var(--blue);
        }

        /* GHSA VALIDATION */
        .dp-val-row {
          display: grid;
          grid-template-columns: 180px 1fr auto;
          gap: 32px;
          align-items: center;
        }
        .dp-val-ghsa {
          font-family: 'DM Mono', monospace;
          font-size: 13px;
          color: var(--ice);
        }
        .dp-val-cvss {
          color: var(--text-dim);
          font-size: 11px;
          display: block;
          margin-top: 4px;
        }
        .dp-val-title {
          font-size: 16px;
          color: var(--text-hi);
        }
        .dp-val-rules {
          font-family: 'DM Mono', monospace;
          font-size: 13px;
          color: #4ade80;
          background: rgba(74, 222, 128, 0.1);
          padding: 6px 12px;
          border-radius: 6px;
        }

        /* ATLAS */
        .dp-atlas-id {
          font-family: 'DM Mono', monospace;
          font-size: 11px;
          color: var(--ice);
          letter-spacing: 0.1em;
          display: block;
          margin-bottom: 8px;
        }
        .dp-atlas-title {
          font-size: 16px;
          font-weight: 600;
          margin-bottom: 8px;
        }
        .dp-atlas-rules {
          font-family: 'DM Mono', monospace;
          font-size: 12px;
          color: var(--text-dim);
        }

        /* PRICING */
        .dp-price-col {
          padding: 48px 40px;
          display: flex;
          flex-direction: column;
        }
        .dp-price-featured {
          position: relative;
          background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));
          border: 1px solid rgba(96,165,250,0.3);
          box-shadow: 0 0 30px rgba(37,99,235,0.1), inset 0 0 20px rgba(255,255,255,0.02);
        }
        .dp-price-badge {
          position: absolute;
          top: -12px;
          left: 50%;
          transform: translateX(-50%);
          background: linear-gradient(90deg, var(--blue), var(--glow-purple));
          color: #fff;
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.05em;
          text-transform: uppercase;
          padding: 4px 16px;
          border-radius: 100px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .dp-tier {
          font-family: 'DM Mono', monospace;
          font-size: 12px;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          color: var(--text-dim);
          margin-bottom: 24px;
        }
        .dp-amount {
          font-family: 'DM Mono', monospace;
          font-size: 48px;
          font-weight: 500;
          line-height: 1;
          margin-bottom: 32px;
        }
        .dp-mo {
          font-size: 16px;
          font-weight: 400;
          color: var(--text-dim);
          margin-left: 8px;
        }
        .dp-features {
          list-style: none;
          padding: 0;
          margin: 0;
          flex-grow: 1;
        }
        .dp-features li {
          padding: 12px 0;
          border-bottom: 1px solid rgba(255,255,255,0.04);
          color: var(--text-mid);
          font-size: 15px;
          display: flex;
          align-items: center;
        }
        .dp-features li:last-child {
          border-bottom: none;
        }
        .dp-features li::before {
          content: '';
          display: inline-block;
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: var(--ice);
          margin-right: 12px;
        }

        /* CTA */
        .dp-cta-sec {
          padding: 160px 48px;
          text-align: center;
          position: relative;
        }
        .dp-cta-glow {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          width: 600px;
          height: 400px;
          background: radial-gradient(circle, rgba(37,99,235,0.1) 0%, transparent 60%);
          filter: blur(40px);
          pointer-events: none;
        }
        .dp-cta-text {
          font-size: clamp(32px, 5vw, 56px);
          font-weight: 700;
          letter-spacing: -0.03em;
          margin-bottom: 48px;
          position: relative;
          z-index: 1;
        }

        /* FOOTER */
        .dp-footer {
          padding: 64px 48px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          flex-wrap: wrap;
          gap: 24px;
        }
        .dp-footer-links {
          display: flex;
          gap: 32px;
        }
        .dp-footer-links a {
          font-size: 14px;
          color: var(--text-dim);
          transition: color .2s ease;
        }
        .dp-footer-links a:hover {
          color: var(--text-hi);
        }

        @media (max-width: 1024px) {
          .dp-grid-3, .dp-grid-4 {
            grid-template-columns: repeat(2, 1fr);
          }
        }
        @media (max-width: 768px) {
          .dp-nav { padding: 0 24px; }
          .dp-nav-links { display: none; }
          .dp-hero { padding: 120px 24px 80px; }
          .dp-section, .dp-number-sec, .dp-cta-sec, .dp-footer { padding: 80px 24px; }
          .dp-grid-2, .dp-grid-3, .dp-grid-4 { grid-template-columns: 1fr; }
          .dp-val-row { grid-template-columns: 1fr; gap: 12px; }
          .dp-hero-stats { gap: 32px; }
        }
        
        .tok-kw { color: #ff7b72; }
        .tok-str { color: #a5d6ff; }
        .tok-fn { color: #d2a8ff; }
        .tok-comment { color: #8b949e; }
        .tok-param { color: #79c0ff; }
      `}</style>

      {/* NAV */}
      <nav className="dp-nav">
        <a href="#home" className="dp-logo">
          <svg className="dp-mark" viewBox="0 0 44 50" fill="none">
            <polygon points="22,2 2,44 22,44" fill="white" />
            <polygon points="22,2 42,44 22,44" fill="rgba(255,255,255,0.42)" />
            <rect x="14" y="44" width="16" height="6" fill="white" />
          </svg>
          <span className="dp-name">aiglos</span>
        </a>
        <ul className="dp-nav-links">
          <li><a href="#intel">Intel</a></li>
          <li><a href="#compare">Compare</a></li>
          <li><a href="#pricing">Pricing</a></li>
          <li><a href="#docs">Docs</a></li>
          <li><a href="#github">GitHub</a></li>
        </ul>
        <div className="dp-nav-cta">
          <a href="#docs" className="dp-btn-ghost">Docs</a>
          <a href="#install" className="dp-btn-primary">pip install</a>
        </div>
      </nav>

      {/* HERO */}
      <section className="dp-hero" id="home">
        <div className="dp-hero-glow"></div>
        <div className="dp-hero-content">
          <div className="dp-badge">
            <span className="dp-badge-dot"></span>
            v0.25.3 — 81 threat families — 1,747 tests passing
          </div>
          <h1>Runtime security for<br /><span>AI agents.</span></h1>
          <p className="dp-hero-sub">
            One import. Every tool call inspected before execution. Under 1ms. The security layer the OpenClaw ecosystem doesn't ship.
          </p>
          <div className="dp-hero-install">
            <div className="dp-install-text">
              <span className="dp-install-label">Install</span>
              <span className="dp-install-code">pip install aiglos && aiglos launch</span>
            </div>
            <button className="dp-copy-btn" onClick={handleCopy}>
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <div className="dp-hero-stats">
            <div className="dp-hstat">
              <span className="dp-hstat-n">81</span>
              <span className="dp-hstat-l">Threat families</span>
            </div>
            <div className="dp-hstat">
              <span className="dp-hstat-n">22</span>
              <span className="dp-hstat-l">Campaign patterns</span>
            </div>
            <div className="dp-hstat">
              <span className="dp-hstat-n">&lt;1ms</span>
              <span className="dp-hstat-l">Per call</span>
            </div>
            <div className="dp-hstat">
              <span className="dp-hstat-n">0</span>
              <span className="dp-hstat-l">Dependencies</span>
            </div>
          </div>
        </div>
      </section>

      <div className="gradient-divider"></div>

      {/* THE NUMBER */}
      <div className="dp-number-sec">
        <span className="dp-big-num">233 / 247</span>
        <p className="dp-num-label">IBM found that shadow AI breaches take <strong>247 days</strong> to detect. SWE-CI ran agents for <strong>233 days</strong>. The agent operates inside its own undetected breach window. Every production deployment running right now.</p>
      </div>

      <div className="gradient-divider"></div>

      {/* HOW IT WORKS */}
      <section className="dp-section">
        <div className="dp-kicker">How it works</div>
        <h2 className="dp-h2">One line. Nothing else changes.</h2>
        <p className="dp-sub">Aiglos intercepts every tool call, HTTP request, and shell command before execution. The agent never knows it's running.</p>
        
        <div className="dp-code-window">
          <div className="dp-code-top">
            <span className="dp-code-dot red"></span>
            <span className="dp-code-dot yellow"></span>
            <span className="dp-code-dot green"></span>
            <span className="dp-code-filename">agent.py</span>
          </div>
          <div className="dp-code-body">
            <div className="dp-code-lines">
              1<br/>2<br/>3<br/>4<br/>5<br/>6<br/>7<br/>8<br/>9
            </div>
            <pre className="dp-code-pre">
<span className="tok-kw">import</span> aiglos
<br/>
aiglos.<span className="tok-fn">attach</span>(
    <span className="tok-param">agent_name</span>=<span className="tok-str">"my-agent"</span>,
    <span className="tok-param">policy</span>=<span className="tok-str">"enterprise"</span>,
)
<br/>
<span className="tok-comment"># The agent keeps running. Nothing else changes.</span>
<span className="tok-comment"># Until something tries to exfiltrate credentials. Then it stops.</span>
            </pre>
          </div>
        </div>

        <div className="dp-grid-3">
          <div className="dp-card">
            <div className="dp-feat-title">81 Threat Families</div>
            <div className="dp-feat-body">T01-T81 covering MCP tool calls, HTTP/API requests, subprocess execution, session data extraction, content wrapper escapes, environment hijacking, .pth supply chain persistence, uncensored model routing.</div>
          </div>
          <div className="dp-card">
            <div className="dp-feat-title">Campaign Detection</div>
            <div className="dp-feat-body">22 multi-step attack patterns. A git log followed by a .env read followed by an outbound POST is a credential exfiltration campaign. Each call looks clean. The sequence is the attack. Aiglos sees sequences.</div>
          </div>
          <div className="dp-card">
            <div className="dp-feat-title">Behavioral Baseline</div>
            <div className="dp-feat-body">After 20 sessions, Aiglos builds a per-agent statistical fingerprint. The DevOps agent that reads .aws/credentials scores LOW. The code review agent that never has — and suddenly does — scores HIGH.</div>
          </div>
          <div className="dp-card">
            <div className="dp-feat-title">Signed Audit Artifact</div>
            <div className="dp-feat-body">Every session closes with a cryptographically signed record of everything the agent did. HMAC-SHA256 minimum. RSA-2048 for regulatory submission. The artifact NDAA §1513 requires. Nothing else produces it.</div>
          </div>
          <div className="dp-card">
            <div className="dp-feat-title">Federation Intelligence</div>
            <div className="dp-feat-body">Every contributing deployment shares anonymized threat patterns via differential privacy (ε=0.1). New deployment, day one: pre-warmed from collective intelligence. The moat that compounds with every install.</div>
          </div>
          <div className="dp-card">
            <div className="dp-feat-title">GOVBENCH</div>
            <div className="dp-feat-body">The first governance benchmark for AI agents. Five dimensions. A-F grade. Published before any standard body required one. The company that defines the benchmark owns the compliance category. Run it: <code>aiglos benchmark run</code></div>
          </div>
        </div>
      </section>

      <div className="gradient-divider"></div>

      {/* STATS */}
      <section className="dp-section">
        <div className="dp-kicker">By the numbers</div>
        <h2 className="dp-h2">Built for the way agents actually work.</h2>
        <div className="dp-grid-4">
          <div className="dp-card" style={{textAlign: 'center', padding: '40px 24px'}}>
            <span className="dp-hstat-n">81</span>
            <span className="dp-hstat-l">Threat families</span>
          </div>
          <div className="dp-card" style={{textAlign: 'center', padding: '40px 24px'}}>
            <span className="dp-hstat-n">93%</span>
            <span className="dp-hstat-l">ATLAS coverage</span>
          </div>
          <div className="dp-card" style={{textAlign: 'center', padding: '40px 24px'}}>
            <span className="dp-hstat-n">3/3</span>
            <span className="dp-hstat-l">GHSAs caught</span>
          </div>
          <div className="dp-card" style={{textAlign: 'center', padding: '40px 24px'}}>
            <span className="dp-hstat-n">1,747</span>
            <span className="dp-hstat-l">Tests passing</span>
          </div>
        </div>
      </section>

      <div className="gradient-divider"></div>

      {/* GHSA VALIDATION */}
      <section className="dp-section">
        <div className="dp-kicker">Empirical validation</div>
        <h2 className="dp-h2">Every published OpenClaw vulnerability.<br/>Caught by existing rules.</h2>
        <p className="dp-sub">The OpenClaw security page has received 288 vulnerability reports. Three have been published. All three are covered by Aiglos rules — before the advisories were disclosed, before any patch existed.</p>
        
        <div style={{display: 'flex', flexDirection: 'column', gap: '16px'}}>
          <div className="dp-card dp-val-row">
            <div>
              <span className="dp-val-ghsa">GHSA-g8p2-7wf7-98mq</span>
              <span className="dp-val-cvss">CVSS 8.8 · High</span>
            </div>
            <div className="dp-val-title">1-Click RCE via Authentication Token Exfiltration from gatewayUrl</div>
            <div className="dp-val-rules">T03 T12 T19 T68 ✓</div>
          </div>
          <div className="dp-card dp-val-row">
            <div>
              <span className="dp-val-ghsa">GHSA-q284-4pvr-m585</span>
              <span className="dp-val-cvss">CVSS 8.6 · High</span>
            </div>
            <div className="dp-val-title">OS Command Injection via Project Root Path in sshNodeCommand</div>
            <div className="dp-val-rules">T03 T04 T70 ✓</div>
          </div>
          <div className="dp-card dp-val-row">
            <div>
              <span className="dp-val-ghsa">GHSA-mc68-q9jw-2h3v</span>
              <span className="dp-val-cvss">CVSS 8.4 · High</span>
            </div>
            <div className="dp-val-title">Command Injection in Clawdbot Docker via PATH Environment Variable</div>
            <div className="dp-val-rules">T03 T70 ✓</div>
          </div>
        </div>
      </section>

      <div className="gradient-divider"></div>

      {/* COMPARE */}
      <section className="dp-section">
        <div className="dp-kicker">Competition</div>
        <h2 className="dp-h2">Everyone watches calls.<br/>Nobody watches sessions.</h2>
        <p className="dp-sub">The gap is not a feature gap. It is architectural. You cannot retrofit sequence detection onto a system built for single-call inspection.</p>
        
        <div className="dp-table-wrap">
          <table className="dp-table">
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
              <tr><td>Azure / Lakera</td><td>Inbound prompt text</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td></tr>
              <tr><td>Kong / Apigee AI</td><td>HTTP traffic only</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td></tr>
              <tr><td>CrowdStrike / Splunk</td><td>Host logs, after the fact</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td></tr>
              <tr><td>Snyk mcp-scan</td><td>Static skill scanning</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td></tr>
              <tr><td>ClawKeeper</td><td>Host configuration</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td><td style={{color:'rgba(255,255,255,0.2)'}}>✗</td></tr>
              <tr className="dp-aiglos-row"><td>Aiglos</td><td>MCP + HTTP + subprocess</td><td style={{color:'#4ade80'}}>✓</td><td style={{color:'#4ade80'}}>✓</td><td style={{color:'#4ade80'}}>✓</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <div className="gradient-divider"></div>

      {/* ATLAS COVERAGE */}
      <section className="dp-section">
        <div className="dp-kicker">OpenClaw ATLAS Threat Model</div>
        <h2 className="dp-h2">93% coverage of the platform's<br/>own documented threat model.</h2>
        <p className="dp-sub">OpenClaw published a formal MITRE ATLAS threat model in February 2026. 22 threats across 8 tactic categories. Aiglos covers 19 fully, 3 partially, 0 gaps.</p>
        
        <div className="dp-grid-2">
          <div className="dp-card">
            <span className="dp-atlas-id">T-EXEC-001 · T-EXEC-002</span>
            <div className="dp-atlas-title">Direct + Indirect Prompt Injection</div>
            <div className="dp-atlas-rules">T05 T01 T54 T60 T74 — FULL</div>
          </div>
          <div className="dp-card">
            <span className="dp-atlas-id">T-PERSIST-001/002/003</span>
            <div className="dp-atlas-title">Skill Installation, Update Poisoning, Config Tampering</div>
            <div className="dp-atlas-rules">T30 T34 T36 T37 — FULL</div>
          </div>
          <div className="dp-card">
            <span className="dp-atlas-id">T-EXFIL-001/002/003</span>
            <div className="dp-atlas-title">Data Theft, Unauthorized Messaging, Credential Harvesting</div>
            <div className="dp-atlas-rules">T09 T12 T14 T19 T37 — FULL</div>
          </div>
          <div className="dp-card">
            <span className="dp-atlas-id">T-DISC-001 · T-DISC-002</span>
            <div className="dp-atlas-title">Tool Enumeration + Session Data Extraction</div>
            <div className="dp-atlas-rules">T73 T56 T75 — FULL</div>
          </div>
        </div>
      </section>

      <div className="gradient-divider"></div>

      {/* PRICING */}
      <section className="dp-section" id="pricing">
        <div className="dp-kicker">Pricing</div>
        <h2 className="dp-h2">Free to detect. Pro to prove.</h2>
        <p className="dp-sub">The free tier runs the full detection engine. Pro adds the federation intelligence and the signed compliance artifact — the document that turns a security tool into a regulatory submission.</p>
        
        <div className="dp-grid-3" style={{alignItems: 'stretch'}}>
          <div className="dp-card dp-price-col">
            <div className="dp-tier">Free</div>
            <div className="dp-amount">$0</div>
            <ul className="dp-features">
              <li>Full runtime engine</li>
              <li>81 threat families</li>
              <li>Local logging</li>
              <li>Community support</li>
            </ul>
          </div>
          <div className="dp-card dp-price-col dp-price-featured">
            <div className="dp-price-badge">Most Popular</div>
            <div className="dp-tier" style={{color: 'var(--ice)'}}>Pro</div>
            <div className="dp-amount">$49<span className="dp-mo">/mo</span></div>
            <ul className="dp-features">
              <li>Everything in Free</li>
              <li>Signed audit artifacts</li>
              <li>Federation intelligence</li>
              <li>Priority support</li>
            </ul>
          </div>
          <div className="dp-card dp-price-col">
            <div className="dp-tier">Enterprise</div>
            <div className="dp-amount">Custom</div>
            <ul className="dp-features">
              <li>Everything in Pro</li>
              <li>Custom policy engineering</li>
              <li>On-premise telemetry</li>
              <li>SLA & Dedicated CSM</li>
            </ul>
          </div>
        </div>
      </section>

      <div className="gradient-divider"></div>

      {/* CTA */}
      <div className="dp-cta-sec">
        <div className="dp-cta-glow"></div>
        <div className="dp-cta-text">The window is measured<br/>in months, not years.</div>
        <a href="#install" className="dp-btn-primary" style={{position: 'relative', zIndex: 1, fontSize: '14px', padding: '12px 24px'}}>Install Aiglos</a>
      </div>

      <div className="gradient-divider"></div>

      {/* FOOTER */}
      <footer className="dp-footer">
        <div className="dp-name" style={{color: 'var(--text-dim)'}}>aiglos</div>
        <div className="dp-footer-links">
          <a href="#intel">Intel</a>
          <a href="#compare">Compare</a>
          <a href="#pricing">Pricing</a>
          <a href="#docs">Docs</a>
          <a href="#github">GitHub</a>
        </div>
        <div style={{fontSize: '12px', color: 'rgba(255,255,255,0.2)'}}>
          &copy; {new Date().getFullYear()} Aiglos. All rights reserved.
        </div>
      </footer>

    </div>
  );
}
