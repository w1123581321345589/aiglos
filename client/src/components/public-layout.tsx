import { Link, useLocation } from "wouter";
import { useState } from "react";
import { Menu, X } from "lucide-react";

const NAV_LINKS = [
  { href: "/scan", label: "Scan" },
  { href: "/govbench", label: "GovBench" },
  { href: "/intel", label: "Intel" },
  { href: "/compare", label: "Compare" },
  { href: "/compliance", label: "Compliance" },
  { href: "/pricing", label: "Pricing" },
  { href: "/reference", label: "Reference" },
];

export default function PublicLayout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#09090b",
        color: "#fff",
        fontFamily: "'Plus Jakarta Sans', 'Inter', sans-serif",
        WebkitFontSmoothing: "antialiased",
      }}
    >
      <nav
        data-testid="nav-public"
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          zIndex: 100,
          background: "rgba(9,9,11,0.85)",
          backdropFilter: "blur(12px)",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
          padding: "0 48px",
          height: "56px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <Link href="/" data-testid="link-home">
          <div style={{ display: "flex", alignItems: "center", gap: "10px", textDecoration: "none", cursor: "pointer" }}>
            <svg width="20" height="24" viewBox="0 0 44 50" fill="none">
              <polygon points="22,2 2,44 22,44" fill="white" />
              <polygon points="22,2 42,44 22,44" fill="rgba(255,255,255,0.42)" />
              <rect x="14" y="44" width="16" height="6" fill="white" />
            </svg>
            <span
              style={{
                fontFamily: "'DM Mono', monospace",
                fontSize: "13px",
                fontWeight: 500,
                letterSpacing: "0.04em",
                color: "#fff",
              }}
            >
              aiglos
            </span>
          </div>
        </Link>

        <ul
          style={{
            display: "flex",
            gap: "24px",
            listStyle: "none",
            margin: 0,
            padding: 0,
          }}
          className="public-nav-links"
        >
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              <Link href={link.href} data-testid={`link-${link.label.toLowerCase()}`}>
                <span
                  style={{
                    fontSize: "13px",
                    color: location === link.href ? "#fff" : "rgba(255,255,255,0.35)",
                    textDecoration: "none",
                    cursor: "pointer",
                    transition: "color 0.15s",
                  }}
                >
                  {link.label}
                </span>
              </Link>
            </li>
          ))}
        </ul>

        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <a
            href="https://github.com/w1123581321345589/aiglos"
            target="_blank"
            rel="noopener noreferrer"
            data-testid="link-github"
            style={{
              fontFamily: "'DM Mono', monospace",
              fontSize: "11px",
              letterSpacing: "0.1em",
              textTransform: "uppercase" as const,
              color: "rgba(255,255,255,0.35)",
              textDecoration: "none",
              padding: "7px 14px",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: "4px",
              transition: "all 0.15s",
            }}
          >
            GitHub
          </a>
          <a
            href="https://pypi.org/project/aiglos/"
            target="_blank"
            rel="noopener noreferrer"
            data-testid="link-pip-install"
            style={{
              fontFamily: "'DM Mono', monospace",
              fontSize: "11px",
              letterSpacing: "0.1em",
              textTransform: "uppercase" as const,
              background: "#fff",
              color: "#09090b",
              padding: "7px 16px",
              borderRadius: "4px",
              textDecoration: "none",
              transition: "opacity 0.15s",
            }}
          >
            pip install
          </a>
          <button
            data-testid="button-mobile-menu"
            onClick={() => setMobileOpen(!mobileOpen)}
            className="public-nav-mobile-toggle"
            style={{
              display: "none",
              background: "transparent",
              border: "none",
              color: "#fff",
              cursor: "pointer",
              padding: "4px",
            }}
          >
            {mobileOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </nav>

      {mobileOpen && (
        <div
          className="public-nav-mobile-menu"
          style={{
            position: "fixed",
            top: "56px",
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(9,9,11,0.98)",
            zIndex: 99,
            padding: "24px",
            display: "flex",
            flexDirection: "column",
            gap: "8px",
          }}
        >
          {NAV_LINKS.map((link) => (
            <Link key={link.href} href={link.href}>
              <div
                onClick={() => setMobileOpen(false)}
                style={{
                  padding: "12px 16px",
                  fontSize: "15px",
                  color: location === link.href ? "#fff" : "rgba(255,255,255,0.5)",
                  cursor: "pointer",
                  borderBottom: "1px solid rgba(255,255,255,0.06)",
                }}
              >
                {link.label}
              </div>
            </Link>
          ))}
        </div>
      )}

      <main style={{ paddingTop: "56px" }}>{children}</main>

      <footer
        style={{
          borderTop: "1px solid rgba(255,255,255,0.06)",
          padding: "40px 48px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
        }}
      >
        <span
          style={{
            fontFamily: "'DM Mono', monospace",
            fontSize: "13px",
            color: "rgba(255,255,255,0.35)",
          }}
        >
          aiglos
        </span>
        <div style={{ display: "flex", gap: "24px" }}>
          {NAV_LINKS.map((link) => (
            <Link key={link.href} href={link.href}>
              <span
                style={{
                  fontSize: "12px",
                  color: "rgba(255,255,255,0.35)",
                  textDecoration: "none",
                  cursor: "pointer",
                }}
              >
                {link.label}
              </span>
            </Link>
          ))}
        </div>
        <span style={{ fontSize: "12px", color: "rgba(255,255,255,0.2)" }}>
          MIT License
        </span>
      </footer>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap');
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes fadeUp { to { opacity: 1; transform: translateY(0); } }
        .fade-up { opacity: 0; transform: translateY(20px); animation: fadeUp 0.6s ease forwards; }
        .delay-1 { animation-delay: .1s; }
        .delay-2 { animation-delay: .2s; }
        .delay-3 { animation-delay: .3s; }
        @media (max-width: 900px) {
          .public-nav-links { display: none !important; }
          .public-nav-mobile-toggle { display: block !important; }
        }
      `}</style>
    </div>
  );
}
