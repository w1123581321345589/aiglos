import { Link, useLocation } from "wouter";
import { useState, useEffect } from "react";
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
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 16);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="min-h-screen bg-pub-dark text-white font-pub-sans antialiased">
      <nav
        data-testid="nav-public"
        className={`fixed top-0 left-0 right-0 z-[100] backdrop-blur-[12px] px-12 h-14 flex items-center justify-between transition-[background,border] duration-200 ${
          scrolled
            ? "bg-pub-dark/90 border-b border-pub-strong"
            : "bg-pub-dark/85 border-b border-pub"
        }`}
      >
        <Link href="/" data-testid="link-home">
          <div className="flex items-center gap-2.5 no-underline cursor-pointer">
            <svg width="20" height="24" viewBox="0 0 44 50" fill="none">
              <polygon points="22,2 2,44 22,44" fill="white" />
              <polygon points="22,2 42,44 22,44" fill="rgba(255,255,255,0.42)" />
              <rect x="14" y="44" width="16" height="6" fill="white" />
            </svg>
            <span className="font-pub-mono text-[13px] font-medium tracking-[0.04em] text-white">
              aiglos
            </span>
          </div>
        </Link>

        <ul className="pub-nav-links flex gap-6 list-none m-0 p-0">
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              <Link href={link.href} data-testid={`link-${link.label.toLowerCase()}`}>
                <span
                  className={`text-[13px] no-underline cursor-pointer transition-colors duration-150 ${
                    location === link.href ? "text-white" : "text-pub-dim hover:text-pub-muted"
                  }`}
                >
                  {link.label}
                </span>
              </Link>
            </li>
          ))}
        </ul>

        <div className="flex gap-2.5 items-center">
          <a
            href="https://github.com/w1123581321345589/aiglos"
            target="_blank"
            rel="noopener noreferrer"
            data-testid="link-github"
            className="font-pub-mono text-[11px] tracking-[0.1em] uppercase text-pub-dim no-underline py-[7px] px-3.5 border border-pub-strong rounded transition-all duration-150 hover:text-pub-muted hover:border-white/20"
          >
            GitHub
          </a>
          <a
            href="https://pypi.org/project/aiglos/"
            target="_blank"
            rel="noopener noreferrer"
            data-testid="link-pip-install"
            className="font-pub-mono text-[11px] tracking-[0.1em] uppercase bg-white text-pub-dark py-[7px] px-4 rounded no-underline transition-opacity duration-150 hover:opacity-90"
          >
            pip install
          </a>
          <button
            data-testid="button-mobile-menu"
            onClick={() => setMobileOpen(!mobileOpen)}
            className="pub-nav-mobile-toggle hidden bg-transparent border-none text-white cursor-pointer p-1"
          >
            {mobileOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </nav>

      {mobileOpen && (
        <div className="fixed top-14 inset-x-0 bottom-0 bg-pub-dark/[0.98] z-[99] p-6 flex flex-col gap-2">
          {NAV_LINKS.map((link) => (
            <Link key={link.href} href={link.href}>
              <div
                onClick={() => setMobileOpen(false)}
                className={`py-3 px-4 text-[15px] cursor-pointer border-b border-pub ${
                  location === link.href ? "text-white" : "text-pub-muted"
                }`}
              >
                {link.label}
              </div>
            </Link>
          ))}
        </div>
      )}

      <main className="pt-14">{children}</main>

      <footer className="border-t border-pub py-14 px-12">
        <div className="max-w-[1200px] mx-auto grid grid-cols-4 pub-grid-4 gap-8">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <svg width="16" height="19" viewBox="0 0 44 50" fill="none">
                <polygon points="22,2 2,44 22,44" fill="white" />
                <polygon points="22,2 42,44 22,44" fill="rgba(255,255,255,0.42)" />
                <rect x="14" y="44" width="16" height="6" fill="white" />
              </svg>
              <span className="font-pub-mono text-[13px] font-medium text-white">aiglos</span>
            </div>
            <p className="text-xs text-pub-dim leading-[1.6] max-w-[200px]">
              Runtime security for AI agents. Zero dependencies. Under 1ms.
            </p>
          </div>
          <div>
            <div className="font-pub-mono text-[10px] tracking-[0.2em] uppercase text-pub-dim mb-4">Product</div>
            {[
              { href: "/scan", label: "Scanner" },
              { href: "/govbench", label: "GovBench" },
              { href: "/intel", label: "Intel" },
              { href: "/pricing", label: "Pricing" },
            ].map((link) => (
              <Link key={link.href} href={link.href}>
                <div className="text-xs text-white/40 no-underline cursor-pointer hover:text-pub-muted transition-colors duration-150 py-1.5">
                  {link.label}
                </div>
              </Link>
            ))}
          </div>
          <div>
            <div className="font-pub-mono text-[10px] tracking-[0.2em] uppercase text-pub-dim mb-4">Resources</div>
            {[
              { href: "/reference", label: "Reference" },
              { href: "/compare", label: "Compare" },
              { href: "/compliance", label: "Compliance" },
            ].map((link) => (
              <Link key={link.href} href={link.href}>
                <div className="text-xs text-white/40 no-underline cursor-pointer hover:text-pub-muted transition-colors duration-150 py-1.5">
                  {link.label}
                </div>
              </Link>
            ))}
            <a href="/docs.html" className="block text-xs text-white/40 no-underline hover:text-pub-muted transition-colors duration-150 py-1.5">Docs</a>
            <a href="/changelog.html" className="block text-xs text-white/40 no-underline hover:text-pub-muted transition-colors duration-150 py-1.5">Changelog</a>
          </div>
          <div>
            <div className="font-pub-mono text-[10px] tracking-[0.2em] uppercase text-pub-dim mb-4">Company</div>
            <a href="https://github.com/w1123581321345589/aiglos" target="_blank" rel="noopener noreferrer" className="block text-xs text-white/40 no-underline hover:text-pub-muted transition-colors duration-150 py-1.5">GitHub</a>
            <a href="https://pypi.org/project/aiglos/" target="_blank" rel="noopener noreferrer" className="block text-xs text-white/40 no-underline hover:text-pub-muted transition-colors duration-150 py-1.5">PyPI</a>
            <div className="text-xs text-pub-ghost py-1.5">MIT License</div>
          </div>
        </div>
        <div className="max-w-[1200px] mx-auto mt-10 pt-6 border-t border-pub text-[11px] text-pub-ghost">
          &copy; {new Date().getFullYear()} Aiglos. Runtime security for autonomous AI agents.
        </div>
      </footer>
    </div>
  );
}
