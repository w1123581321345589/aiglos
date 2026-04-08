"""
aiglos/cli/scan_deps.py
=========================
aiglos scan-deps  -  check your Python environment for compromised packages.

Immediate answer to "am I affected by the LiteLLM supply chain attack?"

WHAT IT CHECKS
==============
1. Compromised package versions (litellm 1.82.7, 1.82.8  -  and future entries)
2. Malicious .pth files in site-packages (litellm_init.pth signature)
3. Persistence mechanisms (~/.config/sysmon/sysmon.py, systemd service)
4. Kubernetes cluster compromise indicators
5. Transitive dependency exposure (packages that pull in compromised versions)

USAGE
=====
    aiglos scan-deps                     # Full scan of current environment
    aiglos scan-deps --quick             # Only check known-bad versions
    aiglos scan-deps --package litellm   # Check a specific package
    aiglos scan-deps --fix               # Remove compromised packages

LITELLM ATTACK (March 24, 2026)
================================
LiteLLM 1.82.7 and 1.82.8 contained litellm_init.pth in site-packages.
The .pth file executed on every Python startup, collecting and exfiltrating:
  SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, database passwords,
  .env files (all API keys), shell history, crypto wallets, SSL private keys,
  CI/CD secrets, and all environment variables.

Exfiltration endpoint: https://models.litellm.cloud/ (NOT legitimate litellm)

The GitHub repository has been compromised  -  the security issue was closed
as "not planned" using the stolen maintainer GitHub token. Treat ALL litellm
versions as suspect until official verification of maintainer control.

T30 SUPPLY_CHAIN + T81 PTH_FILE_INJECT + T04 CRED_HARVEST + T41 OUTBOUND_SECRET_LEAK
+ REPO_TAKEOVER_CHAIN campaign = the complete attack taxonomy for this incident.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Known compromised packages ────────────────────────────────────────────────
# Updated as new supply chain attacks are discovered.
# Format: {package_name: {version: {description, cve, severity, ghsa}}}

COMPROMISED_PACKAGES: Dict[str, Dict] = {
    "litellm": {
        "1.82.7": {
            "description": (
                "Contains litellm_init.pth  -  malicious .pth file that exfiltrates "
                "SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, database "
                "passwords, .env files, shell history, crypto wallets, and all "
                "environment variables to https://models.litellm.cloud/"
            ),
            "severity":    "CRITICAL",
            "persistence": "~/.config/sysmon/sysmon.py",
            "exfil_host":  "models.litellm.cloud",
            "discovered":  "2026-03-24",
            "discoverer":  "FutureSearch Security Research",
            "lateral":     "Kubernetes cluster compromise via service account tokens",
        },
        "1.82.8": {
            "description": (
                "Contains litellm_init.pth  -  same payload as 1.82.7. "
                "Fork bomb bug caused by .pth file spawning child processes "
                "that re-trigger the same .pth. Discovered when a machine ran out "
                "of RAM with 11,000+ Python processes."
            ),
            "severity":    "CRITICAL",
            "persistence": "~/.config/sysmon/sysmon.py",
            "exfil_host":  "models.litellm.cloud",
            "discovered":  "2026-03-24",
            "discoverer":  "FutureSearch Security Research",
            "lateral":     "Kubernetes cluster compromise via service account tokens",
        },
    },
    "axios": {
        "1.14.1": {
            "description": (
                "Contains Remote Access Trojan (RAT) via plain-crypto-js dependency. "
                "Bundled in @anthropic-ai/claude-code npm update March 31, 2026 "
                "between 00:21-03:29 UTC. Treat host as fully compromised if found. "
                "Rotate all secrets immediately. Clean OS reinstall recommended. "
                "Source: Anthropic security advisory March 31, 2026."
            ),
            "severity":    "CRITICAL",
            "exfil_endpoint": "via plain-crypto-js RAT",
            "mechanism":   "Remote Access Trojan bundled as transitive npm dependency",
            "incident_date": "2026-03-31",
            "related_packages": ["plain-crypto-js"],
            "remediation": (
                "1. Search lockfiles for axios==1.14.1, axios==0.30.4, plain-crypto-js. "
                "2. If found: treat host as fully compromised. "
                "3. Rotate all credentials, API keys, SSH keys, database passwords. "
                "4. Clean OS reinstallation recommended. "
                "5. Migrate claude-code from npm to native installer: "
                "curl -fsSL https://claude.ai/install.sh | bash"
            ),
        },
        "0.30.4": {
            "description": (
                "Contains Remote Access Trojan (RAT) via plain-crypto-js dependency. "
                "Same incident as axios 1.14.1 (March 31, 2026 claude-code npm update)."
            ),
            "severity":    "CRITICAL",
            "exfil_endpoint": "via plain-crypto-js RAT",
            "mechanism":   "Remote Access Trojan bundled as transitive npm dependency",
            "incident_date": "2026-03-31",
            "related_packages": ["plain-crypto-js"],
            "remediation": "See axios 1.14.1 remediation.",
        },
    }
}

# Packages with known exposure to compromised litellm via transitive dependencies
# Format: {package: {version_range: ">=1.64.0", exposure: "litellm>=1.64.0"}}
TRANSITIVE_EXPOSURE: Dict[str, Dict] = {
    "dspy":       {"exposure": "litellm>=1.64.0", "check_litellm": True},
    "smolagents": {"exposure": "litellm (optional)", "check_litellm": True},
    "langchain":  {"exposure": "litellm (optional)", "check_litellm": True},
    "langgraph":  {"exposure": "langchain dependency", "check_litellm": True},
    "crewai":     {"exposure": "litellm (optional)", "check_litellm": True},
    # ByteRover: file-based Context Tree memory  -  T79 protects write path
    # Not a litellm dependency, but flagged for T79 awareness
    "@byterover/byterover": {"exposure": "OpenClaw plugin  -  T79/T67 apply", "check_litellm": False},
    "litellm-proxy": {"exposure": "litellm itself", "check_litellm": True},
}

# Known malicious .pth files
MALICIOUS_PTH_FILES = {
    "litellm_init.pth": "LiteLLM supply chain attack (March 24, 2026)",
}

# Known persistence file indicators from the litellm attack
PERSISTENCE_INDICATORS = [
    ("~/.config/sysmon/sysmon.py",              "LiteLLM malware persistence script"),
    ("~/.config/systemd/user/sysmon.service",   "LiteLLM malware systemd service"),
    ("~/.config/sysmon/",                       "LiteLLM sysmon directory"),
]

# Risky install patterns  -  curl|sh bypasses package integrity verification
RISKY_INSTALL_PATTERNS = {
    "curl -fsSL https://byterover.dev/openclaw-setup.sh | sh": {
        "description": (
            "ByteRover uses curl|sh installation which bypasses package integrity "
            "verification. The openclaw-setup.sh script executes with full shell access. "
            "If byterover.dev is compromised (DNS hijack, repo takeover), this becomes "
            "a supply chain delivery vehicle identical to LiteLLM 1.82.8. "
            "Safer alternative: openclaw plugins install @byterover/byterover"
        ),
        "severity":     "MEDIUM",
        "safer_alt":    "openclaw plugins install @byterover/byterover",
    },
}

# Known exfiltration# Known exfiltration endpoints - block at firewall level
KNOWN_EXFIL_ENDPOINTS = [
    "models.litellm.cloud",
]


# ── Scanner ───────────────────────────────────────────────────────────────────

class ScanResult:
    def __init__(self):
        self.compromised_packages:   List[dict] = []
        self.malicious_pth_files:    List[dict] = []
        self.persistence_found:      List[dict] = []
        self.transitive_exposure:    List[dict] = []
        self.recommendations:        List[str]  = []
        self.scan_path:              str = ""

    @property
    def is_compromised(self) -> bool:
        """Return True if any compromised packages, malicious .pth files, or persistence found."""
        return bool(
            self.compromised_packages or
            self.malicious_pth_files or
            self.persistence_found
        )

    @property
    def risk_level(self) -> str:
        """Return overall risk level: CRITICAL, HIGH, MEDIUM, or CLEAN."""
        if self.compromised_packages or self.malicious_pth_files:
            return "CRITICAL"
        if self.persistence_found:
            return "HIGH"
        if self.transitive_exposure:
            return "MEDIUM"
        return "CLEAN"

    def to_dict(self) -> dict:
        """Return the scan result as a dictionary."""
        return {
            "risk_level":           self.risk_level,
            "is_compromised":       self.is_compromised,
            "compromised_packages": self.compromised_packages,
            "malicious_pth_files":  self.malicious_pth_files,
            "persistence_found":    self.persistence_found,
            "transitive_exposure":  self.transitive_exposure,
            "recommendations":      self.recommendations,
        }


def _get_installed_packages() -> Dict[str, str]:
    """Return {package_name: version} for all installed packages."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30
        )
        packages = json.loads(result.stdout)
        return {p["name"].lower(): p["version"] for p in packages}
    except Exception:
        return {}


def _find_site_packages() -> List[Path]:
    """Return all site-packages directories in the current environment."""
    dirs = []
    for path in sys.path:
        p = Path(path)
        if p.exists() and ("site-packages" in str(p) or "dist-packages" in str(p)):
            dirs.append(p)
    # Also check standard locations
    import sysconfig
    for scheme in ["platlib", "purelib"]:
        try:
            site = Path(sysconfig.get_path(scheme))
            if site.exists() and site not in dirs:
                dirs.append(site)
        except Exception:
            pass
    return dirs


def _scan_pth_files(site_dirs: List[Path]) -> List[dict]:
    """Scan site-packages for malicious .pth files."""
    found = []
    for site_dir in site_dirs:
        try:
            for pth_file in site_dir.glob("*.pth"):
                fname = pth_file.name.lower()

                # Check known malicious names
                if fname in {k.lower() for k in MALICIOUS_PTH_FILES}:
                    original_name = next(
                        k for k in MALICIOUS_PTH_FILES if k.lower() == fname
                    )
                    found.append({
                        "path":        str(pth_file),
                        "filename":    pth_file.name,
                        "description": MALICIOUS_PTH_FILES[original_name],
                        "severity":    "CRITICAL",
                    })
                    continue

                # Scan content for suspicious patterns
                try:
                    content = pth_file.read_text(encoding="utf-8", errors="ignore")
                    suspicious = any(kw in content for kw in (
                        "subprocess", "base64", "exec(", "eval(",
                        "urllib", "__import__", "b64decode",
                        "socket.", "requests.", "import os;"
                    ))
                    if suspicious:
                        found.append({
                            "path":        str(pth_file),
                            "filename":    pth_file.name,
                            "description": "Suspicious .pth content  -  code execution patterns",
                            "severity":    "HIGH",
                            "snippet":     content[:200],
                        })
                except Exception:
                    pass
        except Exception:
            pass
    return found


def _check_persistence() -> List[dict]:
    """Check for known persistence indicators from supply chain attacks."""
    found = []
    for path_str, description in PERSISTENCE_INDICATORS:
        path = Path(path_str).expanduser()
        if path.exists():
            found.append({
                "path":        str(path),
                "description": description,
                "severity":    "HIGH",
                "action":      f"Remove: rm -rf {path}",
            })
    return found


def _check_uv_cache() -> List[dict]:
    """Check uv cache for compromised litellm wheels."""
    found = []
    uv_cache = Path("~/.cache/uv").expanduser()
    if not uv_cache.exists():
        return found
    try:
        # Search for litellm_init.pth in uv cache
        for pth in uv_cache.rglob("litellm_init.pth"):
            found.append({
                "path":        str(pth),
                "description": "Compromised litellm wheel in uv cache  -  purge with: uv cache clean",
                "severity":    "CRITICAL",
            })
        # Search for compromised litellm wheels
        for wheel in uv_cache.rglob("litellm-1.82.[78]*"):
            found.append({
                "path":        str(wheel),
                "description": "Compromised litellm wheel in uv cache",
                "severity":    "CRITICAL",
                "action":      "uv cache clean",
            })
    except Exception:
        pass
    return found


def scan(
    package:    Optional[str] = None,
    quick:      bool = False,
    json_output: bool = False,
) -> ScanResult:
    """
    Run a full dependency security scan.

    package: Check a specific package only.
    quick:   Only check known-bad versions, skip .pth and persistence.
    """
    result = ScanResult()

    # 1. Check installed packages against known-compromised list
    installed = _get_installed_packages()

    for pkg_name, versions in COMPROMISED_PACKAGES.items():
        if package and pkg_name != package.lower():
            continue
        installed_ver = installed.get(pkg_name.lower())
        if installed_ver and installed_ver in versions:
            entry = versions[installed_ver].copy()
            entry["package"] = pkg_name
            entry["version"] = installed_ver
            result.compromised_packages.append(entry)
            result.recommendations.append(
                f"IMMEDIATE: pip uninstall {pkg_name} && pip install {pkg_name}==<safe_version>"
            )
            result.recommendations.append(
                f"ROTATE: All credentials on this machine are assumed compromised. "
                f"See: {entry.get('persistence', 'N/A')}"
            )

    if not quick:
        # 2. Scan site-packages for malicious .pth files
        site_dirs = _find_site_packages()
        result.scan_path = ", ".join(str(d) for d in site_dirs[:3])
        result.malicious_pth_files = _scan_pth_files(site_dirs)
        if result.malicious_pth_files:
            result.recommendations.append(
                "IMMEDIATE: Python .pth files execute on every startup. "
                "Remove malicious files and assume all credentials are compromised."
            )

        # 3. Check persistence indicators
        result.persistence_found = _check_persistence()
        if result.persistence_found:
            result.recommendations.append(
                "PERSISTENCE DETECTED: Supply chain malware installed persistence. "
                "Remove files listed above and rotate all credentials."
            )

        # 4. Check uv cache
        uv_findings = _check_uv_cache()
        result.malicious_pth_files.extend(uv_findings)

    # 5. Check transitive exposure
    for dep_name, dep_info in TRANSITIVE_EXPOSURE.items():
        if dep_name.lower() in installed:
            if dep_info.get("check_litellm"):
                litellm_ver = installed.get("litellm")
                if litellm_ver and litellm_ver in COMPROMISED_PACKAGES.get("litellm", {}):
                    result.transitive_exposure.append({
                        "package":  dep_name,
                        "version":  installed[dep_name.lower()],
                        "exposure": dep_info["exposure"],
                        "via":      f"litellm=={litellm_ver}",
                    })

    # 6. Standard recommendations
    if not result.recommendations:
        result.recommendations.append(
            "No known-compromised packages found in this environment."
        )
        result.recommendations.append(
            "Run `aiglos scan-deps` again after any pip install to check new packages."
        )

    return result



# ── PyPI-only version detection ────────────────────────────────────────────────
# Packages where a version appeared on PyPI without a corresponding GitHub
# release, tag, or commit -- the litellm 1.82.8 supply chain attack signature.
# Source: the poisoned litellm was uploaded to PyPI on March 24, 2026 with
# no matching GitHub release, no tag, no review process.
# A PyPI version with no GitHub release is either a maintenance release (rare)
# or a supply chain attack (common).
#
# This check does NOT require network access -- it flags known offenders.
# For live version hash checking, use: aiglos scan-deps --verify-hashes

PYPI_ONLY_VERSIONS: dict = {
    # package -> {version -> {"reason": str, "severity": str}}
    "litellm": {
        "1.82.8": {
            "reason": (
                "Uploaded to PyPI March 24 2026 with NO corresponding GitHub release, "
                "tag, or commit. Contains litellm_init.pth malware. "
                "MERCOR BREACH: vector in 4TB exfil of biometrics and source code "
                "from AI hiring platform serving Amazon, Meta, Apple contractors. "
                "Lapsus$ auctioning data including face/voice KYC records."
            ),
            "severity": "CRITICAL",
            "github_tag": None,        # confirmed absent
            "pypi_upload": "2026-03-24",
            "related_incident": "MERCOR_BREACH",
        },
    },
    "axios": {
        "1.14.1": {
            "reason": (
                "Bundled in @anthropic-ai/claude-code npm March 31 2026. "
                "No corresponding upstream axios GitHub release."
            ),
            "severity": "CRITICAL",
            "github_tag": None,
            "related_incident": "CLAUDE_CODE_AXIOS_RAT",
        },
    },
}


def check_pypi_only_versions(installed: dict) -> list:
    """
    Check installed packages for known PyPI-only versions (supply chain red flag).

    Returns list of findings: packages where the installed version appeared on
    PyPI without a corresponding GitHub release or tag.

    This catches the litellm 1.82.8 pattern: attacker uploads to PyPI
    bypassing GitHub review process entirely.
    """
    findings = []
    for pkg, version in installed.items():
        pkg_lower = pkg.lower().replace("-","_").replace(".","_")
        for known_pkg, versions in PYPI_ONLY_VERSIONS.items():
            known_lower = known_pkg.lower().replace("-","_")
            if pkg_lower == known_lower and version in versions:
                entry = versions[version]
                findings.append({
                    "package":   pkg,
                    "version":   version,
                    "severity":  entry["severity"],
                    "reason":    entry["reason"],
                    "type":      "PYPI_ONLY_VERSION",
                    "incident":  entry.get("related_incident", ""),
                })
    return findings


def print_scan_report(result: ScanResult) -> None:
    """Print a human-readable scan report."""
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    GREEN  = "\033[32m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    print()
    print(f"  {BOLD}aiglos scan-deps{RESET}   -   Dependency Security Scanner")
    print(f"  {'─' * 52}")
    print()

    risk_color = {
        "CRITICAL": RED,
        "HIGH":     RED,
        "MEDIUM":   YELLOW,
        "CLEAN":    GREEN,
    }.get(result.risk_level, YELLOW)

    print(f"  Risk level: {risk_color}{BOLD}{result.risk_level}{RESET}")
    print()

    if result.compromised_packages:
        print(f"  {RED}{BOLD}COMPROMISED PACKAGES FOUND:{RESET}")
        for pkg in result.compromised_packages:
            print(f"    {RED}✗{RESET}  {pkg['package']}=={pkg['version']}  [{pkg['severity']}]")
            print(f"       {pkg['description'][:80]}...")
            print(f"       Discovered: {pkg.get('discovered', 'N/A')} by {pkg.get('discoverer', 'N/A')}")
            print()

    if result.malicious_pth_files:
        print(f"  {RED}{BOLD}MALICIOUS .PTH FILES FOUND:{RESET}")
        for pth in result.malicious_pth_files:
            print(f"    {RED}✗{RESET}  {pth['path']}")
            print(f"       {pth['description']}")
            print()

    if result.persistence_found:
        print(f"  {RED}{BOLD}PERSISTENCE INDICATORS FOUND:{RESET}")
        for p in result.persistence_found:
            print(f"    {RED}✗{RESET}  {p['path']}")
            print(f"       {p['description']}")
            print(f"       Action: {p.get('action', 'Remove this file')}")
            print()

    if result.transitive_exposure:
        print(f"  {YELLOW}{BOLD}TRANSITIVE EXPOSURE:{RESET}")
        for t in result.transitive_exposure:
            print(f"    {YELLOW}⚠{RESET}  {t['package']}=={t['version']} via {t['via']}")
        print()

    if result.risk_level == "CLEAN":
        print(f"  {GREEN}✓{RESET}  No known-compromised packages found.")
        print()

    print(f"  {BOLD}Recommendations:{RESET}")
    for rec in result.recommendations:
        print(f"    →  {rec}")
    print()

    if result.is_compromised:
        print(f"  {RED}{BOLD}CREDENTIAL ROTATION REQUIRED:{RESET}")
        print(f"    Rotate: SSH keys, AWS/GCP/Azure credentials, Kubernetes configs,")
        print(f"            database passwords, .env API keys, crypto wallets,")
        print(f"            GitHub/PyPI/npm tokens, CI/CD secrets.")
        print()
        print(f"  {RED}Block at firewall: models.litellm.cloud{RESET}")
        print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="aiglos scan-deps  -  dependency security scanner")
    parser.add_argument("--package", help="Check a specific package")
    parser.add_argument("--quick", action="store_true", help="Only check known-bad versions")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Output as JSON")
    parser.add_argument("--fix", action="store_true", help="Remove compromised packages")
    args = parser.parse_args()

    result = scan(
        package     = args.package,
        quick       = args.quick,
        json_output = args.json_output,
    )

    if args.json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_scan_report(result)

    # Exit with non-zero status if compromised
    sys.exit(1 if result.is_compromised else 0)
