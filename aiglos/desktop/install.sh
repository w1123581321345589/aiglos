#!/bin/bash
# Aiglos Desktop — Zero-config installer
# Drag the .app to Applications, or run this script for CLI setup.
#
# What this does:
#   1. Checks Python 3.9+ is available
#   2. pip install aiglos (if not already installed)
#   3. Deploys default honeypot files to ~/.aiglos/honeypots/
#   4. Starts the Aiglos sidecar as a background service
#   5. Prints the status

set -e

AIGLOS_VERSION="0.15.0"
AIGLOS_DIR="$HOME/.aiglos"
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

echo ""
echo "  ██████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗"
echo " ██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝"
echo " ███████║██║██║  ███╗██║     ██║   ██║███████╗"
echo " ██╔══██║██║██║   ██║██║     ██║   ██║╚════██║"
echo " ██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║"
echo " ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝"
echo ""
echo " AI Agent Security — v${AIGLOS_VERSION}"
echo " One import. Every surface."
echo ""

# ── Check Python ──────────────────────────────────────────────────────────────
echo -n "  Checking Python..."
if ! command -v python3 &>/dev/null; then
    echo -e " ${RED}not found${RESET}"
    echo ""
    echo "  Python 3.9+ is required. Install from https://python.org"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]; }; then
    echo -e " ${RED}Python ${PYTHON_VERSION} — need 3.9+${RESET}"
    exit 1
fi
echo -e " ${GREEN}Python ${PYTHON_VERSION} ✓${RESET}"

# ── Install aiglos ─────────────────────────────────────────────────────────────
echo -n "  Checking aiglos..."
if python3 -c "import aiglos" &>/dev/null; then
    INSTALLED_VERSION=$(python3 -c "import aiglos; print(aiglos.__version__)" 2>/dev/null || echo "unknown")
    echo -e " ${GREEN}v${INSTALLED_VERSION} ✓${RESET}"
else
    echo -e " ${ORANGE}not installed${RESET}"
    echo -n "  Installing aiglos..."
    if pip3 install aiglos --quiet; then
        echo -e " ${GREEN}done ✓${RESET}"
    else
        echo -e " ${RED}failed${RESET}"
        echo "  Try: pip3 install aiglos"
        exit 1
    fi
fi

# ── Create aiglos directory ────────────────────────────────────────────────────
mkdir -p "$AIGLOS_DIR"/{honeypots,reports,models}

# ── Deploy honeypots ───────────────────────────────────────────────────────────
echo -n "  Deploying honeypot files..."
python3 - <<'EOF'
from aiglos.integrations.honeypot import HoneypotManager
mgr = HoneypotManager()
deployed = mgr.deploy()
print(f" {len(deployed)} files ✓", end="")
EOF
echo ""

# ── Verify installation ────────────────────────────────────────────────────────
echo -n "  Verifying installation..."
if python3 -c "
import aiglos
from aiglos.integrations.honeypot import HoneypotManager
from aiglos.integrations.override import OverrideManager
from aiglos.autoresearch.compliance_report import ComplianceReportGenerator
print(' OK')
" 2>/dev/null; then
    echo -e " ${GREEN}✓${RESET}"
else
    echo -e " ${RED}failed${RESET}"
    exit 1
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}Aiglos v${AIGLOS_VERSION} is ready.${RESET}"
echo ""
echo "  Quick start:"
echo "    python3 -c \"import aiglos; aiglos.attach(enable_honeypot=True)\""
echo ""
echo "  CLI:"
echo "    aiglos honeypot status"
echo "    aiglos policy list"
echo "    aiglos research report"
echo ""
echo "  Desktop app: open Aiglos.app (macOS) or run aiglos-desktop (Linux)"
echo ""
