#!/usr/bin/env bash
# scripts/build_cli.sh
# Generates a self-contained aiglos CLI binary via MCPorter
#
# Prerequisites:
#   - Node 18+ / Bun installed
#   - Python MCP server running (tested via: python aiglos_mcp_server.py)
#
# Usage:
#   ./scripts/build_cli.sh               # default: compile to dist/aiglos
#   ./scripts/build_cli.sh --no-compile  # JS bundle only, no binary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$ROOT_DIR/dist"
SERVER_CMD="python $ROOT_DIR/aiglos_mcp_server.py"
CLI_NAME="aiglos"
COMPILE=true

# Parse flags
for arg in "$@"; do
  case $arg in
    --no-compile) COMPILE=false ;;
    --help)
      echo "Usage: $0 [--no-compile]"
      echo "  --no-compile   Emit JS bundle only (no Bun binary)"
      exit 0
      ;;
  esac
done

echo "==> Aiglos CLI build"
echo "    Server:  $SERVER_CMD"
echo "    Output:  $DIST_DIR/$CLI_NAME"
echo "    Compile: $COMPILE"
echo ""

mkdir -p "$DIST_DIR"

# Step 1: verify the MCP server starts and lists tools
echo "--> Verifying MCP server schema..."
python "$ROOT_DIR/aiglos_mcp_server.py" --help > /dev/null 2>&1 || {
  echo "ERROR: aiglos_mcp_server.py failed to start"
  exit 1
}
echo "    OK"

# Step 2: check MCPorter is available
if ! command -v mcporter &> /dev/null && ! npx mcporter --version &> /dev/null 2>&1; then
  echo "ERROR: mcporter not found. Install with: npm install -g mcporter"
  exit 1
fi

MCPORTER="npx mcporter"
if command -v mcporter &> /dev/null; then
  MCPORTER="mcporter"
fi

# Step 3: generate the CLI
echo "--> Generating CLI from MCP server schema..."
if $COMPILE; then
  $MCPORTER generate-cli \
    --stdio "$SERVER_CMD" \
    --name "$CLI_NAME" \
    --description "Aiglos AI agent runtime security — threat detection, compliance gates, GOVBENCH evaluation" \
    --bundle "$DIST_DIR/${CLI_NAME}.js" \
    --compile \
    --output "$DIST_DIR/${CLI_NAME}.ts" \
    --runtime bun
else
  $MCPORTER generate-cli \
    --stdio "$SERVER_CMD" \
    --name "$CLI_NAME" \
    --description "Aiglos AI agent runtime security — threat detection, compliance gates, GOVBENCH evaluation" \
    --bundle "$DIST_DIR/${CLI_NAME}.js" \
    --output "$DIST_DIR/${CLI_NAME}.ts" \
    --runtime node
fi

echo ""
echo "==> Build complete"

if $COMPILE; then
  BINARY="$DIST_DIR/$CLI_NAME"
  if [[ "$(uname)" == "Darwin" ]]; then
    BINARY="$DIST_DIR/${CLI_NAME}-macos"
  elif [[ "$(uname)" == "Linux" ]]; then
    BINARY="$DIST_DIR/${CLI_NAME}-linux"
  fi

  if [ -f "$BINARY" ]; then
    chmod +x "$BINARY"
    SIZE=$(du -sh "$BINARY" | cut -f1)
    echo "    Binary:  $BINARY ($SIZE)"
    echo ""
    echo "Quick test:"
    echo "    $BINARY rules"
    echo "    $BINARY govbench --suite ndaa-1513 --output-format json"
  fi
else
  echo "    Bundle:  $DIST_DIR/${CLI_NAME}.js"
  echo "    Usage:   node $DIST_DIR/${CLI_NAME}.js rules"
fi

echo ""
echo "To regenerate from this artifact:"
echo "    $MCPORTER generate-cli --from $DIST_DIR/${CLI_NAME}.js"
