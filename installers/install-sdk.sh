#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DOTNET=false
INSTALL_NODE=false
INSTALL_JAVA=false
INSTALL_PYTHON=false
INSTALL_GO=false
INSTALL_MCP=false

for arg in "$@"; do
  case "$arg" in
    --dotnet) INSTALL_DOTNET=true ;;
    --node) INSTALL_NODE=true ;;
    --java) INSTALL_JAVA=true ;;
    --python) INSTALL_PYTHON=true ;;
    --go) INSTALL_GO=true ;;
    --mcp) INSTALL_MCP=true ;;
    --all)
      INSTALL_DOTNET=true
      INSTALL_NODE=true
      INSTALL_JAVA=true
      INSTALL_PYTHON=true
      INSTALL_GO=true
      INSTALL_MCP=true
      ;;
  esac
done

echo "Installing Aegir SDK Beta-1 components..."

if [ "$INSTALL_DOTNET" = true ]; then
  echo "DotNet:"
  echo "  dotnet add package Foxlin.Aegir.Security --version 0.1.1-beta-1"
fi

if [ "$INSTALL_NODE" = true ]; then
  echo "Node:"
  (cd "$REPO_ROOT/packages/npm" && npm install && npm run build)
fi

if [ "$INSTALL_JAVA" = true ]; then
  echo "Java:"
  (cd "$REPO_ROOT/packages/java" && mvn -q -DskipTests package)
fi

if [ "$INSTALL_PYTHON" = true ]; then
  echo "Python:"
  (cd "$REPO_ROOT/packages/python" && python -m pip install -e .)
fi

if [ "$INSTALL_GO" = true ]; then
  echo "Go:"
  (cd "$REPO_ROOT/packages/go" && go test ./...)
fi

if [ "$INSTALL_MCP" = true ]; then
  echo "MCP:"
  (cd "$REPO_ROOT/mcp" && npm install)
fi

echo "Aegir SDK installation wrapper complete."
