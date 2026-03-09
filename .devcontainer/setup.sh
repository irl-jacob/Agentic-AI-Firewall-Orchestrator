#!/bin/bash
set -e

echo "=== AFO Dev Container Setup ==="

# Install Python dependencies
echo "[1/3] Installing Python dependencies..."
pip install -e ".[dev]" --quiet

# Check Ollama connectivity (running on host)
echo "[2/3] Checking Ollama on host..."
if curl -sf http://host.docker.internal:11434/api/tags > /dev/null 2>&1; then
    echo "  Ollama is reachable."
else
    echo "  WARNING: Ollama not reachable."
    echo "  Make sure Ollama is running on your machine (ollama serve)."
fi

# Ingest docs into vector store
echo "[3/3] Ingesting docs into vector store..."
python -m db.vector_store || echo "  Skipped (Ollama needed for embeddings)"

echo ""
echo "=== Dev container ready! ==="
echo "  MCP Server:   fastmcp run afo_mcp.server:mcp"
echo "  TUI:          afo-ui"
echo "  Daemon:       sudo afo-daemon"
echo "  Tests:        pytest tests/ -v"
