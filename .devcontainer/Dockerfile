FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv for fast dependency management
RUN pip install uv

# Copy project files for initial install
COPY pyproject.toml README.md ./
COPY afo_mcp/ afo_mcp/
COPY agents/ agents/
COPY backend/ backend/
COPY services/ services/
COPY afo_daemon/ afo_daemon/
COPY config/ config/
COPY systemd/ systemd/
COPY db/ db/
COPY ui/ ui/
COPY docs/ docs/
COPY tests/ tests/

# Install all dependencies
RUN uv pip install --system -e ".[dev]"

# Create backup directory
RUN mkdir -p /var/lib/afo/backups

# Default environment
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8765
ENV REQUIRE_APPROVAL=1
ENV ROLLBACK_TIMEOUT=30
ENV OLLAMA_HOST=http://host.docker.internal:11434
ENV OLLAMA_MODEL=qwen2.5-coder:3b
ENV EMBED_MODEL=nomic-embed-text

EXPOSE 8765 8501
