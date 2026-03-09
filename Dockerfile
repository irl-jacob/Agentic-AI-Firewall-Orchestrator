FROM python:3.11-slim

# Install system dependencies for nftables
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for development
RUN useradd -m -s /bin/bash afo && \
    echo "afo ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/afo && \
    chmod 0440 /etc/sudoers.d/afo

# Set working directory
WORKDIR /app

# Install uv for fast dependency management
RUN pip install uv

# Copy project files
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

# Install dependencies
RUN uv pip install --system -e ".[dev]"

# Create backup directory
RUN mkdir -p /var/lib/afo/backups && chown afo:afo /var/lib/afo/backups

# Default environment
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8765
ENV REQUIRE_APPROVAL=1
ENV ROLLBACK_TIMEOUT=30
ENV OLLAMA_HOST=http://host.docker.internal:11434
ENV OLLAMA_MODEL=qwen2.5-coder:3b
ENV EMBED_MODEL=nomic-embed-text

# Expose MCP ports
EXPOSE 8765

# Run as non-root user (nftables operations will fail without NET_ADMIN capability)
USER afo

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8765)); s.close()"

# Default command
CMD ["python", "-m", "afo_mcp.server"]
