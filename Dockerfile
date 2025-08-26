# Multi-stage build for Code Hygiene Agent
FROM python:3.10-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    pkg-config \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies in stages for better error handling
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir wheel setuptools \
    && pip install --no-cache-dir -r requirements.txt --verbose \
    && pip list

# Copy source code
COPY . .

# Install the package
RUN pip install -e .

# Production stage
FROM python:3.10-slim as production

# Install system dependencies and external tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir \
        pip-audit \
        safety \
        vulture \
        bandit

# Create non-root user
RUN groupadd -r hygiene && useradd -r -g hygiene hygiene

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages/ /usr/local/lib/python3.10/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY --from=builder /app/ /app/

# Create necessary directories
RUN mkdir -p /app/reports /app/logs \
    && chown -R hygiene:hygiene /app

# Switch to non-root user
USER hygiene

# Set environment variables
ENV PYTHONPATH="/app/src:$PYTHONPATH"
ENV LOG_LEVEL=INFO
ENV PYTHONUNBUFFERED=1

# Expose MCP server port (if applicable)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD code-hygiene-agent check || exit 1

# Default command
ENTRYPOINT ["code-hygiene-agent"]
CMD ["serve"]

# Development stage
FROM production as development

# Switch back to root for development tools
USER root

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-cov \
    pytest-mock \
    black \
    ruff \
    mypy \
    pre-commit

# Install additional development tools
RUN apt-get update && apt-get install -y \
    vim \
    less \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Switch back to non-root user
USER hygiene

# Override CMD for development
CMD ["bash"]