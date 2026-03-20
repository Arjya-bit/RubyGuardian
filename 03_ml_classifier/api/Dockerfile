# RubyGuardian ML Classifier API - Production Dockerfile
#
# Multi-stage build for a minimal, secure container image.
# Stage 1: Install Python dependencies
# Stage 2: Copy only the runtime artifacts into a slim base

# ---------------------------------------------------------------------------
# Stage 1 - Builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install system dependencies needed for building native wheels
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        git && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2 - Runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL maintainer="RubyGuardian Security Research Team"
LABEL description="ML-based Ruby malware classifier API"
LABEL version="1.4.0"

# Create a non-root user for the application
RUN groupadd --gid 1001 rubyguardian && \
    useradd --uid 1001 --gid rubyguardian --shell /bin/false --create-home rubyguardian

# Install minimal runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        tini && \
    rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Application configuration
ENV RUBYGUARDIAN_LOG_LEVEL="INFO"
ENV RUBYGUARDIAN_LOG_DIR="/var/log/rubyguardian"
ENV RUBYGUARDIAN_AUTH_ENABLED="true"
ENV APP_VERSION="1.4.0"
ENV MODEL_DIR="/models"

# Create required directories
RUN mkdir -p /var/log/rubyguardian /models && \
    chown -R rubyguardian:rubyguardian /var/log/rubyguardian /models

WORKDIR /app

# Copy application code
COPY --chown=rubyguardian:rubyguardian . /app/03_ml_classifier

# Health check using the liveness endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/live || exit 1

# Expose the API port
EXPOSE 8000

# Switch to non-root user
USER rubyguardian

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["tini", "--"]

# Start the application with uvicorn
CMD ["uvicorn", "03_ml_classifier.api:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--log-level", "info", \
     "--access-log", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
