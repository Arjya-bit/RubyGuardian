# =============================================================================
# RubyGuardian - Dockerfile for Simulated C2 Server
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This Dockerfile builds a container for the simulated C2 server used in
#   CI/CD poisoning research. The container runs in an isolated environment
#   and performs NO actual malicious operations.
#
#   This container should ONLY be run on isolated research networks or
#   within the RubyGuardian sandbox environment.
#
# MITRE ATT&CK References:
#   - T1610 : Deploy Container (containerized C2 infrastructure)
#   - T1071 : Application Layer Protocol
#
# Build:  docker build -t rubyguardian-c2-sim .
# Run:    docker run --rm -p 4567:4567 --name c2-sim rubyguardian-c2-sim
# =============================================================================

# Use official Ruby slim image to minimize attack surface
FROM ruby:3.3-slim AS base

# Metadata labels for the image
LABEL maintainer="RubyGuardian Security Research Framework"
LABEL description="Simulated C2 server for CI/CD poisoning research (EDUCATIONAL ONLY)"
LABEL org.opencontainers.image.title="RubyGuardian C2 Simulation"
LABEL org.opencontainers.image.description="Educational C2 simulation - NOT for malicious use"

# Install system dependencies required for SQLite3 native extension
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libsqlite3-dev \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for running the simulation
# Even in research, we follow security best practices
RUN groupadd --gid 1001 guardian && \
    useradd --uid 1001 --gid guardian --shell /bin/bash --create-home guardian

# Set working directory
WORKDIR /app

# Copy Gemfile and install dependencies first (layer caching optimization)
COPY Gemfile Gemfile.lock* ./
RUN bundle config set --local without 'development' && \
    bundle install --jobs 4 --retry 3

# Copy application code
COPY . .

# Initialize the SQLite database with schema
RUN mkdir -p db logs && \
    sqlite3 db/c2_simulation.db < db/schema.sql

# Create log directory and set permissions
RUN chown -R guardian:guardian /app

# Switch to non-root user
USER guardian

# Expose the simulation server port
# Default: 4567 (Sinatra default)
EXPOSE 4567

# Environment variables for the simulation
ENV RACK_ENV=production \
    BIND_HOST=0.0.0.0 \
    BIND_PORT=4567 \
    RUBY_GUARDIAN_MODE=simulation \
    RUBY_GUARDIAN_DISCLAIMER="EDUCATIONAL_USE_ONLY"

# Health check to verify the simulation server is responding
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ruby -e "require 'net/http'; Net::HTTP.get(URI('http://localhost:4567/api/v1/health'))" || exit 1

# Start the simulated C2 server using Puma
# --bind ensures we listen on all interfaces within the container
# --workers 2 provides concurrency for handling multiple simulated agents
CMD ["bundle", "exec", "puma", \
     "--bind", "tcp://0.0.0.0:4567", \
     "--workers", "2", \
     "--threads", "1:4", \
     "config.ru"]
