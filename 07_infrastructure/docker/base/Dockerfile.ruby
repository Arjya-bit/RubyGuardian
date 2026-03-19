# =============================================================================
# RubyGuardian - Base Ruby Image
# =============================================================================
# Provides the runtime for the attack framework, detection engine, memory
# forensics toolkit, and honeypot components.
#
# Build:
#   docker build -f Dockerfile.ruby -t rubyguardian/ruby-base:latest .
# =============================================================================

FROM ruby:3.2-slim-bookworm AS base

LABEL maintainer="RubyGuardian Project <security@rubyguardian.dev>"
LABEL org.opencontainers.image.title="RubyGuardian Ruby Base"
LABEL org.opencontainers.image.description="Base Ruby image for RubyGuardian security research platform"
LABEL org.opencontainers.image.version="1.0.0"

# ---- System dependencies ----------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    libreadline-dev \
    libyaml-dev \
    libsqlite3-dev \
    libcurl4-openssl-dev \
    git \
    curl \
    procps \
    strace \
    ltrace \
    iproute2 \
    net-tools \
    tcpdump \
    lsof \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# ---- Non-root user ----------------------------------------------------------
RUN groupadd -r guardian && useradd -r -g guardian -m -s /bin/bash guardian

# ---- Application directory ---------------------------------------------------
WORKDIR /opt/rubyguardian

# ---- Gem dependencies --------------------------------------------------------
COPY Gemfile Gemfile.lock* ./
RUN bundle config set --local deployment 'true' \
    && bundle config set --local without 'development' \
    && bundle install --jobs=$(nproc) --retry=3 \
    && bundle clean --force

# ---- Copy source -------------------------------------------------------------
COPY . .
RUN chown -R guardian:guardian /opt/rubyguardian

# =============================================================================
# Target: detection-agent
# Runs the real-time detection engine with syscall and network monitors.
# =============================================================================
FROM base AS detection-agent

USER guardian

ENV RUBY_GUARDIAN_COMPONENT=detection_engine \
    RUBY_GUARDIAN_LOG_LEVEL=info \
    RUBY_GUARDIAN_LOG_FORMAT=json \
    RUBY_GUARDIAN_ELK_HOST=elk-stack \
    RUBY_GUARDIAN_ELK_PORT=5044

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ruby -e "require 'net/http'; Net::HTTP.get(URI('http://localhost:8080/health'))" || exit 1

EXPOSE 8080

ENTRYPOINT ["bundle", "exec"]
CMD ["ruby", "02_detection_engine/lib/agent/detection_agent.rb", "--daemonize"]

# =============================================================================
# Target: honeypot
# Runs the deceptive gem repository and telemetry collector.
# =============================================================================
FROM base AS honeypot

USER guardian

ENV RUBY_GUARDIAN_COMPONENT=honeypot \
    RUBY_GUARDIAN_LOG_LEVEL=info \
    RUBY_GUARDIAN_LOG_FORMAT=json \
    RUBY_GUARDIAN_HONEYPOT_PORT=9292

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:9292/health || exit 1

EXPOSE 9292

ENTRYPOINT ["bundle", "exec"]
CMD ["ruby", "05_honeypot/lib/server/honeypot_server.rb"]

# =============================================================================
# Target: forensics
# Runs memory forensics analysis as a batch job or on-demand service.
# =============================================================================
FROM base AS forensics

# Forensics needs additional capabilities for memory analysis
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    volatility3 \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

USER guardian

ENV RUBY_GUARDIAN_COMPONENT=forensics \
    RUBY_GUARDIAN_LOG_LEVEL=debug \
    RUBY_GUARDIAN_DUMP_DIR=/opt/rubyguardian/dumps

VOLUME ["/opt/rubyguardian/dumps"]

ENTRYPOINT ["bundle", "exec"]
CMD ["ruby", "04_memory_forensics/lib/forensics_runner.rb"]
