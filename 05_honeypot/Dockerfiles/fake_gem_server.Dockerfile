# RubyGuardian Honeypot - Fake RubyGems Server
# Mimics a RubyGems.org mirror to capture malicious gem install requests.
# All incoming requests are logged with full headers, client info, and payload.
#
# Build:  docker build -f fake_gem_server.Dockerfile -t rg-honeypot-gemserver .
# Run:    docker run -d -p 8808:8808 --name rg-gemserver rg-honeypot-gemserver

FROM ruby:3.3-slim AS base

LABEL maintainer="RubyGuardian Security Research <security@rubyguardian.dev>"
LABEL description="Fake RubyGems server honeypot for supply-chain attack research"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-dev \
    tcpdump \
    tshark \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root honeypot user
RUN groupadd -r honeypot && useradd -r -g honeypot -m -s /bin/bash honeypot

# Set working directory
WORKDIR /opt/rubyguardian/honeypot/gem_server

# Copy Gemfile first for layer caching
COPY Gemfile Gemfile.lock ./
RUN bundle install --without development test --jobs 4 --retry 3

# Copy application code
COPY lib/ lib/
COPY config/ config/
COPY public/ public/

# Create directories for captures and logs
RUN mkdir -p /var/log/rubyguardian/gem_server \
    /var/lib/rubyguardian/captures/gems \
    /var/lib/rubyguardian/captures/requests \
    /var/lib/rubyguardian/db \
    && chown -R honeypot:honeypot /var/log/rubyguardian \
    && chown -R honeypot:honeypot /var/lib/rubyguardian

# Copy the fake gem index (pre-generated to look realistic)
COPY fixtures/specs.4.8.gz public/specs.4.8.gz
COPY fixtures/latest_specs.4.8.gz public/latest_specs.4.8.gz
COPY fixtures/prerelease_specs.4.8.gz public/prerelease_specs.4.8.gz

# Configure environment
ENV RACK_ENV=production \
    HONEYPOT_LOG_LEVEL=debug \
    HONEYPOT_CAPTURE_DIR=/var/lib/rubyguardian/captures \
    HONEYPOT_DB_PATH=/var/lib/rubyguardian/db/gem_requests.sqlite3 \
    HONEYPOT_BIND=0.0.0.0 \
    HONEYPOT_PORT=8808 \
    HONEYPOT_SERVER_NAME="rubygems.org" \
    HONEYPOT_RESPONSE_DELAY_MS=50

# Expose the gem server port
EXPOSE 8808

# Volume for persistent capture data
VOLUME ["/var/lib/rubyguardian/captures", "/var/log/rubyguardian/gem_server"]

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8808/api/v1/health || exit 1

# Start packet capture in background, then launch the fake gem server
USER honeypot

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["tcpdump -i any -w /var/lib/rubyguardian/captures/traffic_$(date +%Y%m%d_%H%M%S).pcap port 8808 & \
     exec ruby lib/gem_server.rb"]
