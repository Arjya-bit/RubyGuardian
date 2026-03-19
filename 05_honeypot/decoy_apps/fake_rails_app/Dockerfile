# RubyGuardian Honeypot - Fake Rails Application Container
#
# This Dockerfile builds the decoy Rails application that serves as
# a honeypot to attract and capture attacker interactions.
#
# HONEYPOT WARNING: This container is a decoy. It deliberately exposes
# vulnerable endpoints and planted credentials for threat intelligence.
# Deploy only in isolated network segments with proper monitoring.

FROM ruby:3.2.2-slim-bookworm AS base

LABEL maintainer="security@rubyguardian.internal"
LABEL description="RubyGuardian Honeypot - Fake Rails Application"
LABEL version="1.0.0"
LABEL honeypot="true"

# Set environment variables that appear realistic to attackers
ENV RAILS_ENV=production \
    RACK_ENV=production \
    RAILS_LOG_TO_STDOUT=true \
    RAILS_SERVE_STATIC_FILES=true \
    BUNDLE_WITHOUT="development:test" \
    BUNDLE_DEPLOYMENT=1 \
    LANG=C.UTF-8 \
    SECRET_KEY_BASE=f4k3s3cr3tk3yb4s3th4t1sv3ryl0ng4ndc0mpl3x123456789abcdef \
    DATABASE_URL=postgres://deploy:D3pl0y$ecret@db.internal:5432/webapp_prod \
    REDIS_URL=redis://cache.internal:6379/0

# Install system dependencies
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      build-essential \
      libpq-dev \
      libssl-dev \
      libyaml-dev \
      libffi-dev \
      curl \
      git \
      netcat-openbsd \
      procps \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create application user
RUN groupadd --gid 1000 webapp && \
    useradd --uid 1000 --gid webapp --shell /bin/bash --create-home webapp

# Set up application directory structure
RUN mkdir -p /opt/webapp/current \
             /opt/webapp/shared/log \
             /opt/webapp/shared/tmp \
             /opt/webapp/shared/pids \
             /opt/webapp/shared/sockets \
             /var/log/rubyguardian/honeypot \
             /var/lib/rubyguardian/honeypot/captures \
             /var/lib/rubyguardian/honeypot/samples \
    && chown -R webapp:webapp /opt/webapp /var/log/rubyguardian /var/lib/rubyguardian

WORKDIR /opt/webapp/current

# Copy Gemfile and install dependencies
COPY --chown=webapp:webapp Gemfile Gemfile.lock* ./
RUN bundle install --jobs 4 --retry 3

# Copy application code
COPY --chown=webapp:webapp . .

# Precompile assets (fake but realistic)
RUN mkdir -p public/assets && \
    echo "/* Precompiled assets */" > public/assets/application.css && \
    echo "// Precompiled assets" > public/assets/application.js

# Create realistic-looking configuration files
RUN mkdir -p config/credentials && \
    echo "f4k3m4st3rk3y1234567890abcdef12" > config/master.key && \
    chmod 600 config/master.key

# Create honeypot log directory structure
RUN mkdir -p log && \
    touch log/production.log && \
    chown -R webapp:webapp log

# Plant canary files that trigger alerts when accessed
RUN mkdir -p /root/.ssh && \
    echo "-----BEGIN RSA PRIVATE KEY-----" > /root/.ssh/id_rsa && \
    echo "CANARY_SSH_KEY_DO_NOT_USE" >> /root/.ssh/id_rsa && \
    echo "-----END RSA PRIVATE KEY-----" >> /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa

# Create a fake .env file in multiple locations
RUN echo "# Production Environment" > .env && \
    echo "SECRET_KEY_BASE=f4k3s3cr3tk3yb4s3th4t1sv3ryl0ng4ndc0mpl3x123456789abcdef" >> .env && \
    echo "DATABASE_URL=postgres://deploy:D3pl0y\$ecret@db.internal:5432/webapp_prod" >> .env && \
    echo "AWS_ACCESS_KEY_ID=AKIAFAKE1234567890AB" >> .env && \
    echo "AWS_SECRET_ACCESS_KEY=fAkEsEcReTkEy1234567890abcdefghijklmnop" >> .env

# Expose ports
EXPOSE 3000 3443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/api/v1/health || exit 1

# Switch to application user
USER webapp

# Start the application server
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb", "-b", "tcp://0.0.0.0:3000"]
