# RubyGuardian Honeypot - Fake CI Runner
# Emulates a GitHub Actions / GitLab CI runner environment to capture
# pipeline injection attempts, malicious build scripts, and exfiltration.
#
# Build:  docker build -f fake_ci_runner.Dockerfile -t rg-honeypot-ci .
# Run:    docker run -d --name rg-ci-runner rg-honeypot-ci

FROM ubuntu:22.04 AS base

LABEL maintainer="RubyGuardian Security Research <security@rubyguardian.dev>"
LABEL description="Fake CI runner honeypot for pipeline injection research"
LABEL version="1.0.0"

# Disable interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install packages that make this look like a real CI runner
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby3.0 ruby3.0-dev \
    python3 python3-pip \
    nodejs npm \
    git curl wget \
    build-essential \
    libssl-dev libffi-dev \
    sqlite3 libsqlite3-dev \
    inotify-tools \
    auditd \
    strace \
    tcpdump \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install gems that would be on a typical CI runner
RUN gem install bundler rake rspec rubocop minitest

# Create a fake CI runner user
RUN useradd -m -s /bin/bash runner \
    && mkdir -p /home/runner/work \
    && mkdir -p /home/runner/.config \
    && mkdir -p /home/runner/.ssh

# Plant fake credentials (honeytokens) for detection
RUN mkdir -p /home/runner/.aws && \
    echo "[default]\naws_access_key_id = AKIAIOSFODNN7HONEYPOT\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYPOTKEY" \
    > /home/runner/.aws/credentials && \
    echo "[default]\nregion = us-east-1" > /home/runner/.aws/config

RUN echo "GITHUB_TOKEN=ghp_honeytoken_fake_00000000000000000000" \
    > /home/runner/.env && \
    echo "SLACK_WEBHOOK=https://hooks.slack.com/services/T00/B00/honeytoken" \
    >> /home/runner/.env && \
    echo "DATABASE_URL=postgres://admin:honeypot_password@db.internal:5432/app" \
    >> /home/runner/.env

RUN mkdir -p /home/runner/.ssh && \
    ssh-keygen -t rsa -b 2048 -f /home/runner/.ssh/id_rsa -N "" -q && \
    echo "Host github.com\n  IdentityFile ~/.ssh/id_rsa" > /home/runner/.ssh/config

# Set up fake GitHub Actions environment variables
ENV CI=true \
    GITHUB_ACTIONS=true \
    GITHUB_WORKSPACE=/home/runner/work \
    GITHUB_REPOSITORY=acme-corp/production-app \
    GITHUB_REF=refs/heads/main \
    GITHUB_SHA=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 \
    GITHUB_ACTOR=deploy-bot \
    GITHUB_RUN_ID=12345678 \
    RUNNER_OS=Linux \
    RUNNER_ARCH=X64 \
    RUNNER_TEMP=/tmp

# Set up the RubyGuardian monitoring layer
WORKDIR /opt/rubyguardian/honeypot/ci_runner

COPY lib/ lib/
COPY config/ config/

RUN mkdir -p /var/log/rubyguardian/ci_runner \
    /var/lib/rubyguardian/captures/ci_artifacts \
    /var/lib/rubyguardian/captures/ci_commands \
    && chown -R runner:runner /var/log/rubyguardian \
    && chown -R runner:runner /var/lib/rubyguardian \
    && chown -R runner:runner /home/runner

# Configure audit rules for filesystem and process monitoring
COPY config/audit.rules /etc/audit/rules.d/honeypot.rules

# Volume for persistent captures
VOLUME ["/var/lib/rubyguardian/captures", "/var/log/rubyguardian/ci_runner"]

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD pgrep -f "ci_monitor" || exit 1

USER runner
WORKDIR /home/runner/work

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["auditd & \
     tcpdump -i any -w /var/lib/rubyguardian/captures/ci_traffic_$(date +%Y%m%d_%H%M%S).pcap & \
     inotifywait -m -r /home/runner --format '%T %w%f %e' --timefmt '%Y-%m-%dT%H:%M:%S' \
       -e access -e modify -e create -e delete \
       >> /var/log/rubyguardian/ci_runner/fs_events.log 2>&1 & \
     exec ruby /opt/rubyguardian/honeypot/ci_runner/lib/ci_monitor.rb"]
