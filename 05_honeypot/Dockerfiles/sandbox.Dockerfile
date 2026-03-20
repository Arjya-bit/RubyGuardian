# RubyGuardian Sandbox - Isolated Malware Analysis Environment
# Provides a locked-down container for safely executing captured malware samples.
# All syscalls, file operations, and network activity are traced and recorded.
#
# Build:  docker build -f sandbox.Dockerfile -t rg-sandbox .
# Run:    Managed by container_manager.rb - do not run directly.

FROM ruby:3.3-slim AS base

LABEL maintainer="RubyGuardian Security Research <security@rubyguardian.dev>"
LABEL description="Isolated sandbox for safe malware sample execution"
LABEL version="1.0.0"

# Install analysis and monitoring tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    ltrace \
    tcpdump \
    inotify-tools \
    procps \
    lsof \
    net-tools \
    iptables \
    libseccomp-dev \
    sqlite3 libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install common gems that malware might try to require
RUN gem install --no-document \
    net-http json yaml base64 openssl \
    httparty rest-client faraday \
    nokogiri oga \
    sqlite3 sequel \
    redis \
    aws-sdk-s3 \
    dotenv

# Create sandbox user with minimal permissions
RUN groupadd -r sandbox && useradd -r -g sandbox -m -s /bin/bash sandbox

# Create directory structure
RUN mkdir -p /opt/rubyguardian/sandbox/{bin,lib,config} \
    /var/lib/rubyguardian/sandbox/{samples,output,traces} \
    /var/log/rubyguardian/sandbox \
    /tmp/sandbox_work \
    && chown -R sandbox:sandbox /var/lib/rubyguardian/sandbox \
    && chown -R sandbox:sandbox /var/log/rubyguardian/sandbox \
    && chown -R sandbox:sandbox /tmp/sandbox_work

WORKDIR /opt/rubyguardian/sandbox

# Copy the tracing wrapper and analysis tools
COPY lib/trace_wrapper.rb lib/trace_wrapper.rb
COPY lib/syscall_monitor.rb lib/syscall_monitor.rb
COPY lib/output_collector.rb lib/output_collector.rb
COPY bin/run_sample.sh bin/run_sample.sh
RUN chmod +x bin/run_sample.sh

# Plant fake targets for the malware to find (honeytokens)
RUN mkdir -p /home/sandbox/.aws /home/sandbox/.ssh /home/sandbox/.gem && \
    echo "[default]\naws_access_key_id=AKIAI44QH8DHBHONEYPOT\naws_secret_access_key=honeytoken_not_real_key_for_sandbox_only" \
    > /home/sandbox/.aws/credentials && \
    echo "-----BEGIN RSA PRIVATE KEY-----\nHONEYTOKEN_FAKE_SSH_KEY_FOR_SANDBOX\n-----END RSA PRIVATE KEY-----" \
    > /home/sandbox/.ssh/id_rsa && \
    echo "machine rubygems.org\nlogin sandbox_honeytoken\npassword not_a_real_password" \
    > /home/sandbox/.gem/credentials && \
    chmod 600 /home/sandbox/.ssh/id_rsa /home/sandbox/.gem/credentials && \
    chown -R sandbox:sandbox /home/sandbox

# Configure DNS to resolve to localhost (prevent real exfiltration)
RUN echo "127.0.0.1 rubygems.org" >> /etc/hosts && \
    echo "127.0.0.1 api.rubygems.org" >> /etc/hosts && \
    echo "127.0.0.1 github.com" >> /etc/hosts && \
    echo "127.0.0.1 raw.githubusercontent.com" >> /etc/hosts

# Environment for sandbox execution
ENV SANDBOX_MODE=true \
    SANDBOX_TIMEOUT=60 \
    SANDBOX_MAX_FILES=1000 \
    SANDBOX_OUTPUT_DIR=/var/lib/rubyguardian/sandbox/output \
    SANDBOX_TRACE_DIR=/var/lib/rubyguardian/sandbox/traces \
    RUBYOPT="-r /opt/rubyguardian/sandbox/lib/trace_wrapper.rb"

# Apply seccomp profile at runtime (passed by container_manager.rb)
# --security-opt seccomp=sandbox_seccomp.json

# Volume for sample input/output
VOLUME ["/var/lib/rubyguardian/sandbox/samples", \
        "/var/lib/rubyguardian/sandbox/output", \
        "/var/lib/rubyguardian/sandbox/traces"]

# No health check needed - sandbox is ephemeral

USER sandbox
WORKDIR /tmp/sandbox_work

# Entry point runs the sample under tracing supervision
ENTRYPOINT ["/opt/rubyguardian/sandbox/bin/run_sample.sh"]
CMD ["--timeout", "60", "--trace-level", "full"]
