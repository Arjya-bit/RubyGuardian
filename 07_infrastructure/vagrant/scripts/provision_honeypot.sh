#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Honeypot VM Provisioning Script
# Installs Ruby, Docker, and deploys honeypot services
# =============================================================================
set -euo pipefail

echo "[*] RubyGuardian Honeypot VM Provisioning"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ruby ruby-dev build-essential docker.io git

# Enable Docker
systemctl enable docker
systemctl start docker
usermod -aG docker vagrant

# Install Ruby dependencies
gem install bundler sinatra puma thin webrick

# Install honeypot dependencies
cd /opt/rubyguardian/05_honeypot
bundle install --quiet 2>/dev/null || echo "[!] Bundler install skipped (no Gemfile)"

# Build honeypot Docker images
echo "[+] Building honeypot containers..."
if [ -f Dockerfiles/fake_gem_server.Dockerfile ]; then
  docker build -f Dockerfiles/fake_gem_server.Dockerfile -t rg-fake-gems:latest . || true
fi
if [ -f Dockerfiles/sandbox.Dockerfile ]; then
  docker build -f Dockerfiles/sandbox.Dockerfile -t rg-sandbox:latest . || true
fi

# Create working directories
mkdir -p /var/log/ruby-guardian/honeypot
mkdir -p /var/lib/ruby-guardian/captures
mkdir -p /var/lib/ruby-guardian/samples

# Set up iptables logging for connection tracking
echo "[+] Configuring network logging..."
iptables -A INPUT -j LOG --log-prefix "RG-HONEYPOT: " --log-level 4 || true

echo "[+] Honeypot VM provisioning complete"
echo "[+] Fake gem server: http://localhost:8808"
echo "[+] Captures dir:    /var/lib/ruby-guardian/captures"
