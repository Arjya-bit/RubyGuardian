#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Attacker VM Provisioning
# =============================================================================
# Installs offensive security tools and the RubyGuardian attack framework
# on the attacker VM.
# =============================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "=========================================="
echo " RubyGuardian: Provisioning Attacker VM"
echo "=========================================="

# ---- System update -----------------------------------------------------------
apt-get update -qq
apt-get upgrade -y -qq

# ---- Core dependencies -------------------------------------------------------
apt-get install -y -qq \
    build-essential \
    git \
    curl \
    wget \
    vim \
    tmux \
    htop \
    unzip \
    jq \
    software-properties-common

# ---- Ruby installation -------------------------------------------------------
echo "[*] Installing Ruby 3.2 via rbenv..."
apt-get install -y -qq \
    libssl-dev \
    libreadline-dev \
    zlib1g-dev \
    libffi-dev \
    libyaml-dev \
    libsqlite3-dev

if [ ! -d "/home/vagrant/.rbenv" ]; then
    su - vagrant -c 'git clone https://github.com/rbenv/rbenv.git ~/.rbenv'
    su - vagrant -c 'git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build'
    su - vagrant -c 'echo "export PATH=\$HOME/.rbenv/bin:\$PATH" >> ~/.bashrc'
    su - vagrant -c 'echo "eval \"\$(rbenv init -)\"" >> ~/.bashrc'
fi

su - vagrant -c 'export PATH="$HOME/.rbenv/bin:$PATH" && eval "$(rbenv init -)" && rbenv install 3.2.2 --skip-existing && rbenv global 3.2.2'

# ---- Python installation -----------------------------------------------------
echo "[*] Installing Python 3.11..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv

# ---- Network / recon tools ---------------------------------------------------
echo "[*] Installing offensive network tools..."
apt-get install -y -qq \
    nmap \
    netcat-openbsd \
    socat \
    dnsutils \
    tcpdump \
    tshark \
    hping3 \
    iproute2 \
    net-tools \
    iptables \
    traceroute \
    whois

# ---- Process analysis tools --------------------------------------------------
echo "[*] Installing process analysis tools..."
apt-get install -y -qq \
    strace \
    ltrace \
    lsof \
    procps \
    gdb

# ---- Install project dependencies -------------------------------------------
echo "[*] Installing RubyGuardian attack framework dependencies..."
cd /opt/rubyguardian

su - vagrant -c 'export PATH="$HOME/.rbenv/bin:$PATH" && eval "$(rbenv init -)" && cd /opt/rubyguardian && gem install bundler && bundle install'

# ---- Configure attacker environment -----------------------------------------
echo "[*] Configuring attacker environment..."

cat >> /home/vagrant/.bashrc <<'BASHRC'

# RubyGuardian Attacker Environment
export RUBY_GUARDIAN_ROLE=attacker
export RUBY_GUARDIAN_HOME=/opt/rubyguardian
export RUBY_GUARDIAN_C2_HOST=172.31.0.10
export RUBY_GUARDIAN_C2_PORT=4443
export RUBY_GUARDIAN_TARGET_HOST=172.31.0.20
export RUBY_GUARDIAN_HONEYPOT_HOST=172.29.0.20

alias rg-attack='cd /opt/rubyguardian/01_attack_framework'
alias rg-run='bundle exec ruby'

echo ""
echo "================================================="
echo "  RubyGuardian Attacker VM"
echo "  Attack framework: /opt/rubyguardian/01_attack_framework"
echo "  Target:     $RUBY_GUARDIAN_TARGET_HOST"
echo "  Honeypot:   $RUBY_GUARDIAN_HONEYPOT_HOST"
echo "================================================="
BASHRC

chown vagrant:vagrant /home/vagrant/.bashrc

# ---- Disable outbound access to real networks --------------------------------
echo "[*] Restricting network access to lab segments only..."
iptables -A OUTPUT -d 172.29.0.0/16 -j ACCEPT    # honeypot segment
iptables -A OUTPUT -d 172.31.0.0/16 -j ACCEPT    # attack segment
iptables -A OUTPUT -d 10.0.2.0/24 -j ACCEPT      # Vagrant NAT (for provisioning)
iptables -A OUTPUT -o lo -j ACCEPT                 # loopback

# Save rules
apt-get install -y -qq iptables-persistent
netfilter-persistent save

echo "[+] Attacker VM provisioning complete."
