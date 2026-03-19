#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Target VM Provisioning
# =============================================================================
# Installs a vulnerable Ruby application environment and the RubyGuardian
# detection engine for monitoring attacks in real time.
# =============================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "=========================================="
echo " RubyGuardian: Provisioning Target VM"
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
    libsqlite3-dev \
    libcurl4-openssl-dev

if [ ! -d "/home/vagrant/.rbenv" ]; then
    su - vagrant -c 'git clone https://github.com/rbenv/rbenv.git ~/.rbenv'
    su - vagrant -c 'git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build'
    su - vagrant -c 'echo "export PATH=\$HOME/.rbenv/bin:\$PATH" >> ~/.bashrc'
    su - vagrant -c 'echo "eval \"\$(rbenv init -)\"" >> ~/.bashrc'
fi

su - vagrant -c 'export PATH="$HOME/.rbenv/bin:$PATH" && eval "$(rbenv init -)" && rbenv install 3.2.2 --skip-existing && rbenv global 3.2.2'

# ---- Python installation (for ML classifier client) -------------------------
echo "[*] Installing Python 3.11..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv

# ---- Monitoring tools --------------------------------------------------------
echo "[*] Installing monitoring and forensics tools..."
apt-get install -y -qq \
    auditd \
    audispd-plugins \
    strace \
    ltrace \
    lsof \
    sysstat \
    inotify-tools \
    tcpdump \
    iproute2 \
    net-tools \
    procps

# ---- Configure auditd for Ruby process monitoring ---------------------------
echo "[*] Configuring auditd rules for Ruby process monitoring..."
cat > /etc/audit/rules.d/rubyguardian.rules <<'AUDITRULES'
# RubyGuardian: Monitor Ruby interpreter syscalls
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/ruby -k rg_ruby_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/local/bin/ruby -k rg_ruby_exec

# Monitor process injection syscalls
-a always,exit -F arch=b64 -S ptrace -k rg_ptrace
-a always,exit -F arch=b64 -S process_vm_readv -k rg_process_vm
-a always,exit -F arch=b64 -S process_vm_writev -k rg_process_vm

# Monitor suspicious file operations in gem directories
-w /usr/local/lib/ruby/gems/ -p wa -k rg_gem_modification
-w /home/vagrant/.rbenv/versions/ -p wa -k rg_gem_modification

# Monitor network connections from Ruby processes
-a always,exit -F arch=b64 -S connect -F exe=/usr/bin/ruby -k rg_ruby_network
-a always,exit -F arch=b64 -S bind -F exe=/usr/bin/ruby -k rg_ruby_network

# Monitor memory mapping operations (for process hollowing detection)
-a always,exit -F arch=b64 -S mmap -F exe=/usr/bin/ruby -k rg_ruby_mmap
-a always,exit -F arch=b64 -S mprotect -F exe=/usr/bin/ruby -k rg_ruby_mprotect
AUDITRULES

systemctl restart auditd

# ---- Install Filebeat for log shipping ---------------------------------------
echo "[*] Installing Filebeat for log shipping to ELK..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg 2>/dev/null || true
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -qq
apt-get install -y -qq filebeat || echo "[WARN] Filebeat installation skipped (offline provisioning)"

# Configure Filebeat
cat > /etc/filebeat/filebeat.yml <<'FILEBEAT'
filebeat.inputs:
  - type: log
    id: rubyguardian-detection
    enabled: true
    paths:
      - /var/log/rubyguardian/*.log
      - /var/log/rubyguardian/**/*.json
    json.keys_under_root: true
    json.add_error_key: true

  - type: log
    id: auditd-logs
    enabled: true
    paths:
      - /var/log/audit/audit.log
    tags: ["auditd"]

output.logstash:
  hosts: ["172.28.0.10:5044"]
  ssl.enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
FILEBEAT

systemctl enable filebeat 2>/dev/null || true

# ---- Install RubyGuardian dependencies --------------------------------------
echo "[*] Installing RubyGuardian detection engine dependencies..."
cd /opt/rubyguardian
su - vagrant -c 'export PATH="$HOME/.rbenv/bin:$PATH" && eval "$(rbenv init -)" && cd /opt/rubyguardian && gem install bundler && bundle install'

# ---- Create log directories --------------------------------------------------
mkdir -p /var/log/rubyguardian
chown vagrant:vagrant /var/log/rubyguardian

# ---- Create systemd service for detection agent ------------------------------
echo "[*] Creating detection agent systemd service..."
cat > /etc/systemd/system/rubyguardian-agent.service <<'SYSTEMD'
[Unit]
Description=RubyGuardian Detection Agent
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=vagrant
Group=vagrant
WorkingDirectory=/opt/rubyguardian
ExecStart=/home/vagrant/.rbenv/shims/ruby 02_detection_engine/lib/agent/detection_agent.rb --daemonize
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rubyguardian-agent

Environment=RUBY_GUARDIAN_COMPONENT=detection_engine
Environment=RUBY_GUARDIAN_LOG_LEVEL=info
Environment=RUBY_GUARDIAN_ELK_HOST=172.28.0.10
Environment=RUBY_GUARDIAN_ELK_PORT=5044
Environment=RUBY_GUARDIAN_ML_API_HOST=172.28.0.10
Environment=RUBY_GUARDIAN_ML_API_PORT=5000

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable rubyguardian-agent 2>/dev/null || true

# ---- Configure target environment -------------------------------------------
cat >> /home/vagrant/.bashrc <<'BASHRC'

# RubyGuardian Target Environment
export RUBY_GUARDIAN_ROLE=target
export RUBY_GUARDIAN_HOME=/opt/rubyguardian
export RUBY_GUARDIAN_LOG_DIR=/var/log/rubyguardian

alias rg-detect='cd /opt/rubyguardian/02_detection_engine'
alias rg-logs='tail -f /var/log/rubyguardian/*.log'
alias rg-agent-status='systemctl status rubyguardian-agent'
alias rg-agent-start='sudo systemctl start rubyguardian-agent'
alias rg-agent-stop='sudo systemctl stop rubyguardian-agent'

echo ""
echo "================================================="
echo "  RubyGuardian Target VM"
echo "  Detection engine: /opt/rubyguardian/02_detection_engine"
echo "  Logs:            /var/log/rubyguardian/"
echo "  Agent status:    systemctl status rubyguardian-agent"
echo "================================================="
BASHRC

chown vagrant:vagrant /home/vagrant/.bashrc

echo "[+] Target VM provisioning complete."
