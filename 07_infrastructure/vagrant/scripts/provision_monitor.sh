#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Monitor VM Provisioning Script
# Installs ELK stack, Grafana, Prometheus, and dashboard dependencies
# =============================================================================
set -euo pipefail

echo "[*] RubyGuardian Monitor VM Provisioning"

# System updates
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget gnupg apt-transport-https software-properties-common

# Install Docker
echo "[+] Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
usermod -aG docker vagrant

# Install Node.js for dashboard
echo "[+] Installing Node.js..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -qq nodejs

# Set sysctl for Elasticsearch
echo "[+] Configuring system limits..."
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf

# Start ELK stack via Docker Compose
echo "[+] Starting ELK stack..."
cd /opt/rubyguardian/07_infrastructure/elk
docker compose up -d || echo "[!] ELK compose not found, skipping"

# Install Grafana
echo "[+] Starting Grafana..."
docker run -d \
  --name grafana \
  --restart unless-stopped \
  -p 3000:3000 \
  -e "GF_SECURITY_ADMIN_PASSWORD=ruby-guardian-dev" \
  grafana/grafana:10.2.0 || echo "[!] Grafana already running"

# Install Prometheus
echo "[+] Starting Prometheus..."
docker run -d \
  --name prometheus \
  --restart unless-stopped \
  -p 9090:9090 \
  -v /opt/rubyguardian/07_infrastructure/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus:v2.48.0 || echo "[!] Prometheus already running"

# Create log directory
mkdir -p /var/log/ruby-guardian

echo "[+] Monitor VM provisioning complete"
echo "[+] Kibana:        http://localhost:5601"
echo "[+] Elasticsearch: http://localhost:9200"
echo "[+] Grafana:       http://localhost:3000"
echo "[+] Prometheus:    http://localhost:9090"
