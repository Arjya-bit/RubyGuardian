# Phase 7: RubyGuardian Infrastructure

This directory contains all infrastructure-as-code configurations for deploying, testing, and operating the RubyGuardian security research platform.

## Directory Structure

```
07_infrastructure/
├── docker/                  # Container definitions
│   ├── base/                # Base Dockerfiles for each component
│   ├── network/             # Docker network and firewall configs
│   └── volumes/             # Persistent volume configurations
├── vagrant/                 # Multi-VM lab environment
│   ├── Vagrantfile          # VM orchestration
│   ├── scripts/             # Provisioning scripts
│   └── configs/             # Per-VM configuration
├── kubernetes/              # K8s manifests for production deployment
│   ├── namespace.yml
│   ├── deployments/         # Workload definitions
│   ├── services/            # Service exposure
│   └── configmaps/          # Runtime configuration
└── ci_cd/                   # Continuous integration / delivery
    ├── .github/workflows/   # GitHub Actions pipelines
    └── scripts/             # Helper scripts
```

## Quick Start

### Docker Compose (Development)

```bash
# From the project root
docker-compose -f docker-compose.dev.yml up --build
```

### Vagrant Lab (Isolated Research)

```bash
cd vagrant/
vagrant up
vagrant ssh monitor
```

### Kubernetes (Production)

```bash
kubectl apply -f kubernetes/namespace.yml
kubectl apply -f kubernetes/configmaps/
kubectl apply -f kubernetes/deployments/
kubectl apply -f kubernetes/services/
```

## Network Architecture

| Network        | CIDR             | Purpose                        |
|----------------|------------------|--------------------------------|
| rg-internal    | 172.28.0.0/16    | Inter-service communication    |
| rg-honeypot    | 172.29.0.0/16    | Isolated honeypot segment      |
| rg-monitoring  | 172.30.0.0/16    | ELK stack and dashboard access |

## Security Considerations

All infrastructure is designed for **controlled research environments only**. The attack framework containers run with limited capabilities and must never be exposed to production networks. Refer to `docker/network/firewall_rules.sh` for isolation policies.

## Prerequisites

- Docker 24.0+ and Docker Compose v2
- Vagrant 2.4+ with VirtualBox 7.0+ (for lab environment)
- kubectl 1.28+ with a configured cluster (for Kubernetes deployment)
- Ruby 3.2+ and Python 3.11+ (for CI/CD scripts)
