# RubyGuardian Setup and Installation Guide

## Overview

RubyGuardian is a security research framework for studying Ruby-based malware techniques, building detection engines, training ML classifiers, performing memory forensics, and deploying honeypots. This guide walks you through a complete installation on a fresh environment.

## Prerequisites

| Requirement       | Minimum Version | Notes                                    |
| ----------------- | --------------- | ---------------------------------------- |
| Ruby              | 3.0.0           | 3.2+ recommended                         |
| Python            | 3.10            | 3.11+ recommended; needed for ML module  |
| Docker & Compose  | 24.0 / 2.20     | Required for infrastructure services     |
| Node.js           | 18 LTS          | Required for the React dashboard         |
| Git               | 2.30            | For repository management                |
| Linux kernel      | 5.10+           | eBPF features require a modern kernel    |
| GCC / Make        | 10+             | Native extension compilation             |

### Operating System Support

- **Linux (primary):** Full support including eBPF tracing and `/proc` analysis.
- **macOS:** Partial support. Process hollowing and ptrace features are Linux-only.
- **Windows/WSL2:** Experimental. Use Docker-based workflow for best results.

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-org/RubyGuardian.git
cd RubyGuardian

# 2. Run the automated setup
make setup

# 3. Start all services via Docker
make docker-up

# 4. Verify everything is running
make detection-status
```

## Step-by-Step Installation

### 1. Ruby Dependencies

RubyGuardian uses Bundler to manage Ruby gems.

```bash
# Install Bundler if not already available
gem install bundler

# Install all gems (including development/test groups)
bundle install
```

Key gems installed:
- `ffi` -- Native API bindings for process manipulation
- `sinatra` / `puma` -- Web framework for C2 server and honeypots
- `sequel` / `sqlite3` -- Database layer for event storage
- `rspec` -- Test framework
- `rubocop` -- Linter

### 2. Python Dependencies

The ML classifier (Phase 3) and portions of the forensics module require Python.

```bash
# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

The `requirements.txt` includes scikit-learn, XGBoost, PyTorch/TensorFlow (for the neural net classifier), pandas, numpy, and loguru.

### 3. Native Extensions

The detection engine includes optional C extensions for eBPF bridging and ptrace helpers.

```bash
cd 02_detection_engine/agent/native_extensions/ebpf_bridge
ruby extconf.rb
make

cd ../ptrace_helper
ruby extconf.rb
make
```

Or simply:

```bash
cd 02_detection_engine && make
```

### 4. Docker Services

RubyGuardian uses Docker Compose to orchestrate infrastructure services.

```bash
# Build all images
make docker-build

# Start services (ELK stack, Grafana, databases, honeypots)
make docker-up

# Verify containers are running
docker compose ps
```

#### Service Ports

| Service         | Port  | Description                       |
| --------------- | ----- | --------------------------------- |
| Elasticsearch   | 9200  | Search and analytics engine       |
| Kibana          | 5601  | Visualization dashboard           |
| Grafana         | 3000  | Metrics dashboard                 |
| Web UI          | 8080  | React-based management interface  |
| ML Classifier   | 8000  | FastAPI prediction endpoint       |
| Honeypot Rails  | 3001  | Fake Rails application            |
| Honeypot Gems   | 9292  | Fake gem server                   |

### 5. Dashboard (Phase 6)

```bash
# Install frontend dependencies
cd 06_dashboard/web_ui
npm install

# Start in development mode
npm run dev
```

## Configuration

### Environment Variables

Create a `.env` file in the project root (not committed to version control):

```bash
# General
RUBY_GUARDIAN_ENV=development
RUBY_GUARDIAN_LOG_LEVEL=info

# Safety controls -- set to "true" only in isolated lab VMs
RUBY_GUARDIAN_AUTO_CONFIRM=false

# ML Classifier
ML_MODEL_PATH=03_ml_classifier/models/saved_models/ensemble_latest.pkl

# Elasticsearch
ELASTICSEARCH_URL=http://localhost:9200
KIBANA_URL=http://localhost:5601

# Database
DATABASE_URL=sqlite://db/ruby_guardian.db
```

### Detection Engine Configuration

Edit `02_detection_engine/config/agent_config.yml`:

```yaml
agent:
  monitors:
    - process_monitor
    - file_monitor
    - network_monitor
    - objectspace_scanner
    - memory_inspector
    - syscall_tracer
  polling_interval: 5
  log_level: info
```

### ML Classifier Configuration

Edit `03_ml_classifier/config/training_config.yml` for training parameters (test/validation split sizes, cross-validation settings) and `03_ml_classifier/config/model_config.yml` for model hyperparameters.

## Verification

Run the test suite to confirm the installation:

```bash
# All tests
make test

# Ruby tests only
make test-ruby

# Python tests only
make test-python

# Linting
make lint
```

## Troubleshooting

### Bundle install fails with FFI errors

Ensure you have `libffi-dev` installed:

```bash
# Debian/Ubuntu
sudo apt-get install libffi-dev build-essential

# Fedora/RHEL
sudo dnf install libffi-devel gcc make
```

### Permission denied when accessing /proc/pid/mem

Memory forensics and detection agent features require elevated privileges:

```bash
sudo bundle exec ruby 04_memory_forensics/scripts/run_full_analysis.rb
```

Or grant `CAP_SYS_PTRACE`:

```bash
sudo setcap cap_sys_ptrace=eip $(which ruby)
```

### Docker Compose services fail to start

Check available disk space and memory. The ELK stack requires at least 4 GB of RAM:

```bash
# Increase vm.max_map_count for Elasticsearch
sudo sysctl -w vm.max_map_count=262144
```

### Python import errors

Ensure your virtual environment is activated and all dependencies are installed:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```
