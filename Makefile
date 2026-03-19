.PHONY: help setup dev test lint clean attack-demo detection-start classifier-api \
       forensics-analyze honeypot-deploy dashboard-start build docker-up docker-down

SHELL := /bin/bash
DOCKER_COMPOSE := docker-compose
BUNDLE := bundle exec
PYTHON := python3

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

# ─── Setup ────────────────────────────────────────────────────────────────────

setup: ## Initial project setup
	@echo "==> Installing Ruby dependencies..."
	bundle install
	@echo "==> Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "==> Setting up pre-commit hooks..."
	pre-commit install
	@echo "==> Building native extensions..."
	cd 02_detection_engine && make
	@echo "==> Setup complete!"

dev: ## Start development environment
	$(DOCKER_COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml up -d

# ─── Docker ───────────────────────────────────────────────────────────────────

docker-up: ## Start all services
	$(DOCKER_COMPOSE) up -d

docker-down: ## Stop all services
	$(DOCKER_COMPOSE) down

docker-build: ## Build all Docker images
	$(DOCKER_COMPOSE) build

docker-logs: ## Tail all service logs
	$(DOCKER_COMPOSE) logs -f

# ─── Attack Framework (Phase 1) ──────────────────────────────────────────────

attack-demo: ## Run attack demonstration (in isolated container)
	@echo "WARNING: Running in isolated container only"
	$(DOCKER_COMPOSE) run --rm attacker ruby 01_attack_framework/1a_process_hollowing/scripts/run_hollow_demo.rb

attack-cicd-demo: ## Run CI/CD poisoning demo
	@echo "WARNING: Running in isolated container only"
	cd 01_attack_framework/1b_cicd_poisoning && bash scripts/run_pipeline_attack.sh

attack-lolruby: ## Show LoLRuby technique matrix
	$(BUNDLE) ruby 01_attack_framework/1c_lolruby/lolruby_database/query_interface.rb --list

# ─── Detection Engine (Phase 2) ──────────────────────────────────────────────

detection-start: ## Start the detection agent
	$(BUNDLE) ruby 02_detection_engine/agent/ruby_guardian_agent.rb start

detection-stop: ## Stop the detection agent
	$(BUNDLE) ruby 02_detection_engine/agent/ruby_guardian_agent.rb stop

detection-status: ## Check detection agent status
	$(BUNDLE) ruby 02_detection_engine/agent/ruby_guardian_agent.rb status

# ─── ML Classifier (Phase 3) ─────────────────────────────────────────────────

classifier-train: ## Train ML models
	$(PYTHON) -m 03_ml_classifier.models.training.train_pipeline

classifier-api: ## Start ML classifier API
	$(PYTHON) -m uvicorn 03_ml_classifier.api.app:app --host 0.0.0.0 --port 8000

classifier-evaluate: ## Run model evaluation
	$(PYTHON) -m 03_ml_classifier.models.evaluation.evaluator

# ─── Memory Forensics (Phase 4) ──────────────────────────────────────────────

forensics-analyze: ## Run forensic analysis on sample dump
	$(BUNDLE) ruby 04_memory_forensics/scripts/run_full_analysis.rb

forensics-dump: ## Capture memory dump of target process
	bash 04_memory_forensics/scripts/capture_memory_dump.sh

# ─── Honeypot (Phase 5) ──────────────────────────────────────────────────────

honeypot-deploy: ## Deploy honeypot services
	$(DOCKER_COMPOSE) up -d honeypot-rails honeypot-gems honeypot-ci

honeypot-status: ## Check honeypot status
	$(DOCKER_COMPOSE) ps honeypot-rails honeypot-gems honeypot-ci

# ─── Dashboard (Phase 6) ─────────────────────────────────────────────────────

dashboard-start: ## Start ELK + Dashboard
	$(DOCKER_COMPOSE) up -d elasticsearch logstash kibana grafana web-ui

dashboard-web: ## Start React web UI only (development)
	cd 06_dashboard/web_ui && npm run dev

# ─── Testing ──────────────────────────────────────────────────────────────────

test: test-ruby test-python ## Run all tests

test-ruby: ## Run Ruby test suite
	$(BUNDLE) rspec

test-python: ## Run Python test suite
	$(PYTHON) -m pytest 03_ml_classifier/tests/ 04_memory_forensics/ -v

test-integration: ## Run integration tests
	$(DOCKER_COMPOSE) -f docker-compose.test.yml up --abort-on-container-exit

# ─── Linting ──────────────────────────────────────────────────────────────────

lint: lint-ruby lint-python ## Run all linters

lint-ruby: ## Run RuboCop
	$(BUNDLE) rubocop

lint-python: ## Run Flake8
	flake8 03_ml_classifier/ 04_memory_forensics/

# ─── Cleanup ──────────────────────────────────────────────────────────────────

clean: ## Clean build artifacts
	rm -rf tmp/ log/ .bundle/
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} +
	$(DOCKER_COMPOSE) down -v --remove-orphans
