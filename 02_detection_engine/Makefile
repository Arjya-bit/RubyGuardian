.PHONY: setup build test run-dev run-prod install-service clean lint \
       build-ebpf build-ptrace docker-build docker-run

RUBY       := ruby
BUNDLE     := bundle
RSPEC      := bundle exec rspec
RUBOCOP    := bundle exec rubocop
DOCKER     := docker
SERVICE    := ruby-guardian-agent
AGENT_BIN  := agent/ruby_guardian_agent.rb
PID_FILE   := /var/run/ruby-guardian-agent.pid
LOG_DIR    := /var/log/ruby-guardian
CONF_DIR   := /etc/ruby-guardian
INSTALL_DIR := /opt/ruby-guardian

# Native extension paths
EBPF_DIR   := agent/native_extensions/ebpf_bridge
PTRACE_DIR := agent/native_extensions/ptrace_helper

## Setup & Build ---------------------------------------------------------

setup:
	@echo "==> Installing Ruby dependencies..."
	$(BUNDLE) install
	@echo "==> Creating log directory..."
	mkdir -p $(LOG_DIR) || true
	@echo "==> Setup complete."

build: build-ebpf build-ptrace
	@echo "==> All native extensions built."

build-ebpf:
	@echo "==> Building eBPF bridge extension..."
	cd $(EBPF_DIR) && $(RUBY) extconf.rb && make

build-ptrace:
	@echo "==> Building ptrace helper extension..."
	cd $(PTRACE_DIR) && $(RUBY) extconf.rb && make

clean:
	@echo "==> Cleaning build artifacts..."
	cd $(EBPF_DIR) && make clean 2>/dev/null || true
	cd $(PTRACE_DIR) && make clean 2>/dev/null || true
	rm -f $(EBPF_DIR)/Makefile $(PTRACE_DIR)/Makefile
	rm -f $(EBPF_DIR)/*.o $(PTRACE_DIR)/*.o
	rm -f $(EBPF_DIR)/*.so $(PTRACE_DIR)/*.so

## Testing ---------------------------------------------------------------

test:
	@echo "==> Running all specs..."
	$(RSPEC) --format documentation

test-unit:
	@echo "==> Running unit specs..."
	$(RSPEC) specs/agent/ rule_engine/specs/ alerting/specs/ --format documentation

test-integration:
	@echo "==> Running integration specs..."
	$(RSPEC) specs/integration/ --format documentation

test-rule-engine:
	@echo "==> Running rule engine specs..."
	$(RSPEC) rule_engine/specs/ --format documentation

lint:
	@echo "==> Running RuboCop..."
	$(RUBOCOP) agent/ rule_engine/ alerting/

## Running ---------------------------------------------------------------

run-dev:
	@echo "==> Starting agent in development mode..."
	RUBY_GUARDIAN_ENV=development $(RUBY) $(AGENT_BIN) --foreground --verbose

run-prod:
	@echo "==> Starting agent in production mode..."
	RUBY_GUARDIAN_ENV=production $(RUBY) $(AGENT_BIN) --daemon --pid $(PID_FILE)

stop:
	@echo "==> Stopping agent..."
	@if [ -f $(PID_FILE) ]; then \
		kill $$(cat $(PID_FILE)) && rm -f $(PID_FILE); \
		echo "Agent stopped."; \
	else \
		echo "PID file not found. Agent may not be running."; \
	fi

status:
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "Agent is running (PID: $$(cat $(PID_FILE)))"; \
	else \
		echo "Agent is not running."; \
	fi

## Installation ----------------------------------------------------------

install: build
	@echo "==> Installing RubyGuardian agent..."
	install -d $(INSTALL_DIR)
	install -d $(CONF_DIR)
	install -d $(LOG_DIR)
	cp -r agent/ $(INSTALL_DIR)/agent/
	cp -r rule_engine/ $(INSTALL_DIR)/rule_engine/
	cp -r alerting/ $(INSTALL_DIR)/alerting/
	cp -r config/ $(CONF_DIR)/
	@echo "==> Installation complete."

install-service: install
	@echo "==> Installing systemd service..."
	cp agent/systemd/ruby-guardian-agent.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable $(SERVICE)
	@echo "==> Service installed. Start with: systemctl start $(SERVICE)"

uninstall-service:
	@echo "==> Removing systemd service..."
	systemctl stop $(SERVICE) 2>/dev/null || true
	systemctl disable $(SERVICE) 2>/dev/null || true
	rm -f /etc/systemd/system/ruby-guardian-agent.service
	systemctl daemon-reload

## Docker ----------------------------------------------------------------

docker-build:
	@echo "==> Building Docker image..."
	$(DOCKER) build -t ruby-guardian-agent -f agent/Dockerfile .

docker-run:
	@echo "==> Running agent in Docker..."
	$(DOCKER) run --rm --privileged --pid=host \
		-v /proc:/host/proc:ro \
		-v /sys:/host/sys:ro \
		-v $(PWD)/config:/etc/ruby-guardian:ro \
		ruby-guardian-agent

## Utilities -------------------------------------------------------------

generate-config:
	@echo "==> Generating default configuration..."
	cp -n config/detection_config.yml $(CONF_DIR)/detection_config.yml
	cp -rn config/signatures/ $(CONF_DIR)/signatures/
	cp -rn config/alerting/ $(CONF_DIR)/alerting/

show-signatures:
	@echo "==> Loaded signature files:"
	@find config/signatures -name "*.yml" -type f | sort

help:
	@echo "RubyGuardian Detection Engine - Available targets:"
	@echo ""
	@echo "  setup             Install Ruby dependencies"
	@echo "  build             Build all native extensions"
	@echo "  clean             Remove build artifacts"
	@echo "  test              Run all specs"
	@echo "  test-unit         Run unit specs only"
	@echo "  test-integration  Run integration specs only"
	@echo "  lint              Run RuboCop linter"
	@echo "  run-dev           Start agent (foreground, verbose)"
	@echo "  run-prod          Start agent (daemon mode)"
	@echo "  stop              Stop running agent"
	@echo "  status            Check agent status"
	@echo "  install           Install to /opt/ruby-guardian"
	@echo "  install-service   Install systemd service"
	@echo "  docker-build      Build Docker image"
	@echo "  docker-run        Run agent in Docker"
	@echo "  help              Show this help"
