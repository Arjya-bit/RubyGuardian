# frozen_string_literal: true

require "json"
require "logger"

module RubyGuardian
  module Honeypot
    module Analysis
      # PatternMatcher matches captured behaviors against known malware family
      # patterns using a YARA-like rule system. Rules are defined declaratively
      # and evaluated against behavior timelines to classify samples.
      class PatternMatcher
        Rule = Struct.new(:name, :family, :description, :severity, :conditions, :tags, keyword_init: true)

        # Built-in rules for known Ruby supply-chain attack patterns.
        BUILTIN_RULES = [
          {
            name: "ruby_gem_backdoor_v1",
            family: "GemBackdoor",
            description: "Classic gem backdoor: reads credentials and exfiltrates via HTTP POST",
            severity: :critical,
            tags: %w[supply_chain credential_theft exfiltration],
            conditions: {
              all: [
                { category: :credential_access, min_count: 1 },
                { category: :network_connection, min_count: 1 },
                { pattern: /\.gem.*credentials|\.aws.*credentials/i, field: :description }
              ]
            }
          },
          {
            name: "reverse_shell_ruby",
            family: "ReverseShell",
            description: "Ruby reverse shell via TCPSocket or system commands",
            severity: :critical,
            tags: %w[reverse_shell remote_access],
            conditions: {
              any: [
                { pattern: /TCPSocket\.new.*\d+\.\d+\.\d+\.\d+/i, field: :details },
                { pattern: /bash\s+-i.*\/dev\/tcp/i, field: :description },
                { pattern: /nc\s+-e|ncat.*-e/i, field: :description }
              ]
            }
          },
          {
            name: "crypto_miner_dropper",
            family: "CryptoMiner",
            description: "Downloads and executes cryptocurrency mining software",
            severity: :high,
            tags: %w[crypto_mining resource_abuse],
            conditions: {
              all: [
                { category: :process_execution, min_count: 1 },
                { pattern: /curl|wget/i, field: :description },
                { pattern: /xmrig|stratum|mining|monero|coinhive/i, field: :details }
              ]
            }
          },
          {
            name: "env_harvester",
            family: "EnvHarvester",
            description: "Harvests environment variables and secrets for exfiltration",
            severity: :high,
            tags: %w[credential_theft reconnaissance],
            conditions: {
              all: [
                { pattern: /ENV|environment/i, field: :description },
                { category: :network_connection, min_count: 1 }
              ]
            }
          },
          {
            name: "ssh_key_stealer",
            family: "SSHStealer",
            description: "Reads SSH private keys and exfiltrates them",
            severity: :critical,
            tags: %w[credential_theft ssh_compromise],
            conditions: {
              all: [
                { pattern: /\.ssh\/(id_rsa|id_ed25519|id_ecdsa)/i, field: :description },
                { category: :network_connection, min_count: 1 }
              ]
            }
          },
          {
            name: "persistence_installer",
            family: "Persistence",
            description: "Installs persistence mechanisms (cron, systemd, shell profile)",
            severity: :high,
            tags: %w[persistence],
            conditions: {
              any: [
                { pattern: /crontab|\/etc\/cron/i, field: :description },
                { pattern: /systemd.*service|systemctl.*enable/i, field: :description },
                { pattern: /\.bashrc|\.profile|\.zshrc/i, field: :description, also: { category: :file_modification } }
              ]
            }
          },
          {
            name: "typosquat_loader",
            family: "TyposquatLoader",
            description: "Typosquatting gem that loads malicious code on require",
            severity: :critical,
            tags: %w[supply_chain typosquatting],
            conditions: {
              all: [
                { category: :process_execution, min_count: 1, within_seconds: 5 },
                { pattern: /eval|instance_eval|class_eval|module_eval/i, field: :description },
                { category: :network_connection, min_count: 1, within_seconds: 30 }
              ]
            }
          },
          {
            name: "dns_exfiltration",
            family: "DNSExfil",
            description: "Exfiltrates data via DNS queries (encoded subdomains)",
            severity: :critical,
            tags: %w[exfiltration dns_tunnel],
            conditions: {
              all: [
                { category: :dns_resolution, min_count: 5 },
                { pattern: /[a-z0-9]{32,}\./i, field: :details }
              ]
            }
          }
        ].freeze

        attr_reader :rules, :results

        def initialize(custom_rules: [], logger: nil)
          @logger = logger || default_logger
          @rules = load_builtin_rules + load_custom_rules(custom_rules)
          @results = []
        end

        # Match a set of behavioral events against all rules.
        # @param events [Array<Hash>] behavioral events from BehaviorRecorder
        # @return [Array<Hash>] matched rules with details
        def match(events)
          @results = []
          return @results if events.empty?

          @logger.info("[PatternMatcher] Matching #{events.size} events against #{@rules.size} rules")

          @rules.each do |rule|
            match_result = evaluate_rule(rule, events)
            if match_result[:matched]
              @results << {
                rule_name: rule.name,
                family: rule.family,
                description: rule.description,
                severity: rule.severity,
                tags: rule.tags,
                matched_events: match_result[:matched_events],
                confidence: match_result[:confidence]
              }
              @logger.warn("[PatternMatcher] MATCH: #{rule.name} (#{rule.family}) - confidence #{match_result[:confidence]}%")
            end
          end

          @logger.info("[PatternMatcher] #{@results.size} rules matched out of #{@rules.size}")
          @results
        end

        # Get the highest-severity match result.
        def top_match
          severity_order = { critical: 4, high: 3, medium: 2, low: 1 }
          @results.max_by { |r| [severity_order[r[:severity]] || 0, r[:confidence]] }
        end

        # Get all matched family names.
        def matched_families
          @results.map { |r| r[:family] }.uniq
        end

        # Generate a match report.
        def report
          {
            total_rules: @rules.size,
            matches_found: @results.size,
            matched_families: matched_families,
            top_match: top_match,
            all_matches: @results.sort_by { |r| -(r[:confidence] || 0) }
          }
        end

        private

        def evaluate_rule(rule, events)
          conditions = rule.conditions
          matched_events = []
          condition_results = []

          if conditions[:all]
            conditions[:all].each do |cond|
              result = evaluate_condition(cond, events)
              condition_results << result[:matched]
              matched_events.concat(result[:events]) if result[:matched]
            end
            all_matched = condition_results.all?
            confidence = all_matched ? (condition_results.count(true).to_f / condition_results.size * 100).round : 0
            { matched: all_matched, matched_events: matched_events.uniq, confidence: confidence }

          elsif conditions[:any]
            conditions[:any].each do |cond|
              result = evaluate_condition(cond, events)
              condition_results << result[:matched]
              matched_events.concat(result[:events]) if result[:matched]
            end
            any_matched = condition_results.any?
            confidence = any_matched ? (condition_results.count(true).to_f / condition_results.size * 80).round : 0
            { matched: any_matched, matched_events: matched_events.uniq, confidence: confidence }

          else
            { matched: false, matched_events: [], confidence: 0 }
          end
        end

        def evaluate_condition(condition, events)
          matching = events.dup

          # Filter by category
          if condition[:category]
            matching = matching.select { |e| e[:category] == condition[:category] }
          end

          # Filter by pattern on a specific field
          if condition[:pattern] && condition[:field]
            matching = matching.select do |e|
              value = e[condition[:field]].to_s
              value.match?(condition[:pattern])
            end
          end

          # Check minimum count
          if condition[:min_count]
            count_met = matching.size >= condition[:min_count]
            return { matched: count_met, events: matching.first(5) }
          end

          # Check time window
          if condition[:within_seconds] && matching.size >= 2
            first_time = Time.parse(matching.first[:timestamp])
            last_time = Time.parse(matching.last[:timestamp])
            within = (last_time - first_time) <= condition[:within_seconds]
            return { matched: within && matching.any?, events: matching.first(5) }
          end

          { matched: matching.any?, events: matching.first(5) }
        end

        def load_builtin_rules
          BUILTIN_RULES.map { |r| Rule.new(**r) }
        end

        def load_custom_rules(custom_rules)
          custom_rules.map do |r|
            r.is_a?(Rule) ? r : Rule.new(**symbolize_keys(r))
          end
        rescue StandardError => e
          @logger.error("[PatternMatcher] Error loading custom rules: #{e.message}")
          []
        end

        def symbolize_keys(hash)
          hash.each_with_object({}) { |(k, v), h| h[k.to_sym] = v.is_a?(Hash) ? symbolize_keys(v) : v }
        end

        def default_logger
          Logger.new($stdout, progname: "RubyGuardian::PatternMatcher")
        end
      end
    end
  end
end
