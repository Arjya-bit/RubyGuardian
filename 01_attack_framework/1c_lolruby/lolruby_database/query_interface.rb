# frozen_string_literal: true

# RubyGuardian Phase 1c -- LoLRuby Database Query Interface
#
# Provides a searchable database of "Living off the Land" Ruby techniques.
# Maps standard Ruby libraries and features to MITRE ATT&CK techniques,
# allowing researchers to query for attack primitives by tactic, technique,
# or Ruby API surface.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.

require 'yaml'
require 'json'

module RubyGuardian
  module LoLRuby
    class QueryInterface
      TACTICS = %w[
        reconnaissance credential_access execution persistence
        defense_evasion exfiltration lateral_movement
      ].freeze

      attr_reader :techniques, :loaded_at

      def initialize(database_path: nil)
        @database_path = database_path || default_database_path
        @techniques = []
        @loaded_at = nil
        load_database!
      end

      # Search techniques by tactic category
      def by_tactic(tactic)
        tactic = tactic.to_s.downcase
        @techniques.select { |t| t[:tactic] == tactic }
      end

      # Search techniques by MITRE ATT&CK ID
      def by_mitre_id(mitre_id)
        @techniques.select { |t| t[:mitre_id]&.upcase == mitre_id.upcase }
      end

      # Search techniques by Ruby standard library used
      def by_stdlib(library_name)
        @techniques.select do |t|
          t[:ruby_apis]&.any? { |api| api.downcase.include?(library_name.downcase) }
        end
      end

      # Full-text search across technique names and descriptions
      def search(query)
        pattern = Regexp.new(Regexp.escape(query), Regexp::IGNORECASE)
        @techniques.select do |t|
          pattern.match?(t[:name].to_s) ||
            pattern.match?(t[:description].to_s) ||
            t[:ruby_apis]&.any? { |api| pattern.match?(api) }
        end
      end

      # Get all unique tactics in the database
      def available_tactics
        @techniques.map { |t| t[:tactic] }.uniq.sort
      end

      # Get detection signatures for a specific technique
      def detections_for(technique_name)
        tech = @techniques.find { |t| t[:name] == technique_name }
        return [] unless tech

        tech[:detection_indicators] || []
      end

      # Export the database as JSON for integration with other tools
      def export_json(output_path)
        data = {
          version: '1.0',
          generated_at: Time.now.utc.iso8601,
          technique_count: @techniques.size,
          techniques: @techniques
        }
        File.write(output_path, JSON.pretty_generate(data))
      end

      # Get statistics about the database
      def stats
        {
          total_techniques: @techniques.size,
          by_tactic: TACTICS.map { |t| [t, by_tactic(t).size] }.to_h,
          unique_ruby_apis: @techniques.flat_map { |t| t[:ruby_apis] || [] }.uniq.size,
          unique_mitre_ids: @techniques.map { |t| t[:mitre_id] }.compact.uniq.size,
          loaded_at: @loaded_at
        }
      end

      private

      def default_database_path
        File.join(__dir__, 'database_schema.rb')
      end

      def load_database!
        if File.exist?(@database_path) && @database_path.end_with?('.yml', '.yaml')
          @techniques = YAML.safe_load(File.read(@database_path), permitted_classes: [Symbol]) || []
        else
          load_builtin_database!
        end
        @loaded_at = Time.now.utc
      end

      def load_builtin_database!
        @techniques = [
          {
            name: 'net_http_recon', tactic: 'reconnaissance',
            mitre_id: 'T1595', description: 'Use Net::HTTP for network scanning',
            ruby_apis: ['Net::HTTP', 'URI', 'Socket'],
            detection_indicators: ['Rapid sequential HTTP requests', 'Connection to many unique hosts'],
            risk_level: 'low'
          },
          {
            name: 'open3_execution', tactic: 'execution',
            mitre_id: 'T1059', description: 'Execute commands via Open3 popen methods',
            ruby_apis: ['Open3.popen3', 'Open3.capture3', 'IO.popen'],
            detection_indicators: ['Shell spawned from Ruby process', 'Command contains encoded strings'],
            risk_level: 'high'
          },
          {
            name: 'drb_lateral_movement', tactic: 'lateral_movement',
            mitre_id: 'T1021', description: 'Abuse DRb for remote code execution',
            ruby_apis: ['DRb', 'DRbServer', 'DRbObject'],
            detection_indicators: ['DRb protocol on non-standard ports', 'Remote object method invocations'],
            risk_level: 'critical'
          },
          {
            name: 'eval_execution', tactic: 'execution',
            mitre_id: 'T1059.007', description: 'Dynamic code execution via eval/instance_eval',
            ruby_apis: ['Kernel.eval', 'BasicObject#instance_eval', 'Module#class_eval'],
            detection_indicators: ['eval called with network-sourced input', 'Base64 decoded eval argument'],
            risk_level: 'critical'
          },
          {
            name: 'file_persistence', tactic: 'persistence',
            mitre_id: 'T1546', description: 'Write to Ruby load path for persistence',
            ruby_apis: ['File.write', '$LOAD_PATH', 'Gem.path'],
            detection_indicators: ['Writes to gem directories', 'Modified .rb files in load path'],
            risk_level: 'high'
          },
          {
            name: 'base64_evasion', tactic: 'defense_evasion',
            mitre_id: 'T1027', description: 'Encode payloads with Base64/Marshal',
            ruby_apis: ['Base64.decode64', 'Marshal.load', 'Zlib::Inflate'],
            detection_indicators: ['Base64 decode followed by eval', 'Marshal.load from untrusted source'],
            risk_level: 'high'
          },
          {
            name: 'socket_exfiltration', tactic: 'exfiltration',
            mitre_id: 'T1048', description: 'Exfiltrate data via raw sockets or DNS',
            ruby_apis: ['TCPSocket', 'UDPSocket', 'Resolv::DNS'],
            detection_indicators: ['Large data written to non-standard ports', 'DNS TXT record queries'],
            risk_level: 'high'
          },
          {
            name: 'env_credential_access', tactic: 'credential_access',
            mitre_id: 'T1552.001', description: 'Harvest credentials from ENV and config files',
            ruby_apis: ['ENV', 'YAML.load_file', 'File.read'],
            detection_indicators: ['Access to credential-related ENV vars', 'Reading .env or secrets files'],
            risk_level: 'medium'
          }
        ]
      end
    end
  end
end
