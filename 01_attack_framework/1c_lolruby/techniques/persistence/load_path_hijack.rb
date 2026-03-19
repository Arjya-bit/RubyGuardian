# frozen_string_literal: true

# RubyGuardian Phase 1c -- LoLRuby Persistence: Load Path Hijacking
#
# Demonstrates persistence through Ruby's $LOAD_PATH manipulation and
# gem directory poisoning. Attackers can inject malicious code that gets
# loaded automatically when Ruby requires certain libraries.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1546 - Event Triggered Execution

module RubyGuardian
  module LoLRuby
    module Persistence
      class LoadPathHijack
        attr_reader :logger, :findings

        def initialize(logger: nil)
          @logger = logger
          @findings = []
        end

        # Enumerate all directories in $LOAD_PATH and check write permissions
        def audit_load_path
          @logger&.info('[LoLRuby] Auditing $LOAD_PATH for writable directories')

          $LOAD_PATH.each do |path|
            writable = File.writable?(path) rescue false
            entry = {
              path: path,
              exists: File.directory?(path),
              writable: writable,
              file_count: writable ? Dir.glob(File.join(path, '**/*.rb')).size : nil,
              risk: writable ? 'HIGH - writable load path' : 'low'
            }
            @findings << entry
          end

          writable_count = @findings.count { |f| f[:writable] }
          @logger&.info("[LoLRuby] Found #{writable_count} writable entries in $LOAD_PATH")
          @findings
        end

        # Enumerate installed gems and check for suspicious modifications
        def audit_gem_directories
          @logger&.info('[LoLRuby] Auditing gem directories')

          Gem.path.each do |gem_path|
            specs_dir = File.join(gem_path, 'specifications')
            next unless File.directory?(specs_dir)

            Dir.glob(File.join(specs_dir, '*.gemspec')).each do |spec_file|
              @findings << {
                source: 'gem_directory',
                gem_path: gem_path,
                spec: File.basename(spec_file),
                writable: File.writable?(spec_file)
              }
            end
          end

          @findings
        end

        # Demonstrate how require can be hijacked (educational - no actual hijack)
        def demonstrate_require_hijack
          {
            technique: 'require_hijack',
            description: 'Place a malicious file earlier in $LOAD_PATH to shadow a legitimate library',
            steps: [
              '1. Identify a commonly required gem (e.g., json, yaml, net/http)',
              '2. Find a writable directory that appears before the gem in $LOAD_PATH',
              '3. Place a malicious file with the same name in that directory',
              '4. When the application calls require, the malicious file loads first',
              '5. The malicious file can load the real library and inject additional code'
            ],
            detection: [
              'Monitor for new .rb files in $LOAD_PATH directories',
              'Compare file hashes against known-good gem contents',
              'Alert on $LOAD_PATH.unshift calls from non-Bundler sources',
              'Track require calls that resolve to unexpected file paths'
            ]
          }
        end

        def describe
          <<~DESC
            Load Path Hijacking (T1546)
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━
            Ruby resolves require calls by searching $LOAD_PATH directories
            in order. An attacker who can write to an early load path entry
            can shadow legitimate libraries with malicious versions.

            This is particularly dangerous in development environments where
            the current directory or writable paths may be in $LOAD_PATH.
          DESC
        end
      end
    end
  end
end
