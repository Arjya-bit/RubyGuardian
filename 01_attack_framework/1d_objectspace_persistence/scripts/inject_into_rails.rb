#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1d -- Demo: Inject into Rails Process
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use this script against production systems or systems you do not own.
#
# This script demonstrates how an attacker could inject persistent objects
# into a running Rails application process. It simulates the injection by
# creating a mock Rails environment and showing each step of the attack.
#
# MITRE ATT&CK: T1055 - Process Injection
#
# DETECTION METHODS:
# - Monitor ObjectSpace.count_objects for unexpected increases
# - Audit instance_variables on Rails.application and middleware objects
# - Use ObjectSpace.trace_object_allocations to track injection source
# - Compare heap dumps before and after suspected compromise
# =============================================================================

require 'json'
require 'optparse'
require 'logger'

# Load persistence modules
lib_dir = File.expand_path('../lib', __dir__)
require File.join(lib_dir, 'objectspace_injector')
require File.join(lib_dir, 'gc_anchor')
require File.join(lib_dir, 'heap_hider')
require File.join(lib_dir, 'callback_installer')
require File.join(lib_dir, 'memory_cloaker')

module RubyGuardian
  module Scripts
    class RailsInjectionDemo
      BANNER = <<~BANNER
        ╔══════════════════════════════════════════════════════════════╗
        ║  RubyGuardian -- Rails Process Injection Demo              ║
        ║  EDUCATIONAL PURPOSE ONLY -- Authorized research only      ║
        ╚══════════════════════════════════════════════════════════════╝
      BANNER

      def initialize(options = {})
        @verbose = options.fetch(:verbose, false)
        @dry_run = options.fetch(:dry_run, true)
        @output = options.fetch(:output, $stdout)
        @logger = Logger.new(@verbose ? $stderr : File::NULL)
        @steps_completed = []
      end

      def run
        @output.puts BANNER
        @output.puts "[*] Mode: #{@dry_run ? 'DRY RUN (safe)' : 'LIVE (educational demo)'}"
        @output.puts "[*] Started at: #{Time.now.utc.iso8601}"
        @output.puts

        step_1_create_mock_rails_env
        step_2_baseline_snapshot
        step_3_inject_payload
        step_4_hide_payload
        step_5_install_callbacks
        step_6_verify_persistence
        step_7_forensic_analysis
        print_summary
      end

      private

      # Step 1: Create a simulated Rails-like environment
      def step_1_create_mock_rails_env
        @output.puts "[Step 1] Creating mock Rails environment..."

        # Simulate Rails.application object with typical instance variables
        @mock_app = Object.new
        @mock_app.instance_variable_set(:@config, {
          'secret_key_base' => 'fake_key_for_demo_only',
          'database' => { 'adapter' => 'postgresql', 'host' => 'localhost' },
          'cache_store' => :memory_store
        })
        @mock_app.instance_variable_set(:@middleware, [
          'Rack::Sendfile', 'ActionDispatch::Executor',
          'Rack::Runtime', 'ActionDispatch::RequestId'
        ])
        @mock_app.instance_variable_set(:@routes, Object.new)
        @mock_app.instance_variable_set(:@initialized, true)

        # Simulate a controller class
        @mock_controller = Class.new do
          def self.name; 'ApplicationController'; end
        end

        @output.puts "  [+] Mock Rails.application created (#{@mock_app.instance_variables.size} ivars)"
        @output.puts "  [+] Mock ApplicationController created"
        @steps_completed << :mock_environment
      end

      # Step 2: Capture ObjectSpace baseline for comparison
      def step_2_baseline_snapshot
        @output.puts "\n[Step 2] Capturing ObjectSpace baseline..."

        @baseline = ObjectSpace.count_objects.dup
        @baseline_classes = ObjectSpace.each_object(Class).count

        @output.puts "  [+] Baseline: #{@baseline[:TOTAL]} total objects"
        @output.puts "  [+] Baseline: #{@baseline_classes} Class objects"
        @output.puts "  [+] Baseline: #{@baseline[:T_STRING]} String objects"
        @steps_completed << :baseline_captured
      end

      # Step 3: Inject payload into the mock Rails process
      def step_3_inject_payload
        @output.puts "\n[Step 3] Injecting payload into process..."

        @injector = ObjectSpacePersistence::ObjectSpaceInjector.new(verbose: @verbose)

        # Inject a simulated command-and-control payload
        @payload = {
          type: 'c2_config',
          callback_url: 'https://demo.example.com/beacon',
          interval: 300,
          commands: ['status', 'exfiltrate', 'persist'],
          note: 'EDUCATIONAL DEMO - NOT A REAL PAYLOAD'
        }

        @payload_oid = @injector.inject(@payload, anchor_strategy: :thread_local)
        @output.puts "  [+] Payload injected (object_id: #{@payload_oid})"

        # Also inject into the mock application object directly
        @injector.inject_into_target(
          @mock_app,
          @payload,
          var_name: '@_action_methods_cache'
        )
        @output.puts "  [+] Payload attached to mock Rails.application as @_action_methods_cache"

        @steps_completed << :payload_injected
      end

      # Step 4: Hide the payload using heap hiding techniques
      def step_4_hide_payload
        @output.puts "\n[Step 4] Hiding payload in heap..."

        @hider = ObjectSpacePersistence::HeapHider.new(verbose: @verbose)

        # Hide in the mock app's config hash
        @hider.hide_in_hash(
          @payload,
          target: @mock_app,
          hash_ivar: '@config',
          key: 'session_store_options_v3'
        )
        @output.puts "  [+] Payload hidden in @config hash as 'session_store_options_v3'"

        # Hide in the middleware array
        @hider.hide_in_array(
          proc { @payload },
          target: @mock_app,
          array_ivar: '@middleware'
        )
        @output.puts "  [+] Payload Proc hidden in @middleware array"

        # Cloak with inspect override (dry_run respects @dry_run flag)
        @cloaker = ObjectSpacePersistence::MemoryCloaker.new(
          logger: @logger,
          dry_run: @dry_run
        )
        @cloaker.cloak_inspect(
          @mock_app.instance_variable_get(:@config),
          disguise_as: 'ActiveSupport::Cache::Entry'
        )
        @output.puts "  [+] Config hash cloaked as ActiveSupport::Cache::Entry"

        @steps_completed << :payload_hidden
      end

      # Step 5: Install persistence callbacks
      def step_5_install_callbacks
        @output.puts "\n[Step 5] Installing persistence callbacks..."

        @callback_installer = ObjectSpacePersistence::CallbackInstaller.new(
          logger: @logger,
          dry_run: @dry_run
        )

        @callback_installer.install_at_exit(tag: 'beacon_on_shutdown')
        @output.puts "  [+] at_exit beacon callback registered (dry_run=#{@dry_run})"

        @callback_installer.install_tracepoint(
          events: [:call],
          tag: 'auth_monitor',
          filter_class: nil
        )
        @output.puts "  [+] TracePoint auth monitor registered (dry_run=#{@dry_run})"

        @steps_completed << :callbacks_installed
      end

      # Step 6: Verify persistence through GC stress
      def step_6_verify_persistence
        @output.puts "\n[Step 6] Verifying persistence through GC cycles..."

        5.times do |i|
          # Allocate garbage to trigger GC pressure
          10_000.times { Object.new }
          GC.start(full_mark: true, immediate_sweep: true)
        end

        report = @injector.status_report
        @output.puts "  [+] After 5 GC cycles:"
        @output.puts "      Alive: #{report[:alive]} / #{report[:total_injected]} injected objects"
        @output.puts "      Collected: #{report[:collected]}"

        @steps_completed << :persistence_verified
      end

      # Step 7: Show forensic analysis (what a defender would see)
      def step_7_forensic_analysis
        @output.puts "\n[Step 7] Forensic analysis (defender perspective)..."

        current = ObjectSpace.count_objects
        @output.puts "\n  ObjectSpace delta since baseline:"
        @baseline.each do |type, count|
          delta = (current[type] || 0) - count
          @output.puts "    #{type}: #{delta > 0 ? '+' : ''}#{delta}" if delta.abs > 10
        end

        @output.puts "\n  Mock Rails.application instance variables:"
        @mock_app.instance_variables.each do |ivar|
          val = @mock_app.instance_variable_get(ivar)
          @output.puts "    #{ivar}: #{val.class} (#{val.inspect[0..60]})"
        end

        # Check for anomalies
        hider_report = @hider.forensic_report
        @output.puts "\n  HeapHider forensic report: #{hider_report.size} hidden payloads"
        hider_report.each do |record|
          @output.puts "    - #{record[:target_class]} / #{record[:ivar_name] || record[:hash_ivar] || record[:array_ivar]} (alive: #{record[:still_alive]})"
        end

        @steps_completed << :forensic_analysis
      end

      def print_summary
        @output.puts "\n" + '=' * 60
        @output.puts "[*] Injection Demo Complete"
        @output.puts "    Steps completed: #{@steps_completed.size}/7"
        @output.puts "    Mode: #{@dry_run ? 'DRY RUN' : 'LIVE'}"
        @output.puts
        @output.puts "  EDUCATIONAL TAKEAWAYS:"
        @output.puts "  1. Ruby's open object model allows runtime injection into any object"
        @output.puts "  2. Payloads can be disguised using innocent-looking ivar names"
        @output.puts "  3. GC anchoring prevents cleanup of injected objects"
        @output.puts "  4. Callbacks provide automatic re-activation"
        @output.puts "  5. Defenders should use ObjectSpace.dump_all, not inspect, for forensics"
        @output.puts '=' * 60

        # Cleanup
        @injector&.cleanup!
        @callback_installer&.cleanup!
        @cloaker&.cleanup!
        ObjectSpacePersistence::GCAnchhor.release_all
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  options = { verbose: false, dry_run: true }

  OptionParser.new do |opts|
    opts.banner = "Usage: ruby inject_into_rails.rb [options]"
    opts.on('-v', '--verbose', 'Enable verbose logging') { options[:verbose] = true }
    opts.on('--live', 'Run in live mode (not dry run)') { options[:dry_run] = false }
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end.parse!

  RubyGuardian::Scripts::RailsInjectionDemo.new(options).run
end
