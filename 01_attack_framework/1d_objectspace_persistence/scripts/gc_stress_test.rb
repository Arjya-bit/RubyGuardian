#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1d -- GC Stress Test for Anchored Objects
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# This script tests the resilience of various object anchoring strategies
# against aggressive garbage collection. It measures how well each strategy
# preserves objects through GC cycles, memory pressure, and compaction.
#
# Understanding GC resistance helps both attackers (persistence) and defenders
# (knowing which forensic artifacts survive cleanup attempts).
#
# Usage:
#   ruby gc_stress_test.rb [--rounds N] [--pressure N] [--verbose]
#
# MITRE ATT&CK: T1055 - Process Injection (persistence sub-technique)
# =============================================================================

require 'optparse'
require 'objspace'
require 'benchmark'

lib_dir = File.expand_path('../lib', __dir__)
require File.join(lib_dir, 'gc_anchor')
require File.join(lib_dir, 'objectspace_injector')

module RubyGuardian
  module Scripts
    class GCStressTest
      BANNER = <<~BANNER
        ╔══════════════════════════════════════════════════════════════╗
        ║  RubyGuardian -- GC Stress Test for Anchored Objects       ║
        ║  EDUCATIONAL PURPOSE ONLY                                  ║
        ╚══════════════════════════════════════════════════════════════╝
      BANNER

      # Anchoring strategies to test
      STRATEGIES = %i[
        thread_local constant global instance_var class_var finalizer
      ].freeze

      def initialize(options = {})
        @rounds = options.fetch(:rounds, 10)
        @pressure = options.fetch(:pressure, 50_000)
        @verbose = options.fetch(:verbose, false)
        @results = {}
      end

      def run
        puts BANNER
        puts "[*] GC Stress Test Configuration:"
        puts "    Rounds: #{@rounds}"
        puts "    Pressure per round: #{@pressure} objects"
        puts "    Strategies: #{STRATEGIES.join(', ')}"
        puts "    Ruby: #{RUBY_VERSION} (#{RUBY_PLATFORM})"
        puts "    GC: #{GC.stat[:gc_by_count] rescue 'N/A'}"
        puts

        baseline_gc_stats
        test_unanchored_baseline
        STRATEGIES.each { |strategy| test_strategy(strategy) }
        test_anchor_chain
        test_combined_pressure
        print_results
      end

      private

      def baseline_gc_stats
        puts "[Baseline] Capturing GC baseline..."
        GC.start(full_mark: true, immediate_sweep: true)
        @baseline_gc = GC.stat.dup
        @baseline_objects = ObjectSpace.count_objects[:TOTAL]
        puts "  Objects: #{@baseline_objects}"
        puts "  GC count: #{@baseline_gc[:count]}"
        puts
      end

      # Test: objects without any anchoring (should be collected)
      def test_unanchored_baseline
        puts "[Test] Unanchored objects (control group)..."

        objects = 100.times.map { +"unanchored_string_#{_1}" }
        object_ids = objects.map(&:object_id)

        # Release all references
        objects = nil

        survived = run_gc_stress(object_ids)
        @results[:unanchored] = {
          total: 100,
          survived: survived,
          rate: (survived.to_f / 100 * 100).round(1)
        }

        puts "  Survived: #{survived}/100 (#{@results[:unanchored][:rate]}%)"
        puts "  Expected: ~0% (no anchoring)"
        puts
      end

      # Test each anchoring strategy individually
      def test_strategy(strategy)
        puts "[Test] Strategy: #{strategy}..."

        injector = ObjectSpacePersistence::ObjectSpaceInjector.new(verbose: false)
        object_ids = []

        10.times do |i|
          payload = +"anchored_payload_#{strategy}_#{i}_#{rand(100_000)}"
          begin
            oid = injector.inject(payload, anchor_strategy: strategy)
            object_ids << oid
          rescue ArgumentError, StandardError => e
            puts "  [!] Strategy #{strategy} failed for object #{i}: #{e.message}" if @verbose
          end
        end

        timing = Benchmark.measure do
          survived = run_gc_stress(object_ids)
          @results[strategy] = {
            total: object_ids.size,
            survived: survived,
            rate: object_ids.empty? ? 0 : (survived.to_f / object_ids.size * 100).round(1)
          }
        end

        result = @results[strategy]
        puts "  Injected: #{result[:total]}"
        puts "  Survived #{@rounds} GC rounds: #{result[:survived]} (#{result[:rate]}%)"
        puts "  Time: #{timing.real.round(3)}s"

        # Cleanup
        injector.cleanup!
        puts
      end

      # Test anchor chains (multiple levels of indirection)
      def test_anchor_chain
        puts "[Test] Anchor chain (depth=5)..."

        anchor = ObjectSpacePersistence::GCAnchhor.new
        object_ids = []

        10.times do |i|
          obj = +"chain_payload_#{i}_#{rand(100_000)}"
          object_ids << obj.object_id
          anchor.create_anchor_chain(obj, depth: 5)
        end

        survived = run_gc_stress(object_ids)
        @results[:anchor_chain] = {
          total: 10,
          survived: survived,
          rate: (survived.to_f / 10 * 100).round(1)
        }

        puts "  Survived: #{survived}/10 (#{@results[:anchor_chain][:rate]}%)"
        ObjectSpacePersistence::GCAnchhor.release_all
        puts
      end

      # Test under extreme memory pressure
      def test_combined_pressure
        puts "[Test] Combined pressure test (all strategies + high allocation)..."

        injector = ObjectSpacePersistence::ObjectSpaceInjector.new(verbose: false)
        all_oids = []

        # Inject using multiple strategies
        [:thread_local, :constant, :global].each do |strategy|
          5.times do |i|
            payload = +"pressure_test_#{strategy}_#{i}"
            begin
              oid = injector.inject(payload, anchor_strategy: strategy)
              all_oids << oid
            rescue StandardError
              # Some strategies may fail under pressure
            end
          end
        end

        # Apply extreme pressure
        puts "  Applying extreme memory pressure (#{@pressure * 3} allocations)..."
        survived = 0
        timing = Benchmark.measure do
          (@rounds * 2).times do |round|
            # Allocate lots of objects to fill heap pages
            garbage = Array.new(@pressure) { Object.new }
            garbage = nil

            # Also allocate strings (different heap page type)
            str_garbage = Array.new(@pressure / 2) { "garbage_#{rand}" }
            str_garbage = nil

            GC.start(full_mark: true, immediate_sweep: true)

            if @verbose && (round % 5 == 0)
              alive = count_alive(all_oids)
              puts "    Round #{round}: #{alive}/#{all_oids.size} alive"
            end
          end

          survived = count_alive(all_oids)
        end

        @results[:combined_pressure] = {
          total: all_oids.size,
          survived: survived,
          rate: all_oids.empty? ? 0 : (survived.to_f / all_oids.size * 100).round(1)
        }

        puts "  Survived extreme pressure: #{survived}/#{all_oids.size} (#{@results[:combined_pressure][:rate]}%)"
        puts "  Time: #{timing.real.round(3)}s"
        puts "  Final GC count: #{GC.count}"

        injector.cleanup!
        puts
      end

      # Run GC stress rounds and return count of surviving objects
      def run_gc_stress(object_ids)
        @rounds.times do |round|
          # Create allocation pressure
          garbage = Array.new(@pressure) { Object.new }
          garbage = nil

          # Full GC with immediate sweep
          GC.start(full_mark: true, immediate_sweep: true)

          if @verbose && (round % 3 == 0)
            alive = count_alive(object_ids)
            puts "    Round #{round}: #{alive}/#{object_ids.size} alive" if @verbose
          end
        end

        count_alive(object_ids)
      end

      def count_alive(object_ids)
        object_ids.count do |oid|
          begin
            ObjectSpace._id2ref(oid)
            true
          rescue RangeError
            false
          end
        end
      end

      def print_results
        puts '=' * 65
        puts "GC Stress Test Results"
        puts '=' * 65
        puts
        puts format("%-25s %8s %8s %8s", "Strategy", "Total", "Survived", "Rate")
        puts '-' * 55

        @results.each do |strategy, data|
          rate_indicator = case data[:rate]
                           when 90..100 then "[STRONG]"
                           when 50..89 then "[MEDIUM]"
                           when 1..49 then "[WEAK]  "
                           else "[NONE]  "
                           end

          puts format("%-25s %8d %8d %7.1f%% %s",
                       strategy, data[:total], data[:survived], data[:rate], rate_indicator)
        end

        puts
        puts "EDUCATIONAL OBSERVATIONS:"
        puts "  - Thread-local and constant strategies typically show high survival"
        puts "  - Global variables are strong GC roots"
        puts "  - Unanchored objects should show ~0% survival (GC working correctly)"
        puts "  - Anchor chains provide redundancy against partial cleanup"
        puts "  - Defenders should use ObjectSpace.dump_all rather than relying on GC"
        puts
        puts "DEFENDER GUIDANCE:"
        puts "  - GC alone cannot remove anchored malicious objects"
        puts "  - Identify and remove the anchor (reference) to allow collection"
        puts "  - Process restart is the most reliable cleanup for compromised processes"
        puts '=' * 65
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  options = { rounds: 10, pressure: 50_000, verbose: false }

  OptionParser.new do |opts|
    opts.banner = "Usage: ruby gc_stress_test.rb [options]"
    opts.on('-r', '--rounds N', Integer, 'GC stress rounds') { |n| options[:rounds] = n }
    opts.on('-p', '--pressure N', Integer, 'Objects per pressure round') { |n| options[:pressure] = n }
    opts.on('-v', '--verbose', 'Verbose output') { options[:verbose] = true }
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end.parse!

  RubyGuardian::Scripts::GCStressTest.new(options).run
end
