#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1d -- Dump Full ObjectSpace for Analysis
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# Forensic tool that dumps the entire ObjectSpace of the current Ruby process,
# categorizing objects by type, identifying anomalies, and generating reports
# suitable for post-compromise analysis.
#
# Usage:
#   ruby dump_objectspace.rb [--format json|text] [--output file] [--verbose]
#
# DETECTION VALUE:
# - Establishes baselines for normal Ruby process object distribution
# - Identifies anonymous classes, suspicious Procs, and unexpected objects
# - Detects signs of ObjectSpace injection and memory persistence
# =============================================================================

require 'json'
require 'optparse'
require 'objspace'

module RubyGuardian
  module Scripts
    class ObjectSpaceDumper
      BANNER = <<~BANNER
        ╔══════════════════════════════════════════════════════════════╗
        ║  RubyGuardian -- ObjectSpace Forensic Dump                 ║
        ║  EDUCATIONAL PURPOSE ONLY                                  ║
        ╚══════════════════════════════════════════════════════════════╝
      BANNER

      # Object types that are suspicious when present in unusual quantities
      SUSPICIOUS_THRESHOLDS = {
        anonymous_classes: 50,
        eval_procs: 5,
        singleton_overrides: 20,
        global_variables_custom: 10
      }.freeze

      def initialize(options = {})
        @format = options.fetch(:format, :text)
        @output_path = options.fetch(:output, nil)
        @verbose = options.fetch(:verbose, false)
        @findings = {
          summary: {},
          object_counts: {},
          anonymous_classes: [],
          suspicious_procs: [],
          singleton_overrides: [],
          global_variables: [],
          finalizers: [],
          anomalies: []
        }
      end

      def run
        puts BANNER
        puts "[*] Starting ObjectSpace dump at #{Time.now.utc.iso8601}"
        puts "[*] Ruby version: #{RUBY_VERSION} (#{RUBY_PLATFORM})"
        puts "[*] PID: #{Process.pid}"
        puts

        collect_object_counts
        scan_anonymous_classes
        scan_suspicious_procs
        scan_singleton_overrides
        scan_global_variables
        scan_finalizer_count
        detect_anomalies
        generate_report
      end

      private

      def collect_object_counts
        puts "[1/7] Collecting object counts..."

        counts = ObjectSpace.count_objects
        @findings[:object_counts] = counts

        # Also count by Ruby class
        class_counts = Hash.new(0)
        ObjectSpace.each_object do |obj|
          class_counts[obj.class.name || '(anonymous)'] += 1
        end

        @findings[:class_distribution] = class_counts
                                           .sort_by { |_, v| -v }
                                           .first(30)
                                           .to_h

        puts "  Total objects: #{counts[:TOTAL]}"
        puts "  FREE slots: #{counts[:FREE]}"
        puts "  T_OBJECT: #{counts[:T_OBJECT]}"
        puts "  T_CLASS: #{counts[:T_CLASS]}"
        puts "  T_STRING: #{counts[:T_STRING]}"
        puts "  T_ARRAY: #{counts[:T_ARRAY]}"
        puts "  T_HASH: #{counts[:T_HASH]}"
        puts "  T_DATA: #{counts[:T_DATA]}"
      end

      def scan_anonymous_classes
        puts "\n[2/7] Scanning for anonymous classes..."

        ObjectSpace.each_object(Class) do |klass|
          next if klass.name

          entry = {
            object_id: klass.object_id,
            superclass: klass.superclass&.name || 'BasicObject',
            instance_methods: klass.instance_methods(false).map(&:to_s),
            class_variables: (klass.class_variables rescue []).map(&:to_s),
            instance_variables: klass.instance_variables.map(&:to_s)
          }

          # Try to get allocation info
          begin
            entry[:allocation_sourcefile] = ObjectSpace.allocation_sourcefile(klass)
            entry[:allocation_sourceline] = ObjectSpace.allocation_sourceline(klass)
          rescue StandardError
            # Allocation tracing may not be active
          end

          @findings[:anonymous_classes] << entry
          if @verbose
            puts "  [!] Anon class (id:#{klass.object_id} super:#{entry[:superclass]} methods:#{entry[:instance_methods].size})"
          end
        end

        puts "  Found #{@findings[:anonymous_classes].size} anonymous classes"
      end

      def scan_suspicious_procs
        puts "\n[3/7] Scanning for suspicious Proc objects..."

        ObjectSpace.each_object(Proc) do |p|
          loc = p.source_location
          next unless loc

          file, line = loc
          suspicious = false
          reason = []

          if file&.include?('(eval)')
            suspicious = true
            reason << 'eval_source'
          end

          if file&.start_with?('/tmp', '/var/tmp', '/dev/shm')
            suspicious = true
            reason << 'temp_directory_source'
          end

          if file && !File.exist?(file) && !file.include?('(eval)')
            suspicious = true
            reason << 'missing_source_file'
          end

          if suspicious
            @findings[:suspicious_procs] << {
              object_id: p.object_id,
              source_location: loc,
              arity: p.arity,
              lambda: p.lambda?,
              reasons: reason
            }
            puts "  [!] Suspicious Proc at #{file}:#{line} (#{reason.join(', ')})" if @verbose
          end
        end

        puts "  Found #{@findings[:suspicious_procs].size} suspicious Procs"
      end

      def scan_singleton_overrides
        puts "\n[4/7] Scanning for singleton method overrides..."

        check_methods = [:inspect, :to_s, :class, :respond_to?, :is_a?]
        count = 0

        ObjectSpace.each_object(Object) do |obj|
          next if obj.frozen? && obj.is_a?(String)
          next if obj.is_a?(Class) || obj.is_a?(Module)

          begin
            sm = obj.singleton_class.instance_methods(false)
            overridden = check_methods & sm
            next if overridden.empty?

            count += 1
            @findings[:singleton_overrides] << {
              object_id: obj.object_id,
              actual_class: obj.method(:object_id).owner.name rescue 'unknown',
              overridden_methods: overridden.map(&:to_s)
            }
          rescue TypeError
            next
          end

          break if count > 500 # Safety limit
        end

        puts "  Found #{@findings[:singleton_overrides].size} objects with singleton overrides"
      end

      def scan_global_variables
        puts "\n[5/7] Scanning global variables..."

        # Standard Ruby globals to ignore
        standard_globals = %w[
          $LOAD_PATH $LOADED_FEATURES $stdout $stderr $stdin
          $PROGRAM_NAME $0 $VERBOSE $DEBUG $SAFE $; $/ $\\ $,
          $. $_ $~ $! $@ $& $` $' $+ $1 $2 $3 $4 $5 $6 $7 $8 $9
        ]

        global_variables.each do |gvar|
          next if standard_globals.include?(gvar.to_s)

          begin
            value = eval(gvar.to_s)
            @findings[:global_variables] << {
              name: gvar.to_s,
              class: value.class.name,
              inspect_preview: value.inspect[0..80]
            }
            puts "  [?] #{gvar} = #{value.class} (#{value.inspect[0..40]})" if @verbose
          rescue StandardError
            next
          end
        end

        puts "  Found #{@findings[:global_variables].size} non-standard global variables"
      end

      def scan_finalizer_count
        puts "\n[6/7] Estimating finalizer registrations..."

        # We cannot directly enumerate finalizers, but we can check GC stats
        gc_stat = GC.stat
        @findings[:gc_stats] = gc_stat
        puts "  GC count: #{gc_stat[:count]}"
        puts "  Heap pages: #{gc_stat[:heap_allocated_pages]}"
        puts "  Total allocated objects: #{gc_stat[:total_allocated_objects]}"
        puts "  Total freed objects: #{gc_stat[:total_freed_objects]}"
      end

      def detect_anomalies
        puts "\n[7/7] Detecting anomalies..."

        if @findings[:anonymous_classes].size > SUSPICIOUS_THRESHOLDS[:anonymous_classes]
          @findings[:anomalies] << {
            type: 'excessive_anonymous_classes',
            count: @findings[:anonymous_classes].size,
            threshold: SUSPICIOUS_THRESHOLDS[:anonymous_classes],
            severity: 'medium'
          }
        end

        if @findings[:suspicious_procs].size > SUSPICIOUS_THRESHOLDS[:eval_procs]
          @findings[:anomalies] << {
            type: 'excessive_eval_procs',
            count: @findings[:suspicious_procs].size,
            threshold: SUSPICIOUS_THRESHOLDS[:eval_procs],
            severity: 'high'
          }
        end

        if @findings[:singleton_overrides].size > SUSPICIOUS_THRESHOLDS[:singleton_overrides]
          @findings[:anomalies] << {
            type: 'excessive_singleton_overrides',
            count: @findings[:singleton_overrides].size,
            threshold: SUSPICIOUS_THRESHOLDS[:singleton_overrides],
            severity: 'high'
          }
        end

        if @findings[:anomalies].empty?
          puts "  [+] No anomalies detected above thresholds"
        else
          @findings[:anomalies].each do |a|
            puts "  [!] ANOMALY: #{a[:type]} (#{a[:count]} > threshold #{a[:threshold]}, severity: #{a[:severity]})"
          end
        end
      end

      def generate_report
        @findings[:summary] = {
          timestamp: Time.now.utc.iso8601,
          ruby_version: RUBY_VERSION,
          platform: RUBY_PLATFORM,
          pid: Process.pid,
          total_objects: @findings[:object_counts][:TOTAL],
          anonymous_classes: @findings[:anonymous_classes].size,
          suspicious_procs: @findings[:suspicious_procs].size,
          singleton_overrides: @findings[:singleton_overrides].size,
          anomaly_count: @findings[:anomalies].size
        }

        output = case @format
                 when :json
                   JSON.pretty_generate(@findings)
                 when :text
                   generate_text_report
                 end

        if @output_path
          File.write(@output_path, output)
          puts "\n[*] Report written to #{@output_path}"
        else
          puts "\n" + '=' * 60
          puts output
        end
      end

      def generate_text_report
        lines = []
        lines << "ObjectSpace Forensic Report"
        lines << "=" * 40
        lines << "Time: #{@findings[:summary][:timestamp]}"
        lines << "Ruby: #{RUBY_VERSION} (#{RUBY_PLATFORM})"
        lines << "PID: #{Process.pid}"
        lines << ""
        lines << "Object Counts:"
        @findings[:object_counts].each { |k, v| lines << "  #{k}: #{v}" }
        lines << ""
        lines << "Top Classes by Instance Count:"
        (@findings[:class_distribution] || {}).first(15).each { |k, v| lines << "  #{v.to_s.rjust(8)}  #{k}" }
        lines << ""
        lines << "Anomalies: #{@findings[:anomalies].size}"
        @findings[:anomalies].each { |a| lines << "  [#{a[:severity].upcase}] #{a[:type]}: #{a[:count]}" }
        lines.join("\n")
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  options = { format: :text, verbose: false }

  OptionParser.new do |opts|
    opts.banner = "Usage: ruby dump_objectspace.rb [options]"
    opts.on('-f', '--format FORMAT', [:text, :json], 'Output format (text/json)') { |f| options[:format] = f }
    opts.on('-o', '--output FILE', 'Write report to file') { |f| options[:output] = f }
    opts.on('-v', '--verbose', 'Verbose output') { options[:verbose] = true }
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end.parse!

  RubyGuardian::Scripts::ObjectSpaceDumper.new(options).run
end
