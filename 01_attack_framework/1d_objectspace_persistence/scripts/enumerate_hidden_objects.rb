#!/usr/bin/env ruby
# frozen_string_literal: true

# RubyGuardian -- Enumerate Hidden Objects in ObjectSpace
#
# Scans Ruby ObjectSpace for anomalous objects that may indicate
# persistence techniques: anonymous classes, ghost objects, and
# suspicious method patches.
#
# Usage: ruby enumerate_hidden_objects.rb [--verbose]

require 'json'
require 'optparse'

module RubyGuardian
  module Scripts
    class ObjectSpaceEnumerator
      def initialize(verbose: false)
        @verbose = verbose
        @findings = { anonymous_classes: [], suspicious_objects: [], patched_methods: [] }
      end

      def run
        puts '[*] RubyGuardian ObjectSpace Enumeration'
        puts '=' * 50

        scan_anonymous_classes
        scan_suspicious_strings
        scan_method_patches
        print_summary
      end

      private

      def scan_anonymous_classes
        puts "\n[*] Scanning for anonymous classes..."
        count = 0
        ObjectSpace.each_object(Class) do |klass|
          next if klass.name

          count += 1
          entry = {
            object_id: klass.object_id,
            superclass: klass.superclass&.name || 'BasicObject',
            methods: klass.instance_methods(false).map(&:to_s),
            ivars: klass.instance_variables.map(&:to_s)
          }
          @findings[:anonymous_classes] << entry
          puts "  [!] Anonymous class (id: #{klass.object_id}, super: #{entry[:superclass]}, methods: #{entry[:methods].size})" if @verbose
        end
        puts "  Found #{count} anonymous classes"
      end

      def scan_suspicious_strings
        puts "\n[*] Scanning for suspicious strings in ObjectSpace..."
        patterns = [/\beval\b/, /\bsystem\b/, /\b`.*`\b/, /Base64\.decode/]
        count = 0

        ObjectSpace.each_object(String) do |str|
          next if str.frozen? && str.length < 10

          patterns.each do |pattern|
            if str.match?(pattern)
              count += 1
              @findings[:suspicious_objects] << {
                type: 'String',
                preview: str[0..80],
                pattern: pattern.source,
                object_id: str.object_id
              }
              break
            end
          end
        end
        puts "  Found #{count} suspicious strings"
      end

      def scan_method_patches
        puts "\n[*] Scanning for method patches..."
        count = 0

        ObjectSpace.each_object(Module) do |mod|
          next unless mod.name

          ancestors = mod.ancestors
          prepended = ancestors.take_while { |a| a != mod }
          next if prepended.empty?

          anonymous_prepends = prepended.reject(&:name)
          next if anonymous_prepends.empty?

          count += anonymous_prepends.size
          @findings[:patched_methods] << {
            module: mod.name,
            anonymous_prepends: anonymous_prepends.size,
            prepend_methods: anonymous_prepends.flat_map { |p| p.instance_methods(false).map(&:to_s) }
          }
        end
        puts "  Found #{count} anonymous prepended modules"
      end

      def print_summary
        puts "\n" + '=' * 50
        puts '[*] Summary'
        puts "  Anonymous classes:     #{@findings[:anonymous_classes].size}"
        puts "  Suspicious strings:    #{@findings[:suspicious_objects].size}"
        puts "  Method patches:        #{@findings[:patched_methods].size}"

        total = @findings.values.map(&:size).sum
        if total > 0
          puts "\n  [!] #{total} potential indicators found"
        else
          puts "\n  [+] No suspicious indicators found"
        end
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  verbose = ARGV.include?('--verbose') || ARGV.include?('-v')
  RubyGuardian::Scripts::ObjectSpaceEnumerator.new(verbose: verbose).run
end
