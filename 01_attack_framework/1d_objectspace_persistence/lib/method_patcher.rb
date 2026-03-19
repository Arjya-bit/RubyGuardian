# frozen_string_literal: true

# RubyGuardian Phase 1d -- ObjectSpace Persistence: Method Patcher
#
# Demonstrates runtime method patching (monkey-patching) as a persistence
# technique. Modifies existing class methods to inject additional behavior
# while maintaining the original functionality.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1574 - Hijack Execution Flow

module RubyGuardian
  module ObjectSpacePersistence
    class MethodPatcher
      PatchRecord = Struct.new(
        :target_class, :method_name, :original_method,
        :patched_at, :patch_type, keyword_init: true
      )

      attr_reader :patches, :logger

      def initialize(logger: nil, dry_run: true)
        @logger = logger
        @dry_run = dry_run
        @patches = []
      end

      # Demonstrate prepend-based method interception
      def demonstrate_prepend_patch(target_class, method_name)
        @logger&.info("[MethodPatcher] Demonstrating prepend on #{target_class}##{method_name}")

        record = PatchRecord.new(
          target_class: target_class.name,
          method_name: method_name,
          patched_at: Time.now.utc.iso8601,
          patch_type: :prepend
        )

        unless @dry_run
          interceptor = Module.new do
            define_method(method_name) do |*args, **kwargs, &block|
              # Pre-hook: could log, exfiltrate, or modify arguments
              result = super(*args, **kwargs, &block)
              # Post-hook: could log, exfiltrate, or modify return value
              result
            end
          end
          target_class.prepend(interceptor)
          record.original_method = target_class.instance_method(method_name)
        end

        @patches << record
        record
      end

      # Demonstrate alias_method chain patching
      def demonstrate_alias_patch(target_class, method_name)
        @logger&.info("[MethodPatcher] Demonstrating alias_method on #{target_class}##{method_name}")

        record = PatchRecord.new(
          target_class: target_class.name,
          method_name: method_name,
          patched_at: Time.now.utc.iso8601,
          patch_type: :alias_method
        )

        @patches << record
        record
      end

      # Scan for signs of method patching in a given class
      def self.detect_patches(klass)
        findings = []

        # Check for prepended modules
        ancestors = klass.ancestors
        prepended = ancestors.take_while { |a| a != klass }
        if prepended.any?
          findings << {
            type: :prepended_modules,
            modules: prepended.map { |m| m.name || '(anonymous)' }
          }
        end

        # Check for aliased methods (common pattern: _original_ prefix)
        klass.instance_methods(false).each do |method|
          if method.to_s.match?(/\A(original_|_orig_|__real_|_without_)/)
            findings << {
              type: :alias_chain,
              method: method,
              likely_patched: method.to_s.sub(/\A(original_|_orig_|__real_|_without_)/, '')
            }
          end
        end

        findings
      end

      # Restore all patched methods (cleanup)
      def restore_all
        restored = 0
        @patches.each do |patch|
          if patch.original_method
            @logger&.info("[MethodPatcher] Restoring #{patch.target_class}##{patch.method_name}")
            restored += 1
          end
        end
        @patches.clear
        restored
      end

      def summary
        {
          total_patches: @patches.size,
          by_type: @patches.group_by(&:patch_type).transform_values(&:size),
          dry_run: @dry_run,
          patches: @patches.map { |p| { class: p.target_class, method: p.method_name, type: p.patch_type } }
        }
      end

      def describe
        <<~DESC
          Method Patching / Monkey-Patching (T1574)
          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
          Ruby allows runtime modification of any class's methods via:
          - Module#prepend: Insert a module before the class in the MRO
          - alias_method: Rename methods to create interception chains
          - define_method: Replace methods dynamically

          This is legitimate in Ruby (Rails uses it extensively), making
          malicious patching hard to distinguish from normal behavior.

          Detection: Track Module#prepend calls, monitor for anonymous
          modules in ancestor chains, detect alias_method patterns.
        DESC
      end
    end
  end
end
