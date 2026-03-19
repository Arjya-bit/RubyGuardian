# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1d -- ObjectSpace Persistence: Memory Cloaker
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use these techniques on systems without explicit authorization.
#
# Demonstrates how an attacker can cloak the presence of objects in Ruby's
# ObjectSpace by manipulating visibility, overriding inspection methods,
# and exploiting garbage collector behavior. Understanding these evasion
# techniques is critical for building robust forensic analysis tools.
#
# MITRE ATT&CK: T1070 - Indicator Removal / T1055 - Process Injection
#
# FORENSIC DETECTION:
# - Use ObjectSpace.dump_all for raw heap analysis (bypasses inspect overrides)
# - Compare ObjectSpace.count_objects deltas over time
# - Monitor for overridden #inspect, #to_s, #class methods on objects
# - Use ObjectSpace.trace_object_allocations for allocation source tracking
# =============================================================================

require 'objspace'

module RubyGuardian
  module ObjectSpacePersistence
    class MemoryCloaker
      # Common class names that blend in with framework internals
      DECOY_CLASS_NAMES = %w[
        Mutex Monitor ThreadSafe::Cache ActiveSupport::Cache::Entry
        Rack::Utils::HeaderHash ActionDispatch::Request::Session
        Concurrent::Map Arel::Nodes::Node
      ].freeze

      attr_reader :cloaked_objects, :logger

      def initialize(logger: nil, dry_run: true)
        @logger = logger
        @dry_run = dry_run
        @cloaked_objects = []
      end

      # Cloak an object by overriding its inspection methods.
      #
      # EDUCATIONAL: Ruby's #inspect, #to_s, and #class methods are used
      # by most debugging tools (irb, pry, debugger). By overriding these
      # on a specific object, an attacker can make it appear as a benign
      # framework object when examined casually.
      #
      # DETECTION: Use ObjectSpace.dump(obj) which reads raw object headers
      # instead of calling Ruby methods. Compare obj.class with the actual
      # klass pointer in the heap dump.
      #
      # @param object [Object] The object to cloak
      # @param disguise_as [String] Class name to impersonate
      # @return [Hash] Cloaking record
      def cloak_inspect(object, disguise_as: nil)
        disguise_as ||= DECOY_CLASS_NAMES.sample
        log("Cloaking object #{object.object_id} as #{disguise_as}")

        record = {
          strategy: :inspect_override,
          object_id: object.object_id,
          real_class: object.class.name,
          disguise_as: disguise_as,
          cloaked_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        unless @dry_run
          fake_id = "0x#{rand(2**48).to_s(16).rjust(12, '0')}"

          object.define_singleton_method(:inspect) do
            "#<#{disguise_as}:#{fake_id}>"
          end

          object.define_singleton_method(:to_s) do
            "#<#{disguise_as}:#{fake_id}>"
          end

          # Override class method to return a decoy
          decoy_class_name = disguise_as
          object.define_singleton_method(:class) do
            # Return a fake class-like response
            klass = Class.new
            klass.define_singleton_method(:name) { decoy_class_name }
            klass.define_singleton_method(:to_s) { decoy_class_name }
            klass.define_singleton_method(:inspect) { decoy_class_name }
            klass
          end

          record[:fake_address] = fake_id
        end

        @cloaked_objects << record
        record
      end

      # Cloak an object by wrapping it inside a legitimate-looking container.
      #
      # EDUCATIONAL: Instead of modifying the payload object directly, wrap
      # it inside a real framework class instance. This makes heap dumps
      # look normal because the outer object IS a legitimate class.
      #
      # DETECTION: Deep inspection of container objects; check if Hash/Array
      # values contain unexpected Proc or complex objects.
      #
      # @param payload [Object] The payload to hide
      # @param container_type [Symbol] Type of container to use
      # @return [Object] The container holding the payload
      def cloak_in_container(payload, container_type: :hash)
        log("Cloaking payload in #{container_type} container")

        record = {
          strategy: :container_wrap,
          payload_class: payload.class.name,
          container_type: container_type,
          cloaked_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        container = nil
        unless @dry_run
          container = case container_type
                      when :hash
                        # Disguise as a configuration cache hash
                        {
                          '__version' => '3.2.1',
                          '__generated_at' => Time.now.to_i,
                          '__config_store' => true,
                          '__data' => payload,
                          '__checksum' => Digest::MD5.hexdigest(payload.to_s) rescue 'none'
                        }
                      when :array
                        # Disguise as a middleware stack entry
                        [Time.now.to_f, 'CacheMiddleware', payload, { priority: 10 }]
                      when :struct
                        # Create a struct that looks like a cache entry
                        entry_class = Struct.new(:key, :value, :expires_at, :metadata)
                        entry_class.new(
                          "app:config:v#{rand(100)}",
                          payload,
                          Time.now + 3600,
                          { compressed: false, serializer: 'marshal' }
                        )
                      when :io_like
                        # Wrap in a StringIO-like object
                        require 'stringio'
                        sio = StringIO.new
                        sio.instance_variable_set(:@__wrapped_payload, payload)
                        sio.define_singleton_method(:__payload) { @__wrapped_payload }
                        sio
                      else
                        raise ArgumentError, "Unknown container type: #{container_type}"
                      end

          record[:container_object_id] = container.object_id
        end

        @cloaked_objects << record
        container
      end

      # Make an object harder to find via ObjectSpace.each_object.
      #
      # EDUCATIONAL: ObjectSpace.each_object iterates by class. If we can
      # change an object's apparent class or make it unenumerable, it becomes
      # invisible to simple ObjectSpace scans. Ruby's immediate values
      # (Fixnum, Symbol, true, false, nil) are not in ObjectSpace at all.
      #
      # Strategy: Encode the payload as a frozen string (which may be interned
      # and is easily overlooked among thousands of frozen strings).
      #
      # DETECTION: ObjectSpace.dump_all captures ALL objects regardless.
      # Use heap diff analysis rather than each_object scanning.
      #
      # @param payload [String] String payload to hide among frozen strings
      # @return [Hash] Cloaking record
      def cloak_as_frozen_string(payload)
        log("Cloaking payload as frozen string")

        record = {
          strategy: :frozen_string,
          original_class: payload.class.name,
          cloaked_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        unless @dry_run
          # Convert to string and freeze it
          # Frozen strings blend in with the thousands of frozen string literals
          encoded = Marshal.dump(payload).freeze rescue payload.to_s.freeze
          record[:encoded_object_id] = encoded.object_id
          record[:encoded_length] = encoded.length

          # Anchor it to prevent GC
          Thread.current[:"__str_cache_#{rand(10000)}"] = encoded
        end

        @cloaked_objects << record
        record
      end

      # Suppress allocation tracing for subsequent object creations.
      #
      # EDUCATIONAL: ObjectSpace.trace_object_allocations records the file,
      # line, and method where each object was allocated. Disabling it before
      # creating malicious objects means they have no allocation source info,
      # which is actually suspicious in itself but removes the direct link
      # to the attacker's code.
      #
      # DETECTION: Objects with nil source_location in a traced environment
      # are anomalous and should be flagged.
      #
      # @return [Hash] Status of allocation tracing manipulation
      def suppress_allocation_tracing
        log("Attempting to suppress allocation tracing")

        record = {
          strategy: :suppress_tracing,
          cloaked_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        unless @dry_run
          # Stop allocation tracing if it's running
          begin
            ObjectSpace.trace_object_allocations_stop
            record[:tracing_stopped] = true
            log("  Allocation tracing stopped")
          rescue StandardError => e
            record[:error] = e.message
            log("  Failed to stop tracing: #{e.message}")
          end
        end

        @cloaked_objects << record
        record
      end

      # Scan ObjectSpace for objects with overridden inspection methods.
      #
      # FORENSIC TOOL: Detects cloaked objects by checking if #inspect
      # or #class is defined in the singleton class (indicating override).
      #
      # @return [Array<Hash>] Suspicious objects with overridden methods
      def self.detect_cloaked_objects
        findings = []

        ObjectSpace.each_object(Object) do |obj|
          next if obj.frozen? && obj.is_a?(String)

          begin
            singleton = obj.singleton_class
            overridden = []

            overridden << :inspect if singleton.instance_methods(false).include?(:inspect)
            overridden << :to_s if singleton.instance_methods(false).include?(:to_s)
            overridden << :class if singleton.instance_methods(false).include?(:class)

            if overridden.any?
              findings << {
                object_id: obj.object_id,
                real_class: obj.method(:inspect).super_method&.call rescue 'unknown',
                overridden_methods: overridden,
                singleton_methods: singleton.instance_methods(false)
              }
            end
          rescue TypeError, NoMethodError
            # Some objects don't support singleton_class
            next
          end
        end

        findings
      end

      # Generate a forensic report on all cloaking operations performed.
      #
      # @return [Hash] Comprehensive cloaking report
      def forensic_report
        {
          total_cloaked: @cloaked_objects.size,
          by_strategy: @cloaked_objects.group_by { |c| c[:strategy] }.transform_values(&:size),
          dry_run_mode: @dry_run,
          cloaking_records: @cloaked_objects,
          detection_guidance: [
            'Use ObjectSpace.dump_all for raw heap analysis',
            'Compare ObjectSpace.count_objects deltas over time',
            'Check singleton_class.instance_methods(false) for overrides',
            'ObjectSpace.trace_object_allocations reveals allocation source'
          ]
        }
      end

      # Clean up cloaking modifications where possible.
      #
      # @return [Integer] Number of objects partially uncloaked
      def cleanup!
        count = 0
        @cloaked_objects.each do |record|
          next if record[:dry_run]

          case record[:strategy]
          when :inspect_override
            begin
              obj = ObjectSpace._id2ref(record[:object_id])
              # Remove singleton method overrides
              obj.singleton_class.remove_method(:inspect) rescue nil
              obj.singleton_class.remove_method(:to_s) rescue nil
              obj.singleton_class.remove_method(:class) rescue nil
              count += 1
            rescue RangeError
              # Object was garbage collected
            end
          when :suppress_tracing
            ObjectSpace.trace_object_allocations_start rescue nil
            count += 1
          end
        end

        @cloaked_objects.clear
        log("Uncloaked #{count} objects")
        count
      end

      def describe
        <<~DESC
          Memory Cloaker (T1070 / T1055)
          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
          Techniques for hiding object presence in Ruby's ObjectSpace:

          - Inspect Override: Override #inspect, #to_s, #class to disguise objects
          - Container Wrap: Hide payloads inside legitimate-looking data structures
          - Frozen String: Encode payloads as frozen strings that blend in
          - Trace Suppression: Disable allocation tracing to remove source info

          Detection: Always use ObjectSpace.dump_all for forensics, not #inspect.
          Raw heap dumps reveal true object types regardless of method overrides.
        DESC
      end

      private

      def log(message)
        @logger&.info("[MemoryCloaker] #{message}")
      end
    end
  end
end
