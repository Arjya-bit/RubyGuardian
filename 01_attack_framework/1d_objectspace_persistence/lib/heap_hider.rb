# frozen_string_literal: false
#
# RubyGuardian Phase 1d - ObjectSpace Persistence Evasion
# Module: Heap Hider
#
# EDUCATIONAL PURPOSE ONLY - Demonstrates how payloads can be attached to
# legitimate Rails/Ruby objects so they blend into normal heap contents.
#
# FORENSIC DETECTION:
# - Use ObjectSpace.reachable_objects_from to map unexpected references
# - Compare instance_variables of key objects against source code expectations
# - Monitor instance_variable_set calls via TracePoint on :c_call
# - Heap dump diffing between known-good baseline and suspect state

require 'objspace'

module RubyGuardian
  module ObjectSpacePersistence
    class HeapHider
      # Categorized hiding spots in a typical Rails application
      HIDING_SPOTS = {
        # Rails framework objects that persist for the process lifetime
        rails_core: %i[
          application config routes middleware logger cache_store
        ],
        # ActiveRecord connection and schema objects
        activerecord: %i[
          connection_pool schema_cache column_map attribute_map
        ],
        # Rack/middleware layer objects
        rack: %i[
          middleware_stack session_store cookie_jar
        ],
        # Ruby standard library persistent objects
        stdlib: %i[
          load_path loaded_features encoding_list
        ]
      }.freeze

      # Instance variable name patterns that mimic framework internals.
      # These names are chosen to blend in with legitimate Rails ivars.
      CAMOUFLAGE_NAMES = {
        rails: %w[
          @_routes_cache @_middleware_builder @_config_store
          @_action_methods_set @_view_context_class @_helpers_module
          @_callback_chain_cache @_attribute_methods_mutex
        ],
        activerecord: %w[
          @_schema_version @_column_types_cache @_arel_table_cache
          @_relation_delegate_cache @_find_by_statement_cache
          @_attribute_type_decorations @_connection_specification
        ],
        rack: %w[
          @_session_options @_cookie_domain @_ssl_redirect_config
          @_request_forgery_token @_cors_origin_cache
        ],
        generic: %w[
          @_mutex @_monitor @_internal_state @_cache_data
          @__memoized @__lazy_init @__thread_safe_cache
        ]
      }.freeze

      attr_reader :hidden_payloads

      def initialize(options = {})
        @hidden_payloads = []
        @verbose = options.fetch(:verbose, false)
        @category = options.fetch(:category, :generic)
      end

      # Hide a payload by attaching it as an instance variable on a legitimate
      # framework object.
      #
      # EDUCATIONAL: Rails objects like the application instance, route set,
      # and middleware stack have dozens of instance variables. Adding one more
      # with a plausible name is extremely difficult to notice without automated
      # comparison against a baseline.
      #
      # @param payload [Object] Data or code to hide
      # @param target [Object] Legitimate object to attach to
      # @param camouflage [Symbol] Category of camouflage names to use
      # @return [Hash] Hiding details for later retrieval
      def hide(payload, target:, camouflage: @category)
        ivar_name = select_camouflage_name(camouflage, target)

        # Wrap the payload to add a layer of indirection
        hidden = wrap_payload(payload)

        # Attach to the target object
        target.instance_variable_set(ivar_name.to_sym, hidden)

        record = {
          target_class: target.class.name,
          target_id: target.object_id,
          ivar_name: ivar_name,
          payload_id: hidden.object_id,
          hidden_at: Time.now
        }
        @hidden_payloads << record

        log("Hidden payload in #{target.class}##{ivar_name}")
        record
      end

      # Hide payload inside a Hash that is already an instance variable of
      # the target. This is even more subtle than adding a new ivar.
      #
      # EDUCATIONAL: Many Rails objects store configuration in Hashes. Adding
      # a key-value pair to an existing Hash doesn't change the ivar list,
      # making it invisible to simple ivar enumeration.
      #
      # FORENSIC DETECTION: Deep comparison of Hash contents against baseline.
      # Monitor Hash#[]= calls on sensitive objects via TracePoint.
      #
      # @param payload [Object] Data to hide
      # @param target [Object] Object that contains a Hash ivar
      # @param hash_ivar [String] Name of the Hash instance variable
      # @param key [String] Key to store payload under
      # @return [Hash] Hiding details
      def hide_in_hash(payload, target:, hash_ivar:, key: nil)
        key ||= generate_innocent_hash_key

        hash_ivar = "@#{hash_ivar}" unless hash_ivar.start_with?("@")
        existing_hash = target.instance_variable_get(hash_ivar.to_sym)

        unless existing_hash.is_a?(Hash)
          log("Warning: #{hash_ivar} is not a Hash, creating one")
          existing_hash = {}
          target.instance_variable_set(hash_ivar.to_sym, existing_hash)
        end

        existing_hash[key] = payload

        record = {
          target_class: target.class.name,
          target_id: target.object_id,
          hash_ivar: hash_ivar,
          key: key,
          payload_id: payload.object_id,
          hidden_at: Time.now
        }
        @hidden_payloads << record

        log("Hidden payload in #{target.class}##{hash_ivar}[#{key.inspect}]")
        record
      end

      # Hide payload inside an Array that belongs to the target.
      #
      # EDUCATIONAL: Arrays like callback chains, middleware stacks, and
      # observer lists are common in Rails. Appending to these is very subtle.
      #
      # @param payload [Object] Data to hide
      # @param target [Object] Object containing an Array ivar
      # @param array_ivar [String] Name of the Array instance variable
      # @return [Hash] Hiding details
      def hide_in_array(payload, target:, array_ivar:)
        array_ivar = "@#{array_ivar}" unless array_ivar.start_with?("@")
        existing_array = target.instance_variable_get(array_ivar.to_sym)

        unless existing_array.is_a?(Array)
          log("Warning: #{array_ivar} is not an Array, creating one")
          existing_array = []
          target.instance_variable_set(array_ivar.to_sym, existing_array)
        end

        existing_array << payload

        record = {
          target_class: target.class.name,
          target_id: target.object_id,
          array_ivar: array_ivar,
          index: existing_array.length - 1,
          payload_id: payload.object_id,
          hidden_at: Time.now
        }
        @hidden_payloads << record

        log("Hidden payload in #{target.class}##{array_ivar}[#{existing_array.length - 1}]")
        record
      end

      # Hide payload as a singleton method on an existing object.
      #
      # EDUCATIONAL: Adding a singleton method to an existing object creates
      # a hidden singleton class. The method's code (a Proc/block) is then
      # referenced by the singleton class, which is referenced by the object.
      # This chain keeps the payload alive as long as the host object lives.
      #
      # FORENSIC DETECTION: Check obj.singleton_methods for unexpected entries.
      # Compare against known singleton methods from source code.
      #
      # @param target [Object] Object to add the method to
      # @param method_name [Symbol] Name for the singleton method
      # @param payload_proc [Proc] Code to execute when method is called
      # @return [Hash] Hiding details
      def hide_as_method(target, method_name:, payload_proc:)
        # Choose a method name that looks like a framework internal
        method_name ||= :"__#{%w[validate serialize normalize marshal].sample}_cached"

        target.define_singleton_method(method_name, &payload_proc)

        record = {
          target_class: target.class.name,
          target_id: target.object_id,
          method_name: method_name,
          payload_source: payload_proc.source_location,
          hidden_at: Time.now
        }
        @hidden_payloads << record

        log("Hidden executable as #{target.class}##{method_name}")
        record
      end

      # Retrieve a previously hidden payload.
      #
      # @param record [Hash] The record returned by a hide method
      # @return [Object] The hidden payload
      def retrieve(record)
        target = ObjectSpace._id2ref(record[:target_id])

        if record[:ivar_name]
          wrapper = target.instance_variable_get(record[:ivar_name].to_sym)
          wrapper.instance_variable_get(:@__data)
        elsif record[:hash_ivar]
          hash = target.instance_variable_get(record[:hash_ivar].to_sym)
          hash[record[:key]]
        elsif record[:array_ivar]
          array = target.instance_variable_get(record[:array_ivar].to_sym)
          array[record[:index]]
        elsif record[:method_name]
          target.method(record[:method_name])
        end
      rescue RangeError
        log("Target object has been garbage collected!")
        nil
      end

      # Generate a forensic report of all hiding spots used.
      #
      # @return [Array<Hash>] Report entries
      def forensic_report
        @hidden_payloads.map do |record|
          alive = begin
            ObjectSpace._id2ref(record[:payload_id])
            true
          rescue RangeError
            false
          end

          record.merge(still_alive: alive)
        end
      end

      private

      # Wrap the payload in an object that looks like a cache entry
      def wrap_payload(payload)
        wrapper = Object.new
        wrapper.instance_variable_set(:@__data, payload)
        wrapper.instance_variable_set(:@__ts, Time.now.to_f)
        wrapper.instance_variable_set(:@__ver, "1.0")

        # Override inspect to look like a mundane cache object
        wrapper.define_singleton_method(:inspect) do
          "#<CacheEntry:0x#{object_id.to_s(16)} ts=#{@__ts}>"
        end

        wrapper.define_singleton_method(:to_s) do
          inspect
        end

        wrapper
      end

      # Select a camouflage instance variable name that doesn't collide
      # with existing ivars on the target
      def select_camouflage_name(category, target)
        existing = target.instance_variables.map(&:to_s)
        names = CAMOUFLAGE_NAMES.fetch(category, CAMOUFLAGE_NAMES[:generic])

        available = names.reject { |n| existing.include?(n) }

        if available.empty?
          # Generate a unique name if all camouflage names are taken
          "@__internal_#{SecureRandom.hex(4)}"
        else
          available.sample
        end
      end

      # Generate a Hash key that looks like a framework configuration key
      def generate_innocent_hash_key
        prefixes = %w[
          cache_store session_config ssl_options cors_config
          rate_limit_config csrf_options content_type_map
        ]
        "#{prefixes.sample}_v#{rand(1..5)}"
      end

      def log(message)
        return unless @verbose
        timestamp = Time.now.strftime("%H:%M:%S.%L")
        $stderr.puts "[HeapHider #{timestamp}] #{message}"
      end
    end
  end
end
