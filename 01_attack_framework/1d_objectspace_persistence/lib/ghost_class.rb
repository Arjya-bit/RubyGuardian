# frozen_string_literal: true

# RubyGuardian Phase 1d -- ObjectSpace Persistence: Ghost Class
#
# Creates anonymous classes that exist in the Ruby heap but are not
# accessible through normal constant lookup. These "ghost" classes
# can hold malicious code while being invisible to reflection.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1055 - Process Injection

module RubyGuardian
  module ObjectSpacePersistence
    class GhostClass
      attr_reader :ghosts, :logger

      def initialize(logger: nil)
        @logger = logger
        @ghosts = []
      end

      # Create an anonymous class with injected methods
      def create_ghost(methods: {}, ivars: {})
        ghost = Class.new do
          methods.each do |name, body|
            define_method(name) { body }
          end
        end

        # Set instance variables on the class object itself
        ivars.each do |name, value|
          ghost.instance_variable_set(:"@#{name}", value)
        end

        entry = {
          object_id: ghost.object_id,
          created_at: Time.now.utc.iso8601,
          method_count: methods.size,
          ivar_count: ivars.size
        }

        # Anchor to prevent GC
        GCAnchhor.anchor(ghost, tag: "ghost_#{ghost.object_id}")
        @ghosts << entry

        @logger&.info("[GhostClass] Created ghost class id=#{ghost.object_id}")
        ghost
      end

      # Enumerate all anonymous classes in ObjectSpace
      def self.scan_for_ghosts
        anonymous_classes = []
        ObjectSpace.each_object(Class) do |klass|
          next if klass.name # Skip named classes

          anonymous_classes << {
            object_id: klass.object_id,
            superclass: klass.superclass&.name,
            instance_methods: (klass.instance_methods(false) rescue []),
            instance_variables: (klass.instance_variables rescue [])
          }
        end
        anonymous_classes
      end

      # Get summary of created ghosts
      def summary
        {
          total_ghosts: @ghosts.size,
          ghosts: @ghosts
        }
      end

      def describe
        <<~DESC
          Ghost Classes (T1055)
          ━━━━━━━━━━━━━━━━━━━━━
          Anonymous classes created with Class.new exist in the Ruby heap
          but have no name and cannot be found via constant lookup. They
          are invisible to typical reflection methods like Module.constants.

          Detection: Scan ObjectSpace for Class objects where .name is nil
          and check for suspicious instance methods or variables.
        DESC
      end
    end
  end
end
