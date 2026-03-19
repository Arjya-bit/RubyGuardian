# frozen_string_literal: true

# RubyGuardian Phase 1d -- ObjectSpace Persistence: GC Anchor
#
# Prevents garbage collection of injected objects by creating strong
# references that survive GC cycles. This ensures persistence of
# malicious objects in the Ruby heap.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1055 - Process Injection

module RubyGuardian
  module ObjectSpacePersistence
    class GCAnchhor
      # Registry of anchored objects that resist garbage collection
      @anchored_objects = {}
      @anchor_mutex = Mutex.new

      class << self
        attr_reader :anchored_objects

        # Anchor an object to prevent GC collection
        def anchor(object, tag: nil)
          tag ||= "anchor_#{object.object_id}"
          @anchor_mutex.synchronize do
            @anchored_objects[tag] = {
              object: object,
              anchored_at: Time.now.utc,
              object_id: object.object_id,
              class_name: object.class.name
            }
          end
          tag
        end

        # Release an anchored object (allow GC)
        def release(tag)
          @anchor_mutex.synchronize do
            @anchored_objects.delete(tag)
          end
        end

        # Release all anchored objects
        def release_all
          @anchor_mutex.synchronize do
            count = @anchored_objects.size
            @anchored_objects.clear
            count
          end
        end

        # Check if an object is currently anchored
        def anchored?(tag)
          @anchor_mutex.synchronize do
            @anchored_objects.key?(tag)
          end
        end

        # Get statistics about anchored objects
        def stats
          @anchor_mutex.synchronize do
            {
              total_anchored: @anchored_objects.size,
              by_class: @anchored_objects.values
                          .group_by { |v| v[:class_name] }
                          .transform_values(&:size),
              oldest: @anchored_objects.values
                        .min_by { |v| v[:anchored_at] }
                        &.dig(:anchored_at)
            }
          end
        end

        # Force a GC run and verify anchored objects survived
        def verify_persistence
          before_ids = @anchor_mutex.synchronize do
            @anchored_objects.transform_values { |v| v[:object_id] }
          end

          GC.start(full_mark: true, immediate_sweep: true)

          survived = before_ids.all? do |tag, oid|
            begin
              ObjectSpace._id2ref(oid)
              true
            rescue RangeError
              false
            end
          end

          { all_survived: survived, checked: before_ids.size }
        end
      end

      # Instance-level anchoring for creating anchor chains
      def initialize
        @local_anchors = []
      end

      # Create a chain of references to make GC collection harder
      def create_anchor_chain(object, depth: 3)
        chain = [object]
        depth.times do
          wrapper = Object.new
          wrapper.instance_variable_set(:@held_ref, chain.last)
          chain << wrapper
        end

        @local_anchors.concat(chain)
        self.class.anchor(chain.last, tag: "chain_#{object.object_id}")
        chain.size
      end
    end
  end
end
