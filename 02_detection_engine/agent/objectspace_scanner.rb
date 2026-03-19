# frozen_string_literal: true

module RubyGuardian
  module Detection
    # Scans Ruby ObjectSpace for tampered, injected, or anomalous objects
    # Detects runtime method patching, hidden classes, and suspicious finalizers
    class ObjectSpaceScanner
      DANGEROUS_METHODS = %i[eval instance_eval class_eval module_eval exec system].freeze
      MAX_SCAN_OBJECTS = 100_000
      BASELINE_INTERVAL = 300

      attr_reader :config, :logger, :event_collector

      def initialize(config:, logger:, event_collector:)
        @config = config
        @logger = logger
        @event_collector = event_collector
        @baseline = {}
        @running = false
        @scan_count = 0
        @mutex = Mutex.new
      end

      def start
        @running = true
        capture_baseline
        @scan_thread = Thread.new { scan_loop }
        logger.info('ObjectSpaceScanner started')
      end

      def stop
        @running = false
        @scan_thread&.join(5)
        logger.info('ObjectSpaceScanner stopped')
      end

      def capture_baseline
        @mutex.synchronize do
          @baseline = {
            class_count: count_by_type(Class),
            module_count: count_by_type(Module),
            proc_count: count_by_type(Proc),
            method_count: count_by_type(Method),
            classes: snapshot_classes,
            core_methods: snapshot_core_methods,
            timestamp: Time.now
          }
        end
        logger.info("Baseline captured: #{@baseline[:class_count]} classes, #{@baseline[:module_count]} modules")
      end

      private

      def scan_loop
        while @running
          begin
            scan_objectspace
            @scan_count += 1
            if @scan_count % 60 == 0
              capture_baseline
            end
          rescue StandardError => e
            logger.error("ObjectSpaceScanner error: #{e.message}")
          end
          sleep(config.fetch(:objectspace_scan_interval, 10))
        end
      end

      def scan_objectspace
        detect_new_classes
        detect_method_patches
        detect_suspicious_procs
        detect_finalizer_abuse
        detect_anonymous_classes
        detect_hidden_constants
      end

      def detect_new_classes
        current_classes = snapshot_classes
        baseline_classes = @mutex.synchronize { @baseline[:classes] || {} }

        new_classes = current_classes.keys - baseline_classes.keys
        return if new_classes.empty?

        new_classes.each do |cls_name|
          next if whitelisted_class?(cls_name)

          event_collector.emit(
            type: :new_class_detected,
            severity: :medium,
            source: 'objectspace_scanner',
            details: {
              class_name: cls_name,
              method_count: current_classes[cls_name][:methods]&.length || 0,
              message: "New class detected at runtime: #{cls_name}"
            }
          )
        end
      end

      def detect_method_patches
        core_classes = [String, Array, Hash, Integer, Kernel, Object, IO, File]
        baseline_methods = @mutex.synchronize { @baseline[:core_methods] || {} }

        core_classes.each do |klass|
          current = klass.instance_methods(false).sort
          original = baseline_methods[klass.name] || []
          added = current - original
          removed = original - current

          next if added.empty? && removed.empty?

          event_collector.emit(
            type: :method_tampering,
            severity: :critical,
            source: 'objectspace_scanner',
            details: {
              class_name: klass.name,
              added_methods: added.map(&:to_s),
              removed_methods: removed.map(&:to_s),
              message: "Core class #{klass.name} methods modified"
            }
          )
        end
      end

      def detect_suspicious_procs
        proc_count = 0
        suspicious = []

        ObjectSpace.each_object(Proc) do |p|
          proc_count += 1
          break if proc_count > MAX_SCAN_OBJECTS

          begin
            source_loc = p.source_location
            next unless source_loc

            file, line = source_loc
            if suspicious_source?(file)
              suspicious << { file: file, line: line, arity: p.arity }
            end
          rescue StandardError
            next
          end
        end

        return if suspicious.empty?

        event_collector.emit(
          type: :suspicious_procs,
          severity: :high,
          source: 'objectspace_scanner',
          details: {
            count: suspicious.length,
            locations: suspicious.first(10),
            message: "#{suspicious.length} suspicious Proc objects detected"
          }
        )
      end

      def detect_finalizer_abuse
        finalized_objects = []
        ObjectSpace.each_object do |obj|
          begin
            if ObjectSpace.respond_to?(:_id2ref)
              id = obj.object_id
              finalizer = ObjectSpace.define_finalizer(obj, proc {})
              ObjectSpace.undefine_finalizer(obj)
              finalized_objects << obj.class.name if finalizer
            end
          rescue StandardError
            next
          end
          break if finalized_objects.length > 100
        end
      end

      def detect_anonymous_classes
        anon_count = 0
        ObjectSpace.each_object(Class) do |klass|
          anon_count += 1 if klass.name.nil? || klass.name.empty?
          break if anon_count > 50
        end

        if anon_count > config.fetch(:max_anonymous_classes, 20)
          event_collector.emit(
            type: :anonymous_class_flood,
            severity: :high,
            source: 'objectspace_scanner',
            details: {
              count: anon_count,
              message: "Excessive anonymous classes: #{anon_count}"
            }
          )
        end
      end

      def detect_hidden_constants
        ObjectSpace.each_object(Module) do |mod|
          begin
            next unless mod.name
            mod.constants(false).each do |const|
              val = mod.const_get(const)
              next unless val.is_a?(Class)
              if val.name.nil? && val.instance_methods(false).any? { |m| DANGEROUS_METHODS.include?(m) }
                event_collector.emit(
                  type: :hidden_dangerous_class,
                  severity: :critical,
                  source: 'objectspace_scanner',
                  details: {
                    parent_module: mod.name,
                    constant: const.to_s,
                    dangerous_methods: val.instance_methods(false).select { |m| DANGEROUS_METHODS.include?(m) }.map(&:to_s),
                    message: "Hidden class with dangerous methods found in #{mod.name}"
                  }
                )
              end
            end
          rescue StandardError
            next
          end
        end
      end

      def count_by_type(type)
        ObjectSpace.count_objects_size[type] || ObjectSpace.each_object(type).count
      rescue StandardError
        0
      end

      def snapshot_classes
        classes = {}
        ObjectSpace.each_object(Class) do |klass|
          next unless klass.name
          classes[klass.name] = {
            methods: klass.instance_methods(false),
            superclass: klass.superclass&.name
          }
        end
        classes
      end

      def snapshot_core_methods
        [String, Array, Hash, Integer, Kernel, Object, IO, File].each_with_object({}) do |klass, hash|
          hash[klass.name] = klass.instance_methods(false).sort
        end
      end

      def suspicious_source?(file)
        return true if file.nil?
        return true if file.start_with?('(eval)')
        return true if file.include?('/tmp/')
        return true if file.include?('/dev/shm/')
        false
      end

      def whitelisted_class?(name)
        config.fetch(:class_whitelist, []).any? { |pattern| name.match?(pattern) }
      end
    end
  end
end
