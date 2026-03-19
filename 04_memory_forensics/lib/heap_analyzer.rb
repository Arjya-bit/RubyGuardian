# frozen_string_literal: true

require 'json'
require 'yaml'

module RubyGuardian
  module MemoryForensics
    # HeapAnalyzer examines Ruby heap layout from memory dumps, detecting
    # anomalies such as heap spray patterns, suspicious allocations,
    # fragmentation issues, and hidden objects.
    class HeapAnalyzer
      RVALUE_SIZE = 40
      HEAP_PAGE_SIZE = 16384
      HEAP_PAGE_OBJ_LIMIT = 409

      T_MASK = 0x1f
      TYPE_NAMES = {
        0x00 => 'T_NONE',   0x01 => 'T_OBJECT', 0x02 => 'T_CLASS',
        0x03 => 'T_MODULE', 0x04 => 'T_FLOAT',  0x05 => 'T_STRING',
        0x06 => 'T_REGEXP', 0x07 => 'T_ARRAY',  0x08 => 'T_HASH',
        0x09 => 'T_STRUCT', 0x0a => 'T_BIGNUM', 0x0b => 'T_FILE',
        0x0c => 'T_DATA',   0x0d => 'T_MATCH',  0x0e => 'T_COMPLEX',
        0x0f => 'T_RATIONAL', 0x1a => 'T_IMEMO', 0x1b => 'T_NODE',
        0x1c => 'T_ICLASS', 0x1d => 'T_ZOMBIE', 0x1e => 'T_MOVED'
      }.freeze

      Anomaly = Struct.new(
        :type, :severity, :description, :evidence, :address,
        :confidence, keyword_init: true
      )

      HeapStats = Struct.new(
        :total_slots, :used_slots, :free_slots, :type_distribution,
        :fragmentation_ratio, :largest_free_run, :pages_analyzed,
        :average_occupancy, keyword_init: true
      )

      SprayPattern = Struct.new(
        :pattern_bytes, :count, :addresses, :avg_spacing,
        :region, keyword_init: true
      )

      attr_reader :dump_parser, :vm_parser, :config, :anomalies, :stats

      def initialize(dump_parser, vm_parser: nil, config: nil)
        @dump_parser = dump_parser
        @vm_parser = vm_parser
        @config = load_config(config)
        @anomalies = []
        @stats = nil
        @type_distribution = Hash.new(0)
        @object_sizes = Hash.new { |h, k| h[k] = [] }
      end

      # Run full heap analysis
      def analyze
        @anomalies.clear
        collect_heap_statistics
        detect_heap_spray
        detect_large_objects
        detect_suspicious_type_ratios
        detect_fragmentation_anomalies
        detect_zombie_objects
        detect_executable_heap_regions
        detect_hidden_objects
        detect_use_after_free_patterns

        {
          stats: @stats&.to_h,
          anomalies: @anomalies.map(&:to_h),
          risk_score: calculate_risk_score
        }
      end

      # Collect statistics about heap usage
      def collect_heap_statistics
        total = 0
        used = 0
        free = 0
        free_runs = []
        current_free_run = 0

        @dump_parser.each_rvalue do |rv|
          total += 1
          if rv.type == :T_NONE
            free += 1
            current_free_run += 1
          else
            used += 1
            @type_distribution[rv.type] += 1
            track_object_size(rv)
            if current_free_run > 0
              free_runs << current_free_run
              current_free_run = 0
            end
          end
        end
        free_runs << current_free_run if current_free_run > 0

        fragmentation = if total > 0 && free > 0
                          largest_run = free_runs.max || 0
                          1.0 - (largest_run.to_f / free)
                        else
                          0.0
                        end

        @stats = HeapStats.new(
          total_slots: total,
          used_slots: used,
          free_slots: free,
          type_distribution: @type_distribution.transform_keys(&:to_s),
          fragmentation_ratio: fragmentation.round(4),
          largest_free_run: free_runs.max || 0,
          pages_analyzed: (total.to_f / HEAP_PAGE_OBJ_LIMIT).ceil,
          average_occupancy: total > 0 ? (used.to_f / total).round(4) : 0.0
        )
      end

      # Detect heap spray patterns (many identical objects at regular intervals)
      def detect_heap_spray
        threshold = @config.dig('analysis', 'heap', 'spray_detection', 'min_identical_objects') || 100
        min_nop_sled = @config.dig('analysis', 'heap', 'spray_detection', 'min_nop_sled_length') || 64

        # Group objects by their data content
        content_groups = Hash.new { |h, k| h[k] = [] }

        @dump_parser.each_rvalue do |rv|
          next if rv.type == :T_NONE

          # Use first 24 bytes of payload as fingerprint
          fingerprint = rv.raw_data[16, 24]
          next unless fingerprint

          content_groups[fingerprint] << rv.address
        end

        content_groups.each do |fingerprint, addresses|
          next if addresses.size < threshold

          # Calculate average spacing between objects
          sorted = addresses.sort
          spacings = sorted.each_cons(2).map { |a, b| b - a }
          avg_spacing = spacings.empty? ? 0 : spacings.sum.to_f / spacings.size

          pattern = SprayPattern.new(
            pattern_bytes: fingerprint.unpack('H*').first,
            count: addresses.size,
            addresses: addresses.first(10),
            avg_spacing: avg_spacing.round(2),
            region: nil
          )

          @anomalies << Anomaly.new(
            type: :heap_spray,
            severity: :critical,
            description: "Heap spray detected: #{addresses.size} identical objects with " \
                         "avg spacing of #{avg_spacing.round(0)} bytes",
            evidence: pattern.to_h,
            address: addresses.first,
            confidence: calculate_spray_confidence(addresses.size, avg_spacing)
          )
        end

        # Detect NOP sled patterns in string objects
        detect_nop_sleds(min_nop_sled)
      end

      # Detect unusually large objects that may indicate exploitation
      def detect_large_objects
        threshold = @config.dig('analysis', 'heap', 'large_object_threshold') || 1_048_576

        @dump_parser.each_rvalue do |rv|
          next unless rv.type == :T_STRING

          flags = rv.flags
          if (flags & 0x2000) != 0 # STR_NOEMBED
            len = rv.raw_data[16, 8].unpack1('q<')
            if len > threshold
              @anomalies << Anomaly.new(
                type: :large_object,
                severity: :medium,
                description: "Unusually large string object: #{format_size(len)}",
                evidence: { length: len, flags: "0x#{flags.to_s(16)}" },
                address: rv.address,
                confidence: 0.7
              )
            end
          end
        end
      end

      # Detect suspicious type distribution ratios
      def detect_suspicious_type_ratios
        return unless @stats && @stats.used_slots > 0

        total_used = @stats.used_slots.to_f

        # Extremely high proportion of strings might indicate string-based attack
        string_ratio = (@type_distribution[:T_STRING] || 0) / total_used
        if string_ratio > 0.85
          @anomalies << Anomaly.new(
            type: :suspicious_ratio,
            severity: :high,
            description: "Abnormally high string ratio: #{(string_ratio * 100).round(1)}% of all objects",
            evidence: { string_count: @type_distribution[:T_STRING], ratio: string_ratio.round(4) },
            address: nil,
            confidence: 0.75
          )
        end

        # High proportion of T_DATA might indicate native extension abuse
        data_ratio = (@type_distribution[:T_DATA] || 0) / total_used
        if data_ratio > 0.5
          @anomalies << Anomaly.new(
            type: :suspicious_ratio,
            severity: :medium,
            description: "High T_DATA ratio: #{(data_ratio * 100).round(1)}% - possible native extension abuse",
            evidence: { data_count: @type_distribution[:T_DATA], ratio: data_ratio.round(4) },
            address: nil,
            confidence: 0.6
          )
        end

        # T_IMEMO ratio check - very high might indicate iseq injection
        imemo_ratio = (@type_distribution[:T_IMEMO] || 0) / total_used
        if imemo_ratio > 0.4
          @anomalies << Anomaly.new(
            type: :suspicious_ratio,
            severity: :high,
            description: "Abnormally high T_IMEMO ratio: #{(imemo_ratio * 100).round(1)}% - possible iseq injection",
            evidence: { imemo_count: @type_distribution[:T_IMEMO], ratio: imemo_ratio.round(4) },
            address: nil,
            confidence: 0.7
          )
        end
      end

      # Detect heap fragmentation anomalies
      def detect_fragmentation_anomalies
        threshold = @config.dig('analysis', 'heap', 'fragmentation_warning_threshold') || 0.7
        return unless @stats

        if @stats.fragmentation_ratio > threshold
          @anomalies << Anomaly.new(
            type: :fragmentation,
            severity: :low,
            description: "High heap fragmentation: #{(@stats.fragmentation_ratio * 100).round(1)}%",
            evidence: {
              fragmentation_ratio: @stats.fragmentation_ratio,
              free_slots: @stats.free_slots,
              largest_free_run: @stats.largest_free_run
            },
            address: nil,
            confidence: 0.8
          )
        end
      end

      # Detect zombie objects (objects being finalized)
      def detect_zombie_objects
        zombie_count = @type_distribution[:T_ZOMBIE] || 0
        return unless zombie_count > 10

        @anomalies << Anomaly.new(
          type: :zombie_objects,
          severity: :medium,
          description: "#{zombie_count} zombie objects detected - possible resource leak or attack interference",
          evidence: { count: zombie_count },
          address: nil,
          confidence: 0.65
        )
      end

      # Detect heap regions with executable permissions (W+X)
      def detect_executable_heap_regions
        @dump_parser.regions.each do |region|
          perms = region.permissions
          next unless perms.include?('w') && perms.include?('x')

          # Writable and executable is suspicious for heap memory
          next if region.pathname.include?('[vdso]') || region.pathname.include?('.so')

          @anomalies << Anomaly.new(
            type: :executable_heap,
            severity: :critical,
            description: "Writable+executable heap region at 0x#{region.start_addr.to_s(16)}",
            evidence: {
              start: "0x#{region.start_addr.to_s(16)}",
              end: "0x#{region.end_addr.to_s(16)}",
              permissions: perms,
              size: region.size
            },
            address: region.start_addr,
            confidence: 0.9
          )
        end
      end

      # Detect objects that may be hidden from ObjectSpace enumeration
      def detect_hidden_objects
        # Look for valid-looking RValues in regions not typically used for Ruby heap
        non_heap_regions = @dump_parser.regions.select do |r|
          r.permissions.include?('rw') &&
            !r.pathname.include?('[heap]') &&
            !r.pathname.include?('ruby') &&
            r.pathname.empty?
        end

        hidden_count = 0
        non_heap_regions.each do |region|
          offset = 0
          while offset + RVALUE_SIZE <= region.data.bytesize
            flags = region.data[offset, 8].unpack1('Q<')
            type_id = flags & T_MASK
            if TYPE_NAMES.key?(type_id) && type_id != 0x00 && flags != 0
              klass = region.data[offset + 8, 8].unpack1('Q<')
              if klass > 0x1000 && klass < 0x0000_8000_0000_0000
                hidden_count += 1
              end
            end
            offset += RVALUE_SIZE
          end
        end

        if hidden_count > 20
          @anomalies << Anomaly.new(
            type: :hidden_objects,
            severity: :high,
            description: "#{hidden_count} potential hidden objects in non-heap memory regions",
            evidence: { count: hidden_count, regions: non_heap_regions.size },
            address: nil,
            confidence: 0.6
          )
        end
      end

      # Detect use-after-free patterns
      def detect_use_after_free_patterns
        # Look for T_NONE slots that still have non-zero klass pointers
        suspicious = 0

        @dump_parser.each_rvalue do |rv|
          next unless rv.type == :T_NONE

          if rv.klass_ptr != 0 && rv.klass_ptr < 0x0000_8000_0000_0000
            # Freed slot with residual class pointer - might indicate UAF
            payload = rv.raw_data[16, 24]
            unless payload == ("\x00" * 24)
              suspicious += 1
            end
          end
        end

        if suspicious > @stats.free_slots * 0.1 && suspicious > 50
          @anomalies << Anomaly.new(
            type: :use_after_free,
            severity: :high,
            description: "#{suspicious} freed slots with residual data - possible use-after-free",
            evidence: { count: suspicious, free_total: @stats.free_slots },
            address: nil,
            confidence: 0.55
          )
        end
      end

      # Calculate overall risk score from anomalies
      def calculate_risk_score
        return 0.0 if @anomalies.empty?

        severity_weights = { critical: 1.0, high: 0.7, medium: 0.4, low: 0.15 }

        weighted_sum = @anomalies.sum do |a|
          weight = severity_weights[a.severity] || 0.1
          weight * a.confidence
        end

        # Normalize to 0-10 scale, capped at 10
        [weighted_sum.round(2), 10.0].min
      end

      private

      def detect_nop_sleds(min_length)
        nop_patterns = [
          "\x90" * min_length,                           # x86 NOP
          ("\x87\xC0" * (min_length / 2)),              # xchg eax, eax
          ("\x66\x90" * (min_length / 2))               # 66 NOP
        ]

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          nop_patterns.each do |pattern|
            offset = 0
            count = 0
            while (pos = region.data.index(pattern, offset))
              count += 1
              offset = pos + 1
            end

            if count > 0
              @anomalies << Anomaly.new(
                type: :nop_sled,
                severity: :critical,
                description: "NOP sled pattern detected (#{count} occurrences, min length #{min_length})",
                evidence: {
                  pattern: pattern[0, 8].unpack1('H*'),
                  count: count,
                  region: region.pathname
                },
                address: region.start_addr,
                confidence: 0.85
              )
            end
          end
        end
      end

      def track_object_size(rv)
        case rv.type
        when :T_STRING
          if (rv.flags & 0x2000) != 0
            len = rv.raw_data[16, 8].unpack1('q<')
            @object_sizes[:T_STRING] << len if len > 0 && len < 100_000_000
          end
        when :T_ARRAY
          if (rv.flags & 0x2000) != 0
            len = rv.raw_data[16, 8].unpack1('q<')
            @object_sizes[:T_ARRAY] << len if len > 0 && len < 100_000_000
          end
        end
      end

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end

      def format_size(bytes)
        units = %w[B KB MB GB]
        idx = 0
        size = bytes.to_f
        while size >= 1024 && idx < units.size - 1
          size /= 1024
          idx += 1
        end
        "#{size.round(2)} #{units[idx]}"
      end
    end
  end
end
