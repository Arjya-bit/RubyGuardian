# frozen_string_literal: true

require 'json'
require 'yaml'
require 'set'

module RubyGuardian
  module MemoryForensics
    # ObjectSpaceReconstructor rebuilds the Ruby ObjectSpace from raw memory,
    # recovering object relationships, class hierarchies, and instance variables.
    class ObjectSpaceReconstructor
      RVALUE_SIZE = 40
      POINTER_SIZE = 8
      T_MASK = 0x1f
      MAX_DEPTH = 20

      TYPE_MAP = {
        0x01 => :T_OBJECT, 0x02 => :T_CLASS, 0x03 => :T_MODULE,
        0x04 => :T_FLOAT,  0x05 => :T_STRING, 0x06 => :T_REGEXP,
        0x07 => :T_ARRAY,  0x08 => :T_HASH,   0x09 => :T_STRUCT,
        0x0a => :T_BIGNUM, 0x0b => :T_FILE,   0x0c => :T_DATA,
        0x0d => :T_MATCH,  0x0e => :T_COMPLEX, 0x0f => :T_RATIONAL,
        0x1a => :T_IMEMO,  0x1b => :T_NODE,   0x1c => :T_ICLASS
      }.freeze

      ReconstructedObject = Struct.new(
        :address, :type, :klass_address, :klass_name, :flags,
        :value, :references, :instance_variables, :frozen,
        :size_estimate, keyword_init: true
      )

      ClassInfo = Struct.new(
        :address, :name, :super_address, :super_name,
        :instance_count, :method_count, :ancestors, keyword_init: true
      )

      ObjectGraph = Struct.new(
        :objects, :classes, :roots, :total_count,
        :type_distribution, :reference_map, keyword_init: true
      )

      attr_reader :dump_parser, :vm_parser, :config
      attr_reader :objects, :classes, :reference_map

      def initialize(dump_parser, vm_parser: nil, config: nil)
        @dump_parser = dump_parser
        @vm_parser = vm_parser
        @config = load_config(config)
        @objects = {}
        @classes = {}
        @reference_map = Hash.new { |h, k| h[k] = Set.new }
        @reverse_references = Hash.new { |h, k| h[k] = Set.new }
        @max_depth = @config.dig('reconstruction', 'objectspace', 'max_depth') || MAX_DEPTH
      end

      # Reconstruct the full ObjectSpace
      def reconstruct
        @objects.clear
        @classes.clear
        @reference_map.clear

        # Phase 1: Enumerate all live objects
        enumerate_objects

        # Phase 2: Resolve class names
        resolve_class_names

        # Phase 3: Build reference graph
        build_reference_graph

        # Phase 4: Extract instance variables where possible
        extract_instance_variables

        build_object_graph
      end

      # Reconstruct a single object and its references up to max_depth
      def reconstruct_object(address, depth: 0)
        return @objects[address] if @objects.key?(address)
        return nil if depth > @max_depth

        rv = @dump_parser.read_rvalue(address)
        return nil unless rv && TYPE_MAP.key?(rv.flags & T_MASK)

        obj = build_reconstructed_object(rv)
        @objects[address] = obj

        # Recursively reconstruct referenced objects
        obj.references.each do |ref_addr|
          reconstruct_object(ref_addr, depth: depth + 1)
          @reference_map[address].add(ref_addr)
          @reverse_references[ref_addr].add(address)
        end

        obj
      end

      # Find all objects of a given class
      def find_by_class(class_name)
        @objects.values.select { |obj| obj.klass_name == class_name }
      end

      # Find all objects of a given type
      def find_by_type(type)
        type_sym = type.is_a?(Symbol) ? type : type.to_sym
        @objects.values.select { |obj| obj.type == type_sym }
      end

      # Get the reference chain from one object to another (BFS)
      def find_reference_path(from_addr, to_addr, max_depth: 10)
        return [from_addr] if from_addr == to_addr

        queue = [[from_addr]]
        visited = Set.new([from_addr])

        while (path = queue.shift)
          current = path.last
          refs = @reference_map[current] || Set.new

          refs.each do |ref|
            next if visited.include?(ref)

            new_path = path + [ref]
            return new_path if ref == to_addr
            return nil if new_path.size >= max_depth

            visited.add(ref)
            queue << new_path
          end
        end

        nil
      end

      # Find objects that are not referenced by any other object (potential roots)
      def find_root_objects
        all_referenced = @reverse_references.keys.to_set
        @objects.keys.reject { |addr| all_referenced.include?(addr) }
      end

      # Find objects with no outgoing references (leaf objects)
      def find_leaf_objects
        @objects.select { |addr, _| @reference_map[addr].empty? }.keys
      end

      # Detect objects that may be hidden from normal ObjectSpace enumeration
      def detect_hidden_objects
        hidden = []

        @dump_parser.regions.each do |region|
          # Look for valid objects in anonymous mmap regions
          next unless region.permissions.include?('rw')
          next if region.pathname.include?('[heap]') || region.pathname.include?('ruby')

          offset = 0
          while offset + RVALUE_SIZE <= region.data.bytesize
            flags = region.data[offset, 8].unpack1('Q<')
            type_id = flags & T_MASK

            if TYPE_MAP.key?(type_id) && flags != 0
              klass = region.data[offset + 8, 8].unpack1('Q<')
              if valid_pointer?(klass)
                addr = region.start_addr + offset
                rv = @dump_parser.read_rvalue(addr)
                if rv
                  obj = build_reconstructed_object(rv)
                  hidden << obj
                end
              end
            end
            offset += RVALUE_SIZE
          end
        end

        hidden
      end

      # Build class hierarchy from reconstructed classes
      def class_hierarchy
        hierarchy = {}

        @classes.each do |addr, cls|
          parent = cls.super_name || 'Object'
          hierarchy[parent] ||= []
          hierarchy[parent] << cls.name unless cls.name.nil?
        end

        hierarchy
      end

      # Generate statistics about reconstructed ObjectSpace
      def statistics
        type_dist = Hash.new(0)
        class_dist = Hash.new(0)
        total_size = 0

        @objects.each_value do |obj|
          type_dist[obj.type] += 1
          class_dist[obj.klass_name || 'unknown'] += 1
          total_size += obj.size_estimate || RVALUE_SIZE
        end

        {
          total_objects: @objects.size,
          total_classes: @classes.size,
          root_objects: find_root_objects.size,
          leaf_objects: find_leaf_objects.size,
          type_distribution: type_dist,
          top_classes: class_dist.sort_by { |_, v| -v }.first(20).to_h,
          estimated_total_size: total_size,
          avg_references_per_object: avg_references,
          max_reference_depth: calculate_max_depth
        }
      end

      private

      def enumerate_objects
        @dump_parser.each_rvalue do |rv|
          next if rv.type == :T_NONE || rv.type == :T_ZOMBIE || rv.type == :T_MOVED

          obj = build_reconstructed_object(rv)
          @objects[rv.address] = obj

          if rv.type == :T_CLASS || rv.type == :T_MODULE
            build_class_info(rv)
          end
        end
      end

      def build_reconstructed_object(rv)
        type = rv.type
        flags = rv.flags
        klass_addr = rv.klass_ptr

        value = extract_object_value(rv)
        refs = extract_references(rv)
        frozen = (flags & (1 << 23)) != 0 # RUBY_FL_FROZEN approximation

        ReconstructedObject.new(
          address: rv.address,
          type: type,
          klass_address: klass_addr,
          klass_name: nil, # Resolved later
          flags: flags,
          value: value,
          references: refs,
          instance_variables: {},
          frozen: frozen,
          size_estimate: estimate_object_size(rv)
        )
      end

      def extract_object_value(rv)
        case rv.type
        when :T_STRING
          extract_string_value(rv)
        when :T_FIXNUM
          # Fixnums are stored as immediate values
          (rv.flags >> 1).to_i
        when :T_FLOAT
          rv.raw_data[16, 8].unpack1('d')
        when :T_SYMBOL
          # Symbol ID is encoded in the value
          (rv.raw_data[16, 8].unpack1('Q<') >> 8)
        when :T_ARRAY
          extract_array_value(rv)
        else
          nil
        end
      rescue StandardError
        nil
      end

      def extract_string_value(rv)
        return nil unless @vm_parser

        @vm_parser.extract_ruby_string_value(rv.address)
      rescue StandardError
        # Fallback: try direct extraction
        flags = rv.flags
        if (flags & 0x2000) != 0
          len = rv.raw_data[16, 8].unpack1('q<')
          ptr = rv.raw_data[24, 8].unpack1('Q<')
          return nil if len <= 0 || len > 65536 || ptr == 0

          @dump_parser.read_at(ptr, [len, 4096].min)
        else
          embed_len = (flags & 0x1f0000) >> 16
          embed_len > 0 && embed_len <= 24 ? rv.raw_data[16, embed_len] : nil
        end
      end

      def extract_array_value(rv)
        flags = rv.flags
        if (flags & 0x2000) != 0
          # Embedded array
          embed_len = (flags & 0x60000) >> 17
          values = []
          embed_len.times do |i|
            val = rv.raw_data[16 + (i * POINTER_SIZE), POINTER_SIZE].unpack1('Q<')
            values << val
          end
          { type: :embedded, length: embed_len, values: values }
        else
          len = rv.raw_data[16, 8].unpack1('q<')
          ptr = rv.raw_data[32, 8].unpack1('Q<')
          { type: :heap, length: len, pointer: ptr }
        end
      rescue StandardError
        nil
      end

      def extract_references(rv)
        refs = []

        # klass pointer is always a reference
        refs << rv.klass_ptr if valid_pointer?(rv.klass_ptr)

        case rv.type
        when :T_OBJECT
          # Instance variable pointers
          if (rv.flags & 0x2000) == 0
            # Embedded ivars
            3.times do |i|
              ptr = rv.raw_data[16 + (i * POINTER_SIZE), POINTER_SIZE]&.unpack1('Q<')
              refs << ptr if ptr && valid_pointer?(ptr)
            end
          else
            ivptr = rv.raw_data[24, 8].unpack1('Q<')
            refs << ivptr if valid_pointer?(ivptr)
          end

        when :T_ARRAY
          if (rv.flags & 0x2000) != 0
            embed_len = (rv.flags & 0x60000) >> 17
            embed_len.times do |i|
              ptr = rv.raw_data[16 + (i * POINTER_SIZE), POINTER_SIZE]&.unpack1('Q<')
              refs << ptr if ptr && valid_pointer?(ptr)
            end
          else
            ptr = rv.raw_data[32, 8].unpack1('Q<')
            refs << ptr if valid_pointer?(ptr)
          end

        when :T_HASH
          ifnone = rv.raw_data[16, 8].unpack1('Q<')
          ntbl = rv.raw_data[24, 8].unpack1('Q<')
          refs << ifnone if valid_pointer?(ifnone)
          refs << ntbl if valid_pointer?(ntbl)

        when :T_CLASS, :T_MODULE
          super_ptr = rv.raw_data[16, 8].unpack1('Q<')
          refs << super_ptr if valid_pointer?(super_ptr)

        when :T_STRING
          if (rv.flags & 0x2000) != 0 # STR_NOEMBED
            ptr = rv.raw_data[24, 8].unpack1('Q<')
            refs << ptr if valid_pointer?(ptr)
          end
        end

        refs.uniq
      end

      def build_class_info(rv)
        super_ptr = rv.raw_data[16, 8].unpack1('Q<')

        @classes[rv.address] = ClassInfo.new(
          address: rv.address,
          name: nil,
          super_address: valid_pointer?(super_ptr) ? super_ptr : nil,
          super_name: nil,
          instance_count: 0,
          method_count: 0,
          ancestors: []
        )
      end

      def resolve_class_names
        # Try to extract class names from the class objects
        @classes.each do |addr, cls|
          name = extract_class_name(addr)
          cls.name = name if name

          if cls.super_address && @classes.key?(cls.super_address)
            cls.super_name = @classes[cls.super_address].name
          end
        end

        # Update all objects with their resolved class names
        @objects.each_value do |obj|
          if obj.klass_address && @classes.key?(obj.klass_address)
            obj.klass_name = @classes[obj.klass_address].name
            @classes[obj.klass_address].instance_count += 1
          end
        end
      end

      def extract_class_name(class_addr)
        # Class name is stored in the class ext structure
        # Try to find it via string references
        rv = @dump_parser.read_rvalue(class_addr)
        return nil unless rv

        # The class name might be stored at a known offset in rb_classext_t
        ext_ptr = rv.raw_data[24, 8].unpack1('Q<')
        return nil unless valid_pointer?(ext_ptr)

        # Try reading a string pointer from the extension
        name_ptr = @dump_parser.read_pointer(ext_ptr + 8)
        if name_ptr && valid_pointer?(name_ptr)
          @dump_parser.read_string(name_ptr, max_length: 256)
        end
      rescue StandardError
        nil
      end

      def build_reference_graph
        @objects.each do |addr, obj|
          obj.references.each do |ref_addr|
            @reference_map[addr].add(ref_addr)
            @reverse_references[ref_addr].add(addr)
          end
        end
      end

      def extract_instance_variables
        @objects.each_value do |obj|
          next unless obj.type == :T_OBJECT

          rv = @dump_parser.read_rvalue(obj.address)
          next unless rv

          if (rv.flags & 0x2000) == 0
            # Embedded ivars (up to 3)
            3.times do |i|
              val = rv.raw_data[16 + (i * POINTER_SIZE), POINTER_SIZE]&.unpack1('Q<')
              if val && val != 0
                obj.instance_variables["@ivar_#{i}"] = format_value(val)
              end
            end
          else
            numiv = rv.raw_data[16, 4].unpack1('V')
            ivptr = rv.raw_data[24, 8].unpack1('Q<')

            if valid_pointer?(ivptr) && numiv > 0 && numiv < 1000
              numiv.times do |i|
                val = @dump_parser.read_pointer(ivptr + (i * POINTER_SIZE))
                if val && val != 0
                  obj.instance_variables["@ivar_#{i}"] = format_value(val)
                end
              end
            end
          end
        end
      end

      def format_value(val)
        # Check if it's a tagged fixnum
        if (val & 1) != 0
          return { type: :fixnum, value: val >> 1 }
        end

        # Check if it points to a known object
        if @objects.key?(val)
          obj = @objects[val]
          return { type: obj.type, address: "0x#{val.to_s(16)}", value: obj.value }
        end

        { type: :raw, value: "0x#{val.to_s(16)}" }
      end

      def estimate_object_size(rv)
        base = RVALUE_SIZE

        case rv.type
        when :T_STRING
          if (rv.flags & 0x2000) != 0
            len = rv.raw_data[16, 8].unpack1('q<')
            base + [len, 0].max
          else
            base
          end
        when :T_ARRAY
          if (rv.flags & 0x2000) == 0
            len = rv.raw_data[16, 8].unpack1('q<')
            base + ([len, 0].max * POINTER_SIZE)
          else
            base
          end
        else
          base
        end
      rescue StandardError
        base
      end

      def valid_pointer?(ptr)
        ptr && ptr > 0x1000 && ptr < 0x0000_8000_0000_0000
      end

      def avg_references
        return 0.0 if @objects.empty?

        total_refs = @reference_map.values.sum(&:size)
        (total_refs.to_f / @objects.size).round(2)
      end

      def calculate_max_depth
        return 0 if @objects.empty?

        roots = find_root_objects
        return 0 if roots.empty?

        max_d = 0
        roots.first(10).each do |root|
          d = bfs_depth(root)
          max_d = d if d > max_d
        end
        max_d
      end

      def bfs_depth(start_addr)
        visited = Set.new([start_addr])
        queue = [[start_addr, 0]]
        max_depth = 0

        while (item = queue.shift)
          addr, depth = item
          max_depth = depth if depth > max_depth
          break if depth >= @max_depth

          (@reference_map[addr] || Set.new).each do |ref|
            unless visited.include?(ref)
              visited.add(ref)
              queue << [ref, depth + 1]
            end
          end
        end

        max_depth
      end

      def build_object_graph
        type_dist = Hash.new(0)
        @objects.each_value { |obj| type_dist[obj.type] += 1 }

        ObjectGraph.new(
          objects: @objects,
          classes: @classes,
          roots: find_root_objects,
          total_count: @objects.size,
          type_distribution: type_dist,
          reference_map: @reference_map
        )
      end

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end
    end
  end
end
