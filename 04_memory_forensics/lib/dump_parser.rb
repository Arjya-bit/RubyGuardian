# frozen_string_literal: true

require 'json'
require 'yaml'
require 'zlib'
require 'digest'
require 'stringio'

module RubyGuardian
  module MemoryForensics
    # DumpParser parses raw memory dumps, identifies Ruby VM structures,
    # and provides an interface for navigating dump contents.
    class DumpParser
      RGMEM_MAGIC = 'RGMEM'
      HEADER_ALIGNMENT = 4096
      RVALUE_SIZE = 40
      POINTER_SIZE = 8

      # Ruby type flag constants
      T_MASK = 0x1f
      TYPE_MAP = {
        0x00 => :T_NONE,   0x01 => :T_OBJECT, 0x02 => :T_CLASS,
        0x03 => :T_MODULE, 0x04 => :T_FLOAT,  0x05 => :T_STRING,
        0x06 => :T_REGEXP, 0x07 => :T_ARRAY,  0x08 => :T_HASH,
        0x09 => :T_STRUCT, 0x0a => :T_BIGNUM, 0x0b => :T_FILE,
        0x0c => :T_DATA,   0x0d => :T_MATCH,  0x0e => :T_COMPLEX,
        0x0f => :T_RATIONAL, 0x11 => :T_NIL,  0x12 => :T_TRUE,
        0x13 => :T_FALSE,  0x14 => :T_SYMBOL, 0x15 => :T_FIXNUM,
        0x16 => :T_UNDEF,  0x1a => :T_IMEMO,  0x1b => :T_NODE,
        0x1c => :T_ICLASS, 0x1d => :T_ZOMBIE, 0x1e => :T_MOVED
      }.freeze

      ParsedRegion = Struct.new(
        :start_addr, :end_addr, :permissions, :pathname,
        :data, :offset_in_dump, :size, keyword_init: true
      )

      RValueEntry = Struct.new(
        :address, :type, :flags, :klass_ptr, :raw_data,
        :region_index, keyword_init: true
      )

      class ParseError < StandardError; end
      class CorruptedDumpError < ParseError; end

      attr_reader :file_path, :regions, :header, :profile, :stats

      def initialize(file_path, profile: nil)
        @file_path = file_path
        @profile = load_profile(profile)
        @regions = []
        @header = nil
        @data = nil
        @stats = { total_size: 0, region_count: 0, rvalues_found: 0 }
        @rvalue_cache = {}
      end

      # Parse the dump file and index its contents
      def parse
        raw_data = read_dump_file
        @stats[:total_size] = raw_data.bytesize

        if raw_data[0, 5] == RGMEM_MAGIC || looks_like_rgmem_header?(raw_data)
          parse_rgmem_dump(raw_data)
        elsif looks_like_elf_core?(raw_data)
          parse_elf_core(raw_data)
        else
          parse_raw_dump(raw_data)
        end

        @stats[:region_count] = @regions.size
        scan_for_ruby_structures
        self
      end

      # Read arbitrary bytes from the dump at a virtual address
      def read_at(address, length)
        region = find_region_for_address(address)
        return nil unless region

        offset = address - region.start_addr
        return nil if offset + length > region.data.bytesize

        region.data[offset, length]
      end

      # Read a pointer (8 bytes little-endian) at a virtual address
      def read_pointer(address)
        data = read_at(address, POINTER_SIZE)
        return nil unless data

        data.unpack1('Q<')
      end

      # Read a 32-bit unsigned integer
      def read_uint32(address)
        data = read_at(address, 4)
        return nil unless data

        data.unpack1('V')
      end

      # Read a 64-bit unsigned integer
      def read_uint64(address)
        data = read_at(address, 8)
        return nil unless data

        data.unpack1('Q<')
      end

      # Read a null-terminated string at address
      def read_string(address, max_length: 4096)
        region = find_region_for_address(address)
        return nil unless region

        offset = address - region.start_addr
        end_offset = [offset + max_length, region.data.bytesize].min
        chunk = region.data[offset...end_offset]
        null_pos = chunk.index("\x00")
        null_pos ? chunk[0, null_pos] : chunk
      end

      # Read an RValue structure at the given address
      def read_rvalue(address)
        return @rvalue_cache[address] if @rvalue_cache.key?(address)

        raw = read_at(address, RVALUE_SIZE)
        return nil unless raw && raw.bytesize == RVALUE_SIZE

        flags = raw[0, 8].unpack1('Q<')
        klass = raw[8, 8].unpack1('Q<')
        type_id = flags & T_MASK
        type = TYPE_MAP[type_id] || :T_UNKNOWN

        entry = RValueEntry.new(
          address: address,
          type: type,
          flags: flags,
          klass_ptr: klass,
          raw_data: raw
        )

        @rvalue_cache[address] = entry
        entry
      end

      # Iterate over all potential RValues in the dump
      def each_rvalue(&block)
        return enum_for(:each_rvalue) unless block_given?

        @regions.each_with_index do |region, region_idx|
          next unless region.permissions.include?('r')

          offset = 0
          while offset + RVALUE_SIZE <= region.data.bytesize
            address = region.start_addr + offset
            flags = region.data[offset, 8].unpack1('Q<')
            type_id = flags & T_MASK

            if TYPE_MAP.key?(type_id) && plausible_rvalue?(flags, region.data, offset)
              entry = RValueEntry.new(
                address: address,
                type: TYPE_MAP[type_id],
                flags: flags,
                klass_ptr: region.data[offset + 8, 8].unpack1('Q<'),
                raw_data: region.data[offset, RVALUE_SIZE],
                region_index: region_idx
              )
              @rvalue_cache[address] = entry
              yield entry
            end

            offset += RVALUE_SIZE
          end
        end
      end

      # Find all RValues of a specific type
      def find_rvalues_by_type(type)
        each_rvalue.select { |rv| rv.type == type }
      end

      # Find the region containing a given virtual address
      def find_region_for_address(address)
        @regions.find do |region|
          address >= region.start_addr && address < region.end_addr
        end
      end

      # Search for a byte pattern across all regions
      def search_pattern(pattern, max_results: 1000)
        results = []
        regex = pattern.is_a?(Regexp) ? pattern : Regexp.new(Regexp.escape(pattern))

        @regions.each do |region|
          next unless region.permissions.include?('r')

          offset = 0
          while (match = region.data.index(regex, offset))
            address = region.start_addr + match
            context_start = [match - 16, 0].max
            context_end = [match + pattern.to_s.bytesize + 16, region.data.bytesize].min
            context = region.data[context_start...context_end]

            results << {
              address: address,
              offset: match,
              region: region.pathname,
              context: context
            }

            break if results.size >= max_results
            offset = match + 1
          end
        end

        results
      end

      # Extract all readable memory as a flat byte array with address mapping
      def flatten
        flat = StringIO.new
        address_map = []

        @regions.sort_by(&:start_addr).each do |region|
          next unless region.permissions.include?('r')

          address_map << {
            flat_offset: flat.pos,
            virtual_address: region.start_addr,
            size: region.data.bytesize
          }
          flat.write(region.data)
        end

        { data: flat.string, address_map: address_map }
      end

      # Generate a summary of the parsed dump
      def summary
        type_counts = Hash.new(0)
        each_rvalue { |rv| type_counts[rv.type] += 1 }

        {
          file: @file_path,
          total_size: @stats[:total_size],
          regions: @regions.map do |r|
            {
              range: "0x#{r.start_addr.to_s(16)}-0x#{r.end_addr.to_s(16)}",
              size: r.size,
              permissions: r.permissions,
              pathname: r.pathname
            }
          end,
          ruby_object_types: type_counts,
          total_rvalues: type_counts.values.sum
        }
      end

      private

      def read_dump_file
        if @file_path.end_with?('.gz')
          Zlib::GzipReader.open(@file_path) { |gz| gz.read }
        else
          File.binread(@file_path)
        end
      rescue Zlib::GzipFile::Error
        # Not actually gzipped, read as raw
        File.binread(@file_path)
      end

      def looks_like_rgmem_header?(data)
        return false if data.bytesize < 8

        len = data[0, 4].unpack1('V')
        len > 0 && len < 1_000_000 && data[4, 1] == '{'
      end

      def looks_like_elf_core?(data)
        data[0, 4] == "\x7FELF"
      end

      def parse_rgmem_dump(data)
        json_len = data[0, 4].unpack1('V')
        header_json = data[4, json_len]
        @header = JSON.parse(header_json)

        # Calculate total header size with padding
        raw_header_size = 4 + json_len
        padded_header_size = ((raw_header_size + HEADER_ALIGNMENT - 1) / HEADER_ALIGNMENT) * HEADER_ALIGNMENT
        body_offset = padded_header_size

        @header['regions'].each do |region_info|
          start_addr = region_info['start'].to_i(16)
          end_addr = region_info['end'].to_i(16)
          region_size = region_info['size'] || (end_addr - start_addr)

          region_data = if body_offset + region_size <= data.bytesize
                          data[body_offset, region_size]
                        else
                          ''
                        end

          @regions << ParsedRegion.new(
            start_addr: start_addr,
            end_addr: end_addr,
            permissions: region_info['permissions'] || 'r--p',
            pathname: region_info['pathname'] || '',
            data: region_data,
            offset_in_dump: body_offset,
            size: region_size
          )

          body_offset += region_size
        end
      end

      def parse_elf_core(data)
        # Minimal ELF core parser - extract PT_LOAD segments
        ei_class = data[4].unpack1('C')
        is_64bit = (ei_class == 2)

        unless is_64bit
          raise ParseError, 'Only 64-bit ELF cores are supported'
        end

        e_phoff = data[32, 8].unpack1('Q<')
        e_phentsize = data[54, 2].unpack1('v')
        e_phnum = data[56, 2].unpack1('v')

        e_phnum.times do |i|
          ph_offset = e_phoff + (i * e_phentsize)
          p_type = data[ph_offset, 4].unpack1('V')
          next unless p_type == 1 # PT_LOAD

          p_offset = data[ph_offset + 8, 8].unpack1('Q<')
          p_vaddr = data[ph_offset + 16, 8].unpack1('Q<')
          p_filesz = data[ph_offset + 32, 8].unpack1('Q<')
          p_memsz = data[ph_offset + 40, 8].unpack1('Q<')
          p_flags = data[ph_offset + 4, 4].unpack1('V')

          perms = ''
          perms += (p_flags & 4) != 0 ? 'r' : '-'
          perms += (p_flags & 2) != 0 ? 'w' : '-'
          perms += (p_flags & 1) != 0 ? 'x' : '-'
          perms += 'p'

          region_data = p_offset + p_filesz <= data.bytesize ? data[p_offset, p_filesz] : ''

          @regions << ParsedRegion.new(
            start_addr: p_vaddr,
            end_addr: p_vaddr + p_memsz,
            permissions: perms,
            pathname: '',
            data: region_data,
            offset_in_dump: p_offset,
            size: p_filesz
          )
        end
      end

      def parse_raw_dump(data)
        # Treat the entire file as a single memory region
        @regions << ParsedRegion.new(
          start_addr: 0,
          end_addr: data.bytesize,
          permissions: 'rw-p',
          pathname: '[raw_dump]',
          data: data,
          offset_in_dump: 0,
          size: data.bytesize
        )
      end

      def scan_for_ruby_structures
        @stats[:rvalues_found] = 0
        each_rvalue { @stats[:rvalues_found] += 1 }
      end

      def plausible_rvalue?(flags, data, offset)
        # Quick heuristic checks for plausibility
        return false if flags == 0
        return false if flags == 0xFFFFFFFFFFFFFFFF

        # klass pointer should look like a valid heap address
        klass = data[offset + 8, 8].unpack1('Q<')
        return false if klass == 0 && (flags & T_MASK) != 0x00
        # Klass should be in a reasonable address range for userspace
        return true if klass == 0
        klass < 0x0000_8000_0000_0000 && klass > 0x0000_0000_0040_0000
      end

      def load_profile(profile)
        return profile if profile.is_a?(Hash)

        profile_name = profile || 'ruby_3_2_linux'
        profile_path = File.join(__dir__, '..', 'config', 'volatility_profiles', "#{profile_name}.json")
        if File.exist?(profile_path)
          JSON.parse(File.read(profile_path))
        else
          {}
        end
      end
    end
  end
end
