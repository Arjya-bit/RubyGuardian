# frozen_string_literal: true

require 'json'

module RubyGuardian
  module MemoryForensics
    # RubyVMParser interprets Ruby VM internal data structures from memory dumps,
    # including RVALUEs, heap pages, instruction sequences, and thread state.
    class RubyVMParser
      RVALUE_SIZE = 40
      POINTER_SIZE = 8
      T_MASK = 0x1f

      RUBY_FL_USHIFT = 12
      RUBY_FL_FROZEN = 1 << (RUBY_FL_USHIFT + 11)
      STR_NOEMBED = 0x2000
      STR_SHARED = 0x4000
      EMBED_LEN_MASK = 0x1f0000
      EMBED_LEN_SHIFT = 16
      ARY_EMBED_FLAG = 0x2000
      ARY_EMBED_LEN_MASK = 0x60000
      ARY_EMBED_LEN_SHIFT = 17

      ISEQ_TYPES = {
        0 => :top, 1 => :method, 2 => :block, 3 => :class,
        4 => :rescue, 5 => :ensure, 6 => :eval, 7 => :main, 8 => :plain
      }.freeze

      VMState = Struct.new(
        :vm_ptr, :running_thread, :ractor_count, :objspace_ptr,
        :frozen_strings_ptr, :threads, keyword_init: true
      )

      ThreadInfo = Struct.new(
        :address, :self_value, :vm_ptr, :cfp_ptr, :status,
        :native_thread_id, :stack_frames, keyword_init: true
      )

      StackFrame = Struct.new(
        :pc, :sp, :iseq_ptr, :self_value, :ep, :block_code,
        :source_location, keyword_init: true
      )

      ISeqInfo = Struct.new(
        :address, :body_ptr, :type, :iseq_size, :encoded_ptr,
        :label, :path, :first_lineno, :local_table_size,
        :param_lead_num, :param_opt_num, :instructions, keyword_init: true
      )

      HeapPage = Struct.new(
        :address, :flags, :total_slots, :free_slots, :final_slots,
        :start_ptr, :freelist_ptr, :prev_ptr, :next_ptr, :body_ptr,
        :slot_entries, keyword_init: true
      )

      attr_reader :dump_parser, :profile, :vm_state

      def initialize(dump_parser, profile: nil)
        @dump_parser = dump_parser
        @profile = profile || load_default_profile
        @vm_state = nil
        @opcodes = build_opcode_table
      end

      # Locate and parse the Ruby VM structure
      def parse_vm(vm_ptr = nil)
        vm_ptr ||= locate_vm_pointer
        return nil unless vm_ptr

        structs = @profile['structures'] || {}
        vm_struct = structs['rb_vm_t'] || {}
        fields = vm_struct['fields'] || {}

        running_thread = @dump_parser.read_pointer(vm_ptr + field_offset(fields, 'running_thread'))
        ractor_cnt_offset = fields.dig('ractor', 'cnt', 'offset') || 16
        ractor_count = @dump_parser.read_uint32(vm_ptr + ractor_cnt_offset)
        objspace_ptr = @dump_parser.read_pointer(vm_ptr + field_offset(fields, 'objspace'))
        frozen_strings = @dump_parser.read_pointer(vm_ptr + field_offset(fields, 'frozen_strings'))

        @vm_state = VMState.new(
          vm_ptr: vm_ptr,
          running_thread: running_thread,
          ractor_count: ractor_count,
          objspace_ptr: objspace_ptr,
          frozen_strings_ptr: frozen_strings,
          threads: []
        )

        parse_threads(running_thread) if running_thread && running_thread > 0
        @vm_state
      end

      # Parse a Ruby thread structure
      def parse_thread(thread_ptr)
        return nil unless thread_ptr && thread_ptr > 0

        structs = @profile['structures'] || {}
        fields = (structs['rb_thread_t'] || {})['fields'] || {}

        self_val = @dump_parser.read_pointer(thread_ptr + field_offset(fields, 'self'))
        vm_ptr = @dump_parser.read_pointer(thread_ptr + field_offset(fields, 'vm'))
        cfp_ptr = @dump_parser.read_pointer(thread_ptr + field_offset(fields, 'cfp'))
        status = @dump_parser.read_uint32(thread_ptr + field_offset(fields, 'status'))
        tid = @dump_parser.read_pointer(thread_ptr + field_offset(fields, 'native_thread_id'))

        frames = parse_stack_frames(cfp_ptr) if cfp_ptr && cfp_ptr > 0

        ThreadInfo.new(
          address: thread_ptr,
          self_value: self_val,
          vm_ptr: vm_ptr,
          cfp_ptr: cfp_ptr,
          status: status,
          native_thread_id: tid,
          stack_frames: frames || []
        )
      end

      # Parse control frame stack to extract stack frames
      def parse_stack_frames(cfp_ptr, max_depth: 100)
        frames = []
        current = cfp_ptr
        cfp_size = 48 # rb_control_frame_t size

        max_depth.times do
          break unless current && current > 0

          frame = parse_control_frame(current)
          break unless frame

          frames << frame
          # Control frames grow downward in memory (toward lower addresses)
          current += cfp_size
        end

        frames
      end

      # Parse a single control frame
      def parse_control_frame(cfp_ptr)
        pc = @dump_parser.read_pointer(cfp_ptr)
        sp = @dump_parser.read_pointer(cfp_ptr + 8)
        iseq_ptr = @dump_parser.read_pointer(cfp_ptr + 16)
        self_val = @dump_parser.read_pointer(cfp_ptr + 24)
        ep = @dump_parser.read_pointer(cfp_ptr + 32)
        block_code = @dump_parser.read_pointer(cfp_ptr + 40)

        return nil if pc == 0 && sp == 0 && iseq_ptr == 0

        source_loc = nil
        if iseq_ptr && iseq_ptr > 0
          iseq = parse_iseq(iseq_ptr)
          source_loc = "#{iseq&.path}:#{iseq&.first_lineno} in `#{iseq&.label}`" if iseq
        end

        StackFrame.new(
          pc: pc, sp: sp, iseq_ptr: iseq_ptr,
          self_value: self_val, ep: ep, block_code: block_code,
          source_location: source_loc
        )
      end

      # Parse an instruction sequence structure
      def parse_iseq(iseq_ptr)
        return nil unless iseq_ptr && iseq_ptr > 0

        structs = @profile['structures'] || {}
        iseq_struct = structs['rb_iseq_t'] || {}
        body_offset = iseq_struct.dig('fields', 'body', 'offset') || 8

        body_ptr = @dump_parser.read_pointer(iseq_ptr + body_offset)
        return nil unless body_ptr && body_ptr > 0

        parse_iseq_body(iseq_ptr, body_ptr)
      end

      # Parse the constant body of an instruction sequence
      def parse_iseq_body(iseq_ptr, body_ptr)
        structs = @profile['structures'] || {}
        body_struct = structs['rb_iseq_constant_body'] || {}
        fields = body_struct['fields'] || {}

        type_raw = @dump_parser.read_uint32(body_ptr + field_offset(fields, 'type'))
        iseq_size = @dump_parser.read_uint32(body_ptr + (fields.dig('iseq_size', 'offset') || 4))
        encoded_ptr = @dump_parser.read_pointer(body_ptr + (fields.dig('iseq_encoded', 'offset') || 8))

        loc_fields = fields['location'] || {}
        path_obj = @dump_parser.read_pointer(body_ptr + (loc_fields.dig('pathobj', 'offset') || 48))
        label_ptr = @dump_parser.read_pointer(body_ptr + (loc_fields.dig('base_label', 'offset') || 56))
        first_lineno = @dump_parser.read_uint32(body_ptr + (loc_fields.dig('first_lineno', 'offset') || 72))

        local_table_size = @dump_parser.read_uint32(body_ptr + (fields.dig('local_table_size', 'offset') || 80))

        param_flags = @dump_parser.read_uint32(body_ptr + (fields.dig('param', 'flags', 'offset') || 16))
        param_lead = @dump_parser.read_uint32(body_ptr + (fields.dig('param', 'lead_num', 'offset') || 20))
        param_opt = @dump_parser.read_uint32(body_ptr + (fields.dig('param', 'opt_num', 'offset') || 24))

        path = extract_ruby_string_value(path_obj)
        label = extract_ruby_string_value(label_ptr)

        instructions = decode_instructions(encoded_ptr, iseq_size) if encoded_ptr && encoded_ptr > 0

        ISeqInfo.new(
          address: iseq_ptr,
          body_ptr: body_ptr,
          type: ISEQ_TYPES[type_raw] || :unknown,
          iseq_size: iseq_size,
          encoded_ptr: encoded_ptr,
          label: label,
          path: path,
          first_lineno: first_lineno,
          local_table_size: local_table_size,
          param_lead_num: param_lead,
          param_opt_num: param_opt,
          instructions: instructions || []
        )
      end

      # Parse a heap page structure
      def parse_heap_page(page_ptr)
        return nil unless page_ptr && page_ptr > 0

        structs = @profile['structures'] || {}
        page_struct = structs['rb_heap_page_t'] || {}
        fields = page_struct['fields'] || {}

        flags = @dump_parser.read_at(page_ptr, 2)&.unpack1('v') || 0
        total_slots = @dump_parser.read_at(page_ptr + 2, 2)&.unpack1('v') || 0
        free_slots = @dump_parser.read_at(page_ptr + 4, 2)&.unpack1('v') || 0
        final_slots = @dump_parser.read_at(page_ptr + 6, 2)&.unpack1('v') || 0
        start_ptr = @dump_parser.read_pointer(page_ptr + 8)
        freelist_ptr = @dump_parser.read_pointer(page_ptr + 16)
        prev_ptr = @dump_parser.read_pointer(page_ptr + 24)
        next_ptr = @dump_parser.read_pointer(page_ptr + 32)
        body_ptr = @dump_parser.read_pointer(page_ptr + 40)

        slots = parse_heap_slots(start_ptr, total_slots) if start_ptr && start_ptr > 0

        HeapPage.new(
          address: page_ptr,
          flags: flags,
          total_slots: total_slots,
          free_slots: free_slots,
          final_slots: final_slots,
          start_ptr: start_ptr,
          freelist_ptr: freelist_ptr,
          prev_ptr: prev_ptr,
          next_ptr: next_ptr,
          body_ptr: body_ptr,
          slot_entries: slots || []
        )
      end

      # Decode YARV instructions from encoded instruction sequence
      def decode_instructions(encoded_ptr, iseq_size)
        return [] unless encoded_ptr && iseq_size && iseq_size > 0

        instructions = []
        offset = 0

        while offset < iseq_size
          opcode_val = @dump_parser.read_pointer(encoded_ptr + (offset * POINTER_SIZE))
          break unless opcode_val

          opcode_name = @opcodes[opcode_val] || "unknown_#{opcode_val}"
          operand_count = opcode_operand_count(opcode_name)

          operands = []
          operand_count.times do |i|
            op_val = @dump_parser.read_pointer(encoded_ptr + ((offset + 1 + i) * POINTER_SIZE))
            operands << op_val
          end

          instructions << {
            offset: offset,
            opcode: opcode_name,
            opcode_value: opcode_val,
            operands: operands
          }

          offset += 1 + operand_count
        end

        instructions
      end

      # Extract a Ruby String value from an RString pointer
      def extract_ruby_string_value(rstring_ptr)
        return nil unless rstring_ptr && rstring_ptr > 0

        rvalue = @dump_parser.read_rvalue(rstring_ptr)
        return nil unless rvalue && rvalue.type == :T_STRING

        flags = rvalue.flags
        raw = rvalue.raw_data

        if (flags & STR_NOEMBED) != 0
          # Heap-allocated string
          len = raw[16, 8].unpack1('q<')
          ptr = raw[24, 8].unpack1('Q<')
          return nil if len <= 0 || len > 1_000_000 || ptr == 0

          @dump_parser.read_at(ptr, len)
        else
          # Embedded string
          embed_len = (flags & EMBED_LEN_MASK) >> EMBED_LEN_SHIFT
          return nil if embed_len <= 0 || embed_len > 24

          raw[16, embed_len]
        end
      rescue StandardError
        nil
      end

      # Enumerate all instruction sequences found in memory
      def find_all_iseqs
        iseqs = []
        @dump_parser.each_rvalue do |rv|
          next unless rv.type == :T_IMEMO || rv.type == :T_DATA

          iseq = parse_iseq(rv.address)
          iseqs << iseq if iseq && iseq.iseq_size > 0 && iseq.iseq_size < 100_000
        end
        iseqs
      end

      private

      def locate_vm_pointer
        # Search for the ruby_current_vm_ptr symbol in memory
        # Look for patterns that identify the VM structure
        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          # Scan for plausible VM pointers by looking for valid thread pointers
          offset = 0
          while offset + 72 <= region.data.bytesize
            candidate = region.start_addr + offset
            running_thread = @dump_parser.read_pointer(candidate)
            if running_thread && running_thread > 0 && running_thread < 0x0000_8000_0000_0000
              objspace = @dump_parser.read_pointer(candidate + 48)
              if objspace && objspace > 0 && objspace < 0x0000_8000_0000_0000
                return candidate
              end
            end
            offset += POINTER_SIZE
          end
        end
        nil
      end

      def parse_threads(starting_thread_ptr)
        thread = parse_thread(starting_thread_ptr)
        @vm_state.threads << thread if thread
      end

      def parse_heap_slots(start_ptr, total_slots)
        entries = []
        total_slots.times do |i|
          addr = start_ptr + (i * RVALUE_SIZE)
          rv = @dump_parser.read_rvalue(addr)
          entries << rv if rv
        end
        entries
      end

      def field_offset(fields, name)
        field = fields[name]
        return 0 unless field

        if field.is_a?(Hash) && field.key?('offset')
          field['offset']
        else
          0
        end
      end

      def build_opcode_table
        opcodes = {}
        if @profile.dig('instructions', 'opcodes')
          @profile['instructions']['opcodes'].each do |num, name|
            opcodes[num.to_i] = name
          end
        end
        opcodes
      end

      def opcode_operand_count(opcode_name)
        # Known operand counts for common YARV instructions
        case opcode_name
        when 'nop', 'putnil', 'putself', 'pop', 'dup', 'swap', 'leave',
             'anytostring', 'concatarray', 'splatarray', 'intern',
             'putobject_INT2FIX_0_', 'putobject_INT2FIX_1_'
          0
        when 'getlocal', 'setlocal', 'getlocal_WC_0', 'getlocal_WC_1',
             'setlocal_WC_0', 'setlocal_WC_1', 'putobject', 'putstring',
             'putspecialobject', 'getinstancevariable', 'setinstancevariable',
             'getclassvariable', 'setclassvariable', 'getconstant', 'setconstant',
             'getglobal', 'setglobal', 'getspecial', 'setspecial',
             'newarray', 'newhash', 'newrange', 'duparray', 'duphash',
             'dupn', 'topn', 'setn', 'adjuststack',
             'jump', 'branchif', 'branchunless', 'branchnil',
             'throw', 'once', 'opt_str_freeze', 'opt_str_uminus',
             'opt_getconstant_path', 'concatstrings'
          1
        when 'getblockparam', 'setblockparam', 'getblockparamproxy',
             'expandarray', 'defined', 'checkmatch', 'checkkeyword',
             'checktype', 'toregexp', 'send', 'opt_send_without_block',
             'invokesuper', 'invokeblock', 'definemethod', 'definesmethod',
             'defineclass', 'opt_case_dispatch', 'opt_aset_with', 'opt_aref_with',
             'newarraykwsplat', 'opt_newarray_send'
          2
        else
          0
        end
      end

      def load_default_profile
        path = File.join(__dir__, '..', 'config', 'volatility_profiles', 'ruby_3_2_linux.json')
        File.exist?(path) ? JSON.parse(File.read(path)) : {}
      end
    end
  end
end
