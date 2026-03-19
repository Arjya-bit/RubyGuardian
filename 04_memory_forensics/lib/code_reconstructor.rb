# frozen_string_literal: true

require 'json'
require 'yaml'
require 'fileutils'

module RubyGuardian
  module MemoryForensics
    # CodeReconstructor recovers Ruby source code from instruction sequences
    # found in memory dumps, translating YARV bytecode back into readable Ruby.
    class CodeReconstructor
      MAX_ISEQ_SIZE = 1_048_576
      INDENT_WIDTH = 2

      # YARV opcode to Ruby source mapping
      OPCODE_CATEGORIES = {
        control_flow: %w[jump branchif branchunless branchnil leave throw],
        method_call: %w[send opt_send_without_block invokesuper invokeblock],
        variable_access: %w[
          getlocal setlocal getinstancevariable setinstancevariable
          getclassvariable setclassvariable getglobal setglobal
          getlocal_WC_0 getlocal_WC_1 setlocal_WC_0 setlocal_WC_1
        ],
        stack_ops: %w[pop dup dupn swap topn setn adjuststack putnil putself putobject putstring],
        arithmetic: %w[opt_plus opt_minus opt_mult opt_div opt_mod opt_eq opt_neq opt_lt opt_le opt_gt opt_ge],
        definition: %w[defineclass definemethod definesmethod],
        literals: %w[putobject_INT2FIX_0_ putobject_INT2FIX_1_ newarray newhash newrange duparray duphash]
      }.freeze

      ReconstructedCode = Struct.new(
        :source, :iseq_address, :path, :label, :type,
        :first_lineno, :local_variables, :parameters,
        :confidence, :warnings, keyword_init: true
      )

      CodeFragment = Struct.new(
        :text, :lineno, :indent_level, :instruction_offset, keyword_init: true
      )

      attr_reader :vm_parser, :dump_parser, :config, :results

      def initialize(vm_parser, config: nil)
        @vm_parser = vm_parser
        @dump_parser = vm_parser.dump_parser
        @config = load_config(config)
        @results = []
        @label_map = {}
      end

      # Reconstruct all code found in the dump
      def reconstruct_all
        @results.clear
        iseqs = @vm_parser.find_all_iseqs

        iseqs.each do |iseq|
          next if iseq.iseq_size > MAX_ISEQ_SIZE
          next if iseq.iseq_size == 0

          result = reconstruct_iseq(iseq)
          @results << result if result
        end

        @results
      end

      # Reconstruct code from a specific instruction sequence
      def reconstruct_iseq(iseq)
        return nil unless iseq && iseq.instructions && !iseq.instructions.empty?

        warnings = []
        fragments = []
        indent = 0
        local_vars = build_local_variable_names(iseq)
        params = build_parameter_list(iseq)

        # Generate method/block/class header
        header = generate_header(iseq, params)
        fragments << CodeFragment.new(text: header, lineno: iseq.first_lineno || 1, indent_level: 0, instruction_offset: 0) if header

        indent += 1 if header
        label_targets = identify_label_targets(iseq.instructions)

        # Process instruction stream
        i = 0
        instructions = iseq.instructions
        while i < instructions.size
          insn = instructions[i]
          opcode = insn[:opcode]

          # Insert label if this offset is a branch target
          if label_targets.include?(insn[:offset])
            # Labels are implicit in Ruby, used for flow analysis
          end

          fragment = translate_instruction(insn, instructions, i, local_vars, indent, label_targets)
          if fragment
            fragments << fragment
            # Adjust indent for block structures
            indent = adjust_indent(indent, fragment.text)
          end

          i += 1
        end

        # Generate footer (end keyword)
        if header
          indent = [indent - 1, 0].max
          fragments << CodeFragment.new(text: 'end', lineno: nil, indent_level: indent, instruction_offset: nil)
        end

        source = assemble_source(fragments)
        confidence = calculate_confidence(iseq, fragments, warnings)

        ReconstructedCode.new(
          source: source,
          iseq_address: iseq.address,
          path: iseq.path,
          label: iseq.label,
          type: iseq.type,
          first_lineno: iseq.first_lineno,
          local_variables: local_vars,
          parameters: params,
          confidence: confidence,
          warnings: warnings
        )
      end

      # Save all reconstructed code to files
      def save_all(output_dir)
        FileUtils.mkdir_p(output_dir)
        manifest = []

        @results.each_with_index do |result, idx|
          filename = generate_filename(result, idx)
          filepath = File.join(output_dir, filename)

          File.write(filepath, format_output(result))
          manifest << {
            file: filename,
            original_path: result.path,
            label: result.label,
            type: result.type.to_s,
            confidence: result.confidence,
            address: "0x#{result.iseq_address.to_s(16)}"
          }
        end

        manifest_path = File.join(output_dir, 'manifest.json')
        File.write(manifest_path, JSON.pretty_generate(manifest))
        manifest
      end

      # Find potentially suspicious reconstructed code
      def find_suspicious_code
        suspicious = []
        suspicious_patterns = [
          { pattern: /eval\s*\(/, reason: 'Dynamic code evaluation', severity: :high },
          { pattern: /system\s*\(|`.*`|%x\{/, reason: 'Shell command execution', severity: :critical },
          { pattern: /Marshal\.(?:load|restore)/, reason: 'Unsafe deserialization', severity: :high },
          { pattern: /Base64\.decode64/, reason: 'Base64 decoding (possible payload)', severity: :medium },
          { pattern: /TCPSocket|UDPSocket|Socket\.new/, reason: 'Network socket creation', severity: :medium },
          { pattern: /File\.(?:write|open.*w)/, reason: 'File write operation', severity: :medium },
          { pattern: /require\s+['"](?:net\/http|open-uri|socket)/, reason: 'Network library loading', severity: :low },
          { pattern: /define_method|method_missing/, reason: 'Dynamic method definition', severity: :medium },
          { pattern: /send\s*\(|__send__/, reason: 'Dynamic method dispatch', severity: :medium },
          { pattern: /ObjectSpace|GC\./, reason: 'Runtime introspection', severity: :low }
        ]

        @results.each do |result|
          matches = []
          suspicious_patterns.each do |sp|
            if result.source.match?(sp[:pattern])
              matches << { reason: sp[:reason], severity: sp[:severity] }
            end
          end

          unless matches.empty?
            suspicious << {
              code: result,
              matches: matches,
              max_severity: matches.map { |m| m[:severity] }.min_by { |s| %i[critical high medium low].index(s) }
            }
          end
        end

        suspicious.sort_by { |s| %i[critical high medium low].index(s[:max_severity]) }
      end

      private

      def generate_header(iseq, params)
        param_str = params.empty? ? '' : "(#{params.join(', ')})"

        case iseq.type
        when :method
          "def #{iseq.label || 'unknown_method'}#{param_str}"
        when :class
          "class #{iseq.label || 'UnknownClass'}"
        when :block
          "do#{param_str.empty? ? '' : " |#{params.join(', ')}|"}"
        when :top, :main
          "# #{iseq.path || 'unknown'}:#{iseq.first_lineno || '?'}"
        when :rescue
          'rescue => e'
        when :ensure
          'ensure'
        else
          "# iseq type: #{iseq.type}"
        end
      end

      def translate_instruction(insn, all_instructions, index, local_vars, indent, label_targets)
        opcode = insn[:opcode]
        operands = insn[:operands] || []

        text = case opcode
               when 'putself'
                 nil # Implicit in Ruby
               when 'putnil'
                 'nil'
               when 'putobject'
                 format_literal(operands[0])
               when 'putobject_INT2FIX_0_'
                 '0'
               when 'putobject_INT2FIX_1_'
                 '1'
               when 'putstring'
                 str = resolve_string_operand(operands[0])
                 str ? "\"#{escape_string(str)}\"" : '"<string>"'
               when 'opt_plus'  then '+'
               when 'opt_minus' then '-'
               when 'opt_mult'  then '*'
               when 'opt_div'   then '/'
               when 'opt_mod'   then '%'
               when 'opt_eq'    then '=='
               when 'opt_neq'   then '!='
               when 'opt_lt'    then '<'
               when 'opt_le'    then '<='
               when 'opt_gt'    then '>'
               when 'opt_ge'    then '>='
               when 'opt_ltlt'  then '<<'
               when 'opt_and'   then '&'
               when 'opt_or'    then '|'
               when 'opt_not'   then '!'
               when 'opt_length'     then '.length'
               when 'opt_size'       then '.size'
               when 'opt_empty_p'    then '.empty?'
               when 'opt_succ'       then '.succ'
               when 'opt_nil_p'      then '.nil?'
               when 'opt_aref'       then '[]'
               when 'opt_aset'       then '[]='
               when 'getlocal', 'getlocal_WC_0', 'getlocal_WC_1'
                 var_name = resolve_local_variable(operands[0], local_vars)
                 var_name
               when 'setlocal', 'setlocal_WC_0', 'setlocal_WC_1'
                 var_name = resolve_local_variable(operands[0], local_vars)
                 "#{var_name} = <value>"
               when 'getinstancevariable'
                 resolve_ivar_name(operands[0]) || '@ivar'
               when 'setinstancevariable'
                 name = resolve_ivar_name(operands[0]) || '@ivar'
                 "#{name} = <value>"
               when 'getglobal'
                 resolve_global_name(operands[0]) || '$global'
               when 'setglobal'
                 name = resolve_global_name(operands[0]) || '$global'
                 "#{name} = <value>"
               when 'getconstant'
                 resolve_constant_name(operands[0]) || 'CONSTANT'
               when 'opt_send_without_block', 'send'
                 reconstruct_method_call(insn, all_instructions, index)
               when 'invokesuper'
                 'super'
               when 'invokeblock'
                 'yield'
               when 'newarray'
                 count = operands[0] || 0
                 count > 0 ? "[#{(['<expr>'] * [count, 10].min).join(', ')}]" : '[]'
               when 'newhash'
                 count = operands[0] || 0
                 count > 0 ? "{ #{(['<key> => <val>'] * [count / 2, 5].min).join(', ')} }" : '{}'
               when 'newrange'
                 exclusive = (operands[0] || 0) != 0
                 exclusive ? '<start>...<end>' : '<start>..<end>'
               when 'concatstrings'
                 count = operands[0] || 0
                 "\"#{(['#{}'] * [count, 5].min).join}\""
               when 'definemethod'
                 name = resolve_method_name(operands[0])
                 "def #{name || 'method_name'}"
               when 'definesmethod'
                 name = resolve_method_name(operands[0])
                 "def self.#{name || 'method_name'}"
               when 'defineclass'
                 name = resolve_class_def_name(operands[0])
                 "class #{name || 'ClassName'}"
               when 'branchif'
                 'if <condition>'
               when 'branchunless'
                 'unless <condition>'
               when 'branchnil'
                 'if <value>.nil?'
               when 'jump'
                 nil # Control flow - handled by structure analysis
               when 'leave'
                 nil # Return from method/block
               when 'throw'
                 'raise'
               when 'nop', 'pop', 'dup', 'dupn', 'swap', 'topn', 'setn', 'adjuststack'
                 nil # Stack manipulation - no direct Ruby equivalent
               when 'toregexp'
                 '/<pattern>/'
               when 'intern'
                 '.to_sym'
               when 'opt_str_freeze'
                 str = resolve_string_operand(operands[0])
                 str ? "\"#{escape_string(str)}\".freeze" : '"<string>".freeze'
               when 'opt_str_uminus'
                 str = resolve_string_operand(operands[0])
                 str ? "-\"#{escape_string(str)}\"" : '-"<string>"'
               when 'opt_regexpmatch2'
                 '=~'
               when 'once'
                 '# once block'
               when 'defined'
                 'defined?(<expr>)'
               when 'checkmatch'
                 '==='
               when 'splatarray'
                 '*<array>'
               when 'concatarray'
                 '<array1> + <array2>'
               else
                 nil
               end

        return nil unless text

        CodeFragment.new(
          text: text,
          lineno: nil,
          indent_level: indent,
          instruction_offset: insn[:offset]
        )
      end

      def reconstruct_method_call(insn, all_instructions, index)
        operands = insn[:operands] || []
        # The method name is typically the first operand (as a symbol ID)
        method_id = operands[0]
        argc = operands[1] || 0

        method_name = resolve_method_name(method_id) || "method_#{method_id}"

        if argc > 0
          args = (['<arg>'] * [argc, 8].min).join(', ')
          "#{method_name}(#{args})"
        else
          method_name
        end
      end

      def identify_label_targets(instructions)
        targets = Set.new
        instructions.each do |insn|
          if %w[jump branchif branchunless branchnil].include?(insn[:opcode])
            target = insn[:operands]&.first
            targets.add(target) if target
          end
        end
        targets
      end

      def adjust_indent(indent, text)
        if text.match?(/\A\s*(?:end|rescue|ensure|else|elsif)\b/)
          [indent - 1, 0].max
        elsif text.match?(/\A\s*(?:def |class |module |if |unless |while |until |for |begin|do|case)\b/) ||
              text.match?(/\bdo\s*(?:\|.*\|)?\s*$/)
          indent + 1
        else
          indent
        end
      end

      def assemble_source(fragments)
        lines = fragments.compact.map do |f|
          padding = ' ' * (f.indent_level * INDENT_WIDTH)
          "#{padding}#{f.text}"
        end
        lines.join("\n")
      end

      def build_local_variable_names(iseq)
        # Generate placeholder names based on local table size
        count = iseq.local_table_size || 0
        names = {}
        count.times { |i| names[i] = "local_#{i}" }
        names
      end

      def build_parameter_list(iseq)
        params = []
        lead = iseq.param_lead_num || 0
        opt = iseq.param_opt_num || 0

        lead.times { |i| params << "arg#{i + 1}" }
        opt.times { |i| params << "opt_arg#{i + 1} = nil" }

        params
      end

      def resolve_local_variable(index, local_vars)
        local_vars[index] || "local_#{index}"
      end

      def resolve_string_operand(ptr)
        return nil unless ptr && ptr > 0

        @vm_parser.extract_ruby_string_value(ptr)
      rescue StandardError
        nil
      end

      def resolve_method_name(id)
        return nil unless id

        # Try to find the method name string in memory
        str = @dump_parser.read_string(id, max_length: 128)
        str && str =~ /\A[a-zA-Z_][a-zA-Z0-9_]*[?!=]?\z/ ? str : nil
      rescue StandardError
        nil
      end

      def resolve_ivar_name(id)
        str = resolve_method_name(id)
        str ? "@#{str}" : nil
      end

      def resolve_global_name(id)
        str = resolve_method_name(id)
        str ? "$#{str}" : nil
      end

      def resolve_constant_name(id)
        resolve_method_name(id)
      end

      def resolve_class_def_name(id)
        resolve_method_name(id)
      end

      def format_literal(value)
        return 'nil' if value.nil?
        return 'true' if value == 0x12 # T_TRUE
        return 'false' if value == 0x13 # T_FALSE

        if value.is_a?(Integer)
          if (value & 1) != 0
            # Tagged fixnum
            (value >> 1).to_s
          elsif value < 256
            value.to_s
          else
            "0x#{value.to_s(16)}"
          end
        else
          value.inspect
        end
      end

      def escape_string(str)
        str.to_s
           .gsub('\\', '\\\\\\\\')
           .gsub('"', '\\"')
           .gsub("\n", '\\n')
           .gsub("\t", '\\t')
           .gsub("\r", '\\r')
      end

      def calculate_confidence(iseq, fragments, warnings)
        score = 1.0

        # Reduce confidence for unknown opcodes
        unknown_ratio = fragments.count { |f| f&.text&.include?('unknown') }.to_f / [fragments.size, 1].max
        score -= unknown_ratio * 0.3

        # Reduce for placeholder values
        placeholder_ratio = fragments.count { |f| f&.text&.include?('<') }.to_f / [fragments.size, 1].max
        score -= placeholder_ratio * 0.2

        # Reduce for warnings
        score -= warnings.size * 0.05

        # Bonus for having source path info
        score += 0.05 if iseq.path

        [score.round(3), 0.0].max
      end

      def generate_filename(result, index)
        base = if result.path
                 File.basename(result.path, '.*')
               else
                 "reconstructed_#{index}"
               end
        label = result.label ? "_#{result.label}" : ''
        "#{base}#{label}_0x#{result.iseq_address.to_s(16)}.rb"
      end

      def format_output(result)
        lines = [
          "# Reconstructed Ruby source code",
          "# Original path: #{result.path || 'unknown'}",
          "# Method/block: #{result.label || 'unknown'}",
          "# Type: #{result.type}",
          "# First line: #{result.first_lineno || '?'}",
          "# ISeq address: 0x#{result.iseq_address.to_s(16)}",
          "# Reconstruction confidence: #{(result.confidence * 100).round(1)}%",
          "#",
          "# WARNING: This is a best-effort reconstruction from YARV bytecode.",
          "# Variable names and some constructs may not match the original source.",
          "",
          result.source
        ]

        unless result.warnings.empty?
          lines.insert(8, "# Warnings: #{result.warnings.join(', ')}")
        end

        lines.join("\n") + "\n"
      end

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end
    end
  end
end
