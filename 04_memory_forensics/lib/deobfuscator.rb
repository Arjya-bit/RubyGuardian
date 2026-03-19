# frozen_string_literal: true

require 'base64'
require 'zlib'
require 'json'
require 'yaml'

module RubyGuardian
  module MemoryForensics
    # Deobfuscator reverses common Ruby obfuscation techniques found in malware,
    # including Base64 encoding, XOR ciphers, eval/Marshal chains, character code
    # assembly, and string packing.
    class Deobfuscator
      MAX_ITERATIONS = 100
      MAX_OUTPUT_SIZE = 10 * 1024 * 1024 # 10 MB

      DeobfuscationResult = Struct.new(
        :original, :deobfuscated, :technique, :iterations,
        :confidence, :chain, :warnings, keyword_init: true
      )

      DeobfuscationStep = Struct.new(
        :technique, :input_preview, :output_preview,
        :transformation, keyword_init: true
      )

      TECHNIQUES = %i[
        base64_encoding eval_string_construction marshal_load
        character_code_assembly xor_encoding zlib_compression
        string_unpack define_method_injection method_missing_abuse
        binding_eval hex_encoding reverse_string rot13
        string_replace_chain gsub_decode
      ].freeze

      # Patterns that identify specific obfuscation techniques
      DETECTION_PATTERNS = {
        base64_encoding: [
          /eval\s*\(\s*Base64\.decode64\s*\(\s*['"]([A-Za-z0-9+\/=\n]+)['"]\s*\)\s*\)/m,
          /Base64\.decode64\s*\(\s*['"]([A-Za-z0-9+\/=\n]+)['"]\s*\)/m
        ],
        eval_string_construction: [
          /eval\s*\(\s*(['"])(.+?)\1\s*\)/m,
          /eval\s*\(\s*\[([^\]]+)\]\.join\s*\)/m,
          /eval\s*\(\s*"([^"]*#\{[^}]+\}[^"]*)"\s*\)/m
        ],
        marshal_load: [
          /Marshal\.(?:load|restore)\s*\(\s*(['"])(.*?)\1\s*\)/m,
          /Marshal\.(?:load|restore)\s*\(\s*Base64\.decode64\s*\(\s*['"]([A-Za-z0-9+\/=]+)['"]\s*\)\s*\)/m
        ],
        character_code_assembly: [
          /\[(\d+(?:\s*,\s*\d+)*)\]\.pack\s*\(\s*['"]U\*['"]\s*\)/,
          /\[(\d+(?:\s*,\s*\d+)*)\]\.map\s*\{\s*\|.\|\s*.\s*\.chr\s*\}\.join/,
          /eval\s*\(\s*\[(\d+(?:\s*,\s*\d+)*)\]\.pack\s*\(\s*['"]C\*['"]\s*\)\s*\)/
        ],
        xor_encoding: [
          /\.bytes\.map\s*\{\s*\|(.)\|\s*\(\1\s*\^\s*(\d+)\)\.chr\s*\}\.join/,
          /\.each_byte\.map\s*\{\s*\|(.)\|\s*\(\1\s*\^\s*0x([0-9a-fA-F]+)\)\.chr\s*\}\.join/
        ],
        zlib_compression: [
          /Zlib::Inflate\.inflate\s*\(\s*(['"])(.*?)\1\s*\)/m,
          /eval\s*\(\s*Zlib::Inflate\.inflate\s*\(/m
        ],
        string_unpack: [
          /['"]([0-9a-fA-F]+)['"]\.scan\(\/..\/\)\.map\s*\{\s*\|.\|\s*.\s*\.to_i\s*\(\s*16\s*\)\.chr\s*\}\.join/,
          /\[['"]([A-Za-z0-9+\/=]+)['"]\]\.pack\s*\(\s*['"]m['"]\s*\)/
        ],
        hex_encoding: [
          /\[['"]([0-9a-fA-F]+)['"]\]\.pack\s*\(\s*['"]H\*['"]\s*\)/,
          /['"]([0-9a-fA-F]+)['"]\.scan\(\/..\/\)\.map\(\&:hex\)\.pack\(['"]C\*['"]\)/
        ],
        reverse_string: [
          /['"](.+)['"]\.reverse/,
          /eval\s*\(\s*['"](.+)['"]\.reverse\s*\)/
        ],
        rot13: [
          /\.tr\s*\(\s*['"]A-Za-z['"]\s*,\s*['"]N-ZA-Mn-za-m['"]\s*\)/,
          /eval\s*\(\s*['"](.+)['"]\.tr\s*\(\s*['"]A-Za-z['"]\s*,\s*['"]N-ZA-Mn-za-m['"]\s*\)\s*\)/
        ],
        gsub_decode: [
          /\.gsub\s*\(\s*\/(.+?)\/\s*\)\s*\{\s*\|(.)\|\s*(.+?)\s*\}/,
          /\.chars\.map\s*\{\s*\|(.)\|\s*(.+?)\s*\}\.join/
        ]
      }.freeze

      attr_reader :config, :results

      def initialize(config: nil)
        @config = load_config(config)
        @max_iterations = @config.dig('reconstruction', 'deobfuscation', 'max_iterations') || MAX_ITERATIONS
        @results = []
        @enabled_techniques = load_enabled_techniques
      end

      # Deobfuscate a string of obfuscated Ruby code
      def deobfuscate(code)
        @results.clear
        chain = []
        current = code.dup
        iteration = 0

        while iteration < @max_iterations
          technique, deobfuscated = try_deobfuscate_step(current)
          break unless technique && deobfuscated
          break if deobfuscated == current # No progress
          break if deobfuscated.bytesize > MAX_OUTPUT_SIZE

          chain << DeobfuscationStep.new(
            technique: technique,
            input_preview: truncate(current, 100),
            output_preview: truncate(deobfuscated, 100),
            transformation: "#{technique}: #{current.bytesize} -> #{deobfuscated.bytesize} bytes"
          )

          current = deobfuscated
          iteration += 1
        end

        result = DeobfuscationResult.new(
          original: code,
          deobfuscated: current,
          technique: chain.map(&:technique).uniq,
          iterations: iteration,
          confidence: calculate_confidence(code, current, chain),
          chain: chain,
          warnings: generate_warnings(current)
        )

        @results << result
        result
      end

      # Detect which obfuscation techniques are present in code
      def detect_techniques(code)
        detected = []

        DETECTION_PATTERNS.each do |technique, patterns|
          patterns.each do |pattern|
            if code.match?(pattern)
              detected << {
                technique: technique,
                pattern: pattern.source[0, 60],
                match: code.match(pattern).to_s[0, 100]
              }
              break
            end
          end
        end

        detected
      end

      # Batch deobfuscate multiple code samples
      def batch_deobfuscate(code_samples)
        code_samples.map { |code| deobfuscate(code) }
      end

      # Analyze obfuscation complexity
      def analyze_complexity(code)
        layers = 0
        current = code.dup
        techniques_used = []

        MAX_ITERATIONS.times do
          technique, result = try_deobfuscate_step(current)
          break unless technique && result && result != current

          layers += 1
          techniques_used << technique
          current = result
        end

        {
          layers: layers,
          techniques: techniques_used,
          original_size: code.bytesize,
          final_size: current.bytesize,
          entropy_original: calculate_entropy(code),
          entropy_final: calculate_entropy(current),
          complexity_score: calculate_complexity_score(layers, techniques_used)
        }
      end

      private

      def try_deobfuscate_step(code)
        @enabled_techniques.each do |technique|
          result = apply_technique(technique, code)
          return [technique, result] if result && result != code
        end
        [nil, nil]
      end

      def apply_technique(technique, code)
        case technique
        when :base64_encoding
          deobfuscate_base64(code)
        when :eval_string_construction
          deobfuscate_eval_string(code)
        when :marshal_load
          deobfuscate_marshal(code)
        when :character_code_assembly
          deobfuscate_char_codes(code)
        when :xor_encoding
          deobfuscate_xor(code)
        when :zlib_compression
          deobfuscate_zlib(code)
        when :string_unpack
          deobfuscate_unpack(code)
        when :hex_encoding
          deobfuscate_hex(code)
        when :reverse_string
          deobfuscate_reverse(code)
        when :rot13
          deobfuscate_rot13(code)
        when :gsub_decode
          deobfuscate_gsub(code)
        end
      rescue StandardError
        nil
      end

      def deobfuscate_base64(code)
        DETECTION_PATTERNS[:base64_encoding].each do |pattern|
          match = code.match(pattern)
          next unless match

          encoded = match.captures.find { |c| c && c.match?(/\A[A-Za-z0-9+\/=\n]+\z/) }
          next unless encoded

          begin
            decoded = Base64.decode64(encoded.gsub(/\s/, ''))
            next unless decoded && printable_ratio(decoded) > 0.7

            return code.sub(match[0], decoded)
          rescue StandardError
            next
          end
        end
        nil
      end

      def deobfuscate_eval_string(code)
        DETECTION_PATTERNS[:eval_string_construction].each do |pattern|
          match = code.match(pattern)
          next unless match

          # Strip eval() wrapper to reveal the code
          inner = match.captures.last
          next unless inner

          # Handle array join: eval(["a","b","c"].join)
          if inner.include?(',')
            parts = inner.scan(/['"]([^'"]*?)['"]/)
            decoded = parts.flatten.join
          else
            decoded = inner
          end

          return decoded if decoded && !decoded.empty?
        end
        nil
      end

      def deobfuscate_marshal(code)
        DETECTION_PATTERNS[:marshal_load].each do |pattern|
          match = code.match(pattern)
          next unless match

          data_str = match.captures.last
          next unless data_str

          begin
            # If it's Base64-wrapped Marshal
            if data_str.match?(/\A[A-Za-z0-9+\/=]+\z/)
              decoded = Base64.decode64(data_str)
              # Do NOT actually Marshal.load for safety - just show the raw data
              return "# Marshal data (decoded from Base64, #{decoded.bytesize} bytes):\n" \
                     "# #{decoded.unpack1('H*')[0, 200]}\n" \
                     "# WARNING: Marshal.load is unsafe - data not deserialized"
            end
          rescue StandardError
            next
          end
        end
        nil
      end

      def deobfuscate_char_codes(code)
        DETECTION_PATTERNS[:character_code_assembly].each do |pattern|
          match = code.match(pattern)
          next unless match

          numbers_str = match[1]
          next unless numbers_str

          numbers = numbers_str.scan(/\d+/).map(&:to_i)
          next if numbers.empty?

          begin
            decoded = numbers.pack('U*')
            next unless printable_ratio(decoded) > 0.8

            # Replace the matched pattern with decoded text, stripping eval if present
            result = code.sub(match[0], decoded)
            result = result.sub(/\Aeval\s*\(\s*/, '').sub(/\s*\)\s*\z/, '') if result.start_with?('eval')
            return result
          rescue StandardError
            next
          end
        end
        nil
      end

      def deobfuscate_xor(code)
        DETECTION_PATTERNS[:xor_encoding].each do |pattern|
          match = code.match(pattern)
          next unless match

          key = if match[2] =~ /\A0x/i
                  match[2].to_i(16)
                else
                  match[2].to_i
                end

          # Find the source string
          str_match = code.match(/['"](.+?)['"]\.(?:bytes|each_byte)/)
          next unless str_match

          begin
            source = str_match[1]
            decoded = source.bytes.map { |b| (b ^ key).chr }.join
            next unless printable_ratio(decoded) > 0.7

            return code.sub(match[0], "\"#{decoded}\"")
          rescue StandardError
            next
          end
        end
        nil
      end

      def deobfuscate_zlib(code)
        DETECTION_PATTERNS[:zlib_compression].each do |pattern|
          match = code.match(pattern)
          next unless match

          compressed = match.captures.last
          next unless compressed

          begin
            # Handle binary string escapes
            binary = eval("\"#{compressed}\"") rescue compressed
            decoded = Zlib::Inflate.inflate(binary)
            next unless printable_ratio(decoded) > 0.7

            return decoded
          rescue Zlib::DataError, Zlib::BufError
            next
          end
        end
        nil
      end

      def deobfuscate_unpack(code)
        DETECTION_PATTERNS[:string_unpack].each do |pattern|
          match = code.match(pattern)
          next unless match

          hex_str = match[1]
          next unless hex_str

          begin
            if hex_str.match?(/\A[A-Za-z0-9+\/=]+\z/) && hex_str.length > 4
              decoded = Base64.decode64(hex_str)
            else
              decoded = [hex_str].pack('H*')
            end
            next unless printable_ratio(decoded) > 0.7

            return decoded
          rescue StandardError
            next
          end
        end
        nil
      end

      def deobfuscate_hex(code)
        DETECTION_PATTERNS[:hex_encoding].each do |pattern|
          match = code.match(pattern)
          next unless match

          hex = match[1]
          next unless hex && hex.match?(/\A[0-9a-fA-F]+\z/)

          begin
            decoded = [hex].pack('H*')
            next unless printable_ratio(decoded) > 0.7

            return code.sub(match[0], "\"#{decoded}\"")
          rescue StandardError
            next
          end
        end
        nil
      end

      def deobfuscate_reverse(code)
        match = code.match(/eval\s*\(\s*['"](.+)['"]\.reverse\s*\)/)
        return nil unless match

        reversed = match[1].reverse
        printable_ratio(reversed) > 0.7 ? reversed : nil
      end

      def deobfuscate_rot13(code)
        DETECTION_PATTERNS[:rot13].each do |pattern|
          match = code.match(pattern)
          next unless match

          if match[1]
            decoded = match[1].tr('A-Za-z', 'N-ZA-Mn-za-m')
            return decoded if printable_ratio(decoded) > 0.7
          else
            # Non-eval wrapped: just note the tr substitution
            return code.sub(match[0], '.tr("A-Za-z","A-Za-z") # ROT13 decoded')
          end
        end
        nil
      end

      def deobfuscate_gsub(code)
        # Handle simple character substitution chains
        match = code.match(/['"](.+?)['"](?:\.gsub\s*\(\s*['"](.)['"]\s*,\s*['"](.)['"]\s*\))+/m)
        return nil unless match

        result = match[1]
        code.scan(/\.gsub\s*\(\s*['"](.)['"]\s*,\s*['"](.)['"]\s*\)/) do |from, to|
          result = result.gsub(from, to)
        end

        result != match[1] ? result : nil
      end

      def calculate_confidence(original, deobfuscated, chain)
        return 0.0 if chain.empty?

        score = 0.5

        # Higher confidence if entropy decreased
        orig_entropy = calculate_entropy(original)
        final_entropy = calculate_entropy(deobfuscated)
        score += 0.2 if final_entropy < orig_entropy

        # Higher confidence if result looks like valid Ruby
        score += 0.15 if looks_like_ruby?(deobfuscated)

        # Lower confidence for many iterations (might be overtransforming)
        score -= 0.05 * [chain.size - 3, 0].max

        # Higher confidence for known technique patterns
        score += 0.1 if chain.any? { |s| %i[base64_encoding xor_encoding].include?(s.technique) }

        [score.round(3), 0.0].max.clamp(0.0, 1.0)
      end

      def calculate_entropy(str)
        return 0.0 if str.nil? || str.empty?

        freq = Hash.new(0)
        str.each_byte { |b| freq[b] += 1 }
        len = str.bytesize.to_f

        -freq.values.sum { |c| p = c / len; p * Math.log2(p) }
      end

      def calculate_complexity_score(layers, techniques)
        base = layers * 2.0
        diversity = techniques.uniq.size * 1.5
        [base + diversity, 10.0].min
      end

      def printable_ratio(str)
        return 0.0 if str.nil? || str.empty?

        printable = str.bytes.count { |b| b >= 0x20 && b <= 0x7E || b == 0x0A || b == 0x0D || b == 0x09 }
        printable.to_f / str.bytesize
      end

      def looks_like_ruby?(code)
        ruby_keywords = %w[def class module end if else unless while until do require include]
        keyword_count = ruby_keywords.count { |kw| code.include?(kw) }
        keyword_count >= 2
      end

      def generate_warnings(code)
        warnings = []
        warnings << 'Contains eval() - may execute arbitrary code' if code.include?('eval')
        warnings << 'Contains system() - may execute shell commands' if code.include?('system')
        warnings << 'Contains Marshal.load - unsafe deserialization' if code.include?('Marshal.load')
        warnings << 'Contains require from /tmp - suspicious code loading' if code.match?(/require.*\/tmp/)
        warnings
      end

      def truncate(str, max_len)
        str.length > max_len ? "#{str[0, max_len]}..." : str
      end

      def load_enabled_techniques
        configured = @config.dig('reconstruction', 'deobfuscation', 'techniques')
        if configured
          configured.map(&:to_sym).select { |t| TECHNIQUES.include?(t) }
        else
          TECHNIQUES
        end
      end

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end
    end
  end
end
