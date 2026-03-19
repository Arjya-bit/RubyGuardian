# frozen_string_literal: true

# RubyGuardian Phase 1c -- LoLRuby Defense Evasion: String Obfuscation
#
# Demonstrates various string obfuscation techniques available in Ruby
# that can be used to evade static analysis and signature detection.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1027 - Obfuscated Files or Information

require 'base64'
require 'zlib'

module RubyGuardian
  module LoLRuby
    module DefenseEvasion
      class StringObfuscator
        TECHNIQUES = %i[
          base64 hex char_codes reverse xor
          zlib_deflate marshal string_concat
        ].freeze

        attr_reader :logger

        def initialize(logger: nil)
          @logger = logger
        end

        # Demonstrate all obfuscation techniques on a sample string
        def demonstrate_all(sample = 'puts "Hello from RubyGuardian"')
          @logger&.info('[LoLRuby] Demonstrating string obfuscation techniques')

          TECHNIQUES.map do |technique|
            result = demonstrate(technique, sample)
            { technique: technique, **result }
          end
        end

        # Demonstrate a specific obfuscation technique
        def demonstrate(technique, input)
          case technique
          when :base64
            encoded = Base64.strict_encode64(input)
            {
              encoded: encoded,
              decoder: "Base64.decode64('#{encoded}')",
              detection: 'Base64 string followed by eval'
            }
          when :hex
            hex = input.bytes.map { |b| '\x%02x' % b }.join
            {
              encoded: hex,
              decoder: "\"#{hex}\"",
              detection: 'Long hex-escaped strings'
            }
          when :char_codes
            codes = input.bytes.join(',')
            {
              encoded: codes,
              decoder: "[#{codes}].pack('C*')",
              detection: 'Array of integers with pack("C*")'
            }
          when :reverse
            reversed = input.reverse
            {
              encoded: reversed,
              decoder: "'#{reversed}'.reverse",
              detection: 'String.reverse before eval'
            }
          when :xor
            key = rand(1..255)
            xored = input.bytes.map { |b| b ^ key }
            {
              encoded: xored.inspect,
              decoder: "#{xored.inspect}.map{|b|b^#{key}}.pack('C*')",
              key: key,
              detection: 'XOR decoding loop patterns'
            }
          when :zlib_deflate
            compressed = Zlib::Deflate.deflate(input)
            b64 = Base64.strict_encode64(compressed)
            {
              encoded: b64,
              decoder: "Zlib::Inflate.inflate(Base64.decode64('#{b64}'))",
              detection: 'Zlib::Inflate followed by eval'
            }
          when :string_concat
            parts = input.scan(/.{1,4}/)
            {
              encoded: parts.map { |p| "'#{p}'" }.join(' + '),
              decoder: "String concatenation of #{parts.size} fragments",
              detection: 'Many small string concatenations'
            }
          else
            { error: "Unknown technique: #{technique}" }
          end
        end

        # Calculate an obfuscation score for a given Ruby source string
        def obfuscation_score(source)
          indicators = {
            base64_patterns: source.scan(/Base64\.(decode64|strict_decode64)/).size,
            eval_calls: source.scan(/\b(eval|instance_eval|class_eval)\b/).size,
            hex_strings: source.scan(/\\x[0-9a-f]{2}/i).size,
            pack_calls: source.scan(/\.pack\s*\(/).size,
            xor_operations: source.scan(/\^/).size,
            zlib_usage: source.scan(/Zlib::(Inflate|Deflate)/).size,
            marshal_loads: source.scan(/Marshal\.load/).size,
            send_calls: source.scan(/\.send\s*\(/).size
          }

          total = indicators.values.sum
          {
            score: [total * 10, 100].min,
            indicators: indicators,
            risk: total > 5 ? 'HIGH' : total > 2 ? 'MEDIUM' : 'LOW'
          }
        end

        def describe
          <<~DESC
            String Obfuscation (T1027)
            ━━━━━━━━━━━━━━━━━━━━━━━━━━
            Ruby's dynamic nature provides many built-in obfuscation options:
            Base64, hex encoding, character code arrays, XOR, Zlib compression,
            Marshal serialization, and string concatenation.

            Detection: Look for eval() calls combined with decoding operations.
            Score code by counting obfuscation indicators.
          DESC
        end
      end
    end
  end
end
