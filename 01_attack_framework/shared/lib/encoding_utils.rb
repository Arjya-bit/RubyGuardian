# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'
require 'zlib'

module RubyGuardian
  module Shared
    # Encoding and encryption utilities for payload obfuscation research
    # Educational: demonstrates how malware encodes payloads to evade detection
    module EncodingUtils
      module_function

      # XOR encode data with a key
      # Detection: Look for XOR loops in disassembly
      def xor_encode(data, key:)
        key_bytes = key.bytes
        data.bytes.each_with_index.map do |byte, i|
          (byte ^ key_bytes[i % key_bytes.length]).chr
        end.join
      end

      # XOR decode (symmetric operation)
      def xor_decode(data, key:)
        xor_encode(data, key: key)
      end

      # AES-256-CBC encryption
      def aes_encrypt(data, key:, iv: nil)
        cipher = OpenSSL::Cipher::AES256.new(:CBC)
        cipher.encrypt
        cipher.key = normalize_key(key, 32)
        iv ||= cipher.random_iv
        cipher.iv = iv

        encrypted = cipher.update(data) + cipher.final
        { data: Base64.strict_encode64(encrypted), iv: Base64.strict_encode64(iv) }
      end

      # AES-256-CBC decryption
      def aes_decrypt(encrypted_data, key:, iv:)
        cipher = OpenSSL::Cipher::AES256.new(:CBC)
        cipher.decrypt
        cipher.key = normalize_key(key, 32)
        cipher.iv = Base64.strict_decode64(iv)

        cipher.update(Base64.strict_decode64(encrypted_data)) + cipher.final
      end

      # Base64 encode with optional URL-safe variant
      def base64_encode(data, url_safe: false)
        url_safe ? Base64.urlsafe_encode64(data) : Base64.strict_encode64(data)
      end

      # Base64 decode
      def base64_decode(data, url_safe: false)
        url_safe ? Base64.urlsafe_decode64(data) : Base64.strict_decode64(data)
      end

      # Generate a random encoding key
      def generate_key(length: 32)
        SecureRandom.random_bytes(length)
      end

      # Compress data using zlib
      def compress(data)
        Zlib::Deflate.deflate(data)
      end

      # Decompress zlib data
      def decompress(data)
        Zlib::Inflate.inflate(data)
      end

      # Multi-layer encoding (compress -> encrypt -> base64)
      # Educational: demonstrates how malware chains encoding to evade detection
      def multi_encode(data, key:)
        compressed = compress(data)
        encrypted = aes_encrypt(compressed, key: key)
        {
          payload: encrypted[:data],
          iv: encrypted[:iv],
          encoding: 'zlib+aes256+base64'
        }
      end

      # Multi-layer decoding (base64 -> decrypt -> decompress)
      def multi_decode(encoded, key:)
        decrypted = aes_decrypt(encoded[:payload], key: key, iv: encoded[:iv])
        decompress(decrypted)
      end

      # Calculate Shannon entropy of data
      # High entropy suggests encryption/encoding
      def shannon_entropy(data)
        return 0.0 if data.empty?

        frequencies = Hash.new(0)
        data.each_byte { |b| frequencies[b] += 1 }
        length = data.bytesize.to_f

        frequencies.values.sum do |count|
          probability = count / length
          -probability * Math.log2(probability)
        end
      end

      private_class_method def self.normalize_key(key, length)
        if key.bytesize >= length
          key[0, length]
        else
          key.ljust(length, "\0")
        end
      end
    end
  end
end
