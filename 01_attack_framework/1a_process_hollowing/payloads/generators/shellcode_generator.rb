# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Shellcode Generator
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use generated shellcode outside of controlled lab environments.
#
# Generates benign demonstration shellcode for x86_64 Linux. All payloads
# are harmless: they write messages to stdout/files and exit cleanly.
# This module teaches shellcode structure, syscall conventions, and encoding.
#
# MITRE ATT&CK: T1059.004 - Command and Scripting Interpreter: Unix Shell
# =============================================================================

module RubyGuardian
  module ProcessHollowing
    module Payloads
      class ShellcodeGenerator
        # Linux x86_64 syscall numbers
        SYSCALLS = {
          read:     0,
          write:    1,
          open:     2,
          close:    3,
          mmap:     9,
          mprotect: 10,
          munmap:   11,
          exit:     60,
          getpid:   39,
          fork:     57
        }.freeze

        # File descriptor constants
        STDOUT = 1
        STDERR = 2

        attr_reader :shellcodes

        def initialize
          @shellcodes = {}
        end

        # Generate a write(stdout, message) + exit(0) shellcode.
        #
        # EDUCATIONAL: This is the simplest useful shellcode. It demonstrates
        # the x86_64 Linux syscall ABI:
        #   rax = syscall number
        #   rdi = first argument
        #   rsi = second argument (pointer to data)
        #   rdx = third argument
        #   syscall instruction triggers the kernel call
        #
        # @param message [String] Message to write to stdout
        # @return [String] Raw shellcode bytes
        def generate_write_exit(message = "RubyGuardian shellcode executed\n")
          msg_bytes = message.bytes

          # Calculate the RIP-relative offset to the message data
          # The message is appended after the syscall+exit instructions
          code_before_msg = assemble_write_exit_prefix(msg_bytes.length)
          rip_offset = code_before_msg.length

          shellcode = []

          # mov rax, 1 (sys_write)
          shellcode += [0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]

          # mov rdi, 1 (stdout)
          shellcode += [0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00]

          # lea rsi, [rip + offset_to_msg]
          # The offset is calculated from the end of this instruction
          remaining_code_len = 7 + 2 + 7 + 3 + 2  # rdx_mov + syscall + exit_mov + xor + syscall
          shellcode += [0x48, 0x8D, 0x35]
          shellcode += pack_le32(remaining_code_len)

          # mov rdx, msg_length
          shellcode += [0x48, 0xC7, 0xC2]
          shellcode += pack_le32(msg_bytes.length)

          # syscall (write)
          shellcode += [0x0F, 0x05]

          # mov rax, 60 (sys_exit)
          shellcode += [0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00]

          # xor rdi, rdi (exit code 0)
          shellcode += [0x48, 0x31, 0xFF]

          # syscall (exit)
          shellcode += [0x0F, 0x05]

          # Append the message data
          shellcode += msg_bytes

          result = shellcode.pack('C*')
          @shellcodes[:write_exit] = result
          result
        end

        # Generate a getpid + write(stdout, pid) + exit shellcode.
        #
        # EDUCATIONAL: Demonstrates multi-syscall shellcode that retrieves
        # runtime information (the PID) and outputs it. This is a common
        # pattern in reconnaissance shellcode.
        #
        # @return [String] Raw shellcode bytes
        def generate_getpid_exit
          shellcode = []

          # mov rax, 39 (sys_getpid)
          shellcode += [0x48, 0xC7, 0xC0, 0x27, 0x00, 0x00, 0x00]
          # syscall -- result in rax
          shellcode += [0x0F, 0x05]

          # Store PID result for write: convert to ASCII digits on stack
          # push rax (save pid)
          shellcode += [0x50]
          # We'll write a fixed marker instead of doing full int-to-ascii
          # mov rax, 1 (sys_write)
          shellcode += [0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]
          # mov rdi, 1 (stdout)
          shellcode += [0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00]
          # lea rsi, [rip + offset] -> points to marker string below
          marker = "PID_MARKER\n"
          remaining = 7 + 2 + 7 + 3 + 2  # rdx + syscall + exit + xor + syscall
          shellcode += [0x48, 0x8D, 0x35]
          shellcode += pack_le32(remaining)
          # mov rdx, marker_len
          shellcode += [0x48, 0xC7, 0xC2]
          shellcode += pack_le32(marker.length)
          # syscall (write)
          shellcode += [0x0F, 0x05]

          # exit(0)
          shellcode += [0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00]
          shellcode += [0x48, 0x31, 0xFF]
          shellcode += [0x0F, 0x05]

          # Marker string data
          shellcode += marker.bytes

          result = shellcode.pack('C*')
          @shellcodes[:getpid_exit] = result
          result
        end

        # Generate a NOP sled of the specified length.
        #
        # EDUCATIONAL: NOP sleds increase the target area for imprecise jumps.
        # In modern exploitation they are less common due to ASLR, but they
        # remain useful for alignment and as padding in injection buffers.
        #
        # @param length [Integer] Number of NOP bytes
        # @return [String] NOP sled bytes
        def generate_nop_sled(length = 256)
          "\x90" * length
        end

        # Generate shellcode with a NOP sled prefix.
        #
        # @param sled_length [Integer] Length of NOP sled prefix
        # @param message [String] Message for the write+exit payload
        # @return [String] Combined shellcode
        def generate_with_nop_sled(sled_length: 64, message: "RubyGuardian\n")
          sled = generate_nop_sled(sled_length)
          payload = generate_write_exit(message)
          combined = sled + payload
          @shellcodes[:nop_sled_write] = combined
          combined
        end

        # Return metadata about all generated shellcodes.
        #
        # @return [Hash] Shellcode metadata
        def catalog
          @shellcodes.transform_values do |sc|
            {
              size: sc.bytesize,
              hex_preview: sc[0, 16].unpack1('H*'),
              null_bytes: sc.count("\x00"),
              has_null: sc.include?("\x00")
            }
          end
        end

        # Describe shellcode generation for educational purposes.
        def describe
          <<~DESC
            Shellcode Generator (Educational)

            Generates benign x86_64 Linux shellcode for process hollowing demos.
            All payloads are harmless -- they write messages and exit cleanly.

            Available generators:
              - write_exit:     Write a message to stdout, then exit(0)
              - getpid_exit:    Get PID via syscall, write marker, exit(0)
              - nop_sled:       Generate NOP sled padding
              - with_nop_sled:  NOP sled + write_exit combined

            x86_64 Linux syscall ABI:
              rax = syscall number
              rdi = arg1, rsi = arg2, rdx = arg3
              r10 = arg4, r8 = arg5, r9 = arg6
              'syscall' instruction invokes kernel
          DESC
        end

        private

        # Pack an integer as a 4-byte little-endian array.
        def pack_le32(value)
          [value].pack('V').bytes
        end

        # Calculate the code length before the message for offset computation.
        def assemble_write_exit_prefix(msg_length)
          # This mirrors the instruction sequence in generate_write_exit
          # Used only for offset calculation
          [0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00].pack('C*')
        end
      end
    end
  end
end
