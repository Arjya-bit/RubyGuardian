# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Sysmon Event Generator
#
# Generates simulated Sysmon-style detection events that would be triggered
# by process hollowing activity. Used for testing detection rules and SIEM
# integrations.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
# =============================================================================

require 'json'
require 'securerandom'
require 'time'

module RubyGuardian
  module ProcessHollowing
    class SysmonEventGenerator
      # Sysmon event IDs relevant to process hollowing
      EVENT_TYPES = {
        process_create:        { id: 1,  name: 'Process Create' },
        process_terminate:     { id: 5,  name: 'Process Terminated' },
        image_loaded:          { id: 7,  name: 'Image Loaded' },
        create_remote_thread:  { id: 8,  name: 'CreateRemoteThread' },
        raw_access_read:       { id: 9,  name: 'RawAccessRead' },
        process_access:        { id: 10, name: 'ProcessAccess' },
        file_create:           { id: 11, name: 'FileCreate' },
        registry_event:        { id: 13, name: 'RegistryEvent' },
        pipe_created:          { id: 17, name: 'PipeCreated' },
        dns_query:             { id: 22, name: 'DNSEvent' },
        process_tampering:     { id: 25, name: 'ProcessTampering' }
      }.freeze

      # Linux auditd equivalents
      AUDITD_TYPES = {
        ptrace:           'PTRACE',
        execve:           'EXECVE',
        mmap:             'MMAP',
        process_vm_writev: 'SYSCALL',
        prctl:            'PRCTL'
      }.freeze

      attr_reader :events

      def initialize(output: $stdout)
        @output = output
        @events = []
        @base_time = Time.now.utc
        @event_counter = 0
      end

      # Generate the complete set of events for a process hollowing attack.
      #
      # @param attacker_pid [Integer] PID of the attacking process
      # @param target_binary [String] Path to the target (victim) binary
      # @param payload_name [String] Descriptive name for the payload
      # @return [Array<Hash>] Generated events
      def generate_hollowing_sequence(attacker_pid: nil, target_binary: '/bin/sleep', payload_name: 'unknown_payload')
        attacker_pid ||= Process.pid
        target_pid = rand(10000..65535)
        @events = []

        # Event 1: Attacker process creates the target process
        add_event(:process_create, {
          parent_pid: attacker_pid,
          parent_image: RbConfig.ruby,
          pid: target_pid,
          image: target_binary,
          command_line: "#{target_binary} 86400",
          creation_flags: 'CREATE_SUSPENDED',
          user: ENV['USER'] || 'unknown',
          description: 'Target process created in suspended state for hollowing'
        })

        # Event 2: Attacker accesses target process memory (ptrace attach)
        add_event(:process_access, {
          source_pid: attacker_pid,
          source_image: RbConfig.ruby,
          target_pid: target_pid,
          target_image: target_binary,
          granted_access: 'PROCESS_ALL_ACCESS',
          call_trace: 'ptrace(PTRACE_ATTACH)',
          description: 'Cross-process memory access for injection'
        })

        # Event 3: Memory map read (reading /proc/pid/maps)
        add_event(:raw_access_read, {
          pid: attacker_pid,
          image: RbConfig.ruby,
          target: "/proc/#{target_pid}/maps",
          description: 'Reading target process memory layout'
        })

        # Event 4: Original image unmapped (the "hollowing" event)
        add_event(:process_tampering, {
          pid: target_pid,
          image: target_binary,
          type: 'Image is replaced',
          source_pid: attacker_pid,
          description: 'Original process image unmapped via ptrace+munmap shellcode'
        })

        # Event 5: New memory allocated in target (mmap via ptrace)
        add_event(:process_access, {
          source_pid: attacker_pid,
          source_image: RbConfig.ruby,
          target_pid: target_pid,
          target_image: target_binary,
          granted_access: 'PROCESS_VM_WRITE',
          call_trace: 'process_vm_writev / ptrace(PTRACE_POKEDATA)',
          description: 'Payload data written to hollowed process memory'
        })

        # Event 6: Thread context modified (RIP redirected)
        add_event(:create_remote_thread, {
          source_pid: attacker_pid,
          source_image: RbConfig.ruby,
          target_pid: target_pid,
          target_image: target_binary,
          start_address: '0x%016x' % rand(0x400000..0x7fffff),
          start_module: '<unknown>',
          description: 'Thread context modified to redirect execution to payload'
        })

        # Event 7: Process resumed
        add_event(:process_access, {
          source_pid: attacker_pid,
          source_image: RbConfig.ruby,
          target_pid: target_pid,
          target_image: target_binary,
          granted_access: 'PROCESS_RESUME',
          call_trace: 'ptrace(PTRACE_DETACH)',
          description: 'Hollowed process resumed with injected payload'
        })

        # Event 8: Potential C2 callback from hollowed process
        add_event(:dns_query, {
          pid: target_pid,
          image: target_binary,
          query_name: 'c2.example.com',
          query_type: 'A',
          description: 'DNS query from hollowed process (potential C2 callback)'
        })

        @events
      end

      # Generate Linux auditd-style events.
      #
      # @return [Array<Hash>] Auditd events
      def generate_auditd_events(attacker_pid: nil, target_pid: nil)
        attacker_pid ||= Process.pid
        target_pid ||= rand(10000..65535)
        events = []

        # ptrace attach
        events << {
          type: 'SYSCALL',
          timestamp: next_timestamp,
          arch: 'x86_64',
          syscall: 'ptrace',
          pid: attacker_pid,
          ppid: Process.ppid,
          uid: Process.uid,
          exe: RbConfig.ruby,
          a0: '0x10',  # PTRACE_ATTACH
          a1: target_pid.to_s,
          success: 'yes',
          key: 'process_injection'
        }

        # process_vm_writev
        events << {
          type: 'SYSCALL',
          timestamp: next_timestamp,
          arch: 'x86_64',
          syscall: 'process_vm_writev',
          pid: attacker_pid,
          ppid: Process.ppid,
          uid: Process.uid,
          exe: RbConfig.ruby,
          a0: target_pid.to_s,
          success: 'yes',
          key: 'process_injection'
        }

        # ptrace setregs
        events << {
          type: 'SYSCALL',
          timestamp: next_timestamp,
          arch: 'x86_64',
          syscall: 'ptrace',
          pid: attacker_pid,
          ppid: Process.ppid,
          uid: Process.uid,
          exe: RbConfig.ruby,
          a0: '0xd',  # PTRACE_SETREGS
          a1: target_pid.to_s,
          success: 'yes',
          key: 'process_injection'
        }

        # ptrace detach
        events << {
          type: 'SYSCALL',
          timestamp: next_timestamp,
          arch: 'x86_64',
          syscall: 'ptrace',
          pid: attacker_pid,
          ppid: Process.ppid,
          uid: Process.uid,
          exe: RbConfig.ruby,
          a0: '0x11',  # PTRACE_DETACH
          a1: target_pid.to_s,
          success: 'yes',
          key: 'process_injection'
        }

        events
      end

      # Output events in various formats for SIEM consumption.
      #
      # @param format [Symbol] Output format (:json, :cef, :ecs)
      # @return [String] Formatted events
      def export(format: :json)
        case format
        when :json
          JSON.pretty_generate({ events: @events })
        when :cef
          @events.map { |e| to_cef(e) }.join("\n")
        when :ecs
          @events.map { |e| to_ecs(e) }.join("\n")
        end
      end

      # Write events to a file.
      def write_to_file(path, format: :json)
        File.write(path, export(format: format))
      end

      private

      def add_event(type, data)
        event_info = EVENT_TYPES[type]
        event = {
          event_id: event_info[:id],
          event_type: event_info[:name],
          timestamp: next_timestamp,
          sequence: @event_counter,
          rule_name: 'RubyGuardian ProcessHollowing Detection',
          data: data,
          mitre_attack: {
            technique: 'T1055.012',
            tactic: 'Defense Evasion',
            name: 'Process Injection: Process Hollowing'
          }
        }
        @events << event
        event
      end

      def next_timestamp
        @event_counter += 1
        (@base_time + @event_counter * 0.05).iso8601(3)
      end

      def to_cef(event)
        "CEF:0|RubyGuardian|AttackFramework|1.0|#{event[:event_id]}|" \
        "#{event[:event_type]}|7|" \
        "src=#{event.dig(:data, :source_pid)} " \
        "dst=#{event.dig(:data, :target_pid)} " \
        "msg=#{event.dig(:data, :description)}"
      end

      def to_ecs(event)
        JSON.generate({
          '@timestamp' => event[:timestamp],
          'event.kind' => 'alert',
          'event.category' => 'process',
          'event.action' => event[:event_type].downcase.gsub(' ', '_'),
          'process.pid' => event.dig(:data, :pid) || event.dig(:data, :source_pid),
          'threat.technique.id' => 'T1055.012',
          'message' => event.dig(:data, :description)
        })
      end
    end
  end
end

# CLI entry point
if __FILE__ == $PROGRAM_NAME
  generator = RubyGuardian::ProcessHollowing::SysmonEventGenerator.new
  events = generator.generate_hollowing_sequence

  puts "Generated #{events.length} Sysmon-style events:"
  puts generator.export(format: :json)

  # Also generate auditd events
  auditd = generator.generate_auditd_events
  puts "\nGenerated #{auditd.length} auditd-style events:"
  puts JSON.pretty_generate(auditd)
end
