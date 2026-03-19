# frozen_string_literal: true

module RubyGuardian
  module Shared
    # Detect if running inside a sandbox, VM, or analysis environment
    # Educational: demonstrates anti-analysis techniques used by malware
    #
    # MITRE ATT&CK: T1497 - Virtualization/Sandbox Evasion
    class SandboxDetector
      SANDBOX_INDICATORS = {
        processes: %w[
          vboxservice vmtoolsd vmwaretray wireshark
          procmon processhacker fiddler x64dbg ollydbg
          ida idaq pestudio regshot
        ],
        files: %w[
          /usr/bin/vboxmanage
          /usr/bin/vmware-toolbox-cmd
          /sys/class/dmi/id/product_name
        ],
        env_vars: %w[
          SANDBOX ANALYSIS_ENV CUCKOO REMNUX
        ],
        mac_prefixes: %w[
          08:00:27 00:0C:29 00:50:56 00:1C:42
        ]
      }.freeze

      class << self
        # Run all sandbox detection checks
        def detect
          results = {
            vm_detected: check_vm_artifacts,
            sandbox_detected: check_sandbox_processes,
            debugger_detected: check_debugger,
            timing_anomaly: check_timing,
            low_resources: check_resources,
            suspicious_env: check_environment,
            container: check_container
          }

          results[:is_sandboxed] = results.values.any? { |v| v == true }
          results
        end

        # Quick check - is this likely a sandbox?
        def sandboxed?
          detect[:is_sandboxed]
        end

        # Require sandbox environment (for safety)
        # Raises unless we're in a known safe environment
        def require_sandbox!
          return if ENV['RUBY_GUARDIAN_ENV'] == 'sandbox'
          return if check_container

          unless sandboxed?
            warn "[SAFETY] Not running in detected sandbox/container."
            warn "[SAFETY] Set RUBY_GUARDIAN_ENV=sandbox to override."
            raise SecurityError, "Refusing to run outside sandbox environment"
          end
        end

        private

        def check_vm_artifacts
          return false unless PlatformDetector.linux?

          if File.exist?('/sys/class/dmi/id/product_name')
            product = File.read('/sys/class/dmi/id/product_name').strip.downcase
            return true if product =~ /virtualbox|vmware|kvm|qemu|xen|hyper-v/
          end

          # Check for VM-specific kernel modules
          if File.exist?('/proc/modules')
            modules = File.read('/proc/modules').downcase
            return true if modules =~ /vboxguest|vmw_balloon|virtio/
          end

          false
        rescue StandardError
          false
        end

        def check_sandbox_processes
          return false unless PlatformDetector.linux?

          processes = `ps aux 2>/dev/null`.downcase
          SANDBOX_INDICATORS[:processes].any? { |p| processes.include?(p) }
        rescue StandardError
          false
        end

        def check_debugger
          # Check if we're being traced (Linux ptrace)
          if PlatformDetector.linux? && File.exist?('/proc/self/status')
            status = File.read('/proc/self/status')
            tracer_pid = status.match(/TracerPid:\s+(\d+)/)&.captures&.first&.to_i
            return true if tracer_pid && tracer_pid > 0
          end

          false
        rescue StandardError
          false
        end

        def check_timing
          # Timing-based detection: sleep should take expected time
          # Sandboxes often accelerate sleep for faster analysis
          start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          sleep(0.1)
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start

          # If sleep was significantly shorter or longer, suspicious
          elapsed < 0.05 || elapsed > 0.5
        rescue StandardError
          false
        end

        def check_resources
          return false unless PlatformDetector.linux?

          # Sandboxes often have minimal resources
          cpu_count = `nproc 2>/dev/null`.strip.to_i
          return true if cpu_count <= 1

          # Check available memory (less than 1GB is suspicious)
          if File.exist?('/proc/meminfo')
            meminfo = File.read('/proc/meminfo')
            total_kb = meminfo.match(/MemTotal:\s+(\d+)/)&.captures&.first&.to_i || 0
            return true if total_kb < 1_048_576 # 1GB in KB
          end

          false
        rescue StandardError
          false
        end

        def check_environment
          SANDBOX_INDICATORS[:env_vars].any? { |var| ENV.key?(var) }
        end

        def check_container
          File.exist?('/.dockerenv') || File.exist?('/run/.containerenv')
        rescue StandardError
          false
        end
      end
    end
  end
end
