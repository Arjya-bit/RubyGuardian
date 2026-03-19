# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Anti-Analysis Module
#
# Demonstrates anti-debugging, anti-VM, and anti-sandbox techniques that
# malware uses to evade dynamic analysis. Understanding these techniques
# is essential for building analysis-resistant detection tools.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# MITRE ATT&CK:
#   T1497.001 - Virtualization/Sandbox Evasion: System Checks
#   T1497.003 - Virtualization/Sandbox Evasion: Time Based Evasion
#   T1622     - Debugger Evasion
#
# DETECTION METHODS:
#   - Behavioral analysis: code that checks for VMs but doesn't need VM info
#   - Timing probes: suspicious sleep() or RDTSC patterns
#   - API monitoring: calls to IsDebuggerPresent, CheckRemoteDebuggerPresent
#   - File system queries for VM artifacts
#   - Process enumeration looking for analysis tools
# =============================================================================

module RubyGuardian
  module ProcessHollowing
    class AntiAnalysis
      # Known VM/hypervisor signatures in DMI/SMBIOS data
      VM_SIGNATURES = {
        virtualbox: %w[vbox virtualbox innotek oracle],
        vmware:     %w[vmware vm],
        kvm:        %w[kvm qemu],
        hyper_v:    %w[hyper-v microsoft],
        xen:        %w[xen],
        parallels:  %w[parallels]
      }.freeze

      # Known analysis tool process names
      ANALYSIS_TOOLS = %w[
        wireshark tcpdump tshark ettercap
        gdb lldb strace ltrace valgrind
        ida idaq ghidra radare2 r2 cutter
        x64dbg ollydbg immunity
        procmon procexp filemon regmon
        processhacker pestudio
        volatility rekall
        cuckoo drakvuf cape remnux
        sysdig falco osquery
      ].freeze

      # VM-specific file paths
      VM_ARTIFACTS = {
        linux: [
          '/sys/class/dmi/id/product_name',
          '/sys/class/dmi/id/sys_vendor',
          '/sys/class/dmi/id/board_vendor',
          '/sys/hypervisor/type',
          '/proc/scsi/scsi',
          '/usr/bin/VBoxControl',
          '/usr/bin/VBoxService',
          '/usr/bin/vmtoolsd',
          '/usr/bin/vmware-toolbox-cmd'
        ],
        windows: [
          'C:\\Windows\\System32\\drivers\\VBoxGuest.sys',
          'C:\\Windows\\System32\\drivers\\vmhgfs.sys',
          'C:\\Windows\\System32\\drivers\\vmmouse.sys'
        ]
      }.freeze

      # MAC address prefixes assigned to VM vendors
      VM_MAC_PREFIXES = {
        virtualbox: ['08:00:27'],
        vmware:     ['00:0C:29', '00:50:56', '00:05:69'],
        hyper_v:    ['00:15:5D'],
        parallels:  ['00:1C:42'],
        xen:        ['00:16:3E']
      }.freeze

      attr_reader :logger, :check_results

      def initialize(logger: nil)
        @logger = logger
        @check_results = {}
      end

      # Run all anti-analysis checks and return a comprehensive report.
      #
      # EDUCATIONAL: Real malware runs these checks early in execution and
      # exits silently if an analysis environment is detected. Some malware
      # alters its behavior (less malicious) rather than exiting, making
      # analysis harder.
      #
      # @return [Hash] Results of all checks
      def run_all_checks
        log_info('Running comprehensive anti-analysis checks')

        @check_results = {
          timestamp: Time.now.utc.iso8601,
          debugger: check_debugger,
          virtual_machine: check_virtual_machine,
          sandbox: check_sandbox_indicators,
          analysis_tools: check_analysis_tools,
          timing_anomalies: check_timing,
          hardware: check_hardware_profile,
          network: check_network_indicators,
          user_activity: check_user_activity
        }

        @check_results[:risk_score] = calculate_risk_score(@check_results)
        @check_results[:recommendation] = recommend_action(@check_results[:risk_score])

        log_info("Anti-analysis complete. Risk score: #{@check_results[:risk_score]}/100")
        @check_results
      end

      # Check for debugger presence.
      #
      # EDUCATIONAL: Debugger detection is the most common anti-analysis check.
      # Methods include:
      #   - /proc/self/status TracerPid (Linux)
      #   - IsDebuggerPresent / CheckRemoteDebuggerPresent (Windows)
      #   - INT 3 trap handler (both platforms)
      #   - Timing-based detection (debuggers slow execution)
      #
      # @return [Hash] Debugger check results
      def check_debugger
        results = { detected: false, methods: {} }

        # Method 1: Check TracerPid in /proc/self/status (Linux)
        if File.exist?('/proc/self/status')
          status = File.read('/proc/self/status')
          tracer_pid = status.match(/TracerPid:\s+(\d+)/)&.captures&.first&.to_i
          if tracer_pid && tracer_pid > 0
            results[:detected] = true
            results[:methods][:tracer_pid] = {
              found: true,
              tracer_pid: tracer_pid,
              technique: 'Checked /proc/self/status TracerPid field'
            }
          else
            results[:methods][:tracer_pid] = { found: false }
          end
        end

        # Method 2: Check for common debugger environment variables
        debug_env_vars = %w[
          DEBUGGER DEBUG GDB_PYTHON_SCRIPT _JAVA_OPTIONS
          RUBY_DEBUG BYEBUG_WAIT
        ]
        found_vars = debug_env_vars.select { |v| ENV.key?(v) }
        results[:methods][:env_vars] = {
          found: !found_vars.empty?,
          variables: found_vars
        }
        results[:detected] = true unless found_vars.empty?

        # Method 3: Check parent process name
        if File.exist?('/proc/self/stat')
          ppid = File.read('/proc/self/stat').split[3].to_i
          if ppid > 0 && File.exist?("/proc/#{ppid}/comm")
            parent_name = File.read("/proc/#{ppid}/comm").strip.downcase
            debugger_parents = %w[gdb lldb strace ltrace valgrind ruby-debug]
            if debugger_parents.any? { |d| parent_name.include?(d) }
              results[:detected] = true
              results[:methods][:parent_process] = {
                found: true,
                parent: parent_name
              }
            end
          end
        end

        # Method 4: Timing-based debugger detection
        # Debuggers significantly slow down execution
        start = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        1000.times { |i| i * i } # Simple computation
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - start

        # If simple computation takes > 1ms, likely debugged
        if elapsed > 1_000_000
          results[:methods][:timing] = {
            found: true,
            elapsed_ns: elapsed,
            technique: 'Computation timing anomaly detected'
          }
          # Don't set detected=true for timing alone (too many false positives)
        else
          results[:methods][:timing] = { found: false, elapsed_ns: elapsed }
        end

        log_info("Debugger check: #{results[:detected] ? 'DETECTED' : 'clean'}")
        results
      rescue StandardError => e
        log_info("Debugger check error: #{e.message}")
        results
      end

      # Check for virtual machine indicators.
      #
      # @return [Hash] VM detection results
      def check_virtual_machine
        results = { detected: false, hypervisor: nil, methods: {} }

        # Method 1: DMI/SMBIOS data
        dmi_paths = {
          product_name: '/sys/class/dmi/id/product_name',
          sys_vendor: '/sys/class/dmi/id/sys_vendor',
          board_vendor: '/sys/class/dmi/id/board_vendor',
          bios_vendor: '/sys/class/dmi/id/bios_vendor'
        }

        dmi_data = {}
        dmi_paths.each do |key, path|
          if File.exist?(path)
            dmi_data[key] = File.read(path).strip.downcase
          end
        rescue StandardError
          next
        end

        VM_SIGNATURES.each do |hypervisor, signatures|
          if dmi_data.values.any? { |v| signatures.any? { |s| v.include?(s) } }
            results[:detected] = true
            results[:hypervisor] = hypervisor
            results[:methods][:dmi] = { found: true, data: dmi_data, hypervisor: hypervisor }
            break
          end
        end
        results[:methods][:dmi] ||= { found: false, data: dmi_data }

        # Method 2: Kernel modules
        if File.exist?('/proc/modules')
          modules = File.read('/proc/modules').downcase
          vm_modules = {
            virtualbox: %w[vboxguest vboxsf vboxvideo],
            vmware: %w[vmw_balloon vmw_vmci vmwgfx vmxnet3],
            kvm: %w[virtio_pci virtio_net virtio_blk],
            hyper_v: %w[hv_vmbus hv_storvsc hv_netvsc]
          }

          vm_modules.each do |hypervisor, mod_names|
            found = mod_names.select { |m| modules.include?(m) }
            unless found.empty?
              results[:detected] = true
              results[:hypervisor] ||= hypervisor
              results[:methods][:kernel_modules] = { found: true, modules: found }
              break
            end
          end
          results[:methods][:kernel_modules] ||= { found: false }
        end

        # Method 3: CPUID-based detection (via /proc/cpuinfo)
        if File.exist?('/proc/cpuinfo')
          cpuinfo = File.read('/proc/cpuinfo').downcase
          if cpuinfo.include?('hypervisor')
            results[:detected] = true
            results[:methods][:cpuid] = {
              found: true,
              technique: 'Hypervisor flag present in CPUID'
            }
          else
            results[:methods][:cpuid] = { found: false }
          end
        end

        # Method 4: MAC address prefix check
        mac_check = check_mac_addresses
        results[:methods][:mac_address] = mac_check
        if mac_check[:found]
          results[:detected] = true
          results[:hypervisor] ||= mac_check[:vendor]
        end

        log_info("VM check: #{results[:detected] ? "DETECTED (#{results[:hypervisor]})" : 'clean'}")
        results
      rescue StandardError => e
        log_info("VM check error: #{e.message}")
        results
      end

      # Check for sandbox-specific indicators.
      #
      # @return [Hash] Sandbox detection results
      def check_sandbox_indicators
        results = { detected: false, methods: {} }

        # Check for sandbox-related environment variables
        sandbox_vars = %w[SANDBOX CUCKOO REMNUX FLARE SANS ANALYSIS MALWARE_ANALYSIS]
        found = sandbox_vars.select { |v| ENV.key?(v) }
        results[:methods][:env_vars] = { found: !found.empty?, variables: found }
        results[:detected] = true unless found.empty?

        # Check for containerization
        results[:methods][:container] = {
          docker: File.exist?('/.dockerenv'),
          podman: File.exist?('/run/.containerenv'),
          cgroup: check_cgroup_container
        }

        # Check hostname patterns (sandboxes often use generic names)
        hostname = Socket.gethostname rescue 'unknown'
        sandbox_patterns = %w[sandbox malware analysis cuckoo remnux flare]
        if sandbox_patterns.any? { |p| hostname.downcase.include?(p) }
          results[:detected] = true
          results[:methods][:hostname] = { found: true, hostname: hostname }
        end

        # Check for recently installed OS (sandboxes are often fresh)
        if File.exist?('/var/log/installer')
          install_time = File.mtime('/var/log/installer') rescue nil
          if install_time && (Time.now - install_time) < 86400 # Less than 1 day
            results[:methods][:fresh_install] = { found: true, install_time: install_time }
          end
        end

        results
      rescue StandardError => e
        log_info("Sandbox check error: #{e.message}")
        results
      end

      # Check for running analysis tools.
      #
      # @return [Hash] Analysis tool detection results
      def check_analysis_tools
        results = { detected: false, tools_found: [] }

        begin
          processes = `ps aux 2>/dev/null`.downcase
          ANALYSIS_TOOLS.each do |tool|
            if processes.include?(tool)
              results[:detected] = true
              results[:tools_found] << tool
            end
          end
        rescue StandardError
          results[:error] = 'Could not enumerate processes'
        end

        log_info("Analysis tools: #{results[:tools_found].length} found")
        results
      end

      # Timing-based evasion checks.
      #
      # EDUCATIONAL: Sandboxes and emulators often have different timing
      # characteristics than real hardware:
      #   - Accelerated sleep (to speed up analysis)
      #   - Inconsistent clock sources
      #   - Slow instruction execution (emulation overhead)
      #
      # @return [Hash] Timing check results
      def check_timing
        results = { anomalies: [] }

        # Test 1: Sleep accuracy
        target_sleep = 0.1
        start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        sleep(target_sleep)
        actual = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start

        deviation = ((actual - target_sleep) / target_sleep * 100).abs
        if deviation > 50 # More than 50% deviation
          results[:anomalies] << {
            test: :sleep_accuracy,
            expected: target_sleep,
            actual: actual,
            deviation_pct: deviation.round(2)
          }
        end

        # Test 2: Monotonic vs wall clock consistency
        mono_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        wall_start = Time.now.to_f
        10_000.times { |i| Math.sqrt(i) }
        mono_elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - mono_start
        wall_elapsed = Time.now.to_f - wall_start

        clock_ratio = mono_elapsed > 0 ? (wall_elapsed / mono_elapsed) : 1.0
        if (clock_ratio - 1.0).abs > 0.5
          results[:anomalies] << {
            test: :clock_consistency,
            monotonic: mono_elapsed,
            wall: wall_elapsed,
            ratio: clock_ratio.round(3)
          }
        end

        results[:detected] = !results[:anomalies].empty?
        results
      rescue StandardError => e
        log_info("Timing check error: #{e.message}")
        { detected: false, anomalies: [], error: e.message }
      end

      # Check hardware profile for VM indicators.
      #
      # @return [Hash] Hardware profile results
      def check_hardware_profile
        results = { suspicious: false }

        # CPU count (VMs often have few CPUs)
        cpu_count = Etc.nprocessors rescue `nproc 2>/dev/null`.strip.to_i
        results[:cpu_count] = cpu_count
        results[:suspicious] = true if cpu_count <= 1

        # Memory (VMs often have limited RAM)
        if File.exist?('/proc/meminfo')
          meminfo = File.read('/proc/meminfo')
          total_kb = meminfo.match(/MemTotal:\s+(\d+)/)&.captures&.first&.to_i || 0
          results[:memory_mb] = total_kb / 1024
          results[:suspicious] = true if total_kb < 2_097_152 # 2GB
        end

        # Disk size
        begin
          df_output = `df -BG / 2>/dev/null`.lines.last
          if df_output
            disk_gb = df_output.split[1].to_i
            results[:disk_gb] = disk_gb
            results[:suspicious] = true if disk_gb < 40
          end
        rescue StandardError
          # Ignore
        end

        results
      rescue StandardError => e
        { suspicious: false, error: e.message }
      end

      # Check network configuration for sandbox indicators.
      #
      # @return [Hash] Network indicator results
      def check_network_indicators
        results = { suspicious: false }

        # Check for common sandbox DNS servers
        if File.exist?('/etc/resolv.conf')
          resolv = File.read('/etc/resolv.conf')
          results[:dns_servers] = resolv.scan(/nameserver\s+(\S+)/).flatten
        end

        # Check for limited network interfaces
        begin
          interfaces = Dir.glob('/sys/class/net/*').map { |p| File.basename(p) }
          results[:interfaces] = interfaces
          results[:suspicious] = true if interfaces.length <= 1
        rescue StandardError
          # Ignore
        end

        results
      rescue StandardError => e
        { suspicious: false, error: e.message }
      end

      # Check for evidence of real user activity.
      #
      # EDUCATIONAL: Sandboxes lack genuine user activity artifacts:
      #   - No browser history
      #   - No documents in home directory
      #   - Fresh user profile with no customization
      #   - No background applications typical of a real workstation
      #
      # @return [Hash] User activity results
      def check_user_activity
        results = { real_user: false, indicators: {} }

        home = ENV['HOME'] || '/root'

        # Check for common user directories with content
        user_dirs = %w[Documents Downloads Desktop Pictures .ssh .config]
        populated = user_dirs.select do |dir|
          path = File.join(home, dir)
          File.directory?(path) && Dir.entries(path).length > 2
        rescue StandardError
          false
        end

        results[:indicators][:populated_dirs] = populated.length
        results[:real_user] = true if populated.length >= 3

        # Check bash history length
        history_file = File.join(home, '.bash_history')
        if File.exist?(history_file)
          lines = File.readlines(history_file).length rescue 0
          results[:indicators][:bash_history_lines] = lines
          results[:real_user] = true if lines > 100
        end

        results
      rescue StandardError => e
        { real_user: false, error: e.message }
      end

      # Describe the technique for educational purposes.
      def describe
        <<~DESC
          Anti-Analysis Techniques (T1497, T1622)

          Anti-analysis encompasses techniques malware uses to detect and
          evade security analysis environments:

          1. Debugger Detection: Check TracerPid, timing anomalies
          2. VM Detection: DMI data, CPUID hypervisor bit, MAC prefixes
          3. Sandbox Detection: Process enumeration, hostname patterns
          4. Timing Evasion: Sleep acceleration detection, clock skew
          5. Hardware Profiling: CPU/RAM/disk checks for minimal VMs
          6. User Activity: Check for signs of real user interaction

          Countermeasures (for analysts):
          - Use bare-metal analysis when possible
          - Emulate realistic user activity in sandboxes
          - Patch VM artifacts to match physical hardware
          - Use transparent debugging (hardware breakpoints)
          - Monitor for anti-analysis API calls as a signal
        DESC
      end

      private

      def check_mac_addresses
        begin
          interfaces = Dir.glob('/sys/class/net/*/address')
          interfaces.each do |path|
            mac = File.read(path).strip.downcase
            VM_MAC_PREFIXES.each do |vendor, prefixes|
              if prefixes.any? { |p| mac.start_with?(p.downcase) }
                return { found: true, mac: mac, vendor: vendor }
              end
            end
          end
        rescue StandardError
          # Ignore
        end
        { found: false }
      end

      def check_cgroup_container
        return false unless File.exist?('/proc/1/cgroup')
        cgroup = File.read('/proc/1/cgroup')
        cgroup.include?('docker') || cgroup.include?('lxc') || cgroup.include?('kubepods')
      rescue StandardError
        false
      end

      def calculate_risk_score(results)
        score = 0
        score += 30 if results[:debugger][:detected]
        score += 25 if results[:virtual_machine][:detected]
        score += 20 if results[:sandbox][:detected]
        score += 15 if results[:analysis_tools][:detected]
        score += 5  if results[:timing_anomalies][:detected]
        score += 5  if results[:hardware][:suspicious]
        [score, 100].min
      end

      def recommend_action(score)
        case score
        when 0..10   then :proceed
        when 11..30  then :proceed_with_caution
        when 31..60  then :delay_execution
        when 61..100 then :abort
        end
      end

      def log_info(message)
        if @logger
          @logger.info(message)
        end
      end
    end
  end
end
