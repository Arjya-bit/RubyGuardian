# frozen_string_literal: true

require 'fileutils'
require 'digest'
require 'json'
require 'yaml'
require 'open3'
require 'time'
require 'zlib'

module RubyGuardian
  module MemoryForensics
    # MemoryDumper captures memory dumps from live Ruby processes using
    # /proc/pid/mem, gcore, or ptrace-based acquisition methods.
    # Maintains chain of custody through cryptographic hashing.
    class MemoryDumper
      ACQUISITION_METHODS = %i[proc_mem gcore ptrace].freeze
      DEFAULT_HASH_ALGORITHMS = %w[sha256 md5].freeze
      MAX_DUMP_SIZE = 10 * 1024 * 1024 * 1024 # 10 GB
      ACQUISITION_TIMEOUT = 300 # seconds

      DumpMetadata = Struct.new(
        :pid, :timestamp, :method, :output_path, :size,
        :hashes, :memory_regions, :ruby_version, :duration,
        :compressed, :acquisition_host, keyword_init: true
      )

      MemoryRegion = Struct.new(
        :start_addr, :end_addr, :permissions, :offset,
        :device, :inode, :pathname, :size, keyword_init: true
      )

      class AcquisitionError < StandardError; end
      class ProcessNotFoundError < AcquisitionError; end
      class PermissionError < AcquisitionError; end
      class DumpSizeExceededError < AcquisitionError; end
      class TimeoutError < AcquisitionError; end

      attr_reader :pid, :config, :logger, :metadata

      def initialize(pid:, config: nil, logger: nil)
        @pid = pid.to_i
        @config = load_config(config)
        @logger = logger || default_logger
        @metadata = nil
        validate_pid!
      end

      # Capture a full memory dump from the target process
      def capture(output:, method: nil, compress: true, pause: true)
        method ||= detect_best_method
        validate_method!(method)

        log_info("Starting memory acquisition for PID #{@pid} using #{method}")
        start_time = Time.now

        FileUtils.mkdir_p(File.dirname(output))
        pause_process if pause

        begin
          raw_path = "#{output}.raw"
          regions = parse_memory_maps

          case method
          when :proc_mem
            dump_via_proc_mem(raw_path, regions)
          when :gcore
            dump_via_gcore(raw_path)
          when :ptrace
            dump_via_ptrace(raw_path, regions)
          end

          final_path = if compress
                         compressed = compress_dump(raw_path, output)
                         FileUtils.rm_f(raw_path) if File.exist?(raw_path) && raw_path != compressed
                         compressed
                       else
                         FileUtils.mv(raw_path, output) unless raw_path == output
                         output
                       end

          duration = Time.now - start_time
          hashes = compute_hashes(final_path)

          @metadata = DumpMetadata.new(
            pid: @pid,
            timestamp: start_time.utc.iso8601,
            method: method.to_s,
            output_path: File.expand_path(final_path),
            size: File.size(final_path),
            hashes: hashes,
            memory_regions: regions.map { |r| region_to_hash(r) },
            ruby_version: detect_ruby_version,
            duration: duration.round(3),
            compressed: compress,
            acquisition_host: Socket.gethostname
          )

          write_metadata(final_path)
          log_info("Acquisition complete: #{final_path} (#{format_size(@metadata.size)}) in #{duration.round(2)}s")

          @metadata
        ensure
          resume_process if pause
        end
      end

      # Capture only specific memory regions matching a filter
      def capture_selective(output:, filter:, compress: true)
        regions = parse_memory_maps
        filtered = regions.select { |r| region_matches_filter?(r, filter) }

        if filtered.empty?
          log_warn("No memory regions matched the filter: #{filter.inspect}")
          return nil
        end

        log_info("Capturing #{filtered.size} of #{regions.size} memory regions")
        dump_regions_to_file(output, filtered)
      end

      # Parse /proc/pid/maps to get memory region information
      def parse_memory_maps
        maps_path = "/proc/#{@pid}/maps"
        unless File.readable?(maps_path)
          raise PermissionError, "Cannot read #{maps_path}. Run with appropriate privileges."
        end

        regions = []
        File.readlines(maps_path).each do |line|
          region = parse_maps_line(line.strip)
          regions << region if region
        end

        log_info("Parsed #{regions.size} memory regions from #{maps_path}")
        regions
      end

      # Get summary information about the target process
      def process_info
        {
          pid: @pid,
          cmdline: read_proc_file('cmdline').tr("\0", ' ').strip,
          exe: File.readlink("/proc/#{@pid}/exe"),
          status: parse_proc_status,
          memory_maps_count: parse_memory_maps.size,
          ruby_version: detect_ruby_version,
          start_time: process_start_time
        }
      rescue Errno::ENOENT, Errno::EACCES => e
        raise ProcessNotFoundError, "Cannot access process #{@pid}: #{e.message}"
      end

      # Verify integrity of an existing dump file
      def self.verify_integrity(dump_path)
        meta_path = "#{dump_path}.meta.json"
        unless File.exist?(meta_path)
          return { verified: false, error: 'No metadata file found' }
        end

        metadata = JSON.parse(File.read(meta_path))
        stored_hashes = metadata['hashes']
        results = {}

        stored_hashes.each do |algo, expected|
          digest = case algo
                   when 'sha256' then Digest::SHA256
                   when 'md5' then Digest::MD5
                   when 'sha1' then Digest::SHA1
                   else next
                   end

          actual = digest.file(dump_path).hexdigest
          results[algo] = {
            expected: expected,
            actual: actual,
            match: expected == actual
          }
        end

        {
          verified: results.values.all? { |r| r[:match] },
          hashes: results,
          metadata: metadata
        }
      end

      private

      def load_config(config)
        return config if config.is_a?(Hash)

        config_path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        if File.exist?(config_path)
          YAML.safe_load(File.read(config_path), permitted_classes: [Symbol])
        else
          {}
        end
      end

      def default_logger
        require 'logger'
        logger = Logger.new($stderr)
        logger.level = Logger::INFO
        logger.formatter = proc { |sev, time, _prog, msg| "[#{time.utc.iso8601}] #{sev}: #{msg}\n" }
        logger
      end

      def validate_pid!
        raise ArgumentError, "Invalid PID: #{@pid}" if @pid <= 0
        raise ProcessNotFoundError, "Process #{@pid} does not exist" unless File.directory?("/proc/#{@pid}")
      end

      def validate_method!(method)
        unless ACQUISITION_METHODS.include?(method)
          raise ArgumentError, "Unknown acquisition method: #{method}. Use one of: #{ACQUISITION_METHODS.join(', ')}"
        end
      end

      def detect_best_method
        if File.readable?("/proc/#{@pid}/mem")
          :proc_mem
        elsif system('which gcore > /dev/null 2>&1')
          :gcore
        else
          :ptrace
        end
      end

      def dump_via_proc_mem(output_path, regions)
        mem_path = "/proc/#{@pid}/mem"
        readable_regions = regions.select { |r| r.permissions.include?('r') }
        total_size = readable_regions.sum(&:size)

        if total_size > MAX_DUMP_SIZE
          raise DumpSizeExceededError, "Dump would be #{format_size(total_size)}, exceeding limit"
        end

        File.open(mem_path, 'rb') do |mem_file|
          File.open(output_path, 'wb') do |out_file|
            # Write a header with region map for later parsing
            header = build_dump_header(readable_regions)
            out_file.write(header)

            readable_regions.each_with_index do |region, idx|
              log_debug("Dumping region #{idx + 1}/#{readable_regions.size}: " \
                        "0x#{region.start_addr.to_s(16)}-0x#{region.end_addr.to_s(16)}")
              begin
                mem_file.seek(region.start_addr)
                data = mem_file.read(region.size)
                out_file.write(data) if data
              rescue Errno::EIO, Errno::EFAULT => e
                log_warn("Skipping unreadable region at 0x#{region.start_addr.to_s(16)}: #{e.message}")
                # Write zeros as placeholder to maintain offset alignment
                out_file.write("\x00" * region.size)
              end
            end
          end
        end

        log_info("Wrote #{format_size(File.size(output_path))} via /proc/pid/mem")
      end

      def dump_via_gcore(output_path)
        basename = File.basename(output_path, '.*')
        dir = File.dirname(output_path)

        stdout, stderr, status = Open3.capture3(
          'gcore', '-o', File.join(dir, basename), @pid.to_s,
          timeout: ACQUISITION_TIMEOUT
        )

        unless status.success?
          raise AcquisitionError, "gcore failed: #{stderr}"
        end

        core_file = Dir.glob(File.join(dir, "#{basename}.*")).first
        if core_file && core_file != output_path
          FileUtils.mv(core_file, output_path)
        end

        log_info("gcore acquisition complete: #{output_path}")
      end

      def dump_via_ptrace(output_path, regions)
        # Use a combination of ptrace attach and /proc/pid/mem reading
        # First attach to pause the process
        log_info("Attaching to process #{@pid} via ptrace wrapper")

        stdout, stderr, status = Open3.capture3(
          'ruby', '-e', ptrace_dump_script(output_path, regions)
        )

        unless status.success?
          raise AcquisitionError, "ptrace-based acquisition failed: #{stderr}"
        end
      end

      def ptrace_dump_script(output_path, regions)
        <<~RUBY
          require 'fiddle'
          PTRACE_ATTACH = 16
          PTRACE_DETACH = 17
          libc = Fiddle.dlopen(nil)
          ptrace = Fiddle::Function.new(libc['ptrace'],
            [Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
            Fiddle::TYPE_LONG)
          ptrace.call(PTRACE_ATTACH, #{@pid}, nil, nil)
          Process.waitpid(#{@pid})
          # Read memory regions while attached
          File.open('/proc/#{@pid}/mem', 'rb') do |mem|
            File.open('#{output_path}', 'wb') do |out|
              #{regions.select { |r| r.permissions.include?('r') }.map { |r|
                "begin; mem.seek(#{r.start_addr}); d = mem.read(#{r.size}); out.write(d) if d; rescue; end"
              }.join("\n              ")}
            end
          end
          ptrace.call(PTRACE_DETACH, #{@pid}, nil, nil)
        RUBY
      end

      def parse_maps_line(line)
        # Format: address perms offset dev inode pathname
        match = line.match(/^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*(.*)$/)
        return nil unless match

        start_addr = match[1].to_i(16)
        end_addr = match[2].to_i(16)

        MemoryRegion.new(
          start_addr: start_addr,
          end_addr: end_addr,
          permissions: match[3],
          offset: match[4],
          device: match[5],
          inode: match[6].to_i,
          pathname: match[7].strip,
          size: end_addr - start_addr
        )
      end

      def build_dump_header(regions)
        header = {
          magic: 'RGMEM',
          version: 1,
          pid: @pid,
          timestamp: Time.now.utc.iso8601,
          region_count: regions.size,
          regions: regions.map { |r| region_to_hash(r) }
        }
        json = JSON.generate(header)
        # Fixed-size header: 4 bytes length + JSON + padding to 4096 boundary
        header_size = 4 + json.bytesize
        padding = (4096 - (header_size % 4096)) % 4096
        [json.bytesize].pack('V') + json + ("\x00" * padding)
      end

      def region_to_hash(region)
        {
          start: "0x#{region.start_addr.to_s(16)}",
          end: "0x#{region.end_addr.to_s(16)}",
          permissions: region.permissions,
          size: region.size,
          pathname: region.pathname
        }
      end

      def region_matches_filter?(region, filter)
        if filter[:permissions]
          return false unless region.permissions.include?(filter[:permissions])
        end
        if filter[:pathname]
          return false unless region.pathname.match?(filter[:pathname])
        end
        if filter[:min_size]
          return false if region.size < filter[:min_size]
        end
        if filter[:writable_executable]
          return false unless region.permissions.include?('w') && region.permissions.include?('x')
        end
        true
      end

      def dump_regions_to_file(output_path, regions)
        File.open("/proc/#{@pid}/mem", 'rb') do |mem|
          File.open(output_path, 'wb') do |out|
            regions.each do |region|
              begin
                mem.seek(region.start_addr)
                data = mem.read(region.size)
                out.write(data) if data
              rescue Errno::EIO, Errno::EFAULT
                next
              end
            end
          end
        end
      end

      def compress_dump(input_path, output_base)
        output_path = "#{output_base}.gz"
        Zlib::GzipWriter.open(output_path) do |gz|
          File.open(input_path, 'rb') do |f|
            buf_size = 4 * 1024 * 1024 # 4 MB buffer
            while (chunk = f.read(buf_size))
              gz.write(chunk)
            end
          end
        end
        log_info("Compressed dump: #{format_size(File.size(input_path))} -> #{format_size(File.size(output_path))}")
        output_path
      end

      def compute_hashes(file_path)
        hashes = {}
        algorithms = @config.dig('acquisition', 'hash_algorithms') || DEFAULT_HASH_ALGORITHMS

        digests = algorithms.map do |algo|
          case algo
          when 'sha256' then [algo, Digest::SHA256.new]
          when 'md5' then [algo, Digest::MD5.new]
          when 'sha1' then [algo, Digest::SHA1.new]
          end
        end.compact

        File.open(file_path, 'rb') do |f|
          buf_size = 1024 * 1024
          while (chunk = f.read(buf_size))
            digests.each { |_, d| d.update(chunk) }
          end
        end

        digests.each { |name, d| hashes[name] = d.hexdigest }
        hashes
      end

      def write_metadata(dump_path)
        meta_path = "#{dump_path}.meta.json"
        File.write(meta_path, JSON.pretty_generate(@metadata.to_h))
        log_info("Metadata written to #{meta_path}")
      end

      def pause_process
        log_info("Sending SIGSTOP to PID #{@pid}")
        Process.kill('STOP', @pid)
      rescue Errno::EPERM
        raise PermissionError, "Cannot pause process #{@pid}. Run with appropriate privileges."
      end

      def resume_process
        log_info("Sending SIGCONT to PID #{@pid}")
        Process.kill('CONT', @pid)
      rescue Errno::ESRCH
        log_warn("Process #{@pid} no longer exists")
      end

      def detect_ruby_version
        cmdline = read_proc_file('cmdline')
        return nil unless cmdline.include?('ruby')

        exe = File.readlink("/proc/#{@pid}/exe") rescue nil
        if exe && exe.include?('ruby')
          stdout, = Open3.capture3(exe, '--version')
          stdout.strip
        end
      rescue StandardError
        nil
      end

      def process_start_time
        stat = read_proc_file('stat')
        fields = stat.split(')')
        return nil if fields.size < 2

        start_ticks = fields.last.strip.split[19].to_i
        clk_tck = `getconf CLK_TCK`.strip.to_i
        clk_tck = 100 if clk_tck == 0
        boot_time = File.read('/proc/stat').scan(/btime\s+(\d+)/).flatten.first.to_i
        Time.at(boot_time + (start_ticks / clk_tck)).utc
      rescue StandardError
        nil
      end

      def parse_proc_status
        status = {}
        read_proc_file('status').each_line do |line|
          key, value = line.strip.split(':', 2)
          status[key.strip] = value&.strip
        end
        status
      end

      def read_proc_file(name)
        File.read("/proc/#{@pid}/#{name}")
      rescue Errno::EACCES
        raise PermissionError, "Cannot read /proc/#{@pid}/#{name}"
      end

      def format_size(bytes)
        units = %w[B KB MB GB TB]
        unit_index = 0
        size = bytes.to_f
        while size >= 1024 && unit_index < units.size - 1
          size /= 1024
          unit_index += 1
        end
        "#{size.round(2)} #{units[unit_index]}"
      end

      def log_info(msg)
        @logger&.info(msg)
      end

      def log_warn(msg)
        @logger&.warn(msg)
      end

      def log_debug(msg)
        @logger&.debug(msg)
      end
    end
  end
end
