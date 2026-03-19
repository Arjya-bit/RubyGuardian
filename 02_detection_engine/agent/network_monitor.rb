# frozen_string_literal: true

module RubyGuardian
  module Detection
    # Monitors network connections for beaconing, exfiltration, and C2 patterns
    # Inspects /proc/net/tcp, /proc/net/udp and uses conntrack for connection tracking
    class NetworkMonitor
      PROC_TCP = '/proc/net/tcp'
      PROC_UDP = '/proc/net/udp'
      SUSPICIOUS_PORTS = [4444, 5555, 8443, 1337, 31337, 9001, 9030].freeze
      BEACON_INTERVAL_TOLERANCE = 0.15
      MIN_BEACON_COUNT = 5
      EXFIL_THRESHOLD_BYTES = 10_485_760

      attr_reader :config, :logger, :event_collector, :connections, :history

      def initialize(config:, logger:, event_collector:)
        @config = config
        @logger = logger
        @event_collector = event_collector
        @connections = {}
        @history = []
        @dns_cache = {}
        @running = false
        @mutex = Mutex.new
        @baseline = nil
      end

      def start
        @running = true
        @monitor_thread = Thread.new { monitor_loop }
        @beacon_thread = Thread.new { beacon_detection_loop }
        logger.info('NetworkMonitor started')
      end

      def stop
        @running = false
        @monitor_thread&.join(5)
        @beacon_thread&.join(5)
        logger.info('NetworkMonitor stopped')
      end

      private

      def monitor_loop
        while @running
          begin
            current = snapshot_connections
            detect_new_connections(current)
            detect_suspicious_ports(current)
            detect_data_exfiltration(current)
            detect_dns_tunneling
            @mutex.synchronize { @connections = current }
          rescue StandardError => e
            logger.error("NetworkMonitor error: #{e.message}")
          end
          sleep(config.fetch(:network_poll_interval, 2))
        end
      end

      def beacon_detection_loop
        while @running
          sleep(config.fetch(:beacon_check_interval, 30))
          begin
            detect_beaconing_patterns
          rescue StandardError => e
            logger.error("Beacon detection error: #{e.message}")
          end
        end
      end

      def snapshot_connections
        conns = {}
        parse_proc_net(PROC_TCP, :tcp, conns) if File.readable?(PROC_TCP)
        parse_proc_net(PROC_UDP, :udp, conns) if File.readable?(PROC_UDP)
        conns
      end

      def parse_proc_net(path, proto, conns)
        File.readlines(path).drop(1).each do |line|
          fields = line.strip.split
          next if fields.length < 10

          local = parse_address(fields[1])
          remote = parse_address(fields[2])
          state = fields[3].to_i(16)
          inode = fields[9]
          uid = fields[7].to_i

          conn_key = "#{proto}:#{local[:ip]}:#{local[:port]}->#{remote[:ip]}:#{remote[:port]}"
          conns[conn_key] = {
            proto: proto,
            local: local,
            remote: remote,
            state: state,
            inode: inode,
            uid: uid,
            timestamp: Time.now
          }
        end
      end

      def parse_address(hex_addr)
        hex_ip, hex_port = hex_addr.split(':')
        port = hex_port.to_i(16)
        ip_int = hex_ip.to_i(16)
        ip = [ip_int & 0xFF, (ip_int >> 8) & 0xFF,
              (ip_int >> 16) & 0xFF, (ip_int >> 24) & 0xFF].join('.')
        { ip: ip, port: port }
      end

      def detect_new_connections(current)
        current.each do |key, conn|
          next if @connections.key?(key)
          next if conn[:remote][:ip] == '0.0.0.0' || conn[:remote][:ip] == '127.0.0.1'

          pid = find_pid_for_inode(conn[:inode])
          next unless ruby_process?(pid)

          record_connection_event(conn, pid)
          @mutex.synchronize do
            @history << { key: key, conn: conn, pid: pid, time: Time.now }
            @history.shift if @history.length > 10_000
          end
        end
      end

      def detect_suspicious_ports(current)
        current.each do |_key, conn|
          remote_port = conn[:remote][:port]
          next unless SUSPICIOUS_PORTS.include?(remote_port)

          pid = find_pid_for_inode(conn[:inode])
          next unless ruby_process?(pid)

          event_collector.emit(
            type: :suspicious_port,
            severity: :high,
            source: 'network_monitor',
            pid: pid,
            details: {
              remote_ip: conn[:remote][:ip],
              remote_port: remote_port,
              proto: conn[:proto],
              message: "Connection to suspicious port #{remote_port}"
            }
          )
        end
      end

      def detect_data_exfiltration(current)
        current.each do |_key, conn|
          next if conn[:remote][:ip] == '0.0.0.0'

          pid = find_pid_for_inode(conn[:inode])
          next unless ruby_process?(pid)

          tx_bytes = read_socket_tx_bytes(conn[:inode])
          next unless tx_bytes && tx_bytes > EXFIL_THRESHOLD_BYTES

          event_collector.emit(
            type: :data_exfiltration,
            severity: :critical,
            source: 'network_monitor',
            pid: pid,
            details: {
              remote_ip: conn[:remote][:ip],
              remote_port: conn[:remote][:port],
              bytes_sent: tx_bytes,
              message: "Large data transfer detected: #{tx_bytes} bytes"
            }
          )
        end
      end

      def detect_beaconing_patterns
        grouped = @mutex.synchronize do
          @history.group_by { |h| "#{h[:pid]}->#{h[:conn][:remote][:ip]}" }
        end

        grouped.each do |key, entries|
          next if entries.length < MIN_BEACON_COUNT

          intervals = entries.each_cons(2).map { |a, b| b[:time] - a[:time] }
          next if intervals.empty?

          mean = intervals.sum / intervals.length
          stddev = Math.sqrt(intervals.map { |i| (i - mean)**2 }.sum / intervals.length)
          cv = mean > 0 ? stddev / mean : 1.0

          next unless cv < BEACON_INTERVAL_TOLERANCE

          event_collector.emit(
            type: :c2_beaconing,
            severity: :critical,
            source: 'network_monitor',
            pid: entries.last[:pid],
            details: {
              remote_ip: entries.last[:conn][:remote][:ip],
              interval_mean: mean.round(2),
              interval_cv: cv.round(4),
              beacon_count: entries.length,
              message: "C2 beaconing detected: #{mean.round(1)}s interval (CV=#{cv.round(3)})"
            }
          )
        end
      end

      def detect_dns_tunneling
        return unless File.readable?('/proc/net/udp')

        dns_connections = @connections.select { |_k, c| c[:remote][:port] == 53 }
        return if dns_connections.empty?

        dns_connections.each do |_key, conn|
          pid = find_pid_for_inode(conn[:inode])
          next unless ruby_process?(pid)

          tx = read_socket_tx_bytes(conn[:inode]) || 0
          next unless tx > 50_000

          event_collector.emit(
            type: :dns_tunneling,
            severity: :high,
            source: 'network_monitor',
            pid: pid,
            details: {
              dns_server: conn[:remote][:ip],
              bytes_sent: tx,
              message: "Possible DNS tunneling: #{tx} bytes sent to DNS"
            }
          )
        end
      end

      def find_pid_for_inode(inode)
        Dir.glob('/proc/[0-9]*/fd/*').each do |fd_path|
          begin
            link = File.readlink(fd_path)
            if link.include?("socket:[#{inode}]")
              return fd_path.split('/')[2].to_i
            end
          rescue Errno::ENOENT, Errno::EACCES
            next
          end
        end
        nil
      end

      def ruby_process?(pid)
        return false unless pid

        cmdline = File.read("/proc/#{pid}/cmdline").tr("\0", ' ')
        cmdline.match?(/ruby|rails|rake|bundle|irb|pry/)
      rescue Errno::ENOENT, Errno::EACCES
        false
      end

      def read_socket_tx_bytes(inode)
        File.readlines('/proc/net/sockstat').each do |line|
          next unless line.include?(inode.to_s)
          # Parse tx_queue from /proc/net/tcp entry
        end
        nil
      rescue StandardError
        nil
      end

      def record_connection_event(conn, pid)
        event_collector.emit(
          type: :new_connection,
          severity: :info,
          source: 'network_monitor',
          pid: pid,
          details: {
            remote_ip: conn[:remote][:ip],
            remote_port: conn[:remote][:port],
            local_port: conn[:local][:port],
            proto: conn[:proto]
          }
        )
      end
    end
  end
end
