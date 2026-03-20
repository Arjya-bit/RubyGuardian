# frozen_string_literal: true

require "benchmark"
require "json"
require "securerandom"
require "logger"
require "tempfile"
require "stringio"

module RubyGuardian
  module Testing
    module Performance
      # BenchmarkForensics measures the performance of memory forensics
      # operations: heap dump parsing, object graph analysis, IOC scanning,
      # string extraction, and reference chain resolution.
      class BenchmarkForensics
        DEFAULT_DUMP_SIZE_MB = 50
        DEFAULT_ITERATIONS = 10

        attr_reader :results

        def initialize(logger: nil)
          @logger = logger || Logger.new($stdout, progname: "RubyGuardian::BenchmarkForensics")
          @results = {}
        end

        # Run all forensics benchmarks.
        def run_all!(dump_size_mb: DEFAULT_DUMP_SIZE_MB, iterations: DEFAULT_ITERATIONS)
          @logger.info("Starting memory forensics benchmarks")
          @logger.info("  Dump size: #{dump_size_mb} MB, Iterations: #{iterations}")

          @results[:dump_parsing] = benchmark_dump_parsing(dump_size_mb, iterations)
          @results[:heap_analysis] = benchmark_heap_analysis(iterations)
          @results[:ioc_scanning] = benchmark_ioc_scanning(iterations)
          @results[:string_extraction] = benchmark_string_extraction(dump_size_mb, iterations)
          @results[:reference_chains] = benchmark_reference_chains(iterations)
          @results[:object_classification] = benchmark_object_classification(iterations)
          @results[:summary] = build_summary

          write_results
          @results
        end

        # Benchmark: parse a simulated memory dump into structured objects.
        def benchmark_dump_parsing(size_mb, iterations)
          @logger.info("Benchmarking dump parsing (#{size_mb} MB)...")
          dump_data = generate_fake_dump(size_mb)

          times = []
          object_counts = []

          iterations.times do |i|
            GC.start
            time = Benchmark.realtime do
              objects = parse_dump(dump_data)
              object_counts << objects.size
            end
            times << time
            @logger.info("  Run #{i + 1}: #{time.round(3)}s, #{object_counts.last} objects")
          end

          {
            dump_size_mb: size_mb,
            iterations: iterations,
            avg_seconds: avg(times).round(4),
            min_seconds: times.min.round(4),
            max_seconds: times.max.round(4),
            mb_per_second: (size_mb / avg(times)).round(2),
            avg_objects_parsed: avg(object_counts).round(0)
          }
        end

        # Benchmark: analyze heap structure (object graph traversal).
        def benchmark_heap_analysis(iterations)
          @logger.info("Benchmarking heap analysis...")
          graph = generate_object_graph(10_000)

          times = { traversal: [], dead_objects: [], cycle_detection: [], size_computation: [] }

          iterations.times do
            times[:traversal] << Benchmark.realtime { traverse_graph(graph) }
            times[:dead_objects] << Benchmark.realtime { find_dead_objects(graph) }
            times[:cycle_detection] << Benchmark.realtime { detect_cycles(graph) }
            times[:size_computation] << Benchmark.realtime { compute_retained_sizes(graph) }
          end

          result = {}
          times.each do |name, measurements|
            result[name] = {
              avg_ms: (avg(measurements) * 1000).round(3),
              min_ms: (measurements.min * 1000).round(3),
              max_ms: (measurements.max * 1000).round(3)
            }
            @logger.info("  #{name}: #{result[name][:avg_ms]} ms avg")
          end

          result[:graph_nodes] = graph.size
          result
        end

        # Benchmark: scan dump for Indicators of Compromise.
        def benchmark_ioc_scanning(iterations)
          @logger.info("Benchmarking IOC scanning...")

          ioc_patterns = generate_ioc_patterns
          scan_targets = generate_scan_targets(50_000)

          times = []
          match_counts = []

          iterations.times do |i|
            matches = 0
            time = Benchmark.realtime do
              scan_targets.each do |target|
                ioc_patterns.each do |pattern|
                  matches += 1 if target.match?(pattern[:regex])
                end
              end
            end
            times << time
            match_counts << matches
            @logger.info("  Run #{i + 1}: #{time.round(3)}s, #{matches} matches")
          end

          patterns_x_targets = ioc_patterns.size * scan_targets.size
          {
            ioc_pattern_count: ioc_patterns.size,
            scan_target_count: scan_targets.size,
            avg_seconds: avg(times).round(4),
            scans_per_second: (patterns_x_targets / avg(times)).round(0),
            avg_matches: avg(match_counts).round(0),
            match_rate_pct: (avg(match_counts).to_f / patterns_x_targets * 100).round(4)
          }
        end

        # Benchmark: extract printable strings from binary dump data.
        def benchmark_string_extraction(size_mb, iterations)
          @logger.info("Benchmarking string extraction (#{size_mb} MB)...")
          binary_data = generate_binary_with_strings(size_mb)

          times = []
          string_counts = []

          iterations.times do |i|
            strings = nil
            time = Benchmark.realtime do
              strings = extract_strings(binary_data, min_length: 6)
            end
            times << time
            string_counts << strings.size
            @logger.info("  Run #{i + 1}: #{time.round(3)}s, #{strings.size} strings")
          end

          {
            data_size_mb: size_mb,
            avg_seconds: avg(times).round(4),
            mb_per_second: (size_mb / avg(times)).round(2),
            avg_strings_found: avg(string_counts).round(0)
          }
        end

        # Benchmark: resolve reference chains (who references what).
        def benchmark_reference_chains(iterations)
          @logger.info("Benchmarking reference chain resolution...")
          graph = generate_object_graph(5_000)
          target_ids = graph.keys.sample(100)

          times = []
          chain_lengths = []

          iterations.times do
            total_length = 0
            time = Benchmark.realtime do
              target_ids.each do |target|
                chain = resolve_reference_chain(graph, target)
                total_length += chain.size
              end
            end
            times << time
            chain_lengths << total_length
          end

          {
            targets_per_run: target_ids.size,
            avg_seconds: avg(times).round(4),
            avg_chain_length: (avg(chain_lengths).to_f / target_ids.size).round(2),
            resolutions_per_second: (target_ids.size / avg(times)).round(0)
          }
        end

        # Benchmark: classify heap objects by type and threat level.
        def benchmark_object_classification(iterations)
          @logger.info("Benchmarking object classification...")
          objects = generate_heap_objects(20_000)

          times = []
          iterations.times do
            time = Benchmark.realtime do
              objects.each { |obj| classify_object(obj) }
            end
            times << time
          end

          {
            object_count: objects.size,
            avg_seconds: avg(times).round(4),
            objects_per_second: (objects.size / avg(times)).round(0),
            avg_us_per_object: (avg(times) / objects.size * 1_000_000).round(2)
          }
        end

        private

        # --- Data generators ---

        def generate_fake_dump(size_mb)
          chunk = "HEAP_OBJ:#{SecureRandom.hex(64)}:class=String:size=#{rand(10..1000)}:refs=#{rand(0..5)}\n"
          repeat = (size_mb * 1024 * 1024) / chunk.bytesize
          chunk * repeat
        end

        def generate_object_graph(node_count)
          graph = {}
          node_count.times do |i|
            refs = Array.new(rand(0..4)) { rand(0..node_count - 1) }.uniq.reject { |r| r == i }
            graph[i] = { id: i, type: %w[String Array Hash Object].sample, size: rand(24..4096), refs: refs }
          end
          graph
        end

        def generate_ioc_patterns
          [
            { name: "ip_address", regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ },
            { name: "url", regex: %r{https?://[^\s"'<>]+} },
            { name: "base64_blob", regex: %r{[A-Za-z0-9+/]{40,}={0,2}} },
            { name: "api_key", regex: /(?:api[_-]?key|token)\s*[=:]\s*[A-Za-z0-9]{20,}/i },
            { name: "crypto_wallet", regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ },
            { name: "aws_key", regex: /AKIA[0-9A-Z]{16}/ },
            { name: "shell_command", regex: /(?:system|exec|`)\s*\(?\s*["'].*["']\s*\)?/ },
            { name: "hex_shellcode", regex: /(?:\\x[0-9a-f]{2}){8,}/i },
            { name: "eval_call", regex: /eval\s*\(/ },
            { name: "dns_exfil", regex: /[a-z0-9]{32,}\.[a-z]{2,6}/i }
          ]
        end

        def generate_scan_targets(count)
          Array.new(count) do
            base = SecureRandom.hex(32)
            case rand(10)
            when 0 then "http://evil.com/#{base}"
            when 1 then "192.168.#{rand(255)}.#{rand(255)}"
            when 2 then "AKIA#{SecureRandom.hex(8).upcase}"
            when 3 then "eval('#{base}')"
            else base
            end
          end
        end

        def generate_binary_with_strings(size_mb)
          total = size_mb * 1024 * 1024
          parts = []
          current = 0
          while current < total
            if rand < 0.1
              str = "PrintableString_#{SecureRandom.alphanumeric(rand(8..64))}"
              parts << str
              current += str.bytesize
            else
              chunk_size = [rand(32..256), total - current].min
              parts << SecureRandom.random_bytes(chunk_size)
              current += chunk_size
            end
          end
          parts.join
        end

        def generate_heap_objects(count)
          types = %w[String Array Hash IO File Socket Thread Proc Class Module]
          Array.new(count) do
            { id: SecureRandom.hex(8), type: types.sample, size: rand(24..8192),
              frozen: [true, false].sample, tainted: rand < 0.05 }
          end
        end

        # --- Processing methods ---

        def parse_dump(data)
          objects = []
          data.each_line do |line|
            next unless line.start_with?("HEAP_OBJ:")
            parts = line.strip.split(":")
            objects << { address: parts[1], class: parts[2], size: parts[3], refs: parts[4] }
          end
          objects
        end

        def traverse_graph(graph)
          visited = Set.new
          stack = [graph.keys.first]
          while (node = stack.pop)
            next if visited.include?(node)
            visited << node
            (graph[node][:refs] || []).each { |r| stack.push(r) }
          end
          visited.size
        end

        def find_dead_objects(graph)
          all_referenced = Set.new
          graph.each_value { |node| node[:refs].each { |r| all_referenced << r } }
          root_set = Set.new(graph.keys.first(10))
          reachable = Set.new
          stack = root_set.to_a
          while (node = stack.pop)
            next if reachable.include?(node)
            reachable << node
            (graph[node][:refs] || []).each { |r| stack.push(r) } if graph[node]
          end
          graph.keys.size - reachable.size
        end

        def detect_cycles(graph)
          visited = Set.new
          in_stack = Set.new
          cycles = 0
          graph.each_key do |node|
            next if visited.include?(node)
            stack = [[node, 0]]
            while (current, ref_idx = stack.last)
              break unless current
              unless visited.include?(current)
                visited << current
                in_stack << current
              end
              refs = graph[current]&.dig(:refs) || []
              if ref_idx < refs.size
                stack.last[1] += 1
                next_node = refs[ref_idx]
                if in_stack.include?(next_node)
                  cycles += 1
                elsif !visited.include?(next_node)
                  stack.push([next_node, 0])
                end
              else
                in_stack.delete(current)
                stack.pop
              end
            end
          end
          cycles
        end

        def compute_retained_sizes(graph)
          graph.each_with_object({}) do |(id, node), sizes|
            retained = node[:size]
            (node[:refs] || []).each { |r| retained += (graph[r]&.dig(:size) || 0) }
            sizes[id] = retained
          end
        end

        def extract_strings(data, min_length: 6)
          data.scan(/[\x20-\x7E]{#{min_length},}/)
        end

        def resolve_reference_chain(graph, target_id, max_depth: 20)
          chain = [target_id]
          current = target_id
          depth = 0
          while depth < max_depth
            parent = graph.find { |_id, node| node[:refs]&.include?(current) }&.first
            break unless parent
            break if chain.include?(parent)
            chain.unshift(parent)
            current = parent
            depth += 1
          end
          chain
        end

        def classify_object(obj)
          threat = :benign
          threat = :suspicious if obj[:tainted]
          threat = :suspicious if obj[:type] == "Socket" || obj[:type] == "IO"
          threat = :high if obj[:type] == "Socket" && obj[:size] > 1024
          { id: obj[:id], type: obj[:type], threat_level: threat }
        end

        def avg(arr)
          arr.sum.to_f / arr.size
        end

        def build_summary
          {
            timestamp: Time.now.utc.iso8601,
            dump_parse_mb_per_sec: @results.dig(:dump_parsing, :mb_per_second),
            heap_traversal_ms: @results.dig(:heap_analysis, :traversal, :avg_ms),
            ioc_scans_per_sec: @results.dig(:ioc_scanning, :scans_per_second),
            string_extract_mb_per_sec: @results.dig(:string_extraction, :mb_per_second),
            ref_chain_resolutions_per_sec: @results.dig(:reference_chains, :resolutions_per_second),
            object_classifications_per_sec: @results.dig(:object_classification, :objects_per_second)
          }
        end

        def write_results
          output_path = File.join(Dir.pwd, "benchmark_forensics_results.json")
          File.write(output_path, JSON.pretty_generate(@results))
          @logger.info("Results written to #{output_path}")
        end
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  bench = RubyGuardian::Testing::Performance::BenchmarkForensics.new
  results = bench.run_all!(
    dump_size_mb: (ARGV[0] || 50).to_i,
    iterations: (ARGV[1] || 10).to_i
  )
  puts "\n=== Summary ==="
  puts JSON.pretty_generate(results[:summary])
end
