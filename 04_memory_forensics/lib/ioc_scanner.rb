# frozen_string_literal: true

require 'json'
require 'yaml'
require 'digest'
require 'open3'
require 'time'

module RubyGuardian
  module MemoryForensics
    # IOCScanner scans memory dumps for indicators of compromise using
    # YARA rules, pattern matching, and heuristic detection techniques.
    class IOCScanner
      YARA_TIMEOUT = 30
      MAX_MATCHES_PER_RULE = 500

      IOCMatch = Struct.new(
        :rule_name, :category, :severity, :offset, :address,
        :matched_data, :matched_strings, :description,
        :confidence, :metadata, keyword_init: true
      )

      ScanResult = Struct.new(
        :total_matches, :matches_by_severity, :matches_by_category,
        :matches, :scan_duration, :rules_loaded, :heuristic_hits,
        keyword_init: true
      )

      # Built-in heuristic patterns for Ruby-specific threats
      HEURISTIC_PATTERNS = {
        eval_injection: {
          pattern: /eval\s*\(\s*(?:Base64\.decode64|Marshal\.(?:load|restore)|`.+`)/,
          severity: :critical,
          description: 'Dynamic code evaluation with dangerous input source',
          confidence: 0.85
        },
        shell_execution: {
          pattern: /(?:system|exec|spawn|`|%x\{|IO\.popen|Open3)\s*\(.{0,200}(?:\$\{|#\{|\bcat\b|\bcurl\b|\bwget\b|\bnc\b|\bbash\b)/m,
          severity: :critical,
          description: 'Shell command execution with suspicious arguments',
          confidence: 0.80
        },
        reverse_shell_ruby: {
          pattern: /TCPSocket\.(?:new|open)\s*\(.+?\)\s*(?:.*?\n){0,5}.*?(?:\$stdin|\$stdout|STDIN|STDOUT|exec|system)/m,
          severity: :critical,
          description: 'Potential Ruby reverse shell pattern',
          confidence: 0.90
        },
        base64_payload: {
          pattern: /Base64\.decode64\s*\(\s*['"][A-Za-z0-9+\/=]{100,}['"]\s*\)/,
          severity: :high,
          description: 'Large Base64-encoded payload being decoded',
          confidence: 0.75
        },
        marshal_deserialization: {
          pattern: /Marshal\.(?:load|restore)\s*\(\s*(?!File|StringIO)/,
          severity: :high,
          description: 'Potentially unsafe Marshal deserialization from untrusted source',
          confidence: 0.70
        },
        require_from_tmp: {
          pattern: /(?:require|load)\s+['"](?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/,
          severity: :critical,
          description: 'Loading code from temporary directory',
          confidence: 0.90
        },
        define_method_injection: {
          pattern: /define_method\s*\(\s*(?:.*?\beval\b|.*?\bsend\b)/,
          severity: :high,
          description: 'Dynamic method definition with eval/send - possible code injection',
          confidence: 0.70
        },
        method_missing_backdoor: {
          pattern: /def\s+method_missing.*?(?:eval|system|exec|send\()/m,
          severity: :high,
          description: 'method_missing used as backdoor for arbitrary execution',
          confidence: 0.75
        },
        crypto_mining: {
          pattern: /(?:stratum\+tcp|xmr(?:ig|stak)|monero|coinhive|cryptonight|hashrate)/i,
          severity: :critical,
          description: 'Cryptocurrency mining indicators',
          confidence: 0.85
        },
        data_exfiltration: {
          pattern: /(?:Net::HTTP|HTTParty|Faraday|RestClient).*?(?:ENV|credentials|secret|password|token|api_key)/im,
          severity: :critical,
          description: 'Potential data exfiltration via HTTP with sensitive data',
          confidence: 0.70
        },
        process_manipulation: {
          pattern: /Process\.(?:kill|detach|daemon)|fork\s*(?:do|\{).*?(?:exec|system)/m,
          severity: :high,
          description: 'Process manipulation for persistence or evasion',
          confidence: 0.65
        },
        objectspace_manipulation: {
          pattern: /ObjectSpace\._id2ref|ObjectSpace\.each_object.*?(?:remove|undef|hide)/,
          severity: :high,
          description: 'ObjectSpace manipulation - possible object hiding technique',
          confidence: 0.80
        }
      }.freeze

      # Known malicious gem patterns
      MALICIOUS_GEM_INDICATORS = [
        'atlas-client', 'event_stream', 'rest-client-1.6.13',
        'strong_password-0.0.7', 'bootstrap-sass-3.2.0.3',
        'rua-*-malicious', 'browser_enum', 'ruby-hierarchical'
      ].freeze

      attr_reader :dump_parser, :config, :yara_rules_dir, :matches

      def initialize(dump_parser, config: nil)
        @dump_parser = dump_parser
        @config = load_config(config)
        @yara_rules_dir = resolve_yara_dir
        @matches = []
        @rules_loaded = 0
      end

      # Run complete IOC scan
      def scan
        start_time = Time.now
        @matches.clear

        yara_matches = scan_with_yara
        heuristic_matches = scan_with_heuristics
        gem_matches = scan_for_malicious_gems
        string_matches = scan_suspicious_strings

        all_matches = yara_matches + heuristic_matches + gem_matches + string_matches

        # Deduplicate overlapping matches
        @matches = deduplicate_matches(all_matches)

        build_scan_result(Time.now - start_time, heuristic_matches.size)
      end

      # Scan using YARA rules
      def scan_with_yara
        matches = []
        return matches unless yara_available?

        rule_files = Dir.glob(File.join(@yara_rules_dir, '**', '*.yar'))
        @rules_loaded = rule_files.size

        # Create a temporary file with all dump data for YARA scanning
        flat = @dump_parser.flatten
        return matches if flat[:data].empty?

        tmp_path = create_temp_dump(flat[:data])

        begin
          rule_files.each do |rule_file|
            file_matches = run_yara_scan(rule_file, tmp_path, flat[:address_map])
            matches.concat(file_matches)
          end
        ensure
          File.delete(tmp_path) if File.exist?(tmp_path)
        end

        matches
      end

      # Scan using built-in heuristic patterns
      def scan_with_heuristics
        return [] unless @config.dig('analysis', 'ioc_scanning', 'heuristic_detection') != false

        min_confidence = @config.dig('analysis', 'ioc_scanning', 'min_confidence') || 0.6
        matches = []

        # Extract all readable text from the dump
        text_regions = extract_text_regions

        HEURISTIC_PATTERNS.each do |name, pattern_def|
          next if pattern_def[:confidence] < min_confidence

          text_regions.each do |text_info|
            scanner = StringScanner.new(text_info[:text]) if defined?(StringScanner)
            # Fallback to scan approach
            text_info[:text].scan(pattern_def[:pattern]) do |match_data|
              matched = match_data.is_a?(Array) ? match_data.first : $~.to_s
              pos = $~.begin(0) rescue 0

              matches << IOCMatch.new(
                rule_name: "heuristic_#{name}",
                category: :heuristic,
                severity: pattern_def[:severity],
                offset: pos,
                address: text_info[:base_address] + pos,
                matched_data: truncate(matched, 200),
                matched_strings: [name.to_s],
                description: pattern_def[:description],
                confidence: pattern_def[:confidence],
                metadata: { technique: name.to_s }
              )
            end
          end
        end

        matches
      end

      # Scan for known malicious gem indicators
      def scan_for_malicious_gems
        matches = []

        MALICIOUS_GEM_INDICATORS.each do |gem_pattern|
          results = @dump_parser.search_pattern(gem_pattern)
          results.each do |result|
            matches << IOCMatch.new(
              rule_name: 'malicious_gem_indicator',
              category: :malware,
              severity: :critical,
              offset: result[:offset],
              address: result[:address],
              matched_data: gem_pattern,
              matched_strings: [gem_pattern],
              description: "Known malicious gem indicator: #{gem_pattern}",
              confidence: 0.85,
              metadata: { gem: gem_pattern }
            )
          end
        end

        matches
      end

      # Scan for suspicious string patterns
      def scan_suspicious_strings
        matches = []
        suspicious_patterns = {
          /(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}/ => { cat: :network, sev: :medium, desc: 'IP:port combination' },
          /(?:password|passwd|secret)\s*[:=]\s*\S+/i => { cat: :credential, sev: :high, desc: 'Exposed credential' },
          /BEGIN (?:RSA |DSA |EC )?PRIVATE KEY/ => { cat: :credential, sev: :critical, desc: 'Private key in memory' },
          /eyJ[A-Za-z0-9_-]{20,}\.eyJ/ => { cat: :credential, sev: :high, desc: 'JWT token in memory' },
          /AKIA[0-9A-Z]{16}/ => { cat: :credential, sev: :critical, desc: 'AWS access key in memory' },
          /sk-[a-zA-Z0-9]{32,}/ => { cat: :credential, sev: :critical, desc: 'API secret key in memory' }
        }

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          suspicious_patterns.each do |pattern, info|
            region.data.scan(pattern) do
              matched = $~.to_s
              pos = $~.begin(0) rescue 0

              matches << IOCMatch.new(
                rule_name: "string_#{info[:cat]}",
                category: info[:cat],
                severity: info[:sev],
                offset: pos,
                address: region.start_addr + pos,
                matched_data: truncate(matched, 100),
                matched_strings: [matched[0, 50]],
                description: info[:desc],
                confidence: 0.65,
                metadata: {}
              )
            end
          end
        end

        matches
      end

      # Check if a hash is in the allowlist
      def allowlisted?(hash_value)
        return false unless @allowlist

        @allowlist.include?(hash_value)
      end

      private

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end

      def resolve_yara_dir
        configured = @config.dig('analysis', 'ioc_scanning', 'yara_rules_dir')
        if configured
          File.expand_path(configured, File.join(__dir__, '..'))
        else
          File.join(__dir__, '..', 'config', 'ioc_patterns')
        end
      end

      def yara_available?
        _, _, status = Open3.capture3('yara', '--version')
        status.success?
      rescue Errno::ENOENT
        false
      end

      def create_temp_dump(data)
        tmp_path = File.join(
          @config.dig('general', 'work_dir') || '/tmp/rubyguardian_forensics',
          "scan_#{Process.pid}_#{Time.now.to_i}.bin"
        )
        FileUtils.mkdir_p(File.dirname(tmp_path))
        File.binwrite(tmp_path, data)
        tmp_path
      end

      def run_yara_scan(rule_file, target_path, address_map)
        matches = []
        timeout = @config.dig('analysis', 'ioc_scanning', 'rule_timeout') || YARA_TIMEOUT

        stdout, stderr, status = Open3.capture3(
          'yara', '-s', '-m', rule_file, target_path,
          timeout: timeout
        )

        return matches unless status.success?

        current_rule = nil
        current_meta = {}

        stdout.each_line do |line|
          line = line.strip
          if line =~ /^(\S+)\s+\[(.+)\]\s+/
            current_rule = $1
            meta_str = $2
            current_meta = parse_yara_meta(meta_str)
          elsif line =~ /^0x([0-9a-f]+):\$(\S+):\s*(.*)$/
            offset = $1.to_i(16)
            string_id = $2
            matched = $3

            virtual_addr = translate_offset_to_address(offset, address_map)

            matches << IOCMatch.new(
              rule_name: current_rule,
              category: current_meta['category']&.to_sym || :yara,
              severity: (current_meta['severity'] || 'medium').to_sym,
              offset: offset,
              address: virtual_addr,
              matched_data: truncate(matched, 200),
              matched_strings: [string_id],
              description: current_meta['description'] || current_rule,
              confidence: 0.90,
              metadata: current_meta
            )
          end
        end

        matches
      rescue Open3::TimeoutError
        []
      end

      def parse_yara_meta(meta_str)
        meta = {}
        meta_str.scan(/(\w+)=(".*?"|[^\s,]+)/) do |key, value|
          meta[key] = value.gsub(/^"|"$/, '')
        end
        meta
      end

      def translate_offset_to_address(offset, address_map)
        address_map.each do |mapping|
          if offset >= mapping[:flat_offset] &&
             offset < mapping[:flat_offset] + mapping[:size]
            return mapping[:virtual_address] + (offset - mapping[:flat_offset])
          end
        end
        offset
      end

      def extract_text_regions
        regions = []
        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          # Extract printable ASCII sequences
          text = region.data.encode('UTF-8', 'binary',
                                     invalid: :replace, undef: :replace, replace: '')
          next if text.empty?

          regions << {
            text: text,
            base_address: region.start_addr,
            size: text.bytesize
          }
        end
        regions
      end

      def deduplicate_matches(matches)
        seen = {}
        matches.select do |m|
          key = "#{m.rule_name}:#{m.address}:#{m.matched_data}"
          if seen.key?(key)
            false
          else
            seen[key] = true
            true
          end
        end
      end

      def build_scan_result(duration, heuristic_count)
        by_severity = Hash.new(0)
        by_category = Hash.new(0)

        @matches.each do |m|
          by_severity[m.severity] += 1
          by_category[m.category] += 1
        end

        ScanResult.new(
          total_matches: @matches.size,
          matches_by_severity: by_severity,
          matches_by_category: by_category,
          matches: @matches,
          scan_duration: duration.round(3),
          rules_loaded: @rules_loaded,
          heuristic_hits: heuristic_count
        )
      end

      def truncate(str, max_len)
        return '' unless str

        str.length > max_len ? "#{str[0, max_len]}..." : str
      end
    end
  end
end
