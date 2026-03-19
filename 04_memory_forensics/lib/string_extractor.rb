# frozen_string_literal: true

require 'json'
require 'yaml'
require 'base64'
require 'uri'
require 'ipaddr'

module RubyGuardian
  module MemoryForensics
    # StringExtractor extracts and categorizes strings from memory dumps,
    # supporting multiple encodings and automatic classification into
    # forensically relevant categories.
    class StringExtractor
      DEFAULT_MIN_LENGTH = 4
      DEFAULT_MAX_LENGTH = 65_536

      ENCODINGS = {
        ascii: { name: 'ASCII', byte_width: 1, filter: /[\x20-\x7E]/ },
        utf8: { name: 'UTF-8', byte_width: 1, filter: nil },
        utf16le: { name: 'UTF-16LE', byte_width: 2, filter: nil },
        utf16be: { name: 'UTF-16BE', byte_width: 2, filter: nil }
      }.freeze

      ExtractedString = Struct.new(
        :value, :address, :length, :encoding, :region,
        :categories, :entropy, :is_ruby_string, keyword_init: true
      )

      CATEGORY_PATTERNS = {
        url: /\Ahttps?:\/\/[^\s]{4,}\z/i,
        ip_address: /\A(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\z/,
        ipv6_address: /\A(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\z/i,
        email: /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/,
        file_path_unix: /\A\/(?:[\w.+-]+\/)*[\w.+-]+\z/,
        file_path_windows: /\A[A-Z]:\\(?:[\w.+-]+\\)*[\w.+-]+\z/i,
        domain: /\A(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,10}\z/,
        base64_blob: /\A[A-Za-z0-9+\/]{40,}={0,2}\z/,
        hex_blob: /\A(?:0x)?[0-9a-fA-F]{32,}\z/,
        shell_command: /\A(?:bash|sh|zsh|cmd|powershell|curl|wget|nc|ncat|python|ruby|perl|php)\s/i,
        api_key: /\A(?:sk-|pk-|ak-|AKIA|AIza|ghp_|gho_|ghu_|ghs_)[A-Za-z0-9_-]{16,}\z/,
        crypto_address: /\A(?:1|3|bc1|0x)[a-zA-Z0-9]{25,}\z/,
        sql_query: /\A\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s/i,
        ruby_code: /\A\s*(?:def |class |module |require |gem |puts |raise )/,
        registry_key: /\AHK(?:EY_|LM|CU|CR|U|CC)/,
        jwt_token: /\AeyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/
      }.freeze

      # Suspicious string indicators
      SUSPICIOUS_KEYWORDS = %w[
        /bin/sh /bin/bash reverse_shell backdoor rootkit
        keylogger trojan payload shellcode exploit
        /etc/passwd /etc/shadow chmod\ 777 nc\ -e
        eval(Base64 Marshal.load system( exec(
        wget\ http curl\ http python\ -c
        PRIVMSG bitcoin monero xmr stratum
      ].freeze

      attr_reader :dump_parser, :config, :strings

      def initialize(dump_parser, config: nil)
        @dump_parser = dump_parser
        @config = load_config(config)
        @strings = []
        @min_length = @config.dig('analysis', 'strings', 'min_length') || DEFAULT_MIN_LENGTH
        @max_length = @config.dig('analysis', 'strings', 'max_length') || DEFAULT_MAX_LENGTH
      end

      # Extract all strings from the dump
      def extract(encodings: [:ascii, :utf8])
        @strings.clear

        encodings.each do |enc|
          extract_with_encoding(enc)
        end

        categorize_all
        @strings
      end

      # Extract only Ruby String objects from the dump
      def extract_ruby_strings
        ruby_strings = []

        @dump_parser.each_rvalue do |rv|
          next unless rv.type == :T_STRING

          str_val = extract_ruby_string_value(rv)
          next unless str_val && str_val.length >= @min_length

          categories = categorize_string(str_val)
          entropy = calculate_entropy(str_val)

          ruby_strings << ExtractedString.new(
            value: str_val,
            address: rv.address,
            length: str_val.length,
            encoding: detect_string_encoding(str_val),
            region: find_region_name(rv.address),
            categories: categories,
            entropy: entropy,
            is_ruby_string: true
          )
        end

        ruby_strings
      end

      # Extract strings matching specific categories
      def extract_by_category(category)
        extract unless @strings.any?
        @strings.select { |s| s.categories.include?(category) }
      end

      # Find suspicious strings
      def find_suspicious
        extract unless @strings.any?
        suspicious = []

        @strings.each do |extracted|
          suspicion_score = 0
          reasons = []

          # Check against suspicious keywords
          SUSPICIOUS_KEYWORDS.each do |keyword|
            if extracted.value.downcase.include?(keyword.downcase)
              suspicion_score += 2
              reasons << "Contains suspicious keyword: #{keyword}"
            end
          end

          # High entropy strings might be encrypted/encoded data
          if extracted.entropy && extracted.entropy > 5.5 && extracted.length > 50
            suspicion_score += 1
            reasons << "High entropy (#{extracted.entropy.round(2)})"
          end

          # Base64 encoded content that decodes to something interesting
          if extracted.categories.include?(:base64_blob)
            decoded = safe_base64_decode(extracted.value)
            if decoded && decoded.bytes.any? { |b| b < 32 && b != 10 && b != 13 && b != 9 }
              suspicion_score += 2
              reasons << 'Base64 decodes to binary content'
            end
          end

          # Strings in executable memory regions
          region = @dump_parser.find_region_for_address(extracted.address)
          if region && region.permissions.include?('x')
            suspicion_score += 1
            reasons << 'Found in executable memory'
          end

          if suspicion_score >= 2
            suspicious << {
              string: extracted,
              score: suspicion_score,
              reasons: reasons
            }
          end
        end

        suspicious.sort_by { |s| -s[:score] }
      end

      # Generate frequency analysis of extracted strings
      def frequency_analysis
        extract unless @strings.any?

        freq = Hash.new(0)
        @strings.each { |s| freq[s.value] += 1 }

        freq.sort_by { |_, count| -count }
            .first(100)
            .map { |value, count| { value: value, count: count } }
      end

      # Generate statistics about extracted strings
      def statistics
        extract unless @strings.any?

        category_counts = Hash.new(0)
        encoding_counts = Hash.new(0)
        length_histogram = Hash.new(0)
        entropy_buckets = Hash.new(0)

        @strings.each do |s|
          s.categories.each { |c| category_counts[c] += 1 }
          encoding_counts[s.encoding] += 1

          bucket = case s.length
                   when 0..10 then '0-10'
                   when 11..50 then '11-50'
                   when 51..200 then '51-200'
                   when 201..1000 then '201-1000'
                   else '1000+'
                   end
          length_histogram[bucket] += 1

          if s.entropy
            ebucket = (s.entropy * 2).floor / 2.0
            entropy_buckets[ebucket] += 1
          end
        end

        {
          total_strings: @strings.size,
          unique_strings: @strings.map(&:value).uniq.size,
          ruby_strings: @strings.count(&:is_ruby_string),
          category_counts: category_counts,
          encoding_counts: encoding_counts,
          length_histogram: length_histogram,
          entropy_distribution: entropy_buckets,
          average_length: @strings.empty? ? 0 : (@strings.sum(&:length).to_f / @strings.size).round(1),
          average_entropy: calculate_average_entropy
        }
      end

      private

      def extract_with_encoding(encoding)
        enc_info = ENCODINGS[encoding]
        return unless enc_info

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          case encoding
          when :ascii
            extract_ascii_strings(region)
          when :utf8
            extract_utf8_strings(region)
          when :utf16le, :utf16be
            extract_utf16_strings(region, encoding)
          end
        end
      end

      def extract_ascii_strings(region)
        data = region.data
        current_string = []
        current_start = 0

        data.each_byte.with_index do |byte, idx|
          if byte >= 0x20 && byte <= 0x7E
            current_string << byte if current_string.empty?
            current_string << byte unless current_string.size > 0 && current_string.last == byte && byte == current_string[-2]
            current_start = idx if current_string.size == 1
            # Rebuild without the dedup logic
          elsif !current_string.empty?
            if current_string.size >= @min_length
              add_extracted_string(current_string, region, current_start, :ascii)
            end
            current_string.clear
          end

          # Re-do simpler logic
        end

        # Simpler approach
        @strings.clear if @strings.empty? # ensure initialized

        i = 0
        while i < data.bytesize
          # Find start of printable sequence
          if data.getbyte(i) >= 0x20 && data.getbyte(i) <= 0x7E
            start = i
            i += 1
            while i < data.bytesize && data.getbyte(i) >= 0x20 && data.getbyte(i) <= 0x7E
              i += 1
              break if (i - start) > @max_length
            end
            len = i - start
            if len >= @min_length
              str = data[start, len]
              address = region.start_addr + start
              @strings << ExtractedString.new(
                value: str,
                address: address,
                length: len,
                encoding: :ascii,
                region: region.pathname,
                categories: [],
                entropy: nil,
                is_ruby_string: false
              )
            end
          else
            i += 1
          end
        end
      end

      def extract_utf8_strings(region)
        # UTF-8 extraction handles multi-byte sequences
        begin
          text = region.data.encode('UTF-8', 'binary',
                                     invalid: :replace, undef: :replace, replace: "\x00")
        rescue StandardError
          return
        end

        text.scan(/[[:print:]]{#{@min_length},#{@max_length}}/) do |match|
          pos = $~.begin(0)
          next if match.ascii_only? # Already captured by ASCII extraction

          @strings << ExtractedString.new(
            value: match,
            address: region.start_addr + pos,
            length: match.bytesize,
            encoding: :utf8,
            region: region.pathname,
            categories: [],
            entropy: nil,
            is_ruby_string: false
          )
        end
      end

      def extract_utf16_strings(region, encoding)
        enc_name = encoding == :utf16le ? 'UTF-16LE' : 'UTF-16BE'
        data = region.data

        # Look for UTF-16 sequences (printable chars interleaved with null bytes)
        i = 0
        while i + 1 < data.bytesize
          chars = []
          start = i

          while i + 1 < data.bytesize
            if encoding == :utf16le
              low = data.getbyte(i)
              high = data.getbyte(i + 1)
            else
              high = data.getbyte(i)
              low = data.getbyte(i + 1)
            end

            codepoint = (high << 8) | low
            break unless codepoint >= 0x20 && codepoint <= 0x7E || codepoint >= 0xA0

            chars << codepoint.chr(Encoding::UTF_8)
            i += 2
          end

          if chars.size >= @min_length
            str = chars.join
            @strings << ExtractedString.new(
              value: str,
              address: region.start_addr + start,
              length: str.length,
              encoding: encoding,
              region: region.pathname,
              categories: [],
              entropy: nil,
              is_ruby_string: false
            )
          end

          i += 2
        end
      end

      def extract_ruby_string_value(rv)
        flags = rv.flags
        raw = rv.raw_data
        str_noembed = 0x2000

        if (flags & str_noembed) != 0
          len = raw[16, 8].unpack1('q<')
          ptr = raw[24, 8].unpack1('Q<')
          return nil if len <= 0 || len > @max_length || ptr == 0

          @dump_parser.read_at(ptr, len)
        else
          embed_len = (flags & 0x1f0000) >> 16
          return nil if embed_len <= 0 || embed_len > 24

          raw[16, embed_len]
        end
      rescue StandardError
        nil
      end

      def categorize_all
        @strings.each do |extracted|
          extracted.categories = categorize_string(extracted.value)
          extracted.entropy = calculate_entropy(extracted.value)
        end
      end

      def categorize_string(str)
        categories = []
        CATEGORY_PATTERNS.each do |category, pattern|
          categories << category if str.match?(pattern)
        end
        categories
      end

      def calculate_entropy(str)
        return 0.0 if str.nil? || str.empty?

        freq = Hash.new(0)
        str.each_byte { |b| freq[b] += 1 }
        len = str.bytesize.to_f

        entropy = 0.0
        freq.each_value do |count|
          p = count / len
          entropy -= p * Math.log2(p) if p > 0
        end

        entropy.round(4)
      end

      def calculate_average_entropy
        with_entropy = @strings.select(&:entropy)
        return 0.0 if with_entropy.empty?

        (with_entropy.sum(&:entropy) / with_entropy.size).round(4)
      end

      def detect_string_encoding(str)
        return :ascii if str.ascii_only?

        case str.encoding.name
        when 'UTF-8' then :utf8
        when 'UTF-16LE' then :utf16le
        when 'UTF-16BE' then :utf16be
        else :binary
        end
      rescue StandardError
        :binary
      end

      def find_region_name(address)
        region = @dump_parser.find_region_for_address(address)
        region&.pathname || 'unknown'
      end

      def safe_base64_decode(str)
        Base64.strict_decode64(str)
      rescue ArgumentError
        nil
      end

      def add_extracted_string(_bytes, _region, _start, _encoding)
        # Placeholder - actual logic in extract_ascii_strings
      end

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end
    end
  end
end
