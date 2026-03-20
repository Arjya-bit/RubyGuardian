# frozen_string_literal: true

require "json"
require "net/http"
require "uri"
require "logger"
require "digest"

module RubyGuardian
  module Honeypot
    module Analysis
      # IPEnricher takes captured IP addresses and enriches them with
      # geolocation data, ASN information, and threat intelligence from
      # multiple sources. Results are cached to minimize API calls.
      class IPEnricher
        PRIVATE_RANGES = [
          IPAddr.new("10.0.0.0/8"),
          IPAddr.new("172.16.0.0/12"),
          IPAddr.new("192.168.0.0/16"),
          IPAddr.new("127.0.0.0/8"),
          IPAddr.new("169.254.0.0/16")
        ].freeze

        # Threat intelligence feed configuration
        FEEDS = {
          ip_api: {
            url: "http://ip-api.com/json/%{ip}?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting",
            rate_limit: 45, # requests per minute
            provides: %i[geolocation asn isp]
          },
          abuseipdb: {
            url: "https://api.abuseipdb.com/api/v2/check?ipAddress=%{ip}&maxAgeInDays=90",
            requires_key: true,
            env_key: "ABUSEIPDB_API_KEY",
            rate_limit: 1000, # per day
            provides: %i[abuse_score reports]
          },
          virustotal: {
            url: "https://www.virustotal.com/api/v3/ip_addresses/%{ip}",
            requires_key: true,
            env_key: "VIRUSTOTAL_API_KEY",
            rate_limit: 4, # per minute
            provides: %i[malicious_votes detections]
          }
        }.freeze

        attr_reader :cache, :enrichment_stats

        def initialize(cache_dir: nil, logger: nil)
          @cache_dir = cache_dir
          @logger = logger || default_logger
          @cache = {}
          @enrichment_stats = { total: 0, cached: 0, api_calls: 0, errors: 0, private_skipped: 0 }
          @rate_limiters = {}
          load_cache_from_disk if @cache_dir
        end

        # Enrich a single IP address.
        # @param ip [String] IP address to enrich
        # @return [Hash] enrichment data
        def enrich(ip)
          @enrichment_stats[:total] += 1

          if private_ip?(ip)
            @enrichment_stats[:private_skipped] += 1
            return private_ip_result(ip)
          end

          if @cache.key?(ip) && cache_fresh?(ip)
            @enrichment_stats[:cached] += 1
            return @cache[ip]
          end

          result = { ip: ip, enriched_at: Time.now.utc.iso8601, sources: {} }

          # Query each available feed
          result[:sources][:geolocation] = query_ip_api(ip)
          result[:sources][:abuseipdb] = query_abuseipdb(ip) if api_key_available?(:abuseipdb)
          result[:sources][:virustotal] = query_virustotal(ip) if api_key_available?(:virustotal)

          # Compute aggregate threat score
          result[:threat_assessment] = compute_threat_assessment(result[:sources])

          @cache[ip] = result
          save_cache_entry(ip, result) if @cache_dir
          result
        rescue StandardError => e
          @enrichment_stats[:errors] += 1
          @logger.error("[IPEnricher] Error enriching #{ip}: #{e.message}")
          { ip: ip, error: e.message, enriched_at: Time.now.utc.iso8601 }
        end

        # Enrich multiple IPs in batch.
        # @param ips [Array<String>] list of IP addresses
        # @return [Array<Hash>] enrichment results
        def enrich_batch(ips)
          unique_ips = ips.uniq.reject { |ip| ip.nil? || ip.empty? }
          @logger.info("[IPEnricher] Enriching batch of #{unique_ips.size} unique IPs")

          unique_ips.map do |ip|
            result = enrich(ip)
            sleep(rate_limit_delay(:ip_api)) # Respect rate limits
            result
          end
        end

        # Generate a summary report for all enriched IPs.
        def summary_report
          {
            stats: @enrichment_stats,
            total_enriched: @cache.size,
            countries: @cache.values.map { |v| v.dig(:sources, :geolocation, :country) }.compact.tally.sort_by { |_, c| -c },
            top_asns: @cache.values.map { |v| v.dig(:sources, :geolocation, :asn) }.compact.tally.sort_by { |_, c| -c }.first(10),
            high_threat_ips: @cache.select { |_, v| (v.dig(:threat_assessment, :score) || 0) >= 70 }
                                   .map { |ip, v| { ip: ip, score: v.dig(:threat_assessment, :score) } }
                                   .sort_by { |h| -h[:score] },
            hosting_providers: @cache.values.count { |v| v.dig(:sources, :geolocation, :hosting) == true },
            proxy_vpn_count: @cache.values.count { |v| v.dig(:sources, :geolocation, :proxy) == true }
          }
        end

        # Persist cache to disk.
        def save_cache
          return unless @cache_dir

          FileUtils.mkdir_p(@cache_dir)
          cache_path = File.join(@cache_dir, "ip_enrichment_cache.json")
          File.write(cache_path, JSON.pretty_generate(@cache))
          @logger.info("[IPEnricher] Cache saved (#{@cache.size} entries)")
        end

        private

        def query_ip_api(ip)
          @enrichment_stats[:api_calls] += 1
          uri = URI(format(FEEDS[:ip_api][:url], ip: ip))
          response = Net::HTTP.get_response(uri)

          if response.is_a?(Net::HTTPSuccess)
            data = JSON.parse(response.body, symbolize_names: true)
            {
              country: data[:country],
              country_code: data[:countryCode],
              region: data[:region],
              city: data[:city],
              lat: data[:lat],
              lon: data[:lon],
              isp: data[:isp],
              org: data[:org],
              asn: data[:as],
              asn_name: data[:asname],
              reverse_dns: data[:reverse],
              is_mobile: data[:mobile],
              proxy: data[:proxy],
              hosting: data[:hosting]
            }
          else
            { error: "HTTP #{response.code}", raw: response.body&.slice(0, 200) }
          end
        rescue StandardError => e
          { error: e.message }
        end

        def query_abuseipdb(ip)
          @enrichment_stats[:api_calls] += 1
          uri = URI(format(FEEDS[:abuseipdb][:url], ip: ip))
          request = Net::HTTP::Get.new(uri)
          request["Key"] = ENV.fetch(FEEDS[:abuseipdb][:env_key])
          request["Accept"] = "application/json"

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          response = http.request(request)

          if response.is_a?(Net::HTTPSuccess)
            data = JSON.parse(response.body, symbolize_names: true).dig(:data) || {}
            {
              abuse_confidence_score: data[:abuseConfidenceScore],
              total_reports: data[:totalReports],
              last_reported_at: data[:lastReportedAt],
              is_tor: data[:isTor],
              usage_type: data[:usageType],
              domain: data[:domain]
            }
          else
            { error: "HTTP #{response.code}" }
          end
        rescue StandardError => e
          { error: e.message }
        end

        def query_virustotal(ip)
          @enrichment_stats[:api_calls] += 1
          uri = URI(format(FEEDS[:virustotal][:url], ip: ip))
          request = Net::HTTP::Get.new(uri)
          request["x-apikey"] = ENV.fetch(FEEDS[:virustotal][:env_key])

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          response = http.request(request)

          if response.is_a?(Net::HTTPSuccess)
            data = JSON.parse(response.body, symbolize_names: true)
            stats = data.dig(:data, :attributes, :last_analysis_stats) || {}
            {
              malicious: stats[:malicious] || 0,
              suspicious: stats[:suspicious] || 0,
              harmless: stats[:harmless] || 0,
              undetected: stats[:undetected] || 0,
              reputation: data.dig(:data, :attributes, :reputation) || 0
            }
          else
            { error: "HTTP #{response.code}" }
          end
        rescue StandardError => e
          { error: e.message }
        end

        def compute_threat_assessment(sources)
          score = 0
          indicators = []

          # AbuseIPDB score contribution
          abuse_score = sources.dig(:abuseipdb, :abuse_confidence_score)
          if abuse_score
            score += abuse_score * 0.4
            indicators << "AbuseIPDB confidence: #{abuse_score}%" if abuse_score > 50
          end

          # VirusTotal contribution
          vt_malicious = sources.dig(:virustotal, :malicious) || 0
          if vt_malicious > 0
            score += [vt_malicious * 5, 40].min
            indicators << "VirusTotal detections: #{vt_malicious}"
          end

          # Hosting/proxy indicators
          if sources.dig(:geolocation, :hosting)
            score += 10
            indicators << "Hosted on cloud/hosting provider"
          end
          if sources.dig(:geolocation, :proxy)
            score += 15
            indicators << "Proxy/VPN/Tor detected"
          end

          {
            score: [score.round, 100].min,
            risk_level: score_to_level(score),
            indicators: indicators
          }
        end

        def score_to_level(score)
          case score
          when 0..20   then :low
          when 21..50  then :medium
          when 51..75  then :high
          else :critical
          end
        end

        def private_ip?(ip)
          addr = IPAddr.new(ip)
          PRIVATE_RANGES.any? { |range| range.include?(addr) }
        rescue IPAddr::InvalidAddressError
          false
        end

        def private_ip_result(ip)
          { ip: ip, is_private: true, enriched_at: Time.now.utc.iso8601,
            threat_assessment: { score: 0, risk_level: :none, indicators: ["Private/internal IP"] } }
        end

        def api_key_available?(feed)
          env_key = FEEDS[feed][:env_key]
          env_key && ENV.key?(env_key) && !ENV[env_key].empty?
        end

        def cache_fresh?(ip, max_age: 86_400) # 24 hours
          entry = @cache[ip]
          return false unless entry && entry[:enriched_at]

          Time.parse(entry[:enriched_at]) > Time.now.utc - max_age
        rescue StandardError
          false
        end

        def rate_limit_delay(feed)
          rpm = FEEDS[feed][:rate_limit] || 60
          60.0 / rpm
        end

        def load_cache_from_disk
          cache_path = File.join(@cache_dir, "ip_enrichment_cache.json")
          return unless File.exist?(cache_path)

          @cache = JSON.parse(File.read(cache_path), symbolize_names: true)
                       .transform_keys(&:to_s)
          @logger.info("[IPEnricher] Loaded #{@cache.size} cached entries from disk")
        rescue StandardError => e
          @logger.warn("[IPEnricher] Could not load cache: #{e.message}")
        end

        def save_cache_entry(ip, data)
          FileUtils.mkdir_p(@cache_dir)
          entry_path = File.join(@cache_dir, "ip_#{Digest::SHA256.hexdigest(ip)[0..15]}.json")
          File.write(entry_path, JSON.pretty_generate(data))
        end

        def default_logger
          Logger.new($stdout, progname: "RubyGuardian::IPEnricher")
        end
      end
    end
  end
end
