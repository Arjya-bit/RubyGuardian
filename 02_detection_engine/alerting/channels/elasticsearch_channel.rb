# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'time'
require 'securerandom'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Channels
        # Sends alerts to Elasticsearch via REST API with bulk indexing support.
        # Supports index templates, ILM policies, and automatic retry with
        # exponential backoff.
        class ElasticsearchChannel
          MAX_BULK_SIZE     = 500
          DEFAULT_TIMEOUT   = 30
          MAX_RETRIES       = 3
          BACKOFF_BASE      = 0.5

          attr_reader :config, :stats

          def initialize(config = {})
            @config = {
              hosts:          Array(config.fetch(:hosts, ['http://localhost:9200'])),
              index_prefix:   config.fetch(:index_prefix, 'rubyguardian-alerts'),
              index_pattern:  config.fetch(:index_pattern, 'daily'),  # daily, weekly, monthly
              username:       config.fetch(:username, nil),
              password:       config.fetch(:password, nil),
              api_key:        config.fetch(:api_key, nil),
              ssl_verify:     config.fetch(:ssl_verify, true),
              timeout:        config.fetch(:timeout, DEFAULT_TIMEOUT),
              bulk_size:      [config.fetch(:bulk_size, 100), MAX_BULK_SIZE].min,
              pipeline:       config.fetch(:pipeline, nil),
              template_name:  config.fetch(:template_name, 'rubyguardian-alerts')
            }
            @buffer = []
            @mutex = Mutex.new
            @stats = { sent: 0, failed: 0, retries: 0, bulk_requests: 0 }
            @current_host_index = 0
          end

          # Send a single alert to Elasticsearch.
          #
          # @param formatted_alert [String] JSON-formatted alert
          def send_alert(formatted_alert)
            @mutex.synchronize { @buffer << formatted_alert }
            flush if @buffer.size >= @config[:bulk_size]
          end

          # Flush the internal buffer, sending all buffered alerts via bulk API.
          def flush
            batch = nil
            @mutex.synchronize do
              return if @buffer.empty?
              batch = @buffer.dup
              @buffer.clear
            end

            send_bulk(batch)
          end

          # Send a batch of alerts using Elasticsearch Bulk API.
          #
          # @param alerts [Array<String>] JSON-formatted alerts
          def send_bulk(alerts)
            return if alerts.nil? || alerts.empty?

            alerts.each_slice(@config[:bulk_size]) do |slice|
              body = build_bulk_body(slice)
              execute_with_retry(body, slice.size)
            end
          end

          # Check the health of the Elasticsearch cluster.
          #
          # @return [Hash] cluster health status
          def health_check
            uri = URI.join(current_host, '/_cluster/health')
            response = execute_request(:get, uri)
            JSON.parse(response.body)
          rescue StandardError => e
            { status: 'unreachable', error: e.message }
          end

          # Ensure the index template exists in Elasticsearch.
          def ensure_template
            uri = URI.join(current_host, "/_index_template/#{@config[:template_name]}")
            template = build_index_template
            execute_request(:put, uri, JSON.generate(template))
          end

          private

          def build_bulk_body(alerts)
            lines = []
            alerts.each do |alert_json|
              alert_data = alert_json.is_a?(String) ? JSON.parse(alert_json) : alert_json
              index_name = resolve_index_name
              action = { index: { _index: index_name } }
              action[:index][:pipeline] = @config[:pipeline] if @config[:pipeline]

              lines << JSON.generate(action)
              lines << (alert_json.is_a?(String) ? alert_json : JSON.generate(alert_json))
            end
            lines.join("\n") + "\n"
          end

          def resolve_index_name
            now = Time.now.utc
            suffix = case @config[:index_pattern]
                     when 'daily'   then now.strftime('%Y.%m.%d')
                     when 'weekly'  then "#{now.strftime('%Y')}.w#{now.strftime('%U')}"
                     when 'monthly' then now.strftime('%Y.%m')
                     else now.strftime('%Y.%m.%d')
                     end
            "#{@config[:index_prefix]}-#{suffix}"
          end

          def execute_with_retry(body, count)
            retries = 0
            begin
              uri = URI.join(current_host, '/_bulk')
              response = execute_request(:post, uri, body, 'application/x-ndjson')
              handle_bulk_response(response, count)
            rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNREFUSED => e
              retries += 1
              @stats[:retries] += 1
              if retries <= MAX_RETRIES
                rotate_host
                sleep(BACKOFF_BASE * (2**retries))
                retry
              end
              @stats[:failed] += count
              raise ConnectionError, "Failed after #{MAX_RETRIES} retries: #{e.message}"
            end
          end

          def handle_bulk_response(response, count)
            @stats[:bulk_requests] += 1
            result = JSON.parse(response.body)

            if result['errors']
              error_items = result['items'].select { |i| i.dig('index', 'error') }
              @stats[:failed] += error_items.size
              @stats[:sent] += (count - error_items.size)
            else
              @stats[:sent] += count
            end
          end

          def execute_request(method, uri, body = nil, content_type = 'application/json')
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = (uri.scheme == 'https')
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless @config[:ssl_verify]
            http.open_timeout = @config[:timeout]
            http.read_timeout = @config[:timeout]

            request = case method
                      when :get  then Net::HTTP::Get.new(uri)
                      when :post then Net::HTTP::Post.new(uri)
                      when :put  then Net::HTTP::Put.new(uri)
                      end

            request['Content-Type'] = content_type
            apply_auth(request)
            request.body = body if body

            http.request(request)
          end

          def apply_auth(request)
            if @config[:api_key]
              request['Authorization'] = "ApiKey #{@config[:api_key]}"
            elsif @config[:username] && @config[:password]
              request.basic_auth(@config[:username], @config[:password])
            end
          end

          def current_host
            @config[:hosts][@current_host_index]
          end

          def rotate_host
            @current_host_index = (@current_host_index + 1) % @config[:hosts].size
          end

          def build_index_template
            {
              index_patterns: ["#{@config[:index_prefix]}-*"],
              template: {
                settings: {
                  number_of_shards: 1,
                  number_of_replicas: 1,
                  'index.lifecycle.name' => 'rubyguardian-alert-policy'
                },
                mappings: {
                  properties: {
                    timestamp:    { type: 'date' },
                    alert_id:     { type: 'keyword' },
                    rule_id:      { type: 'keyword' },
                    rule_name:    { type: 'text', fields: { keyword: { type: 'keyword' } } },
                    severity:     { type: 'keyword' },
                    source_ip:    { type: 'ip' },
                    dest_ip:      { type: 'ip' },
                    event_type:   { type: 'keyword' },
                    mitre_tactics:    { type: 'keyword' },
                    mitre_techniques: { type: 'keyword' },
                    tags:         { type: 'keyword' }
                  }
                }
              }
            }
          end
        end

        class ConnectionError < StandardError; end
      end
    end
  end
end
