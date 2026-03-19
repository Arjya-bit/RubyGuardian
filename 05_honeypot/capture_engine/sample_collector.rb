# frozen_string_literal: true

# RubyGuardian Phase 5 -- Honeypot Capture Engine: Sample Collector
#
# Collects, deduplicates, and stores malware samples captured by the
# honeypot for later analysis by the ML classifier.

require 'digest'
require 'json'
require 'fileutils'

module RubyGuardian
  module Honeypot
    class SampleCollector
      attr_reader :config, :logger, :stats

      def initialize(config: {}, logger: nil)
        @config = config
        @logger = logger
        @sample_dir = config['sample_dir'] || '/var/lib/ruby-guardian/samples'
        @known_hashes = Set.new
        @stats = { collected: 0, duplicates: 0, total_bytes: 0 }
        @mutex = Mutex.new

        FileUtils.mkdir_p(@sample_dir)
        load_known_hashes
      end

      # Collect a new sample
      def collect(payload, metadata: {})
        hash = Digest::SHA256.hexdigest(payload)

        @mutex.synchronize do
          if @known_hashes.include?(hash)
            @stats[:duplicates] += 1
            @logger&.debug("[SampleCollector] Duplicate sample: #{hash[0..15]}")
            return { stored: false, duplicate: true, hash: hash }
          end

          sample_path = File.join(@sample_dir, "#{hash}.sample")
          meta_path = File.join(@sample_dir, "#{hash}.meta.json")

          File.binwrite(sample_path, payload)
          File.write(meta_path, JSON.pretty_generate({
            sha256: hash,
            md5: Digest::MD5.hexdigest(payload),
            size: payload.bytesize,
            collected_at: Time.now.utc.iso8601,
            source: metadata[:source] || 'honeypot',
            content_type: detect_content_type(payload),
            **metadata
          }))

          @known_hashes.add(hash)
          @stats[:collected] += 1
          @stats[:total_bytes] += payload.bytesize

          @logger&.info("[SampleCollector] New sample: #{hash[0..15]} (#{payload.bytesize} bytes)")
          { stored: true, hash: hash, path: sample_path }
        end
      end

      # List all collected samples
      def list_samples
        Dir.glob(File.join(@sample_dir, '*.meta.json')).map do |meta_path|
          JSON.parse(File.read(meta_path))
        end
      end

      # Export samples for ML classifier training
      def export_for_training(output_dir)
        FileUtils.mkdir_p(output_dir)
        samples = list_samples

        manifest = samples.map do |meta|
          sample_path = File.join(@sample_dir, "#{meta['sha256']}.sample")
          next unless File.exist?(sample_path)

          dest = File.join(output_dir, "#{meta['sha256']}.rb")
          FileUtils.cp(sample_path, dest)
          { hash: meta['sha256'], label: 'malicious', path: dest }
        end.compact

        File.write(File.join(output_dir, 'manifest.json'), JSON.pretty_generate(manifest))
        @logger&.info("[SampleCollector] Exported #{manifest.size} samples to #{output_dir}")
        manifest.size
      end

      private

      def load_known_hashes
        Dir.glob(File.join(@sample_dir, '*.sample')).each do |path|
          hash = File.basename(path, '.sample')
          @known_hashes.add(hash)
        end
        @logger&.info("[SampleCollector] Loaded #{@known_hashes.size} known hashes")
      end

      def detect_content_type(payload)
        if payload.start_with?('#!/usr/bin/env ruby', '# frozen_string_literal')
          'ruby_script'
        elsif payload.match?(/\A[\x20-\x7E\s]+\z/)
          'text'
        else
          'binary'
        end
      end
    end
  end
end
