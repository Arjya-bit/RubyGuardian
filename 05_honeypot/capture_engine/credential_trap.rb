# frozen_string_literal: true

require "json"
require "digest"
require "fileutils"
require "logger"
require "securerandom"

module RubyGuardian
  module Honeypot
    module CaptureEngine
      # CredentialTrap deploys and monitors fake credential files (honeytokens)
      # across the filesystem. When analyzed code accesses these files, the
      # access is logged with full context for attribution and analysis.
      class CredentialTrap
        # Honeytoken definitions: where to place fake creds and what they contain.
        HONEYTOKEN_TEMPLATES = {
          aws_credentials: {
            path: "~/.aws/credentials",
            content: lambda { |id|
              <<~CREDS
                [default]
                aws_access_key_id = AKIAI#{id[0..14].upcase}
                aws_secret_access_key = #{SecureRandom.base64(30)}
                [production]
                aws_access_key_id = AKIAP#{id[0..14].upcase}
                aws_secret_access_key = #{SecureRandom.base64(30)}
              CREDS
            },
            description: "AWS credentials file"
          },
          ssh_private_key: {
            path: "~/.ssh/id_rsa",
            content: lambda { |_id|
              <<~KEY
                -----BEGIN OPENSSH PRIVATE KEY-----
                #{Array.new(8) { SecureRandom.base64(48) }.join("\n")}
                -----END OPENSSH PRIVATE KEY-----
              KEY
            },
            description: "SSH private key"
          },
          gem_credentials: {
            path: "~/.gem/credentials",
            content: lambda { |id|
              <<~CREDS
                ---
                :rubygems_api_key: rubygems_honeytoken_#{id}
                :rubygems_otp_seed: #{SecureRandom.hex(16)}
              CREDS
            },
            description: "RubyGems API credentials"
          },
          env_file: {
            path: ".env",
            content: lambda { |id|
              <<~ENV
                DATABASE_URL=postgres://admin:#{SecureRandom.hex(16)}@db.internal:5432/production
                REDIS_URL=redis://:#{SecureRandom.hex(12)}@redis.internal:6379/0
                SECRET_KEY_BASE=#{SecureRandom.hex(64)}
                GITHUB_TOKEN=ghp_#{SecureRandom.alphanumeric(36)}
                SLACK_BOT_TOKEN=xoxb-#{SecureRandom.hex(20)}
                STRIPE_SECRET_KEY=sk_live_#{SecureRandom.alphanumeric(24)}
                HONEYPOT_ID=#{id}
              ENV
            },
            description: "Application environment file"
          },
          docker_config: {
            path: "~/.docker/config.json",
            content: lambda { |id|
              JSON.pretty_generate({
                auths: {
                  "https://index.docker.io/v1/" => {
                    auth: Base64.strict_encode64("honeypot_#{id}:#{SecureRandom.hex(20)}")
                  },
                  "ghcr.io" => {
                    auth: Base64.strict_encode64("honeypot_#{id}:ghp_#{SecureRandom.alphanumeric(36)}")
                  }
                }
              })
            },
            description: "Docker registry credentials"
          },
          netrc: {
            path: "~/.netrc",
            content: lambda { |id|
              <<~NETRC
                machine github.com
                  login honeytoken-#{id}
                  password ghp_#{SecureRandom.alphanumeric(36)}
                machine rubygems.org
                  login honeytoken-#{id}
                  password #{SecureRandom.hex(20)}
                machine api.heroku.com
                  login honeytoken-#{id}@example.com
                  password #{SecureRandom.hex(32)}
              NETRC
            },
            description: "Netrc credentials file"
          }
        }.freeze

        attr_reader :deployed_tokens, :access_log

        def initialize(deploy_dir:, log_dir:, sample_id:, logger: nil)
          @deploy_dir = deploy_dir
          @log_dir = log_dir
          @sample_id = sample_id
          @logger = logger || default_logger
          @trap_id = SecureRandom.hex(8)
          @deployed_tokens = {}
          @access_log = []
          @mutex = Mutex.new
          @watchers = []
        end

        # Deploy all honeytoken files to the filesystem.
        def deploy!
          @logger.info("[CredentialTrap] Deploying honeytokens for sample #{@sample_id}")

          HONEYTOKEN_TEMPLATES.each do |name, template|
            deploy_token(name, template)
          end

          @logger.info("[CredentialTrap] Deployed #{@deployed_tokens.size} honeytokens")
          @deployed_tokens
        end

        # Start monitoring deployed honeytokens for access.
        def start_monitoring!
          @logger.info("[CredentialTrap] Starting honeytoken monitoring")
          @monitoring = true

          @deployed_tokens.each do |name, token_info|
            watcher = Thread.new(name, token_info) do |n, info|
              monitor_token(n, info)
            end
            @watchers << watcher
          end

          self
        end

        # Stop monitoring and collect results.
        def stop_monitoring!
          @monitoring = false
          @watchers.each { |w| w.join(5) }
          @watchers.clear
          flush_access_log
          self
        end

        # Clean up deployed honeytokens.
        def cleanup!
          @deployed_tokens.each do |_name, info|
            FileUtils.rm_f(info[:deployed_path]) if File.exist?(info[:deployed_path])
          end
          @logger.info("[CredentialTrap] Cleaned up #{@deployed_tokens.size} honeytokens")
        end

        # Record an access to a honeytoken.
        def record_access(token_name:, access_type:, details: {})
          entry = {
            timestamp: Time.now.utc.iso8601(6),
            sample_id: @sample_id,
            trap_id: @trap_id,
            token_name: token_name.to_s,
            access_type: access_type.to_s,
            details: details,
            pid: Process.pid
          }

          @mutex.synchronize { @access_log << entry }
          @logger.error("[CredentialTrap] HONEYTOKEN ACCESS: #{token_name} (#{access_type})")
          entry
        end

        # Summary of all credential trap activity.
        def summary
          {
            sample_id: @sample_id,
            trap_id: @trap_id,
            tokens_deployed: @deployed_tokens.size,
            total_accesses: @access_log.size,
            tokens_accessed: @access_log.map { |a| a[:token_name] }.uniq,
            access_types: @access_log.map { |a| a[:access_type] }.tally,
            timeline: @access_log.map { |a| { time: a[:timestamp], token: a[:token_name], type: a[:access_type] } }
          }
        end

        private

        def deploy_token(name, template)
          expanded_path = template[:path].sub("~", @deploy_dir)
          dir = File.dirname(expanded_path)
          FileUtils.mkdir_p(dir)

          content = template[:content].call(@trap_id)
          File.write(expanded_path, content)
          File.chmod(0o600, expanded_path)

          checksum = Digest::SHA256.hexdigest(content)

          @deployed_tokens[name] = {
            deployed_path: expanded_path,
            description: template[:description],
            checksum: checksum,
            deployed_at: Time.now.utc.iso8601,
            size: content.bytesize
          }

          @logger.debug("[CredentialTrap] Deployed #{name} to #{expanded_path}")
        end

        def monitor_token(name, info)
          last_atime = File.stat(info[:deployed_path]).atime rescue nil

          while @monitoring
            begin
              current_stat = File.stat(info[:deployed_path])

              if last_atime && current_stat.atime > last_atime
                record_access(token_name: name, access_type: :read,
                              details: { path: info[:deployed_path], atime: current_stat.atime.iso8601 })
              end

              current_content = File.read(info[:deployed_path])
              current_checksum = Digest::SHA256.hexdigest(current_content)
              if current_checksum != info[:checksum]
                record_access(token_name: name, access_type: :modified,
                              details: { path: info[:deployed_path], original_checksum: info[:checksum],
                                         new_checksum: current_checksum })
                info[:checksum] = current_checksum
              end

              last_atime = current_stat.atime
            rescue Errno::ENOENT
              record_access(token_name: name, access_type: :deleted,
                            details: { path: info[:deployed_path] })
              break
            end

            sleep 0.5
          end
        end

        def flush_access_log
          return if @access_log.empty?

          output_path = File.join(@log_dir, "credential_accesses_#{@sample_id}.json")
          File.write(output_path, JSON.pretty_generate({ sample_id: @sample_id, trap_id: @trap_id,
                                                         summary: summary, accesses: @access_log }))
          @logger.info("[CredentialTrap] Flushed #{@access_log.size} access records")
        end

        def default_logger
          Logger.new($stdout, progname: "RubyGuardian::CredentialTrap")
        end
      end
    end
  end
end
