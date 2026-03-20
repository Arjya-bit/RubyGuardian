#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# RubyGuardian - Simulated C2 Server for CI/CD Poisoning Research
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This file is part of the RubyGuardian security research framework.
#   It simulates a Command & Control (C2) server to demonstrate how
#   attackers exfiltrate data from poisoned CI/CD pipelines.
#
#   ALL operations are LOG-ONLY. No actual malicious activity is performed.
#   This code must NEVER be used against systems without explicit written
#   authorization. Unauthorized use violates computer fraud laws including
#   the CFAA (18 U.S.C. Section 1030) and equivalent international statutes.
#
# MITRE ATT&CK References:
#   - T1071.001 : Application Layer Protocol: Web Protocols
#   - T1041     : Exfiltration Over C2 Channel
#   - T1573.001 : Encrypted Channel: Symmetric Cryptography
#   - T1059.004 : Command and Scripting Interpreter: Unix Shell
#   - T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain
#
# Usage:
#   ruby server.rb                  # Start on default port 4567
#   BIND_PORT=9090 ruby server.rb   # Start on custom port
# =============================================================================

require 'sinatra/base'
require 'json'
require 'securerandom'
require 'logger'
require 'time'
require 'yaml'

# Load internal modules
require_relative 'models/agent_session'
require_relative 'models/exfil_record'
require_relative 'routes/api_routes'

module RubyGuardian
  module C2
    # SimulatedC2Server
    #
    # A Sinatra-based HTTP server that mimics the behavior of a real C2 server
    # used in CI/CD poisoning attacks. Every endpoint logs the interaction
    # but performs no destructive or exfiltrative action.
    class SimulatedC2Server < Sinatra::Base
      # -----------------------------------------------------------------------
      # Configuration
      # -----------------------------------------------------------------------
      CONFIG_PATH = File.expand_path('config/settings.yml', __dir__)

      configure do
        set :server, :puma
        set :bind, ENV.fetch('BIND_HOST', '127.0.0.1')
        set :port, ENV.fetch('BIND_PORT', 4567).to_i
        set :show_exceptions, false
        set :logging, true

        # Load settings from YAML configuration file
        if File.exist?(CONFIG_PATH)
          settings_data = YAML.safe_load(File.read(CONFIG_PATH), permitted_classes: [Symbol])
          set :app_settings, settings_data
        else
          set :app_settings, {}
        end

        # Initialize the simulation logger
        log_dir = File.expand_path('logs', __dir__)
        Dir.mkdir(log_dir) unless Dir.exist?(log_dir)
        set :sim_logger, Logger.new(
          File.join(log_dir, 'c2_simulation.log'),
          'daily'
        )
        settings.sim_logger.formatter = proc do |severity, datetime, _progname, msg|
          "[#{datetime.iso8601}] [#{severity}] [C2-SIM] #{msg}\n"
        end

        # In-memory stores for simulation (no persistent DB required to run)
        set :agents, {}
        set :exfil_records, []
        set :command_queue, {}
      end

      # -----------------------------------------------------------------------
      # Middleware & Helpers
      # -----------------------------------------------------------------------
      before do
        content_type :json

        # Log every incoming request for research analysis
        settings.sim_logger.info(
          "REQUEST #{request.request_method} #{request.path_info} " \
          "from=#{request.ip} ua=#{request.user_agent}"
        )
      end

      helpers do
        # Parse JSON body safely, returning empty hash on failure
        def json_body
          body = request.body.read
          return {} if body.empty?

          JSON.parse(body, symbolize_names: true)
        rescue JSON::ParserError => e
          settings.sim_logger.warn("Malformed JSON body: #{e.message}")
          {}
        end

        # Generate a simulated authentication token
        def generate_token
          SecureRandom.hex(32)
        end

        # Standard JSON response wrapper
        def json_response(status_code, data = {})
          status status_code
          { status: status_code < 400 ? 'ok' : 'error', timestamp: Time.now.iso8601 }.merge(data).to_json
        end
      end

      # -----------------------------------------------------------------------
      # Core C2 Routes (MITRE ATT&CK T1071.001 - Web Protocol C2)
      # -----------------------------------------------------------------------

      # POST /register - Agent registration endpoint
      # Simulates: A compromised CI runner registering with the C2 server
      # ATT&CK: T1071.001, T1195.002
      post '/register' do
        data = json_body
        agent_id = SecureRandom.uuid
        token = generate_token

        session = Models::AgentSession.new(
          agent_id: agent_id,
          hostname: data[:hostname] || 'unknown',
          ip: request.ip,
          first_seen: Time.now,
          last_seen: Time.now,
          status: 'active'
        )

        settings.agents[agent_id] = session
        settings.command_queue[agent_id] = []

        settings.sim_logger.info(
          "[REGISTER] New agent registered: id=#{agent_id} " \
          "hostname=#{session.hostname} ip=#{session.ip}"
        )

        json_response(200, {
          agent_id: agent_id,
          token: token,
          poll_interval: 30,
          message: 'SIMULATION ONLY - Agent registered (no real C2 activity)'
        })
      end

      # POST /heartbeat - Agent heartbeat/check-in endpoint
      # Simulates: Compromised runner maintaining persistent connection
      # ATT&CK: T1071.001, T1573.001
      post '/heartbeat' do
        data = json_body
        agent_id = data[:agent_id]

        unless agent_id && settings.agents.key?(agent_id)
          settings.sim_logger.warn("[HEARTBEAT] Unknown agent: #{agent_id}")
          halt 404, json_response(404, { error: 'Agent not found' })
        end

        # Update last seen timestamp
        settings.agents[agent_id].last_seen = Time.now
        settings.agents[agent_id].status = 'active'

        # Return any queued commands (simulation only)
        queued = settings.command_queue.fetch(agent_id, [])
        settings.command_queue[agent_id] = []

        settings.sim_logger.info(
          "[HEARTBEAT] Agent check-in: id=#{agent_id} " \
          "queued_commands=#{queued.size}"
        )

        json_response(200, {
          agent_id: agent_id,
          commands: queued,
          message: 'SIMULATION ONLY - Heartbeat acknowledged'
        })
      end

      # POST /exfil - Data exfiltration endpoint
      # Simulates: Receiving stolen secrets, tokens, or build artifacts
      # ATT&CK: T1041, T1195.002
      post '/exfil' do
        data = json_body
        agent_id = data[:agent_id]

        record = Models::ExfilRecord.new(
          data_type: data[:data_type] || 'unknown',
          source: data[:source] || 'ci_pipeline',
          size: data[:payload]&.length || 0,
          timestamp: Time.now
        )

        settings.exfil_records << record

        settings.sim_logger.warn(
          "[EXFIL] Simulated exfiltration received: agent=#{agent_id} " \
          "type=#{record.data_type} source=#{record.source} " \
          "size=#{record.size} bytes -- DATA NOT STORED (simulation)"
        )

        # NOTE: In a real C2, the payload would be decrypted and stored.
        # This simulation intentionally discards all payload data.
        json_response(200, {
          received: true,
          record_id: SecureRandom.uuid,
          message: 'SIMULATION ONLY - Data logged but NOT stored'
        })
      end

      # POST /command - Queue a command for an agent
      # Simulates: Operator issuing commands to compromised CI runners
      # ATT&CK: T1059.004
      post '/command' do
        data = json_body
        agent_id = data[:agent_id]
        command = data[:command]

        unless agent_id && settings.agents.key?(agent_id)
          halt 404, json_response(404, { error: 'Agent not found' })
        end

        # Queue the command for the next heartbeat (simulation only)
        cmd_record = {
          id: SecureRandom.uuid,
          command: command,
          queued_at: Time.now.iso8601,
          note: 'SIMULATION - Command will be logged, never executed'
        }

        settings.command_queue[agent_id] << cmd_record

        settings.sim_logger.info(
          "[COMMAND] Queued for agent=#{agent_id}: #{command} " \
          "(SIMULATION ONLY - will not execute)"
        )

        json_response(200, {
          queued: true,
          command_id: cmd_record[:id],
          message: 'SIMULATION ONLY - Command queued for next heartbeat'
        })
      end

      # -----------------------------------------------------------------------
      # Status / Dashboard
      # -----------------------------------------------------------------------

      # GET /status - Overview of simulation state
      get '/status' do
        json_response(200, {
          simulation: true,
          disclaimer: 'This is a security research simulation. No real C2 activity.',
          active_agents: settings.agents.count { |_, a| a.status == 'active' },
          total_agents: settings.agents.size,
          exfil_records_logged: settings.exfil_records.size,
          uptime_seconds: (Time.now - settings.sim_logger.instance_variable_get(:@logdev)&.dev&.ctime rescue 0).to_i
        })
      end

      # -----------------------------------------------------------------------
      # Error Handling
      # -----------------------------------------------------------------------
      not_found do
        json_response(404, { error: 'Endpoint not found' })
      end

      error do
        settings.sim_logger.error("Unhandled error: #{env['sinatra.error']&.message}")
        json_response(500, { error: 'Internal simulation error' })
      end

      # -----------------------------------------------------------------------
      # Entry Point
      # -----------------------------------------------------------------------
      if __FILE__ == $PROGRAM_NAME
        puts '=' * 70
        puts 'RubyGuardian - Simulated C2 Server (EDUCATIONAL USE ONLY)'
        puts 'All operations are logged. No malicious activity is performed.'
        puts '=' * 70
        run!
      end
    end
  end
end
