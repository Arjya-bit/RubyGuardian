# frozen_string_literal: true

# =============================================================================
# RubyGuardian - API Routes Module for Simulated C2 Server
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This Sinatra route module provides REST API endpoints for the simulated
#   C2 server. These endpoints allow the research dashboard to query the
#   state of the simulation, list agents, view exfiltration logs, and
#   manage the simulation lifecycle.
#
#   These routes are for RESEARCH AND EDUCATION ONLY. They expose
#   simulation data, not real compromised systems or stolen data.
#
# MITRE ATT&CK References:
#   - T1071.001 : Application Layer Protocol: Web Protocols
#   - T1106     : Native API (API-based C2 management)
# =============================================================================

require 'sinatra/base'
require 'json'

module RubyGuardian
  module C2
    module Routes
      # ApiRoutes provides REST API endpoints for managing and observing
      # the C2 simulation. These are separate from the core C2 routes
      # (register, heartbeat, exfil, command) and serve the research
      # dashboard and analysis tools.
      module ApiRoutes
        # Register all API routes on the given Sinatra application
        #
        # @param app [Sinatra::Base] the Sinatra application to extend
        def self.registered(app)
          # -------------------------------------------------------------------
          # Agent Management Endpoints
          # -------------------------------------------------------------------

          # GET /api/v1/agents - List all registered agents
          # Returns summary of all agents that have connected during the
          # simulation session, including their current status.
          app.get '/api/v1/agents' do
            agents = settings.agents.values.map(&:to_h)

            settings.sim_logger.info("[API] Listed #{agents.size} agents")

            json_response(200, {
              count: agents.size,
              agents: agents,
              note: 'SIMULATION DATA - These are not real compromised systems'
            })
          end

          # GET /api/v1/agents/:id - Get details for a specific agent
          app.get '/api/v1/agents/:id' do
            agent = settings.agents[params[:id]]

            unless agent
              halt 404, json_response(404, { error: 'Agent not found' })
            end

            agent.refresh_status!

            settings.sim_logger.info("[API] Agent detail requested: #{params[:id]}")

            json_response(200, {
              agent: agent.to_h,
              queued_commands: settings.command_queue.fetch(params[:id], []).size,
              note: 'SIMULATION DATA ONLY'
            })
          end

          # DELETE /api/v1/agents/:id - Remove an agent from the simulation
          app.delete '/api/v1/agents/:id' do
            agent_id = params[:id]

            unless settings.agents.key?(agent_id)
              halt 404, json_response(404, { error: 'Agent not found' })
            end

            settings.agents.delete(agent_id)
            settings.command_queue.delete(agent_id)

            settings.sim_logger.info("[API] Agent removed from simulation: #{agent_id}")

            json_response(200, {
              deleted: agent_id,
              message: 'Agent removed from simulation'
            })
          end

          # -------------------------------------------------------------------
          # Exfiltration Log Endpoints
          # -------------------------------------------------------------------

          # GET /api/v1/exfil - List all exfiltration records
          # Supports optional query parameters for filtering:
          #   ?data_type=env_vars    - Filter by data type
          #   ?severity=critical     - Filter by severity level
          #   ?limit=50              - Limit number of results
          #   ?offset=0              - Pagination offset
          app.get '/api/v1/exfil' do
            records = settings.exfil_records.dup

            # Apply filters if provided
            if params[:data_type]
              records.select! { |r| r.data_type == params[:data_type] }
            end

            if params[:severity]
              records.select! { |r| r.severity.to_s == params[:severity] }
            end

            # Pagination
            limit  = (params[:limit]  || 100).to_i.clamp(1, 1000)
            offset = (params[:offset] || 0).to_i.clamp(0, records.size)
            page   = records[offset, limit] || []

            settings.sim_logger.info(
              "[API] Exfil records listed: total=#{records.size} " \
              "returned=#{page.size} offset=#{offset}"
            )

            json_response(200, {
              total: records.size,
              limit: limit,
              offset: offset,
              records: page.map(&:to_h),
              note: 'SIMULATION DATA - No real data was exfiltrated'
            })
          end

          # GET /api/v1/exfil/stats - Aggregate statistics on exfiltration
          app.get '/api/v1/exfil/stats' do
            records = settings.exfil_records

            stats = {
              total_records: records.size,
              total_bytes: records.sum(&:size),
              by_data_type: records.group_by(&:data_type).transform_values(&:size),
              by_severity: records.group_by(&:severity).transform_values(&:size),
              by_source: records.group_by(&:source).transform_values(&:size),
              unique_mitre_techniques: records.flat_map(&:mitre_techniques).uniq
            }

            settings.sim_logger.info('[API] Exfil statistics requested')

            json_response(200, {
              statistics: stats,
              note: 'SIMULATION STATISTICS ONLY'
            })
          end

          # -------------------------------------------------------------------
          # Simulation Control Endpoints
          # -------------------------------------------------------------------

          # POST /api/v1/simulation/reset - Reset the simulation state
          # Clears all agents, exfil records, and command queues
          app.post '/api/v1/simulation/reset' do
            agent_count = settings.agents.size
            record_count = settings.exfil_records.size

            settings.agents.clear
            settings.exfil_records.clear
            settings.command_queue.clear

            settings.sim_logger.info(
              "[API] Simulation reset: cleared #{agent_count} agents, " \
              "#{record_count} exfil records"
            )

            json_response(200, {
              reset: true,
              cleared_agents: agent_count,
              cleared_records: record_count,
              message: 'Simulation state has been reset'
            })
          end

          # GET /api/v1/simulation/export - Export full simulation data
          # Returns all agents and exfil records for offline analysis
          app.get '/api/v1/simulation/export' do
            export_data = {
              exported_at: Time.now.iso8601,
              framework: 'RubyGuardian C2 Simulation',
              disclaimer: 'EDUCATIONAL AND RESEARCH USE ONLY',
              agents: settings.agents.values.map(&:to_h),
              exfil_records: settings.exfil_records.map(&:to_h),
              mitre_coverage: settings.exfil_records
                .flat_map(&:mitre_techniques)
                .tally
                .sort_by { |_k, v| -v }
                .to_h
            }

            settings.sim_logger.info('[API] Full simulation data exported')

            json_response(200, export_data)
          end

          # GET /api/v1/health - Health check endpoint
          app.get '/api/v1/health' do
            json_response(200, {
              status: 'healthy',
              simulation: true,
              version: '1.0.0',
              framework: 'RubyGuardian'
            })
          end
        end
      end
    end
  end
end
