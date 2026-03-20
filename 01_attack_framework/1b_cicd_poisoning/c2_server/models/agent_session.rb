# frozen_string_literal: true

# =============================================================================
# RubyGuardian - Agent Session Model
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This model represents a connected "agent" in the simulated C2 framework.
#   In real-world CI/CD poisoning attacks, an agent would be a compromised
#   CI runner or build worker that has been infected through a supply chain
#   attack vector (MITRE ATT&CK T1195.002).
#
#   This model is used strictly for logging and simulation purposes.
#   No actual agent connections or remote control is performed.
#
# MITRE ATT&CK References:
#   - T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain
#   - T1071.001 : Application Layer Protocol: Web Protocols
#   - T1082     : System Information Discovery
# =============================================================================

module RubyGuardian
  module C2
    module Models
      # AgentSession tracks the state of a simulated compromised CI runner
      # that has registered with the C2 server.
      #
      # In a real attack scenario, each agent session would represent a
      # build environment that has been compromised through:
      #   - A trojanized dependency (poisoned gem, npm package, etc.)
      #   - A manipulated CI configuration file
      #   - A compromised build tool or plugin
      #
      # Attributes:
      #   agent_id   [String]   - Unique identifier assigned at registration
      #   hostname   [String]   - Reported hostname of the CI runner
      #   ip         [String]   - Source IP address of the agent
      #   first_seen [Time]     - Timestamp of initial registration
      #   last_seen  [Time]     - Timestamp of most recent heartbeat
      #   status     [String]   - Current status: active, stale, disconnected
      class AgentSession
        VALID_STATUSES = %w[active stale disconnected].freeze

        # Threshold in seconds before an agent is considered stale
        STALE_THRESHOLD = 120

        # Threshold in seconds before an agent is considered disconnected
        DISCONNECT_THRESHOLD = 600

        attr_accessor :agent_id, :hostname, :ip, :first_seen, :last_seen, :status

        # Initialize a new AgentSession
        #
        # @param agent_id   [String] Unique agent identifier (UUID)
        # @param hostname   [String] Hostname reported by the agent
        # @param ip         [String] IP address from the registration request
        # @param first_seen [Time]   When the agent first registered
        # @param last_seen  [Time]   When the agent last checked in
        # @param status     [String] Current connection status
        def initialize(agent_id:, hostname:, ip:, first_seen: nil, last_seen: nil, status: 'active')
          @agent_id   = agent_id
          @hostname   = hostname
          @ip         = ip
          @first_seen = first_seen || Time.now
          @last_seen  = last_seen  || Time.now
          @status     = validate_status(status)
        end

        # Check if the agent session is currently active
        #
        # @return [Boolean] true if agent checked in recently
        def active?
          @status == 'active' && seconds_since_last_seen < STALE_THRESHOLD
        end

        # Check if the agent session has gone stale (no recent heartbeat)
        #
        # @return [Boolean] true if agent has not checked in within threshold
        def stale?
          seconds_since_last_seen >= STALE_THRESHOLD &&
            seconds_since_last_seen < DISCONNECT_THRESHOLD
        end

        # Check if the agent should be considered disconnected
        #
        # @return [Boolean] true if agent has exceeded disconnect threshold
        def disconnected?
          seconds_since_last_seen >= DISCONNECT_THRESHOLD
        end

        # Calculate the duration this agent has been connected
        #
        # @return [Float] session duration in seconds
        def session_duration
          (@last_seen - @first_seen).to_f
        end

        # Update the agent status based on the time since last heartbeat.
        # This method is called periodically by the server's reaper thread.
        #
        # @return [String] the updated status
        def refresh_status!
          @status = if disconnected?
                      'disconnected'
                    elsif stale?
                      'stale'
                    else
                      'active'
                    end
        end

        # Record a heartbeat from the agent
        #
        # @return [void]
        def heartbeat!
          @last_seen = Time.now
          @status = 'active'
        end

        # Serialize the session to a hash for JSON responses
        #
        # @return [Hash] session data suitable for JSON serialization
        def to_h
          {
            agent_id: @agent_id,
            hostname: @hostname,
            ip: @ip,
            first_seen: @first_seen&.iso8601,
            last_seen: @last_seen&.iso8601,
            status: @status,
            session_duration_seconds: session_duration.round(2),
            note: 'SIMULATION ONLY - This is not a real compromised agent'
          }
        end

        # Serialize to JSON string
        #
        # @return [String] JSON representation
        def to_json(*_args)
          to_h.to_json
        end

        # Create an AgentSession from a database row hash
        #
        # @param row [Hash] database row with string keys
        # @return [AgentSession] populated session object
        def self.from_db_row(row)
          new(
            agent_id:   row['agent_id'],
            hostname:   row['hostname'],
            ip:         row['ip'],
            first_seen: row['first_seen'] ? Time.parse(row['first_seen']) : nil,
            last_seen:  row['last_seen']  ? Time.parse(row['last_seen'])  : nil,
            status:     row['status'] || 'active'
          )
        end

        private

        # Validate that the given status is one of the allowed values
        #
        # @param status [String] status to validate
        # @return [String] the validated status
        # @raise [ArgumentError] if status is invalid
        def validate_status(status)
          unless VALID_STATUSES.include?(status)
            raise ArgumentError, "Invalid status '#{status}'. Must be one of: #{VALID_STATUSES.join(', ')}"
          end

          status
        end

        # Calculate seconds elapsed since the last heartbeat
        #
        # @return [Float] elapsed seconds
        def seconds_since_last_seen
          (Time.now - @last_seen).to_f
        end
      end
    end
  end
end
