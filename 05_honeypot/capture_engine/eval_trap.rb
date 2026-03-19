# frozen_string_literal: true

# RubyGuardian Phase 5 -- Honeypot Capture Engine: Eval Trap
#
# Intercepts and logs attempts to use eval, system, exec, and other
# dangerous methods within honeypot applications. Records the attack
# payload without executing it.

require 'json'

module RubyGuardian
  module Honeypot
    class EvalTrap
      TRAPPED_METHODS = %i[eval system exec `].freeze

      attr_reader :captures, :logger

      def initialize(logger: nil)
        @logger = logger
        @captures = []
        @mutex = Mutex.new
      end

      # Install traps on dangerous methods (for honeypot context only)
      def install_traps!
        @logger&.info('[EvalTrap] Installing eval/exec traps')

        trap_eval
        trap_system
        trap_exec
      end

      # Get all captured attack attempts
      def captured_attacks
        @mutex.synchronize { @captures.dup }
      end

      # Get summary statistics
      def stats
        @mutex.synchronize do
          {
            total_captures: @captures.size,
            by_method: @captures.group_by { |c| c[:method] }.transform_values(&:size),
            unique_payloads: @captures.map { |c| c[:payload_hash] }.uniq.size
          }
        end
      end

      private

      def trap_eval
        trap = self
        Kernel.define_method(:__honeypot_eval) do |code, *args|
          trap.send(:record_capture, :eval, code, caller_locations(1, 5))
          nil # Don't actually execute
        end
      end

      def trap_system
        trap = self
        Kernel.define_method(:__honeypot_system) do |*cmd|
          trap.send(:record_capture, :system, cmd.join(' '), caller_locations(1, 5))
          false # Return failure
        end
      end

      def trap_exec
        trap = self
        Kernel.define_method(:__honeypot_exec) do |*cmd|
          trap.send(:record_capture, :exec, cmd.join(' '), caller_locations(1, 5))
          raise Errno::ENOENT, 'Command not found (honeypot trap)'
        end
      end

      def record_capture(method, payload, backtrace)
        entry = {
          timestamp: Time.now.utc.iso8601(3),
          method: method,
          payload: payload.to_s[0..2000], # Limit payload size
          payload_hash: Digest::SHA256.hexdigest(payload.to_s),
          backtrace: backtrace&.map(&:to_s)&.first(5),
          pid: Process.pid
        }

        @mutex.synchronize { @captures << entry }
        @logger&.warn("[EvalTrap] Captured #{method} attempt: #{payload.to_s[0..100]}")
      end
    end
  end
end
