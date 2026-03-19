# frozen_string_literal: true

module RubyGuardian
  module Shared
    # Trace removal and cleanup utilities
    # Educational: demonstrates techniques used by attackers to cover tracks
    #
    # MITRE ATT&CK: T1070 - Indicator Removal
    module CleanupUtils
      module_function

      # Kill a process by PID with confirmation
      def kill_process(pid, signal: 'TERM')
        Process.kill(signal, pid)
        true
      rescue Errno::ESRCH
        false # Process not found
      rescue Errno::EPERM
        false # Permission denied
      end

      # Clean up spawned child processes
      def cleanup_children(pids)
        results = {}
        pids.each do |pid|
          results[pid] = kill_process(pid)
        end
        results
      end

      # Remove temporary files created during attack simulation
      def cleanup_temp_files(paths)
        paths.each do |path|
          next unless File.exist?(path)
          next unless path.start_with?('/tmp/', Dir.tmpdir)

          File.delete(path)
        end
      end

      # Clear Ruby ObjectSpace references (for ObjectSpace persistence cleanup)
      def cleanup_objectspace_artifacts(marker: 'ruby_guardian')
        count = 0
        ObjectSpace.each_object(Module) do |mod|
          if mod.name&.include?(marker) || mod.instance_variable_get(:@_rg_marker) rescue false
            # Remove instance variables that anchor the payload
            mod.instance_variables.each do |ivar|
              mod.remove_instance_variable(ivar) if ivar.to_s.start_with?('@_rg_')
            end
            count += 1
          end
        end
        count
      end

      # Reset modified environment variables
      def cleanup_environment(keys)
        keys.each { |key| ENV.delete(key) }
      end

      # Log cleanup actions for audit trail
      def log_cleanup(logger, action:, target:, success:)
        logger.info(
          "[CLEANUP] Action: #{action} | Target: #{target} | Success: #{success}"
        )
      end

      # Full cleanup routine for demo/test environments
      def full_cleanup(pids: [], temp_files: [], env_keys: [], logger: nil)
        results = {
          processes: cleanup_children(pids),
          files: cleanup_temp_files(temp_files),
          env: cleanup_environment(env_keys),
          objectspace: cleanup_objectspace_artifacts
        }

        if logger
          log_cleanup(logger, action: 'full_cleanup', target: 'all', success: true)
        end

        results
      end
    end
  end
end
