# frozen_string_literal: true

# RubyGuardian Phase 1c -- LoLRuby Execution: Eval-based Execution
#
# Demonstrates dynamic code execution techniques using Ruby's built-in
# eval family of methods. These are the most common code execution
# primitives in Ruby-based attacks.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter

require 'base64'

module RubyGuardian
  module LoLRuby
    module Execution
      class EvalExecutor
        EVAL_METHODS = %i[
          kernel_eval instance_eval class_eval module_eval
          method_define binding_eval
        ].freeze

        attr_reader :execution_log, :logger

        def initialize(logger: nil, sandbox: true)
          @logger = logger
          @sandbox = sandbox
          @execution_log = []
        end

        # Demonstrate Kernel.eval with various encoding layers
        def demonstrate_eval_chain(code_string)
          log_execution(:kernel_eval, code_string)

          if @sandbox
            @logger&.info('[LoLRuby] SANDBOX: Would execute eval chain')
            return { executed: false, sandbox: true, code_preview: code_string[0..50] }
          end

          # Layer 1: Direct eval
          # Layer 2: Base64-encoded eval
          # Layer 3: Marshal-encoded eval
          # Each layer demonstrates an obfuscation technique
          {
            executed: false,
            technique: 'eval_chain',
            layers: %w[direct base64 marshal zlib],
            detection_notes: 'Monitor for eval() with decoded/deserialized arguments'
          }
        end

        # Demonstrate instance_eval for object context injection
        def demonstrate_instance_eval(target_class_name)
          log_execution(:instance_eval, "target=#{target_class_name}")

          {
            technique: 'instance_eval_injection',
            description: 'Inject methods into existing object instances at runtime',
            ruby_api: 'BasicObject#instance_eval',
            detection: 'Track instance_eval calls on framework-owned objects'
          }
        end

        # Demonstrate send/public_send for dynamic dispatch
        def demonstrate_dynamic_dispatch(receiver, method_name)
          log_execution(:dynamic_dispatch, "#{receiver}.#{method_name}")

          {
            technique: 'dynamic_dispatch',
            description: 'Call arbitrary methods via send/public_send',
            ruby_api: 'Object#send, Object#public_send',
            detection: 'Monitor send() calls where method name comes from external input'
          }
        end

        # Get a summary of all demonstrated techniques
        def summary
          {
            techniques_demonstrated: @execution_log.size,
            sandbox_mode: @sandbox,
            log: @execution_log
          }
        end

        def describe
          <<~DESC
            Eval-based Execution (T1059.007)
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            Ruby provides multiple eval methods for dynamic code execution:
            - Kernel.eval: Execute arbitrary strings as Ruby code
            - instance_eval: Execute code in the context of any object
            - class_eval/module_eval: Modify classes at runtime
            - send/public_send: Call methods dynamically by name

            These are core Ruby features used legitimately for metaprogramming,
            making detection challenging. Malicious use typically involves
            encoded/obfuscated eval arguments from external sources.
          DESC
        end

        private

        def log_execution(method, details)
          @execution_log << {
            method: method,
            details: details,
            timestamp: Time.now.utc.iso8601,
            sandbox: @sandbox
          }
          @logger&.info("[LoLRuby] Demonstrated: #{method} - #{details}")
        end
      end
    end
  end
end
