# frozen_string_literal: true

module RubyGuardian
  module DetectionEngine
    module RuleEngine
      # Evaluates compiled rule ASTs against event data using boolean logic.
      # Supports nested field access via dot notation, type coercion, and
      # provides detailed match context for forensic analysis.
      class ConditionEvaluator
        attr_reader :stats

        def initialize(options = {})
          @case_sensitive   = options.fetch(:case_sensitive, false)
          @collect_context  = options.fetch(:collect_context, true)
          @null_handling    = options.fetch(:null_handling, :false_on_missing)
          @stats = { evaluations: 0, matches: 0, errors: 0 }
        end

        # Evaluate a compiled rule against an event.
        #
        # @param compiled_rule [CompiledRule] the compiled rule
        # @param event [Hash] the event data
        # @return [EvaluationResult] match result with context
        def evaluate(compiled_rule, event)
          @stats[:evaluations] += 1
          context = EvaluationContext.new

          matched = evaluate_node(compiled_rule.ast, event, context)
          @stats[:matches] += 1 if matched

          EvaluationResult.new(
            matched:   matched,
            rule_id:   compiled_rule.id,
            rule_name: compiled_rule.name,
            severity:  compiled_rule.severity,
            context:   context,
            evaluated_at: Time.now
          )
        rescue => e
          @stats[:errors] += 1
          EvaluationResult.new(
            matched: false,
            rule_id: compiled_rule.id,
            rule_name: compiled_rule.name,
            severity: compiled_rule.severity,
            context: context,
            error: e.message,
            evaluated_at: Time.now
          )
        end

        # Evaluate multiple rules against a single event.
        #
        # @param compiled_rules [Array<CompiledRule>] rules to evaluate
        # @param event [Hash] event data
        # @return [Array<EvaluationResult>] results for matching rules
        def evaluate_all(compiled_rules, event)
          compiled_rules.filter_map do |rule|
            result = evaluate(rule, event)
            result if result.matched
          end
        end

        private

        def evaluate_node(node, event, context)
          case node
          when LogicalNode  then evaluate_logical(node, event, context)
          when ComparisonNode then evaluate_comparison(node, event, context)
          else
            raise EvaluationError, "Unknown AST node type: #{node.class}"
          end
        end

        def evaluate_logical(node, event, context)
          case node.op
          when :and
            node.children.all? { |child| evaluate_node(child, event, context) }
          when :or
            node.children.any? { |child| evaluate_node(child, event, context) }
          when :not
            !evaluate_node(node.children.first, event, context)
          else
            raise EvaluationError, "Unknown logical operator: #{node.op}"
          end
        end

        def evaluate_comparison(node, event, context)
          field_value = resolve_field(node.field, event)
          expected = node.value
          result = perform_comparison(node.op, field_value, expected)

          if @collect_context && result
            context.add_match(
              field:    node.field,
              operator: node.op,
              expected: expected,
              actual:   field_value
            )
          end

          result
        end

        def perform_comparison(op, actual, expected)
          case op
          when :eq
            normalize(actual) == normalize(expected)
          when :neq
            normalize(actual) != normalize(expected)
          when :gt
            to_numeric(actual) > to_numeric(expected)
          when :gte
            to_numeric(actual) >= to_numeric(expected)
          when :lt
            to_numeric(actual) < to_numeric(expected)
          when :lte
            to_numeric(actual) <= to_numeric(expected)
          when :contains
            return false if actual.nil?
            normalize_string(actual.to_s).include?(normalize_string(expected.to_s))
          when :starts_with
            return false if actual.nil?
            normalize_string(actual.to_s).start_with?(normalize_string(expected.to_s))
          when :ends_with
            return false if actual.nil?
            normalize_string(actual.to_s).end_with?(normalize_string(expected.to_s))
          when :matches
            return false if actual.nil?
            pattern = expected.is_a?(Regexp) ? expected : Regexp.new(expected.to_s)
            pattern.match?(actual.to_s)
          when :in
            Array(expected).any? { |v| normalize(actual) == normalize(v) }
          when :not_in
            Array(expected).none? { |v| normalize(actual) == normalize(v) }
          when :exists
            !actual.nil?
          when :not_exists
            actual.nil?
          else
            raise EvaluationError, "Unsupported comparison operator: #{op}"
          end
        end

        # Resolve a dotted field path to a value in the event hash.
        # Supports both string and symbol keys.
        #
        # @param field_path [String] dot-separated field path (e.g., "process.name")
        # @param event [Hash] event data
        # @return [Object, nil] resolved value
        def resolve_field(field_path, event)
          parts = field_path.to_s.split('.')
          current = event

          parts.each do |part|
            case current
            when Hash
              current = current[part] || current[part.to_sym]
            when Array
              index = Integer(part, exception: false)
              return handle_missing_field(field_path) if index.nil?
              current = current[index]
            else
              return handle_missing_field(field_path)
            end

            return handle_missing_field(field_path) if current.nil?
          end

          current
        end

        def handle_missing_field(field_path)
          case @null_handling
          when :false_on_missing then nil
          when :raise_on_missing
            raise EvaluationError, "Field not found: #{field_path}"
          else nil
          end
        end

        def normalize(value)
          case value
          when String then @case_sensitive ? value : value.downcase
          when Symbol then normalize(value.to_s)
          else value
          end
        end

        def normalize_string(str)
          @case_sensitive ? str : str.downcase
        end

        def to_numeric(value)
          case value
          when Numeric then value
          when String
            if value.include?('.')
              Float(value)
            else
              Integer(value)
            end
          else
            raise EvaluationError, "Cannot convert #{value.class} to numeric for comparison"
          end
        end
      end

      # Captures matching context details during evaluation.
      class EvaluationContext
        attr_reader :matched_conditions

        def initialize
          @matched_conditions = []
        end

        def add_match(details)
          @matched_conditions << details
        end
      end

      # Result of evaluating a rule against an event.
      EvaluationResult = Struct.new(:matched, :rule_id, :rule_name, :severity,
                                     :context, :error, :evaluated_at,
                                     keyword_init: true)

      class EvaluationError < StandardError; end
    end
  end
end
