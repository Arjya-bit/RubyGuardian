# frozen_string_literal: true

require 'set'

module RubyGuardian
  module DetectionEngine
    module RuleEngine
      # Compiles rule conditions from YAML definitions into executable matcher
      # objects. Applies optimization passes including constant folding, field
      # index building, and short-circuit evaluation ordering.
      class RuleCompiler
        COMPARISON_OPS = %w[eq neq gt gte lt lte contains starts_with ends_with
                            matches in not_in exists not_exists].freeze

        LOGICAL_OPS = %w[and or not].freeze

        attr_reader :compiled_rules, :compilation_errors

        def initialize(options = {})
          @optimize        = options.fetch(:optimize, true)
          @max_depth       = options.fetch(:max_condition_depth, 10)
          @compiled_rules  = {}
          @compilation_errors = []
          @field_index     = Hash.new { |h, k| h[k] = Set.new }
        end

        # Compile a single rule's conditions into an executable matcher.
        #
        # @param rule [Hash] the rule definition (must have 'id' and 'conditions')
        # @return [CompiledRule] compiled and optimized rule
        def compile(rule)
          validate_compilable!(rule)

          conditions = rule['conditions']
          ast = parse_conditions(conditions, depth: 0)
          ast = optimize_ast(ast) if @optimize

          required_fields = extract_fields(ast)
          update_field_index(rule['id'], required_fields)

          compiled = CompiledRule.new(
            id:              rule['id'],
            name:            rule['name'],
            severity:        rule['severity'],
            ast:             ast,
            required_fields: required_fields,
            metadata:        extract_metadata(rule),
            compiled_at:     Time.now
          )

          @compiled_rules[rule['id']] = compiled
          compiled
        rescue CompilationError => e
          @compilation_errors << { rule_id: rule['id'], error: e.message }
          raise
        end

        # Compile a batch of rules.
        #
        # @param rules [Hash, Array] rules to compile
        # @return [Hash] rule_id => CompiledRule
        def compile_all(rules)
          enumerable = rules.is_a?(Hash) ? rules.values : rules

          enumerable.each do |rule|
            begin
              compile(rule)
            rescue CompilationError => e
              next # errors already tracked
            end
          end

          @compiled_rules
        end

        # Find all compiled rules that reference a given field.
        #
        # @param field_name [String]
        # @return [Set<String>] rule IDs
        def rules_for_field(field_name)
          @field_index[field_name]
        end

        private

        def validate_compilable!(rule)
          raise CompilationError, 'Rule must have an id' unless rule['id']
          raise CompilationError, "Rule '#{rule['id']}' has no conditions" unless rule['conditions']
        end

        def parse_conditions(node, depth:)
          raise CompilationError, "Condition nesting exceeds max depth #{@max_depth}" if depth > @max_depth

          case node
          when Hash
            parse_hash_condition(node, depth)
          when Array
            # Implicit AND for arrays
            children = node.map { |child| parse_conditions(child, depth: depth + 1) }
            LogicalNode.new(:and, children)
          else
            raise CompilationError, "Unexpected condition type: #{node.class}"
          end
        end

        def parse_hash_condition(node, depth)
          if (logical_op = (node.keys & LOGICAL_OPS).first)
            children = Array(node[logical_op]).map { |child| parse_conditions(child, depth: depth + 1) }
            if logical_op == 'not'
              raise CompilationError, "'not' expects exactly one child condition" unless children.size == 1
              LogicalNode.new(:not, children)
            else
              LogicalNode.new(logical_op.to_sym, children)
            end
          elsif node.key?('field')
            parse_comparison(node)
          else
            # Treat as implicit AND of field conditions
            children = node.map do |field, spec|
              next if field.start_with?('_')
              if spec.is_a?(Hash)
                op = spec.keys.first
                ComparisonNode.new(field, op.to_sym, spec[op])
              else
                ComparisonNode.new(field, :eq, spec)
              end
            end.compact
            LogicalNode.new(:and, children)
          end
        end

        def parse_comparison(node)
          field = node['field']
          op = node.fetch('op', 'eq')

          unless COMPARISON_OPS.include?(op)
            raise CompilationError, "Unknown comparison operator '#{op}'"
          end

          value = node['value']
          ComparisonNode.new(field, op.to_sym, value)
        end

        def optimize_ast(node)
          case node
          when LogicalNode
            optimized_children = node.children.map { |c| optimize_ast(c) }

            # Flatten nested AND/OR
            optimized_children = flatten_logical(node.op, optimized_children)

            # Remove redundant single-child logical nodes
            if optimized_children.size == 1 && node.op != :not
              return optimized_children.first
            end

            # Order children: cheaper comparisons first for short-circuit
            if %i[and or].include?(node.op)
              optimized_children = order_by_cost(optimized_children)
            end

            LogicalNode.new(node.op, optimized_children)
          when ComparisonNode
            # Pre-compile regex patterns
            if node.op == :matches && node.value.is_a?(String)
              ComparisonNode.new(node.field, :matches, Regexp.new(node.value))
            else
              node
            end
          else
            node
          end
        end

        def flatten_logical(op, children)
          return children unless %i[and or].include?(op)

          children.flat_map do |child|
            if child.is_a?(LogicalNode) && child.op == op
              child.children
            else
              [child]
            end
          end
        end

        def order_by_cost(children)
          children.sort_by do |child|
            case child
            when ComparisonNode
              case child.op
              when :eq, :neq, :exists, :not_exists then 1
              when :in, :not_in then 2
              when :contains, :starts_with, :ends_with then 3
              when :matches then 5
              else 4
              end
            when LogicalNode then 10
            else 10
            end
          end
        end

        def extract_fields(node)
          fields = Set.new
          case node
          when ComparisonNode
            fields << node.field
          when LogicalNode
            node.children.each { |c| fields.merge(extract_fields(c)) }
          end
          fields
        end

        def update_field_index(rule_id, fields)
          fields.each { |f| @field_index[f] << rule_id }
        end

        def extract_metadata(rule)
          {
            tags:         rule.fetch('tags', []),
            mitre_attack: rule.fetch('mitre_attack', {}),
            status:       rule.fetch('status', 'enabled'),
            description:  rule['description']
          }
        end
      end

      # AST node for logical operations (AND, OR, NOT).
      LogicalNode = Struct.new(:op, :children)

      # AST node for field comparison operations.
      ComparisonNode = Struct.new(:field, :op, :value)

      # A compiled rule ready for evaluation.
      CompiledRule = Struct.new(:id, :name, :severity, :ast, :required_fields,
                                :metadata, :compiled_at, keyword_init: true)

      class CompilationError < StandardError; end
    end
  end
end
