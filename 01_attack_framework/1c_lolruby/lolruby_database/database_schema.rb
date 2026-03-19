# frozen_string_literal: true

# RubyGuardian Phase 1c -- LoLRuby Database Schema
#
# Defines the data model and validation for LoLRuby technique entries.

module RubyGuardian
  module LoLRuby
    class DatabaseSchema
      REQUIRED_FIELDS = %i[name tactic mitre_id description ruby_apis].freeze
      VALID_RISK_LEVELS = %w[low medium high critical].freeze

      TechniqueEntry = Struct.new(
        :name, :tactic, :mitre_id, :description, :ruby_apis,
        :detection_indicators, :risk_level, :examples, :references,
        keyword_init: true
      )

      def self.validate(entry)
        errors = []

        REQUIRED_FIELDS.each do |field|
          value = entry.is_a?(Hash) ? entry[field] : entry.send(field)
          errors << "Missing required field: #{field}" if value.nil? || value.to_s.empty?
        end

        if entry.is_a?(Hash) && entry[:risk_level]
          unless VALID_RISK_LEVELS.include?(entry[:risk_level])
            errors << "Invalid risk_level: #{entry[:risk_level]}"
          end
        end

        { valid: errors.empty?, errors: errors }
      end

      def self.from_hash(hash)
        TechniqueEntry.new(**hash.slice(*TechniqueEntry.members))
      end
    end
  end
end
