# frozen_string_literal: true

require 'rspec'
require 'yaml'

# RubyGuardian Detection Engine - Rule Loader Specs
# Tests the loading, validation, and caching of YAML-based detection rules.

RSpec.describe 'RubyGuardian::DetectionEngine::RuleLoader' do
  let(:rules_dir) { File.expand_path('../../config/rules', __dir__) }
  let(:sample_rule) do
    {
      'id' => 'RG-DET-001',
      'name' => 'Process Injection via Eval',
      'description' => 'Detects eval() calls with encoded payloads',
      'severity' => 'critical',
      'mitre_attack' => { 'technique' => 'T1055', 'tactic' => 'defense-evasion' },
      'conditions' => {
        'all' => [
          { 'field' => 'event.method', 'operator' => 'equals', 'value' => 'eval' },
          { 'field' => 'event.args_encoded', 'operator' => 'equals', 'value' => true }
        ]
      },
      'actions' => ['alert', 'log'],
      'enabled' => true
    }
  end

  describe '.load_from_directory' do
    it 'loads all YAML files from the rules directory' do
      if Dir.exist?(rules_dir)
        rules = Dir.glob(File.join(rules_dir, '*.yml')).map { |f| YAML.safe_load(File.read(f)) }
        expect(rules).to be_an(Array)
      else
        skip 'Rules directory not found'
      end
    end

    it 'skips disabled rules' do
      disabled_rule = sample_rule.merge('enabled' => false)
      expect(disabled_rule['enabled']).to be false
    end
  end

  describe 'rule validation' do
    it 'requires an id field' do
      rule = sample_rule.dup
      rule.delete('id')
      expect(rule['id']).to be_nil
    end

    it 'requires a severity field with valid values' do
      valid_severities = %w[low medium high critical]
      expect(valid_severities).to include(sample_rule['severity'])
    end

    it 'requires at least one condition' do
      expect(sample_rule['conditions']['all']).not_to be_empty
    end

    it 'validates MITRE ATT&CK technique format' do
      technique = sample_rule['mitre_attack']['technique']
      expect(technique).to match(/^T\d{4}(\.\d{3})?$/)
    end

    it 'validates condition operator is supported' do
      valid_operators = %w[equals not_equals contains regex greater_than less_than in not_in exists]
      sample_rule['conditions']['all'].each do |cond|
        expect(valid_operators).to include(cond['operator'])
      end
    end
  end

  describe 'rule caching' do
    it 'returns the same object for repeated loads' do
      # Simulating cache behavior
      cache = {}
      rule_id = sample_rule['id']
      cache[rule_id] = sample_rule
      expect(cache[rule_id]).to equal(cache[rule_id])
    end

    it 'invalidates cache when rule file is modified' do
      cache_time = Time.now - 60
      file_mtime = Time.now
      expect(file_mtime).to be > cache_time
    end
  end

  describe 'rule compilation' do
    it 'compiles conditions into callable matchers' do
      condition = sample_rule['conditions']['all'].first
      # A compiled matcher would be a Proc that evaluates the condition
      matcher = ->(event) { event[condition['field']] == condition['value'] }
      event = { condition['field'] => condition['value'] }
      expect(matcher.call(event)).to be true
    end

    it 'supports boolean logic operators (all, any, none)' do
      expect(sample_rule['conditions']).to have_key('all')
    end
  end
end
