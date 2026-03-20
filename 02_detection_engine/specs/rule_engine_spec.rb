# frozen_string_literal: true

require 'rspec'
require 'tmpdir'
require 'yaml'

require_relative '../rule_engine/lib/rule_loader'
require_relative '../rule_engine/lib/rule_compiler'
require_relative '../rule_engine/lib/condition_evaluator'

RSpec.describe RubyGuardian::DetectionEngine::RuleEngine do
  let(:rule_loader)    { RubyGuardian::DetectionEngine::RuleEngine::RuleLoader }
  let(:rule_compiler)  { RubyGuardian::DetectionEngine::RuleEngine::RuleCompiler }
  let(:evaluator_class) { RubyGuardian::DetectionEngine::RuleEngine::ConditionEvaluator }

  describe RubyGuardian::DetectionEngine::RuleEngine::RuleLoader do
    let(:tmpdir) { Dir.mktmpdir('rg_rules') }

    after { FileUtils.rm_rf(tmpdir) }

    let(:valid_rule) do
      {
        'id' => 'TEST-001',
        'name' => 'Test Process Injection',
        'severity' => 'high',
        'conditions' => [
          { 'field' => 'event_type', 'op' => 'eq', 'value' => 'process_access' }
        ]
      }
    end

    def write_rule(filename, content)
      path = File.join(tmpdir, filename)
      File.write(path, YAML.dump(content))
      path
    end

    it 'loads a valid rule from a YAML file' do
      path = write_rule('test.yml', valid_rule)
      loader = rule_loader.new(rules_dir: tmpdir)
      rules = loader.load_file(path)

      expect(rules).to be_an(Array)
      expect(rules.first['id']).to eq('TEST-001')
      expect(rules.first['severity']).to eq('high')
    end

    it 'loads all rules from a directory' do
      write_rule('rule1.yml', valid_rule)
      write_rule('rule2.yml', valid_rule.merge('id' => 'TEST-002'))

      loader = rule_loader.new(rules_dir: tmpdir)
      rules = loader.load_all

      expect(rules.size).to eq(2)
      expect(rules.keys).to contain_exactly('TEST-001', 'TEST-002')
    end

    it 'rejects rules missing required fields' do
      invalid = { 'id' => 'BAD', 'name' => 'Missing severity and conditions' }
      path = write_rule('invalid.yml', invalid)
      loader = rule_loader.new(rules_dir: tmpdir)

      expect { loader.load_file(path) }.to raise_error(
        RubyGuardian::DetectionEngine::RuleEngine::ValidationError, /missing fields/i
      )
    end

    it 'rejects rules with invalid severity' do
      bad_sev = valid_rule.merge('severity' => 'extreme')
      path = write_rule('bad_severity.yml', bad_sev)
      loader = rule_loader.new(rules_dir: tmpdir)

      expect { loader.load_file(path) }.to raise_error(
        RubyGuardian::DetectionEngine::RuleEngine::ValidationError, /Invalid severity/
      )
    end

    it 'detects duplicate rule IDs across files' do
      write_rule('dup1.yml', valid_rule)
      write_rule('dup2.yml', valid_rule)  # Same ID

      loader = rule_loader.new(rules_dir: tmpdir)
      loader.load_all

      expect(loader.load_errors).not_to be_empty
      expect(loader.load_errors.first[:error]).to match(/Duplicate rule ID/)
    end

    it 'caches loaded rules and returns from cache on unchanged files' do
      path = write_rule('cached.yml', valid_rule)
      loader = rule_loader.new(rules_dir: tmpdir)

      loader.load_file(path)
      loader.load_file(path)

      expect(loader.cache_stats[:hits]).to eq(1)
      expect(loader.cache_stats[:misses]).to eq(1)
    end

    it 'enriches rules with metadata' do
      path = write_rule('enriched.yml', valid_rule)
      loader = rule_loader.new(rules_dir: tmpdir)
      rules = loader.load_file(path)

      expect(rules.first['status']).to eq('enabled')
      expect(rules.first['_source_file']).to eq(path)
      expect(rules.first['_loaded_at']).to be_a(String)
    end
  end

  describe RubyGuardian::DetectionEngine::RuleEngine::RuleCompiler do
    let(:compiler) { rule_compiler.new }

    let(:simple_rule) do
      {
        'id' => 'COMP-001',
        'name' => 'Simple Eq Rule',
        'severity' => 'medium',
        'conditions' => [
          { 'field' => 'event_type', 'op' => 'eq', 'value' => 'process_create' }
        ]
      }
    end

    let(:complex_rule) do
      {
        'id' => 'COMP-002',
        'name' => 'Complex AND/OR Rule',
        'severity' => 'high',
        'conditions' => {
          'and' => [
            { 'field' => 'event_type', 'op' => 'eq', 'value' => 'process_create' },
            { 'or' => [
              { 'field' => 'process_name', 'op' => 'contains', 'value' => 'mimikatz' },
              { 'field' => 'command_line', 'op' => 'matches', 'value' => 'sekurlsa|lsadump' }
            ] }
          ]
        }
      }
    end

    it 'compiles a simple rule into a CompiledRule' do
      compiled = compiler.compile(simple_rule)

      expect(compiled).to be_a(RubyGuardian::DetectionEngine::RuleEngine::CompiledRule)
      expect(compiled.id).to eq('COMP-001')
      expect(compiled.required_fields).to include('event_type')
    end

    it 'compiles complex boolean conditions' do
      compiled = compiler.compile(complex_rule)

      expect(compiled.required_fields).to include('event_type', 'process_name', 'command_line')
    end

    it 'pre-compiles regex patterns during optimization' do
      compiled = compiler.compile(complex_rule)
      # The AST should contain a pre-compiled Regexp
      expect(compiled.ast).not_to be_nil
    end

    it 'builds a field index for compiled rules' do
      compiler.compile(simple_rule)
      compiler.compile(complex_rule)

      rules = compiler.rules_for_field('event_type')
      expect(rules).to include('COMP-001', 'COMP-002')
    end

    it 'rejects rules without conditions' do
      bad = { 'id' => 'BAD', 'name' => 'No conditions' }
      expect { compiler.compile(bad) }.to raise_error(
        RubyGuardian::DetectionEngine::RuleEngine::CompilationError
      )
    end
  end

  describe RubyGuardian::DetectionEngine::RuleEngine::ConditionEvaluator do
    let(:compiler)  { rule_compiler.new }
    let(:evaluator) { evaluator_class.new }

    let(:rule) do
      {
        'id' => 'EVAL-001',
        'name' => 'Process Injection Detection',
        'severity' => 'high',
        'conditions' => {
          'and' => [
            { 'field' => 'event_type', 'op' => 'eq', 'value' => 'process_access' },
            { 'field' => 'access_mask', 'op' => 'in', 'value' => ['0x1F0FFF', '0x001F0FFF'] },
            { 'field' => 'source_process', 'op' => 'not_in',
              'value' => ['csrss.exe', 'lsass.exe', 'svchost.exe'] }
          ]
        }
      }
    end

    let(:compiled_rule) { compiler.compile(rule) }

    it 'matches an event that satisfies all conditions' do
      event = {
        event_type: 'process_access',
        access_mask: '0x1F0FFF',
        source_process: 'evil.exe'
      }

      result = evaluator.evaluate(compiled_rule, event)
      expect(result.matched).to be true
      expect(result.rule_id).to eq('EVAL-001')
    end

    it 'does not match when a condition fails' do
      event = {
        event_type: 'process_access',
        access_mask: '0x0040',
        source_process: 'evil.exe'
      }

      result = evaluator.evaluate(compiled_rule, event)
      expect(result.matched).to be false
    end

    it 'collects match context for matched conditions' do
      event = {
        event_type: 'process_access',
        access_mask: '0x1F0FFF',
        source_process: 'evil.exe'
      }

      result = evaluator.evaluate(compiled_rule, event)
      expect(result.context.matched_conditions).not_to be_empty
    end

    it 'handles nested field paths via dot notation' do
      nested_rule = {
        'id' => 'EVAL-002', 'name' => 'Nested', 'severity' => 'low',
        'conditions' => [{ 'field' => 'process.name', 'op' => 'eq', 'value' => 'cmd.exe' }]
      }
      compiled = compiler.compile(nested_rule)
      event = { process: { name: 'cmd.exe' } }

      result = evaluator.evaluate(compiled, event)
      expect(result.matched).to be true
    end

    it 'returns false for missing fields without raising' do
      event = { event_type: 'process_access' }
      result = evaluator.evaluate(compiled_rule, event)
      expect(result.matched).to be false
    end
  end
end
