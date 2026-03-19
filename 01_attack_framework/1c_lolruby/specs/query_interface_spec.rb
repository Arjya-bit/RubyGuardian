# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1c -- LoLRuby Query Interface Specs
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# These tests validate the LoLRuby database query interface, ensuring that
# technique lookups, filtering, and export functionality work correctly.
# Understanding the database structure helps defenders build detection rules.
# =============================================================================

require 'rspec'
require 'json'
require 'tmpdir'
require_relative '../lolruby_database/query_interface'

RSpec.describe RubyGuardian::LoLRuby::QueryInterface do
  subject(:qi) { described_class.new }

  describe '#initialize' do
    it 'loads the built-in database by default' do
      expect(qi.techniques).not_to be_empty
    end

    it 'sets the loaded_at timestamp' do
      expect(qi.loaded_at).to be_a(Time)
      expect(qi.loaded_at).to be <= Time.now.utc
    end

    context 'with a custom YAML database path' do
      let(:yaml_path) do
        file = Tempfile.new(['lolruby_db', '.yml'])
        file.write(YAML.dump([
          {
            name: 'custom_technique',
            tactic: 'execution',
            mitre_id: 'T9999',
            description: 'A custom test technique',
            ruby_apis: ['Kernel.eval'],
            detection_indicators: ['Custom indicator'],
            risk_level: 'low'
          }
        ]))
        file.close
        file.path
      end

      it 'loads techniques from the YAML file' do
        custom_qi = described_class.new(database_path: yaml_path)
        expect(custom_qi.techniques.size).to eq(1)
        expect(custom_qi.techniques.first[:name]).to eq('custom_technique')
      end
    end

    context 'with a non-existent database path' do
      it 'falls back to the built-in database for non-YAML paths' do
        qi = described_class.new(database_path: '/nonexistent/path.rb')
        expect(qi.techniques).not_to be_empty
      end
    end
  end

  describe '#by_tactic' do
    it 'returns techniques matching the given tactic' do
      results = qi.by_tactic('execution')
      expect(results).to be_an(Array)
      expect(results).to all(include(tactic: 'execution'))
    end

    it 'is case-insensitive' do
      lower = qi.by_tactic('execution')
      upper = qi.by_tactic('EXECUTION')
      expect(lower).to eq(upper)
    end

    it 'accepts symbols' do
      results = qi.by_tactic(:execution)
      expect(results).not_to be_empty
    end

    it 'returns an empty array for unknown tactics' do
      expect(qi.by_tactic('nonexistent_tactic')).to be_empty
    end
  end

  describe '#by_mitre_id' do
    it 'finds techniques by MITRE ATT&CK ID' do
      results = qi.by_mitre_id('T1059')
      expect(results).not_to be_empty
      expect(results.first[:mitre_id]).to eq('T1059')
    end

    it 'is case-insensitive for MITRE IDs' do
      upper = qi.by_mitre_id('T1059')
      lower = qi.by_mitre_id('t1059')
      expect(upper).to eq(lower)
    end

    it 'supports sub-technique IDs' do
      results = qi.by_mitre_id('T1059.007')
      expect(results).not_to be_empty
    end

    it 'returns empty array for unknown MITRE IDs' do
      expect(qi.by_mitre_id('T0000')).to be_empty
    end
  end

  describe '#by_stdlib' do
    it 'finds techniques using a specific Ruby standard library' do
      results = qi.by_stdlib('Net::HTTP')
      expect(results).not_to be_empty
    end

    it 'performs partial matching on library names' do
      results = qi.by_stdlib('Socket')
      expect(results).not_to be_empty
      results.each do |tech|
        has_socket = tech[:ruby_apis].any? { |api| api.downcase.include?('socket') }
        expect(has_socket).to be true
      end
    end

    it 'is case-insensitive' do
      upper = qi.by_stdlib('DRb')
      lower = qi.by_stdlib('drb')
      expect(upper).to eq(lower)
    end
  end

  describe '#search' do
    it 'performs full-text search across names' do
      results = qi.search('eval')
      expect(results).not_to be_empty
    end

    it 'searches across descriptions' do
      results = qi.search('credential')
      expect(results).not_to be_empty
    end

    it 'searches across ruby_apis' do
      results = qi.search('Marshal')
      expect(results).not_to be_empty
    end

    it 'escapes regex special characters' do
      expect { qi.search('Open3.popen3') }.not_to raise_error
    end

    it 'returns empty array for no matches' do
      expect(qi.search('zzz_no_match_zzz')).to be_empty
    end
  end

  describe '#available_tactics' do
    it 'returns sorted unique tactics' do
      tactics = qi.available_tactics
      expect(tactics).to be_an(Array)
      expect(tactics).to eq(tactics.sort)
      expect(tactics).to eq(tactics.uniq)
    end

    it 'includes known tactics from the built-in database' do
      tactics = qi.available_tactics
      expect(tactics).to include('execution')
      expect(tactics).to include('reconnaissance')
    end
  end

  describe '#detections_for' do
    it 'returns detection indicators for a known technique' do
      detections = qi.detections_for('eval_execution')
      expect(detections).to be_an(Array)
      expect(detections).not_to be_empty
    end

    it 'returns empty array for unknown techniques' do
      expect(qi.detections_for('nonexistent')).to be_empty
    end
  end

  describe '#export_json' do
    it 'writes the database to a JSON file' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'export.json')
        qi.export_json(path)

        expect(File.exist?(path)).to be true
        data = JSON.parse(File.read(path))
        expect(data['version']).to eq('1.0')
        expect(data['technique_count']).to eq(qi.techniques.size)
        expect(data['techniques']).to be_an(Array)
      end
    end
  end

  describe '#stats' do
    it 'returns comprehensive statistics' do
      stats = qi.stats
      expect(stats[:total_techniques]).to be_positive
      expect(stats[:by_tactic]).to be_a(Hash)
      expect(stats[:unique_ruby_apis]).to be_positive
      expect(stats[:unique_mitre_ids]).to be_positive
      expect(stats[:loaded_at]).to be_a(Time)
    end

    it 'counts techniques per tactic correctly' do
      stats = qi.stats
      tactic_sum = stats[:by_tactic].values.sum
      # Some techniques may belong to tactics not in the TACTICS constant
      expect(tactic_sum).to be <= stats[:total_techniques]
    end
  end

  describe 'TACTICS constant' do
    it 'defines known MITRE ATT&CK tactic categories' do
      expect(described_class::TACTICS).to include('execution')
      expect(described_class::TACTICS).to include('persistence')
      expect(described_class::TACTICS).to include('exfiltration')
      expect(described_class::TACTICS).to be_frozen
    end
  end
end
