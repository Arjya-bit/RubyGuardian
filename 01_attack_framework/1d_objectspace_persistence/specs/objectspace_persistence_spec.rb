# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1d -- ObjectSpace Persistence Unit Tests
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# These tests validate ObjectSpace persistence techniques to ensure they
# behave predictably. Understanding these mechanisms helps defenders build
# detection and forensic tools.
# =============================================================================

require 'rspec'
require 'logger'
require 'stringio'
require_relative '../lib/gc_anchor'
require_relative '../lib/ghost_class'
require_relative '../lib/objectspace_injector'
require_relative '../lib/method_patcher'
require_relative '../lib/callback_installer'
require_relative '../lib/memory_cloaker'
require_relative '../lib/heap_hider'

RSpec.describe 'ObjectSpace Persistence Modules' do
  let(:log_output) { StringIO.new }
  let(:logger) { Logger.new(log_output) }

  # ─────────────────────────────────────────────────────────────
  # GCAnchhor (note: typo preserved from source to match existing code)
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::ObjectSpacePersistence::GCAnchhor do
    after(:each) do
      described_class.release_all
    end

    describe '.anchor' do
      it 'stores an object with a tag' do
        obj = Object.new
        tag = described_class.anchor(obj, tag: 'test_obj')
        expect(tag).to eq('test_obj')
        expect(described_class.anchored?('test_obj')).to be true
      end

      it 'generates a tag if none is provided' do
        obj = Object.new
        tag = described_class.anchor(obj)
        expect(tag).to start_with('anchor_')
        expect(described_class.anchored?(tag)).to be true
      end
    end

    describe '.release' do
      it 'removes the anchored object' do
        obj = Object.new
        described_class.anchor(obj, tag: 'release_me')
        described_class.release('release_me')
        expect(described_class.anchored?('release_me')).to be false
      end
    end

    describe '.release_all' do
      it 'removes all anchored objects and returns count' do
        3.times { |i| described_class.anchor(Object.new, tag: "obj_#{i}") }
        count = described_class.release_all
        expect(count).to eq(3)
        expect(described_class.anchored_objects).to be_empty
      end
    end

    describe '.stats' do
      it 'returns statistics about anchored objects' do
        described_class.anchor("hello", tag: 'str1')
        described_class.anchor([1, 2], tag: 'arr1')
        stats = described_class.stats
        expect(stats[:total_anchored]).to eq(2)
        expect(stats[:by_class]).to include('String' => 1, 'Array' => 1)
      end
    end

    describe '.verify_persistence' do
      it 'confirms anchored objects survive GC' do
        obj = +"test_string_that_should_survive"
        described_class.anchor(obj, tag: 'gc_test')
        result = described_class.verify_persistence
        expect(result[:all_survived]).to be true
        expect(result[:checked]).to eq(1)
      end
    end

    describe '#create_anchor_chain' do
      it 'creates a reference chain of the specified depth' do
        instance = described_class.new
        obj = Object.new
        chain_size = instance.create_anchor_chain(obj, depth: 5)
        expect(chain_size).to eq(6) # original + 5 wrappers
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # GhostClass
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::ObjectSpacePersistence::GhostClass do
    subject(:ghost_factory) { described_class.new(logger: logger) }

    after(:each) do
      RubyGuardian::ObjectSpacePersistence::GCAnchhor.release_all
    end

    describe '#create_ghost' do
      it 'creates an anonymous class' do
        ghost = ghost_factory.create_ghost(methods: { hello: 'world' })
        expect(ghost).to be_a(Class)
        expect(ghost.name).to be_nil
      end

      it 'installs specified methods on the ghost class' do
        ghost = ghost_factory.create_ghost(methods: { greet: 'hi', farewell: 'bye' })
        instance = ghost.new
        expect(instance.greet).to eq('hi')
        expect(instance.farewell).to eq('bye')
      end

      it 'sets instance variables on the class' do
        ghost = ghost_factory.create_ghost(ivars: { secret: 'payload_data' })
        expect(ghost.instance_variable_get(:@secret)).to eq('payload_data')
      end

      it 'tracks created ghosts' do
        ghost_factory.create_ghost
        ghost_factory.create_ghost
        expect(ghost_factory.ghosts.size).to eq(2)
      end
    end

    describe '.scan_for_ghosts' do
      it 'returns an array of anonymous class details' do
        results = described_class.scan_for_ghosts
        expect(results).to be_an(Array)
        results.each do |r|
          expect(r).to have_key(:object_id)
          expect(r).to have_key(:superclass)
        end
      end
    end

    describe '#summary' do
      it 'returns ghost creation summary' do
        ghost_factory.create_ghost
        summary = ghost_factory.summary
        expect(summary[:total_ghosts]).to eq(1)
      end
    end

    describe '#describe' do
      it 'provides educational description' do
        expect(ghost_factory.describe).to include('T1055')
        expect(ghost_factory.describe).to include('anonymous')
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # ObjectSpaceInjector
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::ObjectSpacePersistence::ObjectSpaceInjector do
    subject(:injector) { described_class.new(verbose: false) }

    after(:each) { injector.cleanup! }

    describe '#inject' do
      it 'injects a payload and returns its object_id' do
        oid = injector.inject("secret_data", anchor_strategy: :thread_local)
        expect(oid).to be_a(Integer)
      end

      it 'records injection in the log' do
        injector.inject("data", anchor_strategy: :thread_local)
        expect(injector.injection_log.size).to eq(1)
        expect(injector.injection_log.first[:strategy]).to eq(:thread_local)
      end

      it 'supports multiple anchor strategies' do
        strategies = [:thread_local, :constant, :global]
        strategies.each do |strategy|
          expect {
            injector.inject("data_#{strategy}", anchor_strategy: strategy)
          }.not_to raise_error
        end
      end

      it 'raises on unknown anchor strategy' do
        expect {
          injector.inject("data", anchor_strategy: :nonexistent)
        }.to raise_error(ArgumentError, /Unknown anchor strategy/)
      end
    end

    describe '#inject_into_target' do
      it 'attaches payload to a target object' do
        target = Object.new
        oid = injector.inject_into_target(target, "hidden_data", var_name: "@test_cache")
        expect(target.instance_variable_get(:@test_cache)).to eq("hidden_data")
        expect(oid).to be_a(Integer)
      end

      it 'auto-prepends @ to variable names' do
        target = Object.new
        injector.inject_into_target(target, "data", var_name: "my_var")
        expect(target.instance_variable_get(:@my_var)).to eq("data")
      end
    end

    describe '#status_report' do
      it 'reports alive and collected objects' do
        injector.inject("alive_data", anchor_strategy: :thread_local)
        report = injector.status_report
        expect(report[:total_injected]).to eq(1)
        expect(report[:alive]).to be >= 0
        expect(report).to have_key(:object_count_delta)
      end
    end

    describe '#cleanup!' do
      it 'clears all injected objects and logs' do
        injector.inject("data1", anchor_strategy: :thread_local)
        injector.inject("data2", anchor_strategy: :thread_local)
        injector.cleanup!
        expect(injector.injected_objects).to be_empty
        expect(injector.injection_log).to be_empty
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # MethodPatcher
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::ObjectSpacePersistence::MethodPatcher do
    subject(:patcher) { described_class.new(logger: logger, dry_run: true) }

    describe '#demonstrate_prepend_patch' do
      it 'records a prepend patch demonstration' do
        record = patcher.demonstrate_prepend_patch(String, :upcase)
        expect(record.patch_type).to eq(:prepend)
        expect(record.target_class).to eq('String')
        expect(record.method_name).to eq(:upcase)
      end
    end

    describe '#demonstrate_alias_patch' do
      it 'records an alias_method patch demonstration' do
        record = patcher.demonstrate_alias_patch(Array, :push)
        expect(record.patch_type).to eq(:alias_method)
      end
    end

    describe '.detect_patches' do
      it 'returns findings about patched classes' do
        findings = described_class.detect_patches(String)
        expect(findings).to be_an(Array)
      end
    end

    describe '#summary' do
      it 'summarizes patch operations' do
        patcher.demonstrate_prepend_patch(String, :reverse)
        patcher.demonstrate_alias_patch(Hash, :merge)
        summary = patcher.summary
        expect(summary[:total_patches]).to eq(2)
        expect(summary[:dry_run]).to be true
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # CallbackInstaller
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::ObjectSpacePersistence::CallbackInstaller do
    subject(:installer) { described_class.new(logger: logger, dry_run: true) }

    describe '#install_at_exit' do
      it 'records an at_exit installation in dry_run mode' do
        record = installer.install_at_exit(tag: 'test_exit')
        expect(record[:type]).to eq(:at_exit)
        expect(record[:tag]).to eq('test_exit')
        expect(record[:dry_run]).to be true
      end
    end

    describe '#install_tracepoint' do
      it 'records a tracepoint installation in dry_run mode' do
        record = installer.install_tracepoint(events: [:call, :return], tag: 'test_tp')
        expect(record[:type]).to eq(:tracepoint)
        expect(record[:events]).to eq([:call, :return])
        expect(record[:dry_run]).to be true
      end
    end

    describe '#install_method_interceptor' do
      it 'records a method interceptor in dry_run mode' do
        record = installer.install_method_interceptor(
          target_class: String,
          method_name: :upcase
        )
        expect(record[:type]).to eq(:method_interceptor)
        expect(record[:target_class]).to eq('String')
      end
    end

    describe '#install_set_trace_func' do
      it 'records set_trace_func in dry_run mode' do
        record = installer.install_set_trace_func(tag: 'test_trace')
        expect(record[:type]).to eq(:set_trace_func)
        expect(record[:dry_run]).to be true
      end
    end

    describe '.scan_for_tracepoints' do
      it 'returns array of TracePoint information' do
        results = described_class.scan_for_tracepoints
        expect(results).to be_an(Array)
      end
    end

    describe '#summary' do
      it 'summarizes all installations' do
        installer.install_at_exit(tag: 'e1')
        installer.install_tracepoint(tag: 'tp1')
        summary = installer.summary
        expect(summary[:total_installed]).to eq(2)
        expect(summary[:by_type]).to include(at_exit: 1, tracepoint: 1)
      end
    end

    describe '#describe' do
      it 'provides educational content' do
        desc = installer.describe
        expect(desc).to include('T1546')
        expect(desc).to include('at_exit')
        expect(desc).to include('TracePoint')
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # MemoryCloaker
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::ObjectSpacePersistence::MemoryCloaker do
    subject(:cloaker) { described_class.new(logger: logger, dry_run: true) }

    describe '#cloak_inspect' do
      it 'records an inspect cloak in dry_run mode' do
        obj = Object.new
        record = cloaker.cloak_inspect(obj, disguise_as: 'Mutex')
        expect(record[:strategy]).to eq(:inspect_override)
        expect(record[:disguise_as]).to eq('Mutex')
        expect(record[:dry_run]).to be true
      end
    end

    describe '#cloak_in_container' do
      it 'records a container cloak in dry_run mode' do
        record = cloaker.cloak_in_container("payload", container_type: :hash)
        expect(record[:strategy]).to eq(:container_wrap)
        expect(record[:container_type]).to eq(:hash)
      end
    end

    describe '#cloak_as_frozen_string' do
      it 'records a frozen string cloak in dry_run mode' do
        record = cloaker.cloak_as_frozen_string("secret")
        expect(record[:strategy]).to eq(:frozen_string)
        expect(record[:dry_run]).to be true
      end
    end

    describe '#suppress_allocation_tracing' do
      it 'records suppression attempt in dry_run mode' do
        record = cloaker.suppress_allocation_tracing
        expect(record[:strategy]).to eq(:suppress_tracing)
      end
    end

    describe '#forensic_report' do
      it 'generates a comprehensive report' do
        cloaker.cloak_inspect(Object.new)
        cloaker.cloak_as_frozen_string("test")
        report = cloaker.forensic_report
        expect(report[:total_cloaked]).to eq(2)
        expect(report[:detection_guidance]).to be_an(Array)
      end
    end

    describe '#describe' do
      it 'provides educational content' do
        desc = cloaker.describe
        expect(desc).to include('T1070')
        expect(desc).to include('ObjectSpace')
      end
    end
  end
end
