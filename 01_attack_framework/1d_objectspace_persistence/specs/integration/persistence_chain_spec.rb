# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1d -- ObjectSpace Persistence Integration Tests
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# These integration tests validate the full persistence chain: injection,
# anchoring, cloaking, and callback installation working together. This
# mirrors how a real attacker would combine techniques for resilient
# in-memory persistence.
#
# Understanding the full chain helps defenders build comprehensive detection
# that covers all stages of the attack lifecycle.
# =============================================================================

require 'rspec'
require 'logger'
require 'stringio'
require_relative '../../lib/gc_anchor'
require_relative '../../lib/ghost_class'
require_relative '../../lib/objectspace_injector'
require_relative '../../lib/method_patcher'
require_relative '../../lib/callback_installer'
require_relative '../../lib/memory_cloaker'
require_relative '../../lib/heap_hider'

RSpec.describe 'Persistence Chain Integration' do
  let(:log_output) { StringIO.new }
  let(:logger) { Logger.new(log_output) }

  after(:each) do
    RubyGuardian::ObjectSpacePersistence::GCAnchhor.release_all
  end

  # ─────────────────────────────────────────────────────────────
  # Full injection -> anchor -> survive GC chain
  # ─────────────────────────────────────────────────────────────
  describe 'Injection and GC Survival' do
    let(:injector) { RubyGuardian::ObjectSpacePersistence::ObjectSpaceInjector.new(verbose: false) }

    after(:each) { injector.cleanup! }

    it 'injects an object that survives garbage collection' do
      payload = +"critical_secret_data_#{rand(100_000)}"
      oid = injector.inject(payload, anchor_strategy: :thread_local)

      # Force aggressive GC
      3.times { GC.start(full_mark: true, immediate_sweep: true) }

      # Verify the wrapper object is still alive
      report = injector.status_report
      expect(report[:alive]).to be >= 1
    end

    it 'supports redundant injection across multiple strategies' do
      payload = "redundant_payload"
      oids = injector.inject_redundant(
        payload,
        strategies: [:thread_local, :constant]
      )

      expect(oids.size).to eq(2)

      GC.start(full_mark: true, immediate_sweep: true)

      report = injector.status_report
      expect(report[:total_injected]).to be >= 2
    end
  end

  # ─────────────────────────────────────────────────────────────
  # Ghost class creation -> anchor -> enumeration
  # ─────────────────────────────────────────────────────────────
  describe 'Ghost Class Lifecycle' do
    let(:ghost_factory) { RubyGuardian::ObjectSpacePersistence::GhostClass.new(logger: logger) }

    it 'creates ghost classes that persist through GC' do
      ghost = ghost_factory.create_ghost(
        methods: { execute: 'payload_result' },
        ivars: { config: { target: 'localhost' } }
      )

      # Record the object_id before GC
      ghost_id = ghost.object_id

      GC.start(full_mark: true, immediate_sweep: true)

      # Ghost should still be accessible
      recovered = ObjectSpace._id2ref(ghost_id)
      expect(recovered).to be_a(Class)
      expect(recovered.new.execute).to eq('payload_result')
    end

    it 'ghost classes are detectable via ObjectSpace scanning' do
      ghost_factory.create_ghost(methods: { marker: 'rg_ghost_marker' })

      ghosts = RubyGuardian::ObjectSpacePersistence::GhostClass.scan_for_ghosts
      # There should be at least one anonymous class (ours)
      expect(ghosts).not_to be_empty

      # Our ghost should be among anonymous classes with instance methods
      has_methods = ghosts.any? { |g| g[:instance_methods].include?(:marker) }
      expect(has_methods).to be true
    end
  end

  # ─────────────────────────────────────────────────────────────
  # HeapHider -> Injection -> Retrieval
  # ─────────────────────────────────────────────────────────────
  describe 'Heap Hiding and Retrieval' do
    let(:hider) { RubyGuardian::ObjectSpacePersistence::HeapHider.new(verbose: false) }

    it 'hides a payload on a target object and retrieves it' do
      target = Object.new
      target.instance_variable_set(:@legitimate_data, "normal")

      record = hider.hide("secret_payload", target: target, camouflage: :generic)

      # Payload should be retrievable
      retrieved = hider.retrieve(record)
      expect(retrieved).to eq("secret_payload")
    end

    it 'hides payload inside an existing hash on the target' do
      target = Object.new
      target.instance_variable_set(:@config, { 'normal_key' => 'normal_value' })

      record = hider.hide_in_hash(
        "hidden_in_hash",
        target: target,
        hash_ivar: '@config',
        key: 'cache_store_v1'
      )

      config = target.instance_variable_get(:@config)
      expect(config['normal_key']).to eq('normal_value')
      expect(config['cache_store_v1']).to eq('hidden_in_hash')

      retrieved = hider.retrieve(record)
      expect(retrieved).to eq('hidden_in_hash')
    end

    it 'hides payload inside an existing array on the target' do
      target = Object.new
      target.instance_variable_set(:@callbacks, ['existing_callback'])

      record = hider.hide_in_array(
        "hidden_in_array",
        target: target,
        array_ivar: '@callbacks'
      )

      callbacks = target.instance_variable_get(:@callbacks)
      expect(callbacks.size).to eq(2)
      expect(callbacks.first).to eq('existing_callback')
      expect(callbacks.last).to eq('hidden_in_array')
    end

    it 'generates forensic reports' do
      target = Object.new
      hider.hide("data1", target: target)
      hider.hide("data2", target: target)

      report = hider.forensic_report
      expect(report.size).to eq(2)
      expect(report).to all(include(:still_alive))
    end
  end

  # ─────────────────────────────────────────────────────────────
  # Callback Installation in dry_run mode
  # ─────────────────────────────────────────────────────────────
  describe 'Callback Chain (dry_run)' do
    let(:installer) do
      RubyGuardian::ObjectSpacePersistence::CallbackInstaller.new(
        logger: logger, dry_run: true
      )
    end

    it 'installs multiple callback types and summarizes them' do
      installer.install_at_exit(tag: 'persist_beacon')
      installer.install_tracepoint(events: [:call], tag: 'method_monitor')
      installer.install_set_trace_func(tag: 'global_trace')

      summary = installer.summary
      expect(summary[:total_installed]).to eq(3)
      expect(summary[:by_type]).to eq(
        at_exit: 1,
        tracepoint: 1,
        set_trace_func: 1
      )
    end

    it 'cleans up all callbacks' do
      installer.install_at_exit(tag: 'cleanup_test')
      installer.install_tracepoint(tag: 'cleanup_tp')

      count = installer.cleanup!
      expect(installer.installed_callbacks).to be_empty
    end
  end

  # ─────────────────────────────────────────────────────────────
  # Memory Cloaking in dry_run mode
  # ─────────────────────────────────────────────────────────────
  describe 'Memory Cloaking Chain (dry_run)' do
    let(:cloaker) do
      RubyGuardian::ObjectSpacePersistence::MemoryCloaker.new(
        logger: logger, dry_run: true
      )
    end

    it 'applies multiple cloaking strategies' do
      obj = Object.new
      cloaker.cloak_inspect(obj, disguise_as: 'Mutex')
      cloaker.cloak_in_container("payload", container_type: :hash)
      cloaker.cloak_as_frozen_string("encoded_secret")

      report = cloaker.forensic_report
      expect(report[:total_cloaked]).to eq(3)
      expect(report[:by_strategy]).to include(
        inspect_override: 1,
        container_wrap: 1,
        frozen_string: 1
      )
    end
  end

  # ─────────────────────────────────────────────────────────────
  # Full attack chain: inject -> cloak -> anchor -> callback
  # ─────────────────────────────────────────────────────────────
  describe 'Complete Persistence Chain (dry_run components)' do
    it 'demonstrates the full attack lifecycle' do
      # Step 1: Create a ghost class to hold the payload
      ghost_factory = RubyGuardian::ObjectSpacePersistence::GhostClass.new(logger: logger)
      ghost = ghost_factory.create_ghost(
        methods: { run: 'simulated_payload_output' }
      )

      # Step 2: Inject payload into the process
      injector = RubyGuardian::ObjectSpacePersistence::ObjectSpaceInjector.new(verbose: false)
      injector.inject(ghost, anchor_strategy: :thread_local)

      # Step 3: Install callback for re-activation (dry_run)
      installer = RubyGuardian::ObjectSpacePersistence::CallbackInstaller.new(
        logger: logger, dry_run: true
      )
      installer.install_at_exit(tag: 'reactivation')

      # Step 4: Verify the chain is intact after GC
      GC.start(full_mark: true, immediate_sweep: true)

      report = injector.status_report
      expect(report[:alive]).to be >= 1

      callback_summary = installer.summary
      expect(callback_summary[:total_installed]).to eq(1)

      # Cleanup
      injector.cleanup!
      installer.cleanup!
    end
  end

  # ─────────────────────────────────────────────────────────────
  # Detection and forensic scanning
  # ─────────────────────────────────────────────────────────────
  describe 'Forensic Detection Capabilities' do
    it 'detects active tracepoints via CallbackInstaller.scan_for_tracepoints' do
      results = RubyGuardian::ObjectSpacePersistence::CallbackInstaller.scan_for_tracepoints
      expect(results).to be_an(Array)
    end

    it 'detects suspicious procs via CallbackInstaller.scan_for_suspicious_procs' do
      results = RubyGuardian::ObjectSpacePersistence::CallbackInstaller.scan_for_suspicious_procs
      expect(results).to be_an(Array)
    end

    it 'MethodPatcher.detect_patches scans for anomalous ancestor chains' do
      findings = RubyGuardian::ObjectSpacePersistence::MethodPatcher.detect_patches(String)
      expect(findings).to be_an(Array)
      findings.each do |f|
        expect(f[:type]).to be_in([:prepended_modules, :alias_chain])
      end
    end
  end
end
