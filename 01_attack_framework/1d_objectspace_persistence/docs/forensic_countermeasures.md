# Forensic Countermeasures for ObjectSpace Persistence

## Detection Framework

This document describes techniques for detecting and neutralizing in-memory
persistence in Ruby processes. These are the defensive counterparts to the
attack techniques demonstrated in this module.

## 1. Heap Snapshot Diffing

The most powerful forensic technique: take periodic heap snapshots and compare
them to a known-good baseline.

```ruby
require 'objspace'

# Capture baseline at boot (before any requests)
def capture_baseline
  baseline = {}
  ObjectSpace.each_object do |obj|
    baseline[obj.object_id] = {
      class: obj.class.name,
      frozen: obj.frozen?,
      source: (ObjectSpace.allocation_sourcefile(obj) rescue nil)
    }
  end
  baseline
end

# Compare current state to baseline
def detect_injected_objects(baseline)
  suspicious = []
  ObjectSpace.each_object do |obj|
    next if baseline.key?(obj.object_id)
    info = {
      class: obj.class.name,
      object_id: obj.object_id,
      source: (ObjectSpace.allocation_sourcefile(obj) rescue nil),
      memsize: (ObjectSpace.memsize_of(obj) rescue 0)
    }
    # Flag anonymous classes, eval-sourced objects, and large objects
    if obj.class.name.nil? || info[:source] == "(eval)" || info[:memsize] > 10_000
      info[:risk] = :high
    end
    suspicious << info
  end
  suspicious
end
```

## 2. Anonymous Class Detection

Ghost classes (anonymous classes) are a strong indicator of injection:

```ruby
def detect_anonymous_classes
  anonymous = []
  ObjectSpace.each_object(Class) do |klass|
    if klass.name.nil?
      anonymous << {
        object_id: klass.object_id,
        superclass: klass.superclass&.name,
        methods: klass.instance_methods(false),
        source: (ObjectSpace.allocation_sourcefile(klass) rescue nil)
      }
    end
  end
  anonymous
end

# Also check for modules
def detect_anonymous_modules
  anonymous = []
  ObjectSpace.each_object(Module) do |mod|
    next if mod.is_a?(Class)  # Already covered above
    if mod.name.nil?
      anonymous << {
        object_id: mod.object_id,
        methods: mod.instance_methods(false),
        source: (ObjectSpace.allocation_sourcefile(mod) rescue nil)
      }
    end
  end
  anonymous
end
```

## 3. Method Integrity Verification

Detect monkey-patched methods by checking source locations:

```ruby
def verify_method_integrity(klass, expected_source_dir)
  tampered = []
  klass.instance_methods(false).each do |method_name|
    method = klass.instance_method(method_name)
    source = method.source_location
    next unless source  # C methods have nil source_location

    file, line = source
    unless file.start_with?(expected_source_dir)
      tampered << {
        class: klass.name,
        method: method_name,
        expected_dir: expected_source_dir,
        actual_source: "#{file}:#{line}"
      }
    end
  end
  tampered
end

# Usage:
# verify_method_integrity(UsersController, "/app/controllers/")
```

## 4. Callback Chain Auditing

Verify Rails callback chains against expected values:

```ruby
def audit_callbacks(model_class, callback_type)
  chain = model_class.send("_#{callback_type}_callbacks")
  chain.map do |callback|
    filter = callback.filter
    {
      kind: callback.kind,  # :before, :after, :around
      filter: filter,
      source: case filter
              when Symbol
                model_class.instance_method(filter).source_location
              when Proc
                filter.source_location
              else
                "unknown"
              end
    }
  end
end

# Usage:
# audit_callbacks(User, :save)
# Compare output against known-good list from source code
```

## 5. ObjectSpace Method Integrity

Verify that ObjectSpace itself hasn't been tampered with:

```ruby
def verify_objectspace_integrity
  issues = []

  # Core ObjectSpace methods should be C-implemented (source_location => nil)
  [:each_object, :_id2ref, :count_objects, :define_finalizer].each do |method|
    source = ObjectSpace.method(method).source_location
    if source
      issues << {
        method: method,
        source: source,
        message: "ObjectSpace.#{method} has been monkey-patched!"
      }
    end
  end

  # Check GC module
  [:start, :enable, :disable].each do |method|
    source = GC.method(method).source_location
    if source
      issues << {
        method: "GC.#{method}",
        source: source,
        message: "GC.#{method} has been monkey-patched!"
      }
    end
  end

  issues
end
```

## 6. Finalizer Enumeration

Detect suspicious finalizers:

```ruby
def enumerate_finalizers
  finalizer_objects = []
  ObjectSpace.each_object do |obj|
    begin
      # Objects with finalizers have internal references
      # We can detect them via ObjectSpace.dump
      dump = ObjectSpace.dump(obj)
      if dump.include?('"finalizer"')
        finalizer_objects << {
          class: obj.class.name,
          object_id: obj.object_id,
          dump: dump
        }
      end
    rescue => e
      # Some objects can't be dumped
    end
  end
  finalizer_objects
end
```

## 7. Global Variable Monitoring

```ruby
def audit_global_variables(known_globals)
  current = global_variables
  unexpected = current - known_globals
  unexpected.map do |var|
    value = eval(var.to_s)
    {
      name: var,
      class: value.class.name,
      value_preview: value.inspect[0..100]
    }
  end
end
```

## 8. TracePoint-Based Monitoring

Set up runtime monitoring for suspicious activity:

```ruby
def install_security_monitor
  # Monitor class/module creation
  TracePoint.new(:class) do |tp|
    if tp.self.name.nil?
      Rails.logger.warn(
        "[SECURITY] Anonymous class created at #{tp.path}:#{tp.lineno}"
      )
    end
  end.enable

  # Monitor method definitions
  TracePoint.new(:c_call) do |tp|
    if tp.method_id == :define_method
      Rails.logger.warn(
        "[SECURITY] define_method called at #{tp.path}:#{tp.lineno}"
      )
    end
  end.enable
end
```

## 9. Memory Forensics Workflow

Complete forensic investigation procedure:

```
1. PRESERVE: Capture heap dump immediately
   ObjectSpace.dump_all(output: File.open("heap.jsonl", "w"))

2. BASELINE: Compare against known-good baseline
   diff heap_baseline.jsonl heap.jsonl

3. ENUMERATE: Find all anonymous classes and modules
   Run detect_anonymous_classes and detect_anonymous_modules

4. VERIFY: Check method integrity for critical classes
   Run verify_method_integrity on controllers and models

5. AUDIT: Review callback chains
   Run audit_callbacks on all models and controllers

6. TRACE: Follow reference chains from suspicious objects
   Use ObjectSpace.reachable_objects_from to trace anchors

7. NEUTRALIZE: Remove persistence mechanisms
   - Undefine finalizers: ObjectSpace.undefine_finalizer(obj)
   - Remove callbacks: klass._save_callbacks.delete(suspicious)
   - Restore methods: klass.define_method(:name, original_method)
   - Remove globals: remove instance variables from anchor objects

8. VERIFY: Re-run detection suite to confirm neutralization
```

## 10. Continuous Monitoring Recommendations

- Run heap diff every N requests in staging/development
- Alert on anonymous class creation in production (via TracePoint)
- Periodically verify ObjectSpace method integrity
- Maintain a baseline of expected global variables, constants, and callback chains
- Use `ObjectSpace.trace_object_allocations` in development to track allocation sources
