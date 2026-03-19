# Garbage Collector Evasion Techniques

## Understanding Ruby's GC

Ruby uses a generational, incremental, mark-and-sweep garbage collector (since Ruby 2.1+).

### Generational GC

Objects are classified into generations:
- **Young (Eden)**: Newly created objects. Collected frequently (minor GC).
- **Old (Tenured)**: Objects that survived 3+ minor GC cycles. Collected rarely (major GC).

**Attacker Implication**: An injected object that survives a few GC cycles gets
promoted to Old generation, making it even less likely to be examined.

### Mark-and-Sweep Overview

```
MARK PHASE:
  Start from GC roots (globals, stack, constants, class vars)
  Recursively traverse all reachable objects
  Mark each reachable object as "alive"

SWEEP PHASE:
  Walk all heap pages
  Any object NOT marked is freed (returned to free list)
  Clear all marks for next cycle
```

## Evasion Technique 1: Strong Reference Chains

The simplest approach: ensure at least one reference chain from a GC root to the
payload.

```ruby
# EDUCATIONAL EXAMPLE: Anchoring to a global variable
$__hidden = { payload: proc { system("echo pwned") } }
# This will NEVER be collected because $__hidden is a GC root.

# More subtle: hide inside an existing global
$LOAD_PATH.instance_variable_set(:@__meta, { payload: "data" })
# The $LOAD_PATH array is a GC root; its instance variables are also reachable.
```

## Evasion Technique 2: Constant Registration

Constants are GC roots. Creating a constant with a non-obvious name provides
persistence:

```ruby
# EDUCATIONAL EXAMPLE
# Hide a constant inside a deeply nested module
module Kernel
  # Kernel is always loaded; this constant hides in plain sight
  RUBY_INTERNAL_CACHE_v3 = { data: "payload" }.freeze
end
```

## Evasion Technique 3: Finalizer Resurrection

When an object's finalizer runs, it can "resurrect" the object by creating a new
reference to it:

```ruby
# EDUCATIONAL EXAMPLE: Self-resurrecting object
class Phoenix
  def self.create
    obj = new
    potion = proc { |_id|
      # Re-create when collected
      $stderr.puts "[EDUCATIONAL] Object resurrecting..."
      Phoenix.create
    }
    ObjectSpace.define_finalizer(obj, potion)
    # Anchor it
    (@@instances ||= []) << obj
    obj
  end
end
```

**Detection**: Monitor `ObjectSpace.define_finalizer` calls. Finalizers that
create new objects are highly suspicious.

## Evasion Technique 4: Write Barrier Exploitation

Ruby's GC uses write barriers to track references from old objects to young objects.
If a payload attaches itself to an old-generation object, it benefits from the
write barrier protection:

```ruby
# EDUCATIONAL EXAMPLE
# Rails.application is an old-generation object (created at boot)
# Attaching to it means the payload is only examined during major GC
Rails.application.instance_variable_set(:@__internal_ref_cache, payload)
```

## Evasion Technique 5: Thread-Local Anchoring

Each thread maintains its own set of GC roots through thread-local variables:

```ruby
# EDUCATIONAL EXAMPLE
# In a Puma thread pool, each thread persists for many requests
Thread.current[:__rack_session_validator] = payload_proc
# Name it something that looks like legitimate Rack internals
```

## Evasion Technique 6: Frozen Object Persistence

Frozen objects receive special treatment in Ruby's GC. While they CAN be collected,
the frozen string deduplication table provides additional anchoring:

```ruby
# EDUCATIONAL EXAMPLE
encoded = "payload_data_base64_encoded_here".freeze
# This frozen string may be deduplicated and cached by the VM
```

## Evasion Technique 7: Symbol Table Abuse

Symbols in Ruby are never garbage collected (prior to Ruby 2.2) or collected only
under specific conditions (2.2+). Dynamic symbols created from user input can
persist:

```ruby
# EDUCATIONAL EXAMPLE (Ruby < 2.2: permanent persistence)
# (Ruby >= 2.2: dynamic symbols can be collected, but pinned symbols cannot)
:"payload_marker_#{SecureRandom.hex(4)}"
# In older Ruby versions, this symbol persists forever
```

## Evasion Technique 8: ObjectSpace.each_object Override

An attacker can redefine `ObjectSpace.each_object` to filter out payload objects:

```ruby
# EDUCATIONAL EXAMPLE - DO NOT USE IN PRODUCTION
module ObjectSpace
  class << self
    alias_method :original_each_object, :each_object

    def each_object(*args, &block)
      return original_each_object(*args) unless block_given?
      original_each_object(*args) do |obj|
        # Skip objects marked as hidden
        next if obj.respond_to?(:__hidden?) && obj.__hidden?
        block.call(obj)
      end
    end
  end
end
```

**Detection**: Check `ObjectSpace.method(:each_object).source_location`. If it
returns a file path (instead of nil for C-implemented methods), it has been
monkey-patched.

## Forensic Countermeasures Summary

| Technique | Detection Method |
|-----------|-----------------|
| Global anchoring | Audit `global_variables` and compare to baseline |
| Constant hiding | Walk `Module.constants(true)` recursively |
| Finalizer resurrection | Monitor `ObjectSpace.define_finalizer` |
| Write barrier exploitation | Full heap dump analysis |
| Thread-local anchoring | Inspect `Thread.list.map { \|t\| t.keys }` |
| ObjectSpace override | Check `source_location` of ObjectSpace methods |
| Symbol abuse | Compare `Symbol.all_symbols` against baseline |
