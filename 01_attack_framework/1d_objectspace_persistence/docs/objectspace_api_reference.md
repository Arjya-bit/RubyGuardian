# ObjectSpace API Reference for Security Research

## Core ObjectSpace Methods

### ObjectSpace.each_object([klass])

Iterates over every live object, optionally filtered by class. This is the primary
enumeration tool for both attackers (finding targets) and defenders (finding anomalies).

```ruby
# Count all live objects by type
counts = Hash.new(0)
ObjectSpace.each_object { |obj| counts[obj.class] += 1 }
counts.sort_by { |_k, v| -v }.first(10).each { |k, v| puts "#{k}: #{v}" }

# SECURITY NOTE: Attackers can override each_object to hide objects.
# Defenders should verify ObjectSpace.method(:each_object).source_location
```

### ObjectSpace._id2ref(object_id)

Converts an object_id back to the object reference. Useful for forensic analysis
when you have an object_id but need to inspect the actual object.

```ruby
obj = "secret payload"
id = obj.object_id
# Later, from a different context:
recovered = ObjectSpace._id2ref(id)  # => "secret payload"

# SECURITY NOTE: This can raise RangeError if the object has been GC'd.
# Attackers may use this to verify their payloads are still alive.
```

### ObjectSpace.define_finalizer(obj, proc)

Registers a callback that fires when an object is about to be garbage collected.
This is a persistence mechanism: the finalizer can re-create the payload.

```ruby
# EDUCATIONAL: Finalizer-based persistence
payload = Object.new
poison = proc { |id|
  # This runs when 'payload' is about to be collected.
  # An attacker could re-inject the payload here.
  $stderr.puts "[FINALIZER] Object #{id} being collected, re-injecting..."
  new_payload = Object.new
  ObjectSpace.define_finalizer(new_payload, poison)
}
ObjectSpace.define_finalizer(payload, poison)
```

### ObjectSpace.undefine_finalizer(obj)

Removes all finalizers from an object. Defenders can use this to neutralize
finalizer-based persistence.

```ruby
ObjectSpace.undefine_finalizer(suspicious_object)
```

### ObjectSpace.count_objects

Returns a hash of object counts by internal type. Useful for detecting anomalous
object counts that might indicate injection.

```ruby
ObjectSpace.count_objects
# => {:TOTAL=>62421, :FREE=>562, :T_OBJECT=>1235, :T_CLASS=>904, ...}

# SECURITY NOTE: A sudden spike in T_CLASS or T_MODULE may indicate
# ghost class creation. Baseline these values in production.
```

### ObjectSpace.count_objects_size (require 'objspace')

Returns memory consumption by object type.

```ruby
require 'objspace'
ObjectSpace.count_objects_size
# => {:TOTAL=>5765280, :T_OBJECT=>213840, :T_STRING=>1432000, ...}
```

### ObjectSpace.dump(obj) / ObjectSpace.dump_all

Dumps object metadata as JSON. `dump_all` creates a complete heap snapshot.

```ruby
require 'objspace'

# Dump a single object
obj = "test"
puts ObjectSpace.dump(obj)
# => {"address":"0x...", "type":"STRING", "class":"0x...", "embedded":true, ...}

# Dump entire heap to a file (forensic gold mine)
File.open("heap_dump.jsonl", "w") { |f| ObjectSpace.dump_all(output: f) }

# SECURITY NOTE: Heap dumps contain ALL strings in memory, including
# secrets, API keys, and session tokens. Handle with extreme care.
```

### ObjectSpace.trace_object_allocations / ObjectSpace.allocation_sourcefile

Tracks where objects were allocated. Essential for forensic analysis.

```ruby
require 'objspace'
ObjectSpace.trace_object_allocations_start

obj = Object.new

puts ObjectSpace.allocation_sourcefile(obj)  # => "script.rb"
puts ObjectSpace.allocation_sourceline(obj)  # => 4
puts ObjectSpace.allocation_class_path(obj)  # => ""
puts ObjectSpace.allocation_method_id(obj)   # => nil

# SECURITY NOTE: Objects created via eval or dynamic code may show
# "(eval)" as the source file, which is a detection signal.
```

### ObjectSpace.memsize_of(obj)

Returns the memory consumption of a single object in bytes.

```ruby
require 'objspace'
str = "x" * 10_000
ObjectSpace.memsize_of(str)  # => 10041 (approximately)

# SECURITY NOTE: Unusually large objects may be payload containers.
```

### ObjectSpace.reachable_objects_from(obj)

Returns an array of all objects directly referenced by the given object.

```ruby
require 'objspace'
hash = { key: "value", nested: [1, 2, 3] }
refs = ObjectSpace.reachable_objects_from(hash)
# => [String, Array, Symbol, ...]

# SECURITY NOTE: Use this to trace reference chains from suspicious objects
# back to their GC anchors. Essential for understanding persistence mechanisms.
```

## GC Module (Companion to ObjectSpace)

### GC.start

Forces a full garbage collection cycle. Used to test persistence.

```ruby
# Stress test: force multiple GC cycles
5.times do
  GC.start(full_mark: true, immediate_sweep: true)
end
```

### GC.stat

Returns GC statistics. Useful for detecting unusual GC behavior.

```ruby
GC.stat
# => {:count=>15, :heap_allocated_pages=>120, :heap_eden_pages=>118, ...}
```

### GC.disable / GC.enable

Disabling GC prevents object collection. An attacker might disable GC temporarily
during injection to prevent race conditions.

```ruby
GC.disable
# ... inject objects ...
GC.enable
```
