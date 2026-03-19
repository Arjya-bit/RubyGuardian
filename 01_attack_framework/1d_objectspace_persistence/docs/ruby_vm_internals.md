# Ruby VM Internals for ObjectSpace Persistence

## Educational Reference Document

### Ruby Object Model in Memory

Every Ruby object is represented internally by a C struct called `RVALUE`. The Ruby
VM maintains a linked list of heap pages, each containing a fixed number of RVALUE
slots (typically 409 per page on 64-bit systems).

```
+------------------+
| Heap Page 0      |
|  [RVALUE][RVALUE]|  <-- Each slot is 40 bytes (Ruby 3.x)
|  [RVALUE][RVALUE]|
+------------------+
| Heap Page 1      |
|  [RVALUE][RVALUE]|
|  [RVALUE][FREE]  |  <-- Free slots are linked together
+------------------+
```

### RVALUE Structure

```c
// Simplified from ruby/include/ruby/ruby.h
typedef struct RVALUE {
    union {
        struct RBasic  basic;
        struct RObject object;
        struct RClass  klass;
        struct RFloat  flonum;
        struct RString string;
        struct RArray  array;
        struct RHash   hash;
        // ... other types
    } as;
} RVALUE;

struct RBasic {
    VALUE flags;   // Object type, frozen status, GC marks
    VALUE klass;   // Pointer to the object's class
};
```

### How ObjectSpace Maps to the Heap

`ObjectSpace` is Ruby's public API for iterating over all live objects on the heap.
Internally, `ObjectSpace.each_object` walks every heap page and yields each RVALUE
that is not on the free list.

```ruby
# This iterates over ALL live objects in the Ruby process
ObjectSpace.each_object { |obj| puts obj.class }

# Filter by type
ObjectSpace.each_object(String) { |s| puts s if s.length > 100 }
```

### Object Lifecycle

1. **Allocation**: Ruby allocates from free list slots. If no free slots exist, a
   new heap page is allocated from the OS.
2. **Reference**: Objects are kept alive as long as at least one reference exists
   from a GC root (stack variables, global variables, constants, class variables).
3. **Mark Phase**: The GC walks from roots, marking all reachable objects.
4. **Sweep Phase**: Unmarked objects are returned to the free list.

### GC Roots (Important for Persistence)

These are the starting points for GC mark traversal:

- **Machine stack** - Local variables in the current call stack
- **Global variables** (`$global_var`)
- **Constants** (including class/module names like `MyClass`)
- **Class variables** (`@@var`)
- **Finalizers** registered via `ObjectSpace.define_finalizer`
- **Thread-local variables**
- **Internal VM references** (frozen string cache, symbol table, etc.)

### Security Implications

An attacker who can inject code into a running Ruby process can:

1. Create objects that reference each other (preventing GC)
2. Attach references to long-lived framework objects (GC roots)
3. Monkey-patch methods to execute arbitrary code
4. Create anonymous classes that are hard to enumerate
5. Override `ObjectSpace` methods to hide injected objects

### Ruby's Object ID System

Every Ruby object has a unique `object_id`. For small integers (Fixnum), the
object_id is derived from the value: `(value * 2) + 1`. For heap-allocated objects,
the object_id is based on the memory address of the RVALUE slot.

```ruby
# object_id reveals memory layout information
obj = Object.new
puts obj.object_id  # e.g., 70368527964560
# This is (memory_address / 2) on most implementations
```

### Frozen String Optimization

Ruby interns (deduplicates) frozen string literals. These strings live in a special
hash table and are never garbage collected, making them a potential hiding spot:

```ruby
# This string is interned and will never be GC'd
str = "payload data".freeze
# The interned copy persists for the lifetime of the process
```

### WeakRef and Soft References

Ruby provides `WeakRef` which does NOT prevent GC. Attackers must avoid WeakRef
and instead use strong references to maintain persistence. Understanding this
distinction is critical for both attack and defense.

```ruby
require 'weakref'
obj = Object.new
weak = WeakRef.new(obj)
obj = nil
GC.start
weak.__getobj__  # raises RefError - object was collected
```
