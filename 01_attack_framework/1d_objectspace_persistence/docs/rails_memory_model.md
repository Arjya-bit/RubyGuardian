# Rails Memory Model and Persistence Opportunities

## How Rails Manages Memory

### Application Boot Sequence

When a Rails application boots, it creates a rich object graph that persists for
the lifetime of the process:

```
1. Ruby VM starts
2. Bundler loads all gems (hundreds of modules/classes)
3. Rails::Application is initialized
4. config/application.rb executes
5. All initializers run (config/initializers/*.rb)
6. Routes are compiled into a routing table
7. ActiveRecord establishes connection pool
8. ActionController loads controller classes
9. The app is ready to serve requests
```

All objects created during boot persist as long as the process runs. This creates
a large attack surface for hiding payloads among legitimate objects.

### Long-Lived Rails Objects

These objects survive for the entire process lifetime and serve as potential
GC anchors:

| Object | Access Path | Type |
|--------|------------|------|
| Application instance | `Rails.application` | Rails::Application |
| Configuration | `Rails.application.config` | Rails::Application::Configuration |
| Route set | `Rails.application.routes` | ActionDispatch::Routing::RouteSet |
| Middleware stack | `Rails.application.middleware` | ActionDispatch::MiddlewareStack |
| Logger | `Rails.logger` | ActiveSupport::Logger |
| Cache store | `Rails.cache` | ActiveSupport::Cache::Store |
| Connection pool | `ActiveRecord::Base.connection_pool` | ConnectionPool |
| Inflections | `ActiveSupport::Inflector` | Module |
| Callbacks | Various `_callbacks` class variables | Array |

### Request Lifecycle

```
Request arrives at Puma/Unicorn
  -> Rack middleware stack processes request
    -> Router matches route to controller#action
      -> Controller instance created (NEW per request)
        -> Before filters execute
          -> Action method executes
            -> View renders
          -> After filters execute
        -> Response sent
      -> Controller instance eligible for GC
    -> Middleware unwinds
  -> Response sent to client
```

**Key Insight**: Controller instances are short-lived, but the controller CLASS
is long-lived. Attaching payloads to the class (not instances) provides persistence.

### ActiveSupport::Callbacks

Rails uses an extensive callback system. Each model and controller class maintains
callback chains as class-level data:

```ruby
# These callback chains persist as class-level data
class User < ApplicationRecord
  before_save :hash_password
  after_create :send_welcome_email
  # Internally stored in User._save_callbacks (an ActiveSupport::CallbackChain)
end
```

An attacker can append to these callback chains, causing payload execution on
every model save, controller action, etc.

### ActiveSupport::Notifications

Rails instruments many internal events. Subscribers persist for the process lifetime:

```ruby
# This subscriber will fire on every SQL query for the life of the process
ActiveSupport::Notifications.subscribe("sql.active_record") do |*args|
  event = ActiveSupport::Notifications::Event.new(*args)
  # Attacker payload here - sees every SQL query
end
```

### Middleware Injection

Rack middleware objects persist for the process lifetime. Injecting a middleware
provides code execution on every request:

```ruby
# Middleware is instantiated once and persists
Rails.application.middleware.use(MaliciousMiddleware)
```

### Class Variables and Instance Variables on Modules

Class variables (`@@var`) on modules/classes are GC roots. Instance variables on
class objects (`@var` inside `class << self`) are also persistent:

```ruby
# Both of these persist as long as the User class exists (forever)
class User
  @@hidden_data = "payload"       # Class variable - GC root
  @hidden_data = "payload"        # Instance variable on the class object
end
```

### Thread-Local Storage

Puma uses a thread pool. Thread-local variables persist for the life of the thread:

```ruby
Thread.current[:payload] = "hidden data"
# This persists across requests handled by this thread
```

### Frozen String Pool

Rails freezes many strings for performance. These enter the frozen string pool
and are never collected:

```ruby
# With frozen_string_literal: true, all string literals are interned
"payload_marker".freeze  # Never garbage collected
```

## Detection Opportunities for Defenders

1. **Baseline object counts at boot** - Compare `ObjectSpace.count_objects` after
   boot vs. during operation. Unexpected growth in T_CLASS or T_MODULE is suspicious.

2. **Audit callback chains** - Periodically dump all `_callbacks` on model and
   controller classes. Compare against source code to find injected callbacks.

3. **Monitor middleware stack** - Compare `Rails.application.middleware` against
   a known-good list.

4. **Check notification subscribers** - Enumerate
   `ActiveSupport::Notifications.notifier.listeners_for(name)` for unexpected
   subscribers.

5. **Heap snapshots** - Use `ObjectSpace.dump_all` to create periodic snapshots
   and diff them to find injected objects.
