# frozen_string_literal: true

# SAMPLE MALICIOUS SCRIPT -- FOR TESTING ONLY
# Demonstrates obfuscation techniques used by real Ruby malware.
# All dangerous operations are COMMENTED OUT.
#
# Classification: MALICIOUS
# Techniques: T1027 (Obfuscation), T1059.007 (Scripting), T1055 (Injection)

require 'zlib'
require 'base64'

# Pattern 1: Char code array to string conversion
payload_bytes = [112, 117, 116, 115, 32, 34, 72, 101, 108, 108, 111, 34]
_payload_string = payload_bytes.pack('C*')
# DISABLED: eval(_payload_string)

# Pattern 2: XOR-encoded payload
xor_key = 0x42
encoded = [0x32, 0x37, 0x36, 0x31, 0x7a, 0x10].map { |b| b ^ xor_key }
_decoded = encoded.pack('C*')
# DISABLED: eval(_decoded)

# Pattern 3: Zlib compressed payload
compressed = Zlib::Deflate.deflate('puts "decompressed payload"')
_decompressed = Zlib::Inflate.inflate(compressed)
# DISABLED: eval(_decompressed)

# Pattern 4: String concatenation obfuscation
_cmd = 'sy' + 'st' + 'em'
_arg = 'who' + 'ami'
# DISABLED: Kernel.send(_cmd, _arg)

# Pattern 5: ObjectSpace manipulation for stealth
# DISABLED: ObjectSpace.each_object(Class) { |c| c.class_eval { ... } }

# Pattern 6: Method aliasing for persistence
# DISABLED: alias :original_require :require
# DISABLED: define_method(:require) { |name| inject_payload(name); original_require(name) }

# Pattern 7: Gem extension hook (supply chain)
# DISABLED: Gem.pre_install { |installer| inject_into_gem(installer) }

puts '[TEST] This script contains obfuscation patterns for ML training only'
