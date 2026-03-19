# frozen_string_literal: true

module RubyGuardian
  module Shared
    # Detect operating system, architecture, and Ruby environment
    # Used by attack modules to select platform-specific techniques
    class PlatformDetector
      PlatformInfo = Struct.new(
        :os, :os_version, :arch, :ruby_version, :ruby_engine,
        :container, :vm, :hostname, :username, :pid,
        keyword_init: true
      )

      class << self
        def detect
          PlatformInfo.new(
            os: detect_os,
            os_version: detect_os_version,
            arch: detect_arch,
            ruby_version: RUBY_VERSION,
            ruby_engine: RUBY_ENGINE,
            container: detect_container?,
            vm: detect_vm?,
            hostname: detect_hostname,
            username: detect_username,
            pid: Process.pid
          )
        end

        def linux?
          RUBY_PLATFORM.include?('linux')
        end

        def windows?
          RUBY_PLATFORM =~ /mswin|mingw|cygwin/
        end

        def macos?
          RUBY_PLATFORM.include?('darwin')
        end

        def x86_64?
          RUBY_PLATFORM.include?('x86_64') || RUBY_PLATFORM.include?('x64')
        end

        def arm?
          RUBY_PLATFORM.include?('arm') || RUBY_PLATFORM.include?('aarch64')
        end

        private

        def detect_os
          case RUBY_PLATFORM
          when /linux/   then :linux
          when /darwin/  then :macos
          when /mswin|mingw|cygwin/ then :windows
          when /freebsd/ then :freebsd
          else :unknown
          end
        end

        def detect_os_version
          if linux?
            File.read('/etc/os-release').match(/VERSION_ID="?([^"\n]+)/)&.captures&.first
          elsif macos?
            `sw_vers -productVersion`.strip
          elsif windows?
            `ver`.strip
          end
        rescue StandardError
          'unknown'
        end

        def detect_arch
          case RUBY_PLATFORM
          when /x86_64|x64|amd64/ then :x86_64
          when /i[3-6]86/         then :x86
          when /aarch64|arm64/    then :arm64
          when /arm/              then :arm
          else :unknown
          end
        end

        def detect_container?
          return true if File.exist?('/.dockerenv')
          return true if File.exist?('/run/.containerenv')

          if File.exist?('/proc/1/cgroup')
            cgroup = File.read('/proc/1/cgroup')
            return true if cgroup.include?('docker') || cgroup.include?('containerd')
          end

          false
        rescue StandardError
          false
        end

        def detect_vm?
          return false unless linux?

          indicators = []

          # Check DMI data
          if File.exist?('/sys/class/dmi/id/product_name')
            product = File.read('/sys/class/dmi/id/product_name').strip.downcase
            indicators << true if product =~ /virtualbox|vmware|kvm|qemu|xen|hyper-v/
          end

          # Check for common VM artifacts
          indicators << File.exist?('/dev/vboxguest')
          indicators << File.exist?('/usr/bin/vmware-toolbox-cmd')

          indicators.any?
        rescue StandardError
          false
        end

        def detect_hostname
          Socket.gethostname
        rescue StandardError
          'unknown'
        end

        def detect_username
          ENV['USER'] || ENV['USERNAME'] || 'unknown'
        end
      end
    end
  end
end
