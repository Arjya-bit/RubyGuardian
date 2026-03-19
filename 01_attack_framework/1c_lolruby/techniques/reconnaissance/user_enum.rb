# frozen_string_literal: true

# =============================================================================
# RubyGuardian - LoLRuby Phase 1c
# Technique: User Enumeration
# LoLRuby ID: LR-R-004
# MITRE ATT&CK: T1087.001 - Account Discovery: Local Account
# =============================================================================
#
# EDUCATIONAL PURPOSE ONLY
# Demonstrates how Ruby's Etc module and file system access can enumerate
# local user accounts, groups, and associated metadata without external tools.
#
# DETECTION METHODS:
# - Monitor access to /etc/passwd, /etc/shadow, /etc/group
# - File access auditing (auditd) on user database files
# - Watch for Ruby processes calling Etc module functions
# - Monitor /home directory listing operations from non-standard processes
# =============================================================================

require 'etc'
require 'json'
require 'logger'

module RubyGuardian
  module LoLRuby
    module Reconnaissance
      class UserEnum
        attr_reader :results, :logger

        def initialize(log_output: $stdout)
          @results = { users: [], groups: [], sudo_users: [], logged_in: [] }
          @logger = Logger.new(log_output)
          @logger.progname = 'LoLRuby::UserEnum'
        end

        def describe
          puts <<~DESC
            LoLRuby Technique: User Enumeration (LR-R-004)
            MITRE ATT&CK: T1087.001 - Account Discovery: Local Account

            Ruby Methods Used:
              - Etc.passwd { |u| ... } — Iterate all passwd entries
              - Etc.group { |g| ... } — Iterate all group entries
              - Etc.getlogin — Get current logged-in user
              - Dir['/home/*'] — List home directories
              - File.read('/etc/passwd') — Raw passwd parsing

            Why It Works:
              The Etc module provides a Ruby-native interface to the system user
              database. Unlike reading /etc/passwd directly, it works through
              NSS (Name Service Switch), capturing LDAP/NIS users too.

            Detection:
              - Audit rules on /etc/passwd, /etc/group, /etc/shadow
              - Monitor Etc module usage in Ruby process strace output
              - Alert on bulk user database enumeration patterns
          DESC
        end

        # Enumerate all local users via Etc module
        # Educational: Etc.passwd iterates through NSS, not just /etc/passwd
        def enumerate_users
          @logger.info("Enumerating local users via Etc module")
          users = []

          Etc.passwd do |entry|
            user_info = {
              name: entry.name,
              uid: entry.uid,
              gid: entry.gid,
              gecos: entry.gecos,
              home: entry.dir,
              shell: entry.shell,
              is_system: entry.uid < 1000 && entry.uid != 0,
              is_root: entry.uid == 0,
              has_login_shell: login_shell?(entry.shell),
              home_exists: Dir.exist?(entry.dir),
              home_writable: (File.writable?(entry.dir) rescue false)
            }
            users << user_info
          end

          @results[:users] = users
          @logger.info("Found #{users.length} users (#{users.count { |u| u[:has_login_shell] }} with login shells)")
          users
        end

        # Enumerate all groups
        # Educational: Group membership reveals privilege levels
        def enumerate_groups
          @logger.info("Enumerating local groups via Etc module")
          groups = []

          Etc.group do |entry|
            group_info = {
              name: entry.name,
              gid: entry.gid,
              members: entry.mem
            }
            groups << group_info
          end

          @results[:groups] = groups
          @logger.info("Found #{groups.length} groups")
          groups
        end

        # Find users with sudo/wheel privileges
        # Educational: These users are high-value targets for privilege escalation
        def find_privileged_users
          @logger.info("Identifying privileged users")
          privileged = []

          # Check sudo/wheel group membership
          sudo_groups = ['sudo', 'wheel', 'admin', 'root']
          sudo_groups.each do |group_name|
            begin
              group = Etc.getgrnam(group_name)
              group.mem.each do |member|
                privileged << { user: member, via: "#{group_name} group" }
              end
            rescue ArgumentError
              # Group doesn't exist on this system
            end
          end

          # Check /etc/sudoers if readable
          sudoers_path = '/etc/sudoers'
          if File.readable?(sudoers_path)
            File.readlines(sudoers_path).each do |line|
              next if line.strip.start_with?('#') || line.strip.empty?
              if line =~ /^(\w+)\s+ALL\s*=/
                privileged << { user: $1, via: 'sudoers file' }
              end
            end
          end

          @results[:sudo_users] = privileged.uniq
          @logger.info("Found #{privileged.length} privileged user entries")
          privileged
        end

        # Enumerate currently logged-in users
        # Educational: Shows who is active, useful for attacker situational awareness
        def enumerate_logged_in
          @logger.info("Enumerating logged-in users")
          logged_in = []

          # Method 1: /var/run/utmp parsing (simplified)
          # Method 2: who command via Ruby
          begin
            who_output = `who 2>/dev/null`
            who_output.each_line do |line|
              parts = line.split
              next if parts.length < 3
              logged_in << {
                user: parts[0],
                terminal: parts[1],
                login_time: parts[2..3]&.join(' ')
              }
            end
          rescue StandardError
            # Fall back to Etc.getlogin for current user only
            current = Etc.getlogin
            logged_in << { user: current, terminal: 'current', login_time: 'now' } if current
          end

          @results[:logged_in] = logged_in
          @logger.info("Found #{logged_in.length} logged-in sessions")
          logged_in
        end

        # Discover home directory contents
        # Educational: Home directories reveal user activity and potential targets
        def enumerate_home_dirs
          @logger.info("Enumerating home directory contents")
          home_info = {}

          home_dirs = Dir.glob('/home/*').select { |d| File.directory?(d) }
          home_dirs << '/root' if File.directory?('/root')

          home_dirs.each do |home|
            username = File.basename(home)
            info = { path: home, readable: File.readable?(home) }

            if info[:readable]
              # Look for interesting dotfiles and directories
              interesting_items = []
              dotfiles = Dir.glob("#{home}/.*", File::FNM_DOTMATCH).reject { |f| f.end_with?('.', '..') }

              dotfiles.each do |dotfile|
                name = File.basename(dotfile)
                interesting_items << {
                  name: name,
                  type: File.directory?(dotfile) ? 'directory' : 'file',
                  readable: File.readable?(dotfile)
                }
              end

              info[:dotfiles] = interesting_items
              info[:has_ssh] = File.directory?("#{home}/.ssh")
              info[:has_bash_history] = File.exist?("#{home}/.bash_history")
              info[:has_aws_config] = File.directory?("#{home}/.aws")
              info[:has_kube_config] = File.exist?("#{home}/.kube/config")
              info[:has_docker_config] = File.exist?("#{home}/.docker/config.json")
            end

            home_info[username] = info
          end

          @results[:home_dirs] = home_info
          home_info
        end

        # Run full enumeration
        def full_enumeration
          enumerate_users
          enumerate_groups
          find_privileged_users
          enumerate_logged_in
          enumerate_home_dirs
          @results
        end

        # Generate report
        def report(format: :json)
          case format
          when :json
            JSON.pretty_generate({
              scan_time: Time.now.iso8601,
              hostname: Socket.gethostname,
              current_user: Etc.getlogin,
              current_uid: Process.uid,
              current_gid: Process.gid,
              results: @results
            })
          when :text
            generate_text_report
          end
        end

        private

        def login_shell?(shell)
          return false unless shell
          non_login = ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin', '/bin/sync']
          !non_login.include?(shell)
        end

        def generate_text_report
          lines = ["=" * 60, "LoLRuby User Enumeration Report", "=" * 60]
          lines << "Current User: #{Etc.getlogin} (UID: #{Process.uid})"
          lines << ""

          if @results[:users]
            login_users = @results[:users].select { |u| u[:has_login_shell] && !u[:is_system] }
            lines << "Users with login shells (#{login_users.length}):"
            login_users.each do |u|
              flag = u[:is_root] ? ' [ROOT]' : ''
              lines << "  #{u[:name]} (UID:#{u[:uid]}) #{u[:home]} #{u[:shell]}#{flag}"
            end
          end

          if @results[:sudo_users] && !@results[:sudo_users].empty?
            lines << "\nPrivileged Users:"
            @results[:sudo_users].each { |u| lines << "  #{u[:user]} (via #{u[:via]})" }
          end

          if @results[:logged_in] && !@results[:logged_in].empty?
            lines << "\nCurrently Logged In:"
            @results[:logged_in].each { |u| lines << "  #{u[:user]} on #{u[:terminal]}" }
          end

          lines.join("\n")
        end
      end
    end
  end
end
