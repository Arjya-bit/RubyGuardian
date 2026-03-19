# frozen_string_literal: true

# A simple benign web server for testing the ML classifier.
# Uses standard library only - should be classified as benign.

require 'webrick'
require 'json'

server = WEBrick::HTTPServer.new(Port: 8080, Logger: WEBrick::Log.new('/dev/null'))

server.mount_proc '/' do |_req, res|
  res['Content-Type'] = 'application/json'
  res.body = JSON.generate({
    status: 'ok',
    message: 'RubyGuardian test server',
    timestamp: Time.now.utc.iso8601
  })
end

server.mount_proc '/health' do |_req, res|
  res['Content-Type'] = 'text/plain'
  res.body = 'healthy'
end

trap('INT') { server.shutdown }

if __FILE__ == $PROGRAM_NAME
  puts 'Starting test server on port 8080...'
  server.start
end
