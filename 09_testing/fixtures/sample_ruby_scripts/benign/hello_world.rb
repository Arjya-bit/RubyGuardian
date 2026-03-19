# frozen_string_literal: true

# A simple benign Ruby script for testing the ML classifier.
# This should be classified as benign with high confidence.

class Greeter
  def initialize(name)
    @name = name
  end

  def greet
    "Hello, #{@name}! Welcome to RubyGuardian."
  end

  def farewell
    "Goodbye, #{@name}!"
  end
end

if __FILE__ == $PROGRAM_NAME
  greeter = Greeter.new('World')
  puts greeter.greet
  puts greeter.farewell

  # Standard Ruby operations
  numbers = [1, 2, 3, 4, 5]
  sum = numbers.reduce(:+)
  puts "Sum: #{sum}"

  # File reading (benign)
  if File.exist?('README.md')
    lines = File.readlines('README.md').size
    puts "README has #{lines} lines"
  end
end
