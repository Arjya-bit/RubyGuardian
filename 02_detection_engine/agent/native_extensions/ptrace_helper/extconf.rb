require 'mkmf'

have_header('sys/ptrace.h')
have_header('sys/user.h')
have_header('sys/wait.h')

$CFLAGS << ' -Wall -Wextra -std=c11'

create_makefile('ptrace_helper')
