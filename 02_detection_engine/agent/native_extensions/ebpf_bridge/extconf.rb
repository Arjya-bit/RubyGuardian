require 'mkmf'

have_header('linux/bpf.h')
have_header('sys/syscall.h')
have_library('elf')
have_library('bpf')

$CFLAGS << ' -Wall -Wextra -std=c11'

create_makefile('ebpf_bridge')
