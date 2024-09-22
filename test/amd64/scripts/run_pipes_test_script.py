#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger

d = debugger("binaries/run_pipes_test")

def on_enter_write(t, sh):
    if b"flag" in t.memory[t.syscall_arg1, 50]:
        t.memory[t.syscall_arg1, 50] = t.memory[t.syscall_arg1, 50].replace(b"flag{provola}", b"flag{nahmate}")

def strcmp_admin_mode(t, bp):
    t.regs.rax = 3

def on_signal_sigprovola(t, sc):
    print("SIGPROVOLA")

d.run(redirect_pipes=False)

bp = d.breakpoint(0x401218, callback=strcmp_admin_mode)

sh = d.handle_syscall("write", on_enter=on_enter_write)

sc = d.catch_signal(50, callback=on_signal_sigprovola)
d.signals_to_block = [50]

d.cont()

d.wait()

d.terminate()