#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger, libcontext

"""
Single thread test
"""
d = debugger("../binaries/amd64/basic_test")

# libcontext.terminal = ["tmux", "splitw", "-h"]
# libcontext.terminal = ["gnome-terminal", "--tab", "--"]

d.run()

bp = d.breakpoint("register_test")

d.step()
d.step()

print(hex(d.regs.rip))

d.gdb()

print(hex(d.regs.rip))

d.cont()
d.wait()

print(hex(d.regs.rip))

d.step()

print(hex(d.regs.rip))

d.kill()

"""
Multi thread test 1
"""
d = debugger("../binaries/amd64/multithread_input")

d.run(redirect_pipes=False)

# Before other threads are created
d.bp(0x12e1, file="binary")

d.cont()

d.wait()


# Continue until all the threads are created
d.gdb()

assert len(d.threads) > 1

d.kill()


"""
Multi thread test 2
"""
d = debugger("../binaries/amd64/multithread_input")

d.run(redirect_pipes=False)

# After other threads are created
d.bp(0x1390, file="binary")

d.cont()

d.wait()

# Continue and input until a couple of threads finish their execution
d.gdb()

assert len([t for t in d.threads if t.dead]) > 1

d.kill()
