![logo](https://github.com/libdebug/libdebug/blob/dev/media/libdebug_header.png?raw=true)
# libdebug [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.13151549.svg)](https://doi.org/10.5281/zenodo.13151549)

libdebug is an open source Python library for programmatic debugging of userland binary executables. 

libdebug provides a comprehensive set of building blocks designed to facilitate the development of debugging tools for different purposes, including reverse engineering and exploitation. **Build Your Own Debugger!**

With libdebug you have full control of the flow of your debugged executable. With it you can:
- Access process memory and registers 
- Control the execution flow of the process
- Handle and hijack syscalls
- Catch and hijack signals
- Debug multithreaded applications with ease
- Seamlessly switch to GDB for interactive analysis
- Multiarch: currently supports Linux AMD64 and AArch64 and i386 (both native and in 32-bit compatibility mode)

When running the same executable multiple times, choosing efficient implementations can make the difference. For this reason, libdebug prioritizes performance.

## Project Links
Homepage: https://libdebug.org  \
Documentation: https://docs.libdebug.org

## Installation
```bash
python3 -m pip install libdebug
```

Please visit the [build guide](https://docs.libdebug.org/development/building_libdebug/) for more information on how to manually build libdebug from source.

## Your first script

Now that you have libdebug installed, you can start using it in your scripts. Here is a simple example of how to use libdebug to debug a binary:

```python

from libdebug import debugger

d = debugger("./test")

# Start debugging from the entry point
d.run()

my_breakpoint = d.breakpoint("function")

# Continue the execution until the breakpoint is hit
d.cont()

# Print RAX
print(f"RAX is {hex(d.regs.rax)}")

# Write to memory
d.memory[0x10ad, 8, "binary"] = b"Hello!\x00\x00"

# Continue the execution
d.cont()
```

The above script will run the binary `test` in the working directory and stop at the function corresponding to the symbol "function". It will then print the value of the RAX register and kill the process.

There is so much more that can be done with libdebug. Please read the [documentation](https://docs.libdebug.org/) to find out more.

## The cool stuff

libdebug offers many advanced features. Take a look at this script doing magic with signals:

```python
from libdebug import debugger, libcontext

libcontext.terminal = ['tmux', 'splitw', '-h']

# Define signal catchers
def catcher_SIGUSR1(thread, catcher) -> None:
    thread.signal = 0x0
    print(f"SIGUSR1: Signal number {catcher}")

def catcher_SIGINT(thread, catcher) -> None:
    print(f"SIGINT: Signal number {catcher}")

def catcher_SIGPIPE(thread, catcher) -> None:
    print(f"SIGPIPE: Signal number {catcher}")

def handler_geteuid(thread, handler) -> None:
	thread.regs.rax = 0x0

# Initialize the debugger
d = debugger('/path/to/executable', continue_to_binary_entrypoint=False, aslr=False)

# Register signal catchers
catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
catcher2 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
catcher3 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

# Register signal hijackings
d.hijack_signal("SIGQUIT", "SIGTERM")
d.hijack_signal("SIGINT", "SIGPIPE", recursive=True)

# Define which signals to block
d.signals_to_block = ["SIGPOLL", "SIGIO", "SIGALRM"]

d.handle_syscall("geteuid", on_exit=handler_geteuid)

# Continue execution
d.cont()

# Disable the catchers after execution
catcher1.disable()
catcher2.disable()
catcher3.disable()

bp = d.breakpoint(0xdeadc0de, hardware=True)

d.cont()
d.wait()

d.gdb()
```

## Auto Interrupt on Command
libdebug also allows you to make all commands execute as soon as possible, without having to wait for a stopping event. To enable this mode, you can use the `auto_interrupt_on_command=True` 

```python
from libdebug import debugger

d = debugger("/path/to/executable", auto_interrupt_on_command=True)

pipes = d.run()

bp = d.breakpoint("function")

d.cont()

# Read shortly after the cont is issued
# The process is forcibly stopped to read the register
value = d.regs.rax
print(f"RAX is {hex(value)}")

system_offset = d.symbols.filter("system")[0].start
libc_base = d.maps.filter("libc")[0].base

system_address = libc_base + system_offset

d.memory[0x12ebe, 8, "libc"] = int.to_bytes(system_address, 8, "little")

d.cont()
d.wait()

# Here we should be at the breakpoint

# This value is read while the process is stopped at the breakpoint
ip_value = d.regs.rip

print(f"RIP is {hex(ip_value)}")

d.kill()
```

## Attribution
If you intend to use libdebug in your projects, please cite the software using the following bibtex:
```bibtex
@software{libdebug_2024,
	title = {libdebug: {Build} {Your} {Own} {Debugger}},
	copyright = {MIT Licence},
	url = {https://libdebug.org},
	publisher = {libdebug.org},
	author = {Digregorio, Gabriele and Bertolini, Roberto Alessandro and Panebianco, Francesco and Polino, Mario},
	year = {2024},
	doi = {10.5281/zenodo.13151549},
}
```

We've also published a poster on libdebug. If you use libdebug in your research, you can cite the associated short paper:
```bibtex
@inproceedings{10.1145/3658644.3691391,
author = {Digregorio, Gabriele and Bertolini, Roberto Alessandro and Panebianco, Francesco and Polino, Mario},
title = {Poster: libdebug, Build Your Own Debugger for a Better (Hello) World},
year = {2024},
isbn = {9798400706363},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3658644.3691391},
doi = {10.1145/3658644.3691391},
booktitle = {Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security},
pages = {4976–4978},
numpages = {3},
keywords = {debugging, reverse engineering, software security},
location = {Salt Lake City, UT, USA},
series = {CCS '24}
}
```
