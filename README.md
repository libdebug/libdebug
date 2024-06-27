![logo](https://github.com/libdebug/libdebug/blob/dev/media/libdebug_logo_horiz.png?raw=true)
# libdebug
libdebug is an open source Python library to automate the debugging of a binary executable.

With libdebug you have full control of the flow of your debugged executable. With it you can:
- Access process memory and registers 
- Control the execution flow of the process
- Hook and hijack syscalls
- Hook and hijack signals
- Debug multithreaded applications with ease
- Seamlessly switch to GDB for interactive analysis
- Soon to be multiarch (currently only supports Linux AMD64)

When running the same executable multiple times, choosing efficient implementations can make the difference. For this reason, libdebug prioritizes performance.

## Project Links
Homepage: https://libdebug.org
Documentation: https://docs.libdebug.org

### Installation Requirements:
Ubuntu: \
`sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg` \
Debian: \
`sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg` \
Arch Linux: \
`sudo pacman -S python libelf libdwarf gcc make debuginfod` \
Fedora: \
`sudo dnf install -y python3 python3-devel kernel-devel binutils-devel libdwarf-devel`

## Install from PyPI
```bash
pip install libdebug
```

## Install from source
```bash
python3 -m pip install git+https://github.com/libdebug/libdebug.git
```
PyPy3 is supported but not recommended, as it performs worse on most of our tests.

If you want to stay up to date with the most cutting-edge features (and you don't mind being on an unstable branch) you can install from a different branch (e.g., dev).

```bash
git clone https://github.com/libdebug/libdebug.git
cd libdebug
git checkout dev
pip install .
```

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

# Kill the process
d.kill()
```

The above script will run the binary `test` in the working directory and stop at the function corresponding to the symbol "function". It will then print the value of the RAX register and kill the process.

There is so much more that can be done with libdebug. Please read the [documentation](https://docs.libdebug.org) to find out more.

## The cool stuff

```python
# TODO: Insert here a cool libdebug script that does something with signals / sycalls or multithreading. Also include comments and a quick explaination afterwards
```

## Attribution
If you intend to use libdebug in your work, please cite this repository using the following biblatex:

```biblatex
@software{libdebug_2024,
	title = {libdebug: an {Open} {Source} {Scriptable} {Python} {Debugger}},
	copyright = {MIT Licence},
	url = {https://libdebug.org},
	publisher = {libdebug.org},
	author = {TODO,INSERT},
	year = {2024},
}
```
