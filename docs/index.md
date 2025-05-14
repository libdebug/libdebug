---
search:
    boost: 2
---
# Home
<div style="text-align: center;">
    <img src="assets/libdebug_logo_horiz_light.webp#only-light" loading="lazy" width="512" />
    <img src="assets/libdebug_logo_horiz_dark.webp#only-dark" loading="lazy" width="512" />
</div>

---

[![Static Badge](https://img.shields.io/badge/libdebug.org--white?style=for-the-badge&labelColor=%23009944&color=teal&link=https%3B%2F%2Flibdebug.org)](https://libdebug.org)&nbsp;&nbsp;&nbsp;
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.13151549-blue?style=for-the-badge)](https://doi.org/10.5281/zenodo.13151549)&nbsp;&nbsp;&nbsp;
![PyPI - Downloads](https://img.shields.io/pypi/dm/libdebug?style=for-the-badge)

## :material-lightning-bolt: Quick Start
Welcome to **libdebug**! This powerful Python library can be used to debug your binary executables programmatically, providing a robust, user-friendly interface. Debugging multithreaded and multiprocess applications can be a nightmare, but **libdebug** has you covered. Hijack and manage signals and syscalls through a simple API.

!!! tip "Did you know?"
    With **libdebug**, you can easily interact with the **standard input, output, and error** of the debugged process. This means you can send data to and receive data from the process programmatically, making it easier to automate your debugging tasks.

!!! INFO "Supported Systems"
    **libdebug** currently supports Linux under the x86_64, x86 and ARM64 architectures. Other operating systems and architectures are not supported at this time.

## Dependencies
To install **libdebug**, you first need to have some dependencies that will not be automatically resolved. These dependencies are libraries, utilities and development headers which are required by **libdebug** to compile its internals during installation.

=== ":material-ubuntu: Ubuntu"
    ```bash
    sudo apt install -y python3 python3-dev g++ libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg
    ```

=== ":material-arch: Arch Linux"
    ```bash
    sudo pacman -S python libelf libdwarf gcc make debuginfod
    ```

=== ":material-fedora: Fedora"
    ```bash
    sudo dnf install -y python3 python3-devel kernel-devel g++ binutils-devel libdwarf-devel
    ```

=== ":material-debian: Debian"
    ```bash
    sudo apt install -y python3 python3-dev g++ libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg
    ```

!!! QUESTION "Is your distro missing?"
    If you are using a Linux distribution that is not included in this section, you can search for equivalent packages for your distro. Chances are the naming convention of your system's repository will only change a prefix or suffix.


## Installation
Installing **libdebug** once you have dependencies is as simple as running the following command:

=== "stable"
    ```bash
    python3 -m pip install libdebug
    ```
=== "development"
    ```bash
    python3 -m pip install git+https://github.com/libdebug/libdebug.git@dev
    ```

If you want to test your installation when installing from source, we provide a suite of tests that you can run:

```bash title="Testing your installation"
cd test
python run_suite.py
```

## Your First Script
Now that you have **libdebug** installed, you can start using it in your scripts. Here is a simple example of how to use **libdebug** to debug an executable:

```python title="libdebug's Hello World!"
from libdebug import debugger

def callback(thread, bp) -> None:
	# This callback will be called when the breakpoint is hit
	print(f"RDX is {hex(thread.regs.rdx)}")
	print(f"This is the {bp.hit_count} time the breakpoint was hit")

d = debugger("./test") # (1)!

# Start the process
io = d.run() # (2)!

my_breakpoint = d.breakpoint("function", hardware=True, file="binary") # (3)!
my_callback_breakpoint = d.bp("f2", callback=callback, file="binary") # (4)!

# Continue the execution
d.cont() # (5)!

# Interact with the process
io.sendline(b"Hello world!") # (6)!
io.recvuntil(b"libdebug is like sushi") # (7)!

# Print RAX. This will execute as soon as the process is stopped
print(f"RAX is {hex(d.regs.rax)}") # (8)!

# Write to memory
d.memory[0x10ad, 8, "binary"] = b"Hello!\x00\x00" # (9)!
```

1. A debugger is created for the `test` executable
2. The process is spawned and the entry point is reached
3. A breakpoint without a callback is set on the function `function` in the binary
4. A breakpoint with a callback is set on the function `f2` in the binary. Here, we use an alias for `d.breakpoint()`
5. A continuation command is issued, execution resumes
6. Send `Hello world!` to the standard input of the process
7. Wait for the process to print `libdebug is like sushi` on the standard output
8. The value of the RAX register is read and printed when the process is stopped at the `my_breakpoint` breakpoint
9. A memory write is performed at address `0x10ad` in the binary

The above script will run the binary `test` in the working directory and set two breakpoints: one at the function `function` and another at `f2`. 

The first breakpoint has no callback, so it will just stop the execution and wait for your script to interact with the process. When the process stops at this breakpoint, you can read and write memory, access registers, and so on. In the example, we print the value of the RAX register and write a string to memory. Then, we continue the execution of the process.

The second breakpoint has a callback that will be called when the breakpoint is hit. Inside a callback, you can interact with the process, read and write memory, access registers, and so on. At the end of the callback, libdebug will automatically continue the execution of the process.

## Conflicts with other Python packages
!!! BUG "Using pwntools alongside **libdebug**"
    The current version of **libdebug** is incompatible with [pwntools](https://github.com/Gallopsled/pwntools).

    While having both installed in your Python environment is not a problem, starting a process with pwntools in a **libdebug** script will cause unexpected behaviors as a result of some race conditions.

Examples of some known issues include:

- `ptrace` not intercepting SIGTRAP signals when the process is run with pwntools. This behavior is described in [:octicons-issue-opened-24: Issue #48](https://github.com/libdebug/libdebug/issues/48).
- Attaching **libdebug** to a process that was started with pwntools with `shell=True` will cause the process to attach to the shell process instead. This behavior is described in [:octicons-issue-opened-24: Issue #57](https://github.com/libdebug/libdebug/issues/57).

!!! TIP "Using **libdebug** with pwntools"

    <div class="grid cards" markdown">

    -   :no_entry_sign: __DONT! (please just don't even try)__
        <div markdown style="--md-code-hl-color:#E55050; --md-code-hl-color--light: #4a2728">

        ```python hl_lines="4 5" 
        from libdebug import debugger
        from pwn import *

        io = process("./provola") # (1)!
        d.attach(io.pid)
        ...
        leak = u64(io.recvline())
        value = 0xbadf00d
        fmtstr = fmtstr_payload(6, {leak: value})
        io.sendline(fmtstr.encode()) # (2)!
        ```

        1. The process is started with pwntools, then **libdebug** is attached to it
        2. The payload is sent to the process using **pwntools**
        </div>

    -   :white_check_mark: __DO (if you need to)__
        <div markdown style="--md-code-hl-color:#129990; --md-code-hl-color--light: #274a39">

        ```python hl_lines="4 5" 
        from libdebug import debugger
        from pwn import fmtstr_payload, u64

        d = debugger("./provola") # (1)!
        io = d.run()
        ...
        leak = u64(io.recvline())
        value = 0xbadf00d
        fmtstr = fmtstr_payload(6, {leak: value})
        io.sendline(fmtstr.encode()) # (2)!
        ```

        1. The process is started with **libdebug**
        2. The payload is sent to the process using **libdebug**
        </div>

    </div>

## :fontawesome-solid-clock-rotate-left: Older versions of the documentation
The documentation for versions of **libdebug** older that 0.7.0 has to be accessed manually at [http://docs.libdebug.org/archive/VERSION](http://docs.libdebug.org/archive/VERSION), where `VERSION` is the version number you are looking for.

## :material-format-quote-open: Cite Us
We have a poster on **libdebug**. If you use **libdebug** in your research, you can cite the associated poster paper:

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

Need to cite **libdebug** as software used in your work? This is the way to cite us:

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