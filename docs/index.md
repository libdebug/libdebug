# Home
<div style="text-align: center;">
    <img src="assets/libdebug_logo_horiz_light.webp#only-light" loading="lazy" width="512" />
    <img src="assets/libdebug_logo_horiz_dark.webp#only-dark" loading="lazy" width="512" />
</div>

---

[![Static Badge](https://img.shields.io/badge/libdebug.org--white?style=for-the-badge&labelColor=%23009944&color=teal&link=https%3B%2F%2Flibdebug.org)](https://libdebug.org)&nbsp;&nbsp;&nbsp;
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.13151549-blue?style=for-the-badge)](https://doi.org/10.5281/zenodo.13151549)&nbsp;&nbsp;&nbsp;
[![Built with Material for MkDocs](https://img.shields.io/badge/Material_for_MkDocs-526CFE?style=for-the-badge&logo=MaterialForMkDocs&logoColor=white)](https://squidfunk.github.io/mkdocs-material/)



## :material-lightning-bolt: Quick Start
Welcome to libdebug! This powerful Python library can be used to debug your binary executables programmatically, providing a robust, user-friendly interface. Debugging multithreaded applications can be a nightmare, but libdebug has you covered. Hijack, and manage signals and syscalls with a simple API.

!!! INFO "Supported Systems"
    libdebug currently supports Linux under the x86_64 and AArch64 architectures. Other operating systems and architectures are not supported at this time.

## Dependencies
To install libdebug, you first need to have some dependencies that will not be automatically resolved. These dependencies are libraries, utilities and development headers which are required by libdebug to compile its internals during installation.

=== ":material-ubuntu: Ubuntu"
    ```bash
    sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg
    ```

=== ":material-debian: Debian"
    ```bash
    sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg
    ```

=== ":material-arch: Arch Linux"
    ```bash
    sudo pacman -S python libelf libdwarf gcc make debuginfod
    ```

=== ":material-fedora: Fedora"
    ```bash
    sudo dnf install -y python3 python3-devel kernel-devel binutils-devel libdwarf-devel
    ```

!!! QUESTION "Is your distro missing?"
    If you are using a Linux distribution that is not included in this section, you can search for equivalent packages for your distro. Chances are the naming convention of your system's repository will only change a prefix or suffix.


## Installation
Installing libdebug once you have dependencies is as simple as running the following command:

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

!!! NOTE
    The test folder includes the `Makefile` that was used to build the required binaries for transparency. However, the compiled binaries may differ due to scheduling, hardware, and compiler versions. Some tests have hardcoded absolute addresses and will likely fail as a result.

## Your First Script
Now that you have libdebug installed, you can start using it in your scripts. Here is a simple example of how to use libdebug to debug a binary:

```python title="libdebug's Hello World!"
from libdebug import debugger

d = debugger("./test") # (1)

# Start debugging from the entry point
d.run() # (2)

my_breakpoint = d.breakpoint("function") # (3)

# Continue the execution until the breakpoint is hit
d.cont() # (4)

# Print RAX
print(f"RAX is {hex(d.regs.rax)}") # (5)
```

1. A debugger is created for the `test` executable
2. The process is spawned and the entry point is reached
3. A breakpoint is placed at the symbol `<function>` in the binary
4. A continuation command is issued, execution resumes
5. The value of the RAX register is read and printed

## Conflicts with other Python packages
!!! BUG "Using pwntools alongside libdebug"
    The current version of libdebug is incompatible with [pwntools](https://github.com/Gallopsled/pwntools).

    While having both installed in your Python environment is not a problem, starting a process with pwntools in a libdebug script will cause unexpected behaviors as a result of some race conditions.

Examples of some known issues include:

- `ptrace` not intercepting SIGTRAP signals when the process is run with pwntools. This behavior is described in [:material-github: Issue #48](https://github.com/libdebug/libdebug/issues/48).
- Attaching libdebug to a process that was started with pwntools with `shell=True` will cause the process to attach to the shell process instead. This behavior is described in [:material-github: Issue #57](https://github.com/libdebug/libdebug/issues/57).

## :material-format-quote-open: Cite Us
Need to cite libdebug in your research? Use the following BibTeX entry:

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