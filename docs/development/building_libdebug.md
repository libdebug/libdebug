---
icon: material/wrench
search:
    boost: 4
---
# :material-wrench: Building **libdebug** from source

Manually building **libdebug** from source is a straightforward process. This guide will walk you through the steps required to compile and install **libdebug** on your system.

## :chains: Resolving Dependencies
To install **libdebug**, you first need to have some dependencies that will not be automatically resolved. These dependencies are libraries, utilities and development headers which are required by **libdebug** to compile its internals during installation.

=== ":material-ubuntu: Ubuntu"
    ```bash
    sudo apt install -y python3 python3-dev g++ libdwarf-dev libelf-dev libiberty-dev
    ```

=== ":material-arch: Arch Linux"
    ```bash
    sudo pacman -S base-devel python3 elfutils libdwarf binutils
    ```

=== ":material-fedora: Fedora"
    ```bash
    sudo dnf install -y python3 python3-devel g++ elfutils-devel libdwarf-devel binutils-devel
    ```

=== ":material-debian: Debian"
    ```bash
    sudo apt install -y python3 python3-dev g++ libdwarf-dev libelf-dev libiberty-dev
    ```

=== ":material-linux: openSUSE"
    ```bash
    sudo zypper install -y gcc-c++ make python3 python3-devel libelf-devel libdwarf-devel binutils-devel
    ```

=== ":material-linux: Alpine Linux"
    ```bash
    sudo apk add -y python3 python3-dev py3-pip linux-headers elfutils-dev libdwarf-dev binutils-dev
    ```

!!! QUESTION "Is your distro missing?"
    If you are using a Linux distribution that is not included in this section, you can search for equivalent packages for your distro. Chances are the naming convention of your system's repository will only change a prefix or suffix.

## :construction_site: Building

To build **libdebug** from source, from the root directory of the repository, simply run the following command:

```bash
python3 -m pip install .
```

Alternatively, without cloning the repository, you can directly install **libdebug** from the GitHub repository using the following command:

```bash
python3 -m pip install git+https://github.com/libdebug/libdebug.git@<branch_or_commit>
```
Replace `<branch_or_commit>` with the desired branch or commit hash you want to install. If not specified, the default branch will be used.

!!! INFO "Editable Install"
    If you want to install **libdebug** in editable mode, allowing you to modify the source code and have those changes reflected immediately, you can use the following command, exclusively from a local clone of the repository:

    ```bash
    python3 -m pip install --no-build-isolation -Ceditable.rebuild=true -ve .
    ```

    This will ensure that every time you make changes to the source code, they will be immediately available without needing to reinstall the package, even for the compiled C++ extensions.

### Nanobind distribution modes

Source builds use linked nanobind 3 by default. This works on all supported
architectures, including i386 and Alpine, without a separate nanobind runtime
dependency. Python 3.10 and 3.11 receive interpreter-specific wheels; linked
builds on Python 3.12 and newer target `cp312-abi3`.

The published glibc x86_64 and AArch64 wheels use nanobind's split mode. Each
platform has one `cp310-abi3` libdebug wheel for regular CPython 3.10 and newer.
Pip also installs `nanobind-backend>=1.0`, which supplies the interpreter-specific
dispatcher. The wheel remains specific to its architecture and libc; it is not
a pure-Python wheel and does not support free-threaded Python.

To build a split wheel or editable installation on a supported glibc platform:

```bash
LIBDEBUG_NANOBIND_SPLIT=1 python3 -m pip wheel .
LIBDEBUG_NANOBIND_SPLIT=1 python3 -m pip install -e .
```

Use the environment setting rather than a CMake override: it selects the
extension ABI, wheel tag, build dependencies and runtime metadata together.
Leave it unset, or set it to `0`, for linked builds. Build caches are separated
by mode and interpreter. Isolated builds install their own build dependencies.
For `--no-build-isolation`, first install the requirements from
`[build-system]` in `pyproject.toml`, plus `nanobind-backend>=1.0` for split mode.

The external backend does not currently provide i386 or musllinux wheels.
Those distributions retain linked mode. Split wheels use the manylinux 2.28
floor and a shared system C++ runtime, as required by the backend.

All three native stubs are generated during compilation and installed beside
their extensions, together with the package's `py.typed` marker. The wheel CI
checks their contents and type-checks consumers from outside the source tree.
It also installs the same split artifact across CPython 3.10–3.14, with a
separate, non-blocking Python 3.15 probe.

Nanobind 3's STL casters and vector iterators provide the sequence construction
and iteration optimizations used by these bindings. Existing bindings have no
custom casters, trampolines, runtime-computed return policies or handwritten
Python sequence builders requiring migration. Class mutability and GIL
release behavior are preserved. LTO and nanobind's default size optimization
remain enabled; forcing `NOMINSIZE` did not consistently improve the measured
register, symbol and breakpoint workloads.

### :octicons-gear-24: Build Options

There are some configurable build options that can be set during the installation process, to avoid linking against certain libraries or to enable/disable specific features. These options can be set using environment variables before running the installation command.

| Option | Description | Default Value |
| --- | --- | --- |
| `USE_LIBDWARF` | Include `libdwarf`, which is used for symbol resolution and debugging information. | `True` |
| `USE_LIBELF` | Include `libelf`, which is used for reading ELF files. | `True` |
| `USE_LIBIBERTY` | Include `libiberty`, which is used for demangling C++ symbols. | `True` |

Changing these options can be done by setting the environment variable before running the installation command. For example, to disable `libdwarf`, you can run:

```bash
CMAKE_ARGS=-USE_LIBDWARF=OFF python3 -m pip install .
```

## :fontawesome-solid-helmet-safety: Testing Your Installation

We provide a comprehensive suite of tests to ensure that your installation is working correctly. Here's how you can run the tests:

```bash
cd test
python3 run_suite.py <suite>
```

We have different test suites available. By default, we run the `fast`, that skips some tests which require a lot of time to run.
You can specify which test suite to run using the `suite` option. The available test suites are:

| Suite Name | Description |
| --- | --- |
| `fast`   | Runs all but a few tests to verify full functionality of the library. |
| `slow`   | Runs the complete set of tests, including those that may take longer to execute. |
| `stress` | Runs a set of tests designed to detect issues in multithreaded processes. |
| `memory` | Runs a set of tests designed to detect memory leaks in **libdebug**. |

## :material-hammer-wrench: Troubleshooting

Here we list some common build errors you might encounter when building **libdebug** from source, along with their solutions.
If you encounter any of these errors while installing **libdebug** from PyPI, please open an [:octicons-issue-opened-24: Issue](https://github.com/libdebug/libdebug/issues) to help us improve the installation process.

----

**:fontawesome-solid-circle-exclamation: FileNotFoundError**{style="color:#ff7070"} : No such file or directory: `'[...]/jumpstart'`

!!! QUESTION "What's jumpstart?"
    `jumpstart` is the executable that is used to bootstrap the debugging process, by calling `PTRACE_TRACEME` before exeuting the target program.
    If building **libdebug** from source in editable mode, it might not be automatically installed in the correct location.<br><br>

To resolve this issue, you can manually install `jumpstart` by running the following command from the root directory of the repository:

```bash
gcc -o [ERROR_PATH] libdebug/ptrace/jumpstart/jumpstart.c -O3
```

**Parameters**

- Replace `[ERROR_PATH]` with the path where the `jumpstart` executable should be installed, as indicated in the error message.
<br><br>

----

**:fontawesome-solid-circle-exclamation: RuntimeError**{style="color:#ff7070"} : Autodetect executable for `ptrace_fpregs` layout not found at `[...]/autodetect_fpregs_layout`.

!!! QUESTION "What's going on?"
    This error indicates that the `autodetect_fpregs_layout` executable is missing. This executable is used to automatically detect the layout of the floating-point registers for the target architecture. If you are building **libdebug** from source in editable mode, it might not be automatically installed in the correct location.

To resolve this issue, you can manually install `autodetect_fpregs_layout` by running the following command from the root directory of the repository:

```bash
gcc -o [ERROR_PATH] [SRC_PATH] -O3
```

**Parameters**

- Replace `[ERROR_PATH]` with the path where the `autodetect_fpregs_layout` executable should be installed, as indicated in the error message.
- Choose `[SRC_PATH]` based on your architecture:

    === "<span style="font-size: 2em; vertical-align: middle;">:simple-intel:</span> (i386 / AMD64)"

        ``` 
        libdebug/ptrace/native/shared/x86_autodetect_fpregs_layout.c
        ```

    === "<span style="font-size: 2em; vertical-align: middle;">:simple-arm:</span> (AArch64)"

        ``` 
        libdebug/ptrace/native/aarch64/aarch64_autodetect_fpregs_layout.c
        ```
        Please note that for AArch64 this is just a dummy file, as the layout is fixed and does not require autodetection for the current implementation.
