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

## Common Build Errors

Here we list some common build errors you might encounter when building **libdebug** from source, along with their solutions.
If you encounter any of these errors while installing **libdebug** from PyPI, please open an issue on the [GitHub repository](https://github.com/libdebug/libdebug/issues) to help us improve the installation process.

### FileNotFoundError: No such file or directory: '[...]/jumpstart'
`jumpstart` is the executable that is used to bootstrap the debugging process, by calling `PTRACE_TRACEME` before exeuting the target program.
If building **libdebug** from source in editable mode, it might not be automatically installed in the correct location.
To resolve this issue, you can manually install `jumpstart` by running the following command from the root directory of the repository:

```bash
gcc -o ERROR_PATH libdebug/ptrace/jumpstart/jumpstart.c -O3
```

Replace `ERROR_PATH` with the path where the `jumpstart` executable should be installed, as indicated in the error message.

### RuntimeError: Autodetect executable for ptrace_fpregs layout not found at [...]/autodetect_fpregs_layout.
This error indicates that the `autodetect_fpregs_layout` executable is missing.
This executable is used to automatically detect the layout of the floating-point registers for the target architecture.
If building **libdebug** from source in editable mode, it might not be automatically installed in the correct location.
To resolve this issue, you can manually install `autodetect_fpregs_layout` by running the following command from the root directory of the repository:

```bash
gcc -o ERROR_PATH SRC_PATH -O3
```
Replace `ERROR_PATH` with the path where the `autodetect_fpregs_layout` executable should be installed, as indicated in the error message.

Choose `SRC_PATH` based on your architecture:

* For x86_64 and i686: `libdebug/ptrace/native/shared/x86_autodetect_fpregs_layout.c`
* For aarch64: `libdebug/ptrace/native/aarch64/aarch64_autodetect_fpregs_layout.c`

Please note that for aarch64 this is just a dummy file, as the layout is fixed and does not require autodetection for the current implementation.