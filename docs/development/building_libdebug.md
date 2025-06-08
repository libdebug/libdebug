---
icon: material/wrench
search:
    boost: 4
---
# :material-wrench: Building **libdebug** from source

Building **libdebug** from source is a straightforward process. This guide will walk you through the steps required to compile and install **libdebug** on your system.

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
