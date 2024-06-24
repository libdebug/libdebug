.. libdebug documentation master file, created by
   sphinx-quickstart on Sun Jun  2 14:40:43 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: _static/libdebug.png
    :alt: libdebug logo
    :align: center

----

Quick Start
====================================
Welcome to libdebug! This powerful Python library automates the debugging of binary executables, providing a robust, user-friendly interface that simplifies and accelerates your workflow.

Debugging multithreaded applications used to be a nighmare, but libdebug has a simple handling of Hook, hijack, and manage signals and syscalls with a simple API. You have full control over the debugging process, down to the signal level.

Join the community of developers who trust libdebug for their debugging needs. Simplify your debugging process and take control with libdebug today!

Supported Architectures
-----------------------

libdebug currently supports Linux under the x86_64 architecture.

Other operating systems and architectures are not supported at this time.

Dependencies
------------

To install libdebug, you first need to have some dependencies that will not be automatically resolved. Depending on your distro, their names may change.

.. tabs::

    .. code-tab:: bash
        :caption: Ubuntu

        sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg

    .. code-tab:: bash
        :caption: Debian

        sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg

    .. code-tab:: bash
        :caption: Arch Linux

        sudo pacman -S python libelf libdwarf gcc make debuginfod

    .. code-tab:: bash
        :caption: Fedora

        sudo dnf install -y python3 python3-devel kernel-devel binutils-devel libdwarf-devel

Installation
------------
Installing libdebug once you have dependencies is as simple as running the following command:

.. code-block:: bash

    pip install libdebug

This will install the stable build of the library. If you don't mind a few hicups, you can install the latest dev build from the Github repository:

.. code-block:: bash

    git clone https://github.com/libdebug/libdebug.git
    cd libdebug
    git checkout dev
    pip install .


Your first script
------------

Now that you have libdebug installed, you can start using it in your scripts. Here is a simple example of how to use libdebug to debug a binary:

.. code-block:: python

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

The above script will run the binary `test` in the working directory and stop at the function corresponding to the symbol "function". It will then print the value of the RAX register and kill the process.

.. toctree::
    :maxdepth: 2
    :caption: Contents:
    
    basic_features
    breakpoints
    syscall_hooking
    signal_hooking
    multithreading
    quality_of_life
    logging

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   libdebug

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
