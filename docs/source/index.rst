.. libdebug documentation master file, created by
   sphinx-quickstart on Sun Jun  2 14:40:43 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: _static/libdebug.png
    :alt: libdebug logo
    :align: center

----

.. image:: https://zenodo.org/badge/DOI/10.5281/zenodo.13151549.svg
  :target: https://doi.org/10.5281/zenodo.13151549

Quick Start
====================================
Welcome to libdebug! This powerful Python library can be used to debug your binary executables programmatically, providing a robust, user-friendly interface.

Debugging multithreaded applications can be a nightmare, but libdebug has you covered. Hijack, and manage signals and syscalls with a simple API.

Looking for previous versions?
------------------------------

Go to https://docs.libdebug.org/archive/VERSION to find the documentation for a specific version of libdebug.

e.g, for version 0.5.0, go to https://docs.libdebug.org/archive/0.5.0

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

    python3 -m pip install libdebug

This will install the stable build of the library. If you don't mind a few hiccups, you can install the latest dev build from the Github repository:

.. code-block:: bash

    python3 -m pip install git+https://github.com/libdebug/libdebug.git@dev

If you want to to test your installation when installing from source, we provide a suite of tests that you can run:

.. code-block:: bash

    cd test
    python run_suite.py

The test folder includes the Makefile that was used to build the required binaries for transparency. However, the compiled binaries may differ due to scheduling, hardware, and compiler versions. Some tests have hardcoded absolute addresses and will likely fail as a result. 

Your first script
-----------------

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

Conflicts with other python packages
------------------------------------

The current version of libdebug is incompatible with https://github.com/Gallopsled/pwntools.

While having both installed in your python environment is not a problem, starting a process with pwntools in a libdebug scripts will cause unexpected behaviors as a result of some race conditions.

Examples of some known issues include:

- ptrace not intercepting SIGTRAP signals when process is run with pwntools.
    This behavior is described in https://github.com/libdebug/libdebug/issues/48.
- Attaching libdebug to a process that was started with pwntools with ``shell=True`` will cause the process to attach to the shell process instead.
    This behavior is described in https://github.com/libdebug/libdebug/issues/57.

Cite Us
-------
Need to cite libdebug in your research? Use the following BibTeX entry:

.. code-block:: bibtex

    @software{libdebug_2024,
        title = {libdebug: {Build} {Your} {Own} {Debugger}},
        copyright = {MIT Licence},
        url = {https://libdebug.org},
        publisher = {libdebug.org},
        author = {Digregorio, Gabriele and Bertolini, Roberto Alessandro and Panebianco, Francesco and Polino, Mario},
        year = {2024},
        doi = {10.5281/zenodo.13151549},
    }

.. toctree::
    :maxdepth: 2
    :caption: Contents:
    
    basic_features
    breakpoints
    handle_syscalls
    catch_signals
    multithreading
    quality_of_life
    logging
    examples

.. autosummary::
   :toctree: _autosummary

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   libdebug

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
