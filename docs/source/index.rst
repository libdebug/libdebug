.. libdebug documentation master file, created by
   sphinx-quickstart on Sun Jun  2 14:40:43 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: libdebug.png
   :alt: libdebug logo
   :align: center

Quick Start
====================================

Dependencies
------------

To install libdebug, you first need to have some dependencies that will not be automatically resolved. Depending on your distro, their names may change.

- **Ubuntu:**

.. code-block:: bash

    sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg

- **Debian:**

.. code-block:: bash

    sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg

- **Arch Linux:**

.. code-block:: bash

    sudo pacman -S python libelf libdwarf gcc make debuginfod

- **Fedora:**

.. code-block:: bash

    sudo dnf install -y python3 python3-devel kernel-devel binutils-devel libdwarf-devel

run the following command:

Installation
------------

.. code-block:: bash

    pip install libdebug


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   libdebug

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
