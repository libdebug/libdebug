---
icon: material/alphabetical
search:
    boost: 4
---
## :material-alphabetical: Symbol Resolution
In many of its functions, libdebug accepts ELF symbols as an alternative to actual addresses.

Sometimes, parsing symbol is an expensive operation. Because of this, libdebug offers the possibility of setting the level of symbol resolution.

There are six different levels for symbol resolutions, as follows:

- 0: Symbol resolution is disabled.
- 1: Parse the ELF symbol table (.symtab) and dynamic symbol table (.dynsym).
- 2: Parse the ELF DWARF.
- 3: Follow the external debug file link in the .gnu_debuglink and/or .gnu_debugaltlink sections. If the file is present in the system, read its .symtab and .dynsym.
- 4: Parse the external debug file DWARF, if the file exists in the system.
- 5: Download the external debug file using `debuginfod`. The file is cached in the default folder for `debuginfod`.

The default value is level 4 can be modified at runtime in the following way:

.. code-block:: python

    from libdebug import libcontext

    libcontext.sym_lvl = 5
    d.breakpoint('main')

or also

.. code-block:: python

    from libdebug import libcontext

    with libcontext.tmp(sym_lvl = 5):
        d.breakpoint('main')


Additionally, since reverse-engineering C++ binaries can be a struggle, libdebug automatically demangles C++ symbols.