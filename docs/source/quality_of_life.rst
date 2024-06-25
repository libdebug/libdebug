Quality of Life
===============
For your convenience, libdebug offers a few functions that will speed up your debugging process.

Automatic Evasion of Anti-Debugging Techniques
----------------------------------------------

A common anti-debugging technique for Linux ELF binaries is to invoke the `ptrace` syscall with the `PTRACE_TRACEME` argument. The syscall will fail if the binary is currently being traced by a debugger. Bypassing this technique involves intercepting such syscalls and altering the return value to make the binary believe that it is not being traced. While this can absolutely be performed manually in libdebug, there is also the possibility of passing `escape_antidebug=True` when creating the debugger object. The debugger will take care of the rest.

Syscall Trace Pretty Print
--------------------------

When debugging a binary, it is often much faster to guess what the intended functionality is by looking at the syscalls that are being invoked. libdebug offers a function that will intercept any syscall and print its arguments and return value. This can be done by setting the property `pprint_syscalls = True` in the debugger object. The output will be printed to the console in color. Additionally, syscalls hijacked through the libdebug API will be highlighted as striken through, allowing you to monitor both the original behavior and your own changes to the flow.

TODO: Put an example here @Io_no, you certainly have one

Symbol Resolution
-----------------
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