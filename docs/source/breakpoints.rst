Breakpoints
===========

Breakpoints and watchpoints are a powerful way to debug your code. They allow you to pause the execution of your code at a specific point and inspect the state of your program.

Software breakpoints in the Linux kernel are implemented by patching the running code with an interrupt instruction that is conventionally used for debugging. For example, in the i386 and AMD64 architectures, `int3` is used. When the `int3` instruction is executed, the CPU raises a `SIGTRAP` signal, which is caught by the debugger. The debugger then restores the original instruction and resumes the execution of the program. Software breakpoints are unlimited, but they can break when the program uses self-modifying code.

Hardware breakpoints are a more reliable way to set breakpoints than software breakpoints. They are also faster and more flexible. However, hardware breakpoints are limited in number and are hardware-dependent.

Breakpoints
-----------

libdebug provides a simple API to set breakpoints in your debugged program. The `breakpoint()` function sets a breakpoint at a specific address. 

.. code-block:: python

    from libdebug import Debugger

    d = debugger("./test_program")

    d.run()

    bp = d.breakpoint(0x10ab)

    d.cont()

In the provided example, the debugger will set a breakpoint at the address `0x10ab` (relative to the program's base address) and continue the execution of the program.

When the program reaches the breakpoint, it will pause. You can enable and disable breakpoint `bp` with the `bp.enable()` and `bp.disable()` functions, respectively.

Breakpoint hits
^^^^^^^^^^^^^^^

Let's now assume to have a program that executes a specific instruction multiple times. Depending on your use-case, you could be interested in the number of times a certain breakpoint has been hit. You could also want to perform a certain set of actions in your script as a result of the hit.

The callback and hit_count properties of a Breakpoint object are useful for exactly this purpose. The following syntax is used to set a callback function for your breakpoint:

.. code-block:: python

    def on_breakpoint_hit(t, bp):
        print(f"RAX: {t.regs.rax}")

    d.breakpoint(0x11f0, callback=on_breakpoint_hit)

The signature of a callback function is as follows:

.. code-block:: python

    def callback(t: ThreadContext, bp: Breakpoint) -> None:

The first parameter is a thread context object. This kind of object is described in :doc:`multithreading`.
The second parameter is the breakpoint object that triggered the callback.

As for the hit_count property, the following is an example of how to it:

.. code-block:: python

    while bp.hit_count < 100:
        d.cont()
        print(f"Hit count: {bp.hit_count}")


Symbolic addressing
^^^^^^^^^^^^^^^^^^^

Just like with memory access, you can use symbolic addressing to set breakpoints. The following syntax is used to set a breakpoint at a specific function:

.. code-block:: python

    d.breakpoint("vuln")

Relative addressing with respect to a symbol is also supported. The offset is specified as an hexadecimal number following the symbol name:

.. code-block:: python

    d.breakpoint("vuln+1f")

Hardware breakpoints
^^^^^^^^^^^^^^^^^^^^

You can easily set a hardware breakpoint with the same api as a software breakpoint. Just set the hardware parameter to True:

.. code-block:: python

    d.breakpoint(0x10ab, hardware=True)

As previously mentioned, hardware breakpoints are limited in number. For example, in the x86 architecture, there are only 4 hardware breakpoints available. If you exceed that number, a `RuntimeError` will be raised.

Watchpoints
-----------

Watchpoints are a special type of hardware breakpoint that triggers when a specific memory location is accessed. You can set a watchpoint to trigger on read, write, read/write, or execute access.

Features of watchpoints are shared with breakpoints, so you can set callbacks, check the `hit_count` and activate / deactivate the watchpoint in the same way. While you can use the breakpoint API to set up a breakpoint, a specific API is provided on watchpoints for your convenience:

.. code-block:: python

    def watchpoint(
        position=...,
        condition=...,
        length=...,
        callback=...) -> Breakpoint:

Again, the position can be specified both as a relative address or as a symbol.
The condition parameter specifies the type of access that triggers the watchpoint. The following values are supported:

- ``"w"``: write access
- ``"rw"``: read/write access
- ``"x"``: execute access

By default, the watchpoint is triggered only on write access.

The length parameter specifies the size of the word being watched. The following values are supported:

- ``1``: byte
- ``2``: word
- ``4``: dword
- ``8``: qword

By default, the watchpoint is set to watch a byte.

