Syscalls
========

libdebug allows the user to manage syscalls of the debugged program. Specifically, you can choose to **handle** or **hijack** a specific syscall.

In the case of *handling*, the user can provide a callback function that will be called whenever the handled syscall is executed or decide to pause the script when the syscall is executed.

In the case of *hijacking*, the user can modify the syscall that was supposed to be executed, either by changing its parameters or replacing it with another syscall.

Handlers
-------
When handling a syscall, the user can provide up to two callback functions that will be called whenever the handled syscall is executed. One that is called before executing the syscall (`on_enter`), the other is called after executing the syscall (`on_exit`).

Please note that it is not necessary to specify both `on_enter` and `on_exit` callbacks. It is sufficient to specify only one of them. The callback function must have the following signature:

.. code-block:: python

    def callback(t: ThreadContext, handler: SyscallHandler) -> None:

The first parameter is a thread context object. This kind of object is described in :doc:`multithreading`.
The second parameter is the handler object that triggered the callback. 

When choosing which syscall to handle, you can either specify its number or its name. The following example shows how to handle the `open` syscall:

.. code-block:: python

    def on_enter_open(t: ThreadContext, handler: SyscallHandler):
        print("entering open")
        t.syscall_arg0 = 0x1

    def on_exit_open(t: ThreadContext, handler: SyscallHandler):
        print("exiting open")
        t.syscall_return = 0x0

    handler = d.handle_syscall(syscall="open", on_enter=on_enter_open, on_exit=on_exit_open)

You can also decide to pause the script when a syscall is executed by not specifying a callback function.

.. code-block:: python

    handler = d.handle_syscall(syscall="open")
    d.cont()

    d.wait()
    if handler.hit_on_enter(d):
        print("open syscall was entered")
    elif handler.hit_on_exit(d):
        print("open syscall was exited")

If the user chooses to pass the common name of the syscall, a definition list for Linux syscalls will be fetched from `mebeim's syscall list <https://syscalls.mebeim.net>`__. The list is then cached internally. 

You can enable and disable a syscall handle `handler` with the `handler.enable()` and `handler.disable()` functions, respectively.

Exactly as with breakpoints, you can access the `hit_count` property to get the number of times the syscall was executed:

.. code-block:: python

    while handler.hit_count < 100:
        d.cont()
        print(f"Hit count: {handler.hit_count}")

Please note that there can be at most **one** user-defined handler for each syscall.

Builtin handlers of syscalls within libdebug does not cound toward that limit. For example, the pretty print function (described in :doc:`multithreading`) will not count as a user-defined handler.

If a new handler is defined for a syscall that is already handled or hijacked, the new handler will replace the old one, and a warning will be printed.

For example, in the following code, `handler_2` will override `handler_1`, showing a warning:

.. code-block:: python

    handler_1 = d.handler_syscall(syscall="open", on_enter=on_enter_open_1, on_exit=on_exit_open_1)
    handler_2 = d.handler_syscall(syscall="open", on_enter=on_enter_open_2, on_exit=on_exit_open_2)

Hijacking
---------

While handling a syscall allows the user to monitor the syscall execution, hijacking a syscall allows the user to *alter* the syscall execution. 

When hijacking a syscall, the user can provide an alternative syscall to be executed in place of the original one:

.. code-block:: python

    handler = d.hijack_syscall("read", "write")

In this example, the `read` syscall will be replaced by the `write` syscall. The parameters of the `read` syscall will be passed to the `write` syscall.
Again, it is possible to specify a syscall by its number in the syscall table or by its common name.

Hijacking Loop Detection
^^^^^^^^^^^^^^^^^^^^^^^^

When carelessly hijacking syscalls, it could happen that loops are created. libdebug automatically performs checks to avoid these situations with syscall hijacking and raises an exception if an infinite loop is detected.

For example, the following code raises a `RuntimeError`:

.. code-block:: python

    handler = d.hijack_syscall("read", "write")
    handler = d.hijack_syscall("write", "read")


Recursion
^^^^^^^^^^^^^^
Mixing syscall handling and hijacking can become messy. Because of this, libdebug provides users with the choice of whether to execute the handler for a syscall that was triggered *by* a hijack.

This behavior is enabled by the parameter `recursive`, available when instantiating a hijack or a handler. By default, the parameter is set to False.