Syscall Handling
================

libdebug allows the user to handle syscalls of the debugged program. Specifically, you can choose to **hook** or **hijack** a specific syscall. 
In the case of *hooking*, the user can provide a callback function that will be called whenever the hooked syscall is executed.
In the case of *hijacking*, the user can modify the syscall that was supposed to be executed, either by cancelling it, changing its parameters or .replacing it with another syscall.

Hooking
-------
When hooking a syscall, the user can provide up to two callback functions that will be called whenever the hooked syscall is executed. One that is called before executing the syscall (`on_enter`), the other is called after executing the syscall (`on_exit`). 
Please note that it is not necessary to specify both `on_enter` and `on_exit` callbacks. It is sufficient to specify only one of them. The callback function must have the following signature:

.. code-block:: python

    def callback(d: ThreadContext, bp: Breakpoint) -> None:

The first parameter can either be a debugger object or a thread context object. This kind of object is described in :doc:`multithreading`.
The second parameter is the number of the syscall as defined by the kernel.

When choosing which syscall to hook, you can either specify its number or its name. The following example shows how to hook the `open` syscall:

.. code-block:: python
    def on_enter_open(d: ThreadContext, syscall_number: int):
        print("entering open")
        d.syscall_arg0 = 0x1

    def on_exit_open(d: ThreadContext, syscall_number: int):
        print("exiting open")
        d.syscall_return = 0x0

    sys_hook = d.hook_syscall(syscall="open", on_enter=on_enter_open, on_exit=on_exit_open)

If the user chooses to pass the common name of the syscall, a definition list for Linux syscalls will be fetched from `Mebeim's list`__ <syscalls.mebeim.net>. The list is then cached internally. 

You can enable and disable a syscall hook `sys_hook` with the `sys_hook.enable()` and `sys_hook.disable()` functions, respectively.

Exactly as with breakpoints, you can access the `hit_count` property to get the number of times the syscall was executed:

.. code-block:: python

    while sys_hook.hit_count < 100:
        d.cont()
        print(f"Hit count: {sys_hook.hit_count}")

Please note that there can be at most **one** user-defined hook for each syscall. \
Builtin hooking of syscalls within libdebug does not cound toward that limit. For example, the pretty print function (described in :doc:`multithreading`) will not count as a user-defined hook.
If a new hook is defined for a syscall that is already hooked or hijacked, the new hook will replace the old one, and a warning will be printed.

For example, in the following code, `sys_hook_2` will override `sys_hook_1`, showing a warning:

.. code-block:: python

    sys_hook_1 = d.hook_syscall(syscall="open", on_enter=on_enter_open_1, on_exit=on_exit_open_1)
    sys_hook_2 = d.hook_syscall(syscall="open", on_enter=on_enter_open_2, on_exit=on_exit_open_2)

Hijacking
---------

While hooking a syscall allows the user to monitor the syscall execution, hijacking a syscall allows the user to *alter* the syscall execution. 
When hijacking a syscall, the user can provide an alternative syscall to be executed in place of the original one:

.. code-block:: python
    hook = d.hijack_syscall("read", "write")

In this example, the `read` syscall will be replaced by the `write` syscall. The parameters of the `read` syscall will be passed to the `write` syscall.
Again, it is possible to specify a syscall by its number in the syscall table or by its common name.

Hijacking Loop Detection
^^^^^^^^^^^^^^^^^^^^^^^^

When carelessly hijacking syscalls, it could happen that loops are created. libdebug automatically performs checks to avoid these situations with syscall hijacking and raises an exception if an infinite loop is detected.
For example, the following code raises a `RuntimeError`:
.. code-block:: python
    hook = d.hijack_syscall("read", "write")
    hook = d.hijack_syscall("write", "read")


Hook on Hijack
^^^^^^^^^^^^^^
When mixing syscall hooking and hijacking can become messy. Because of this, libdebug provides users with the choice of whether to execute the callback function for a syscall that was triggered *by* a hijack.
This behavior is enabled by the parameter `hook_hijack`, available when instantiating a hijack. By default, the parameter is set to True, making the "hook on hijack" a predefined behavior.