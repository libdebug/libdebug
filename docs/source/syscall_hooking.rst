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

If the user chooses to pass the common name of the syscall, a definition list for Linux syscalls will be downloaded from `Mebeim's list`__ <syscalls.mebeim.net>. The list is then cached internally. 

Hijacking
---------