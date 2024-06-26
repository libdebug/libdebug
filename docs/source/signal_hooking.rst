Signals
=======

libdebug supports hooking of signals in a similar way to syscalls. You can, in fact, execute a callback when a specific signal directed at the debugged process is intercepted by the tracer. \
The following is the signature of the callback function:

.. code-block:: python

    def callback(d: ThreadContext, signal_number: int) -> None:

along with the thread where the signal was intercepted from, the callback is also passed the signal number. \

When registering a signal hook, you can either specify the signal number or the conventional signal name (e.g. 'SIGINT').

.. code-block:: python

    # Define hooks
    def hook_SIGUSR1(t, signal_number):
        t.signal = 0x0
        print("Look mum, I'm hooking a signal")

    def hook_SIGINT(t, signal_number):
        print("Look mum, I'm hooking another signal")

    # Register hooks
    hook1 = d.hook_signal(10, callback=hook_SIGUSR1)
    hook2 = d.hook_signal('SIGINT', callback=hook_SIGINT)

    d.cont()

    d.unhook_signal(hook1)

Note: You cannot hook **SIGSTOP**, **SIGTRAP**, and **SIGKILL**.

These signals are internally used by the ptrace and the debugger, or are enforced by the kernel to be passed directly to the child process without the possibility of being caught.

Just like with syscalls, there can be at most one user-defined hook for each signal.

If a new hook is defined for a signal that is already hooked or hijacked, the new hook will replace the old one, and a warning is printed.

Signal Filtering
----------------
Instead of setting a callback on signals, you could want to filter which signals are not to be forwarded to the debugged process during execution.

By default, all signals not related to the libdebug's internals are forwarded. For example, SIGSTOP is never passed to the process.

.. code-block:: python
    
    d.signals_to_block = [10, 15, 'SIGINT', 3, 13]


The same syntax will work in multithreaded applications, by setting `signals_to_block`` on the desired thread context object. See :doc:`multithreading` for more information.

Arbitrary Signals
-----------------
You can also send an arbitrary signal to the process. The signal will be forwarded upon calling `d.cont()`, just before continuing the exectution.

.. code-block:: python

    d.signal = 10
    d.cont()

The same syntax will work in multithreaded applications, by setting the signal on the desired thread context object.  See :doc:`multithreading` for more information.

Signal Hijacking
----------------
libdebug also provides a direct way to intercept a signal and modify it before sending it to the child process. In other words, it allows you to hijack an incoming signal and change it to a different signal. This works in a similar way to syscall hijacking.

When registering a signal hijack, you can either specify the signal number or the conventional signal name (e.g. 'SIGINT').

.. code-block:: python

    hook1 = d.hijack_signal("SIGQUIT", "SIGTERM")
    hook2 = d.hijack_signal("SIGINT", 10)

Note: You cannot hook **SIGSTOP**, **SIGTRAP**, and **SIGKILL**.

These signals are internally used by the ptrace and the debugger, or are enforced by the kernel to be passed directly to the child process without the possibility of being caught.

Hijacking Loop Detection
^^^^^^^^^^^^^^^^^^^^^^^^
When carelessly hijacking syscalls, it could happen that loops are created. libdebug automatically performs checks to avoid these situations with syscall hijacking and raises an exception if an infinite loop is detected.

For example, the following code raises a `RuntimeError`:

.. code-block:: python

    hook = d.hijack_signal("SIGPIPE", "SIGINT")
    hook = d.hijack_signal("SIGINT", "SIGPIPE")

Hook on hijack
^^^^^^^^^^^^^^
Mixing signal hooking and hijacking can become messy. Because of this, libdebug provides users with the choice of whether to execute the callback function for a signal that was triggered *by* a hijack.

This behavior is enabled by the parameter `hook_hijack`, available when instantiating a hijack. By default, the parameter is set to True, making the "hook on hijack" a predefined behavior.

In the following example, we replace the SIGINT signal with a SIGPIPE, but we do not want to execute the callback function for the SIGPIPE signal.

For this reason, we set `hook_hijack` to False upon registering the hijack.

.. code-block:: python

    def hook_SIGPIPE(d: ThreadContext, syscall_number: int):
        print("entering write")

    d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)
    d.hijack_signal("SIGINT", "SIGPIPE", hook_hijack=False)

