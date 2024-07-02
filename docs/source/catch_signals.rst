Signals
=======

libdebug supports catching of signals. You can, in fact, execute a callback or pause the script when a specific signal directed at the debugged process is intercepted by the tracer. \
The following is the signature of the callback function:

.. code-block:: python

    def callback(d: ThreadContext, catcher: SignalCatcher) -> None:

along with the thread where the signal was intercepted from, the callback is also passed the `SignalCatcher` object. \

When registering a signal catcher, you can either specify the signal number or the conventional signal name (e.g. 'SIGINT').

.. code-block:: python

    # Define the callback function
    def cather_SIGUSR1(t, catcher):
        t.signal = 0x0
        print("Look mum, I'm catching a signal")

    def catcher_SIGINT(t, catcher):
        print("Look mum, I'm catching another signal")

    # Register the signal catchers
    catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1)
    catcher2 = d.catch_signal('SIGINT', callback=catcher_SIGINT)

    d.cont()


You can also decide to pause the script when a signal is caught by not specifying a callback function.

.. code-block:: python

    catcher = d.catch_signal(10)
    d.cont()

    d.wait()
    if catcher.hit_on(d):
        print("Signal 10 was caught")

You can enable and disable a signal catcher `catcher` with the `catcher.enable()` and `catcher.disable()` functions, respectively.

As with breakpoints and syscall handlers, you can access the `hit_count` property to get the number of times the signal was caught:

.. code-block:: python

    while catcher.hit_count < 100:
        d.cont()
        print(f"Hit count: {catcher.hit_count}")

Note: You cannot catch **SIGSTOP**, **SIGTRAP**, and **SIGKILL**.

These signals are internally used by the ptrace and the debugger, or are enforced by the kernel to be passed directly to the child process without the possibility of being caught.

Just like with syscalls, there can be at most one user-defined catcher for each signal.

If a new catcher is defined for a signal that is already catched or hijacked, the new catcher will replace the old one, and a warning is printed.

Signal Filtering
----------------
Instead of setting a catcher on signals, you could want to filter which signals are not to be forwarded to the debugged process during execution.

By default, all signals not related to the libdebug's internals are forwarded. For example, SIGSTOP is never passed to the process.

.. code-block:: python
    
    d.signals_to_block = [10, 15, 'SIGINT', 3, 13]



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

    catcher1 = d.hijack_signal("SIGQUIT", "SIGTERM")
    catcher2 = d.hijack_signal("SIGINT", 10)

Note: Just like with catchers, you cannot hijack **SIGSTOP**, **SIGTRAP**, and **SIGKILL**.

These signals are internally used by the ptrace and the debugger, or are enforced by the kernel to be passed directly to the child process without the possibility of being caught.

Hijacking Loop Detection
^^^^^^^^^^^^^^^^^^^^^^^^
When carelessly hijacking syscalls, it could happen that loops are created. libdebug automatically performs checks to avoid these situations with signal hijacking and raises an exception if an infinite loop is detected.

For example, the following code raises a `RuntimeError`:

.. code-block:: python

    catcher1 = d.hijack_signal("SIGPIPE", "SIGINT")
    catcher2 = d.hijack_signal("SIGINT", "SIGPIPE")

Recursion
^^^^^^^^^^^^^^
Mixing signal catching and hijacking can become messy. Because of this, libdebug provides users with the choice of whether to execute the catcher for a signal that was triggered *by* a hijack.

This behavior is enabled by the parameter `recursive`, available when instantiating a hijack or a catcher. By default, the parameter is set to False.

In the following example, we replace the SIGINT signal with a SIGPIPE, but we do not want to execute the callback function for the SIGPIPE signal.

For this reason, we set `recursive` to False upon registering the hijack.

.. code-block:: python

    def catcher_SIGPIPE(d: ThreadContext, catcher: SignalCatcher):
        print("entering write")

    d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)
    d.hijack_signal("SIGINT", "SIGPIPE", recursive=False)

