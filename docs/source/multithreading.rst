Multithreading
==============
.. _multithreading:

libdebug provides a simple way to debug multithreaded programs. Each time the process forks, the new thread is automatically traced and registered in the `threads` property of the debugger object.

.. code-block:: python

    # Create a debugger object
    d = debugger("./threaded_test")

    # Start debugging and continue until the first stopping event
    d.run()
    d.cont()

    # Print thread id and program counter value for all threads
    for thread in d.threads:
        print(thread.thread_id, hex(thread.regs.rip))

    d.cont()

    # Kill all threads
    d.kill()

Objects in the `threads` list are `ThreadContext` objects, which behave similarly to the debugger. Each thread object has a `regs` property that exposes the registers of the thread and a `memory` property that exposes the memory of the thread. These properties work exactly as the :ref:`corresponding properties<basic_features:register-access-paragraph>` of the debugger object.

Control Flow Operations
-----------------------

Control flow is synchronous between threads: they are either either are all stopped or all running. To this end, the debugger stops all the threads every time a single thread stops. This is a design choice to avoid unexpected behavior as a result of concurrency. The following is a list of behaviors to keep in mind when using control flow funcions in multithreaded programs.

- `cont` will continue all threads.
- `step` and `step_until` will step the selected thread.
- `finish` will have different behavior depending on the selected heuristic.
    - `backtrace` will continue on all threads but will stop at any breakpoint that any of the threads hit.
    - `step-mode` will step exclusively on the thread that has been specified.

When performing thread-specific control flow operations, such as step and finish, the thread context object must be passed as an argument. 

Breakpoints
-----------

Breakpoints are shared between all threads. This means that if a breakpoint is hit by one thread, all threads will stop. This is a design choice to avoid unexpected behavior as a result of concurrency. This, of course, requires a way for the user to distinguish which thread has hit the breakpoint.
The :class:`libdebug.data.Breakpoint` class contains a function called `hit_on`. Given a thread, it will return whether the breakpoint has been hit on that thread.

.. code-block:: python

    # Create a breakpoint at address 0x4005a0
    bp = d.breakpoint(0x15a0)

    d.cont()

    # Print thread id and program counter value for all threads
    for thread in d.threads:
        if bp.hit_on(thread):
            print("Thread", thread.thread_id, "hit the breakpoint")