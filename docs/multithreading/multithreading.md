---
icon: material/table-column-plus-after
search:
    boost: 4
---
# :material-table-column-plus-after: Debugging Multithreaded Applications
Debugging multi-threaded applications can be a daunting task, particularly in an interactive debugger that is designed to operate on one thread at a time. **libdebug** offers a few features that will help you debug multi-threaded applications more intuitively and efficiently.

## :material-human-male-child: Child Threads
**libdebug** automatically registers new threads and exposes their state with the same API as the main [Debugger](../../from_pydoc/generated/debugger/debugger/) object. While technically threads can be running or stopped independently, **libdebug** will enforce a coherent state. This means that if a thread is stopped, all other threads will be stopped as well and if a continuation command is issued, all threads will be resumed.

To access the threads of a process, you can use the `threads` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object. This attribute will return a list of [ThreadContext](../../from_pydoc/generated/state/thread_context/) objects, each representing a thread of the process. Similarly, you can access the [Debugger](../../from_pydoc/generated/debugger/debugger/) object from any [ThreadContext](../../from_pydoc/generated/state/thread_context/) through the `debugger` attribute.

!!! WARNING "Meaning of the debugger object"
    When accessing state fields of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object (e.g. registers, memory), the debugger will act as an alias for the main thread. For example, doing d.regs.rax will be equivalent to doing d.threads[0].regs.rax.

!!! INFO "Child Processes"
    **libdebug** does not support debugging child processes (only threads). If a child process is created by the main process, a warning will be printed, prompting the user to attach to the child process manually.

## :material-share: Shared and Unshared State
Each thread has its own register set, stack, and instruction pointer. However, there are shared resources between threads that you should be aware of:

- :fontawesome-solid-memory: The virtual address space is mostly shared between threads. Currently, **libdebug** does not handle the multiprocessing.

- :material-sign-caution: Software breakpoints are implemented through code patching in the process memory. This means that a breakpoint set in one thread will be replicated across all threads.
    - When using [synchronous](../../stopping_events/debugging_flow) breakpoints, you will need to "diagnose" the stopping event to determine which thread triggered the breakpoint. You can do this by checking the return value of the [`hit_on()`](../../stopping_events/debugging_flow/#hit-records) method of the [Breakpoint](../../from_pydoc/generated/data/breakpoint/) object. Passing the [ThreadContext](../../from_pydoc/generated/state/thread_context/) as an argument will return `True` if the breakpoint was hit by that thread.

    - When using [asynchronous](../../stopping_events/debugging_flow) breakpoints, the breakpoint will be more intuitive to handle, as the signature of the [callback function](../../stopping_events/breakpoints#callback-signature) includes the [ThreadContext](../../from_pydoc/generated/state/thread_context/) object that triggered the breakpoint.

- :octicons-cpu-24: While hardware breakpoints are thread-specific, **libdebug** mirrors them across all threads. This is done to avoid asymmetries with software breakpoints. Watchpoints are hardware breakpoints, so this applies to them as well.

- :fontawesome-solid-terminal: For consistency, [syscall handlers](../../stopping_events/syscalls) are also enabled across all threads. The same considerations for synchronous and asynchronous breakpoints apply here as well.

!!! WARNING "Concurrency in Syscall Handling"
    When debugging entering and exiting events in syscalls, be mindful of the scheduling. The kernel may schedule a different thread to handle the syscall exit event right after the enter event of another thread.

- :material-traffic-light-outline: [Signal Catching](../../stopping_events/signals) is also shared among threads. Apart from consistency, this is a necessity. In fact, the kernel does not guarantee that a signal sent to a process will be dispatched to a specific thread.
    - By contrast, when sending arbitrary signals through the [ThreadContext](../../from_pydoc/generated/state/thread_context/) object, the signal will be sent to the requested thread.


!!! EXAMPLE "How to access TLS?"
    While the virtual address space is shared between threads, each thread has its own [Thread Local Storage (TLS)](https://en.wikipedia.org/wiki/Thread-local_storage) area. As it stands, **libdebug** does not provide a direct interface to the TLS area.