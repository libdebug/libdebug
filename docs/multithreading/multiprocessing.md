---
icon: material/server
search:
    boost: 4
---
# :material-server: Debugging Multiprocess Applications
Since version **0.8** :sushi: *Chutoro Nigiri* :sushi:, **libdebug** supports debugging multiprocess applications. This feature allows you to attach to multiple processes and debug them simultaneously. This document explains how to use this feature and provides examples to help you get started.

## :fontawesome-solid-baby: A Child Process is Born
By default, **libdebug** will monitor all new children processes created by the tracee process. Of course, it will not retrieve past forked processes that have been created before an attach. 

A new process is a big deal. For this reason, **libdebug** will provide you with a brand new [Debugger](/from_pydoc/generated/debugger/debugger/) object for each new child process. This object will be available in the list `children` attribute of the parent [Debugger](/from_pydoc/generated/debugger/debugger/) object.

!!! ABSTRACT "Usage Example"
    ```python
    from libdebug import debugger

    d = debugger("test")
    d.run()

    [...]
    
    print(f"The process has spawned {len(d.children)} children")

    for child in d.children: # (1)!
        print(f"Child PID: {child.pid}")
    ```

    1. The `children` attribute is a regular list. Indexing, slicing, and iterating are all supported.

### :fontawesome-solid-angles-down: Inherited Properties
When a child process is spawned, it inherits the properties of the parent debugger. This includes whether ASLR is enabled, fast memory reading, and [other properties}(/basics/libdebug101/#what-else-can-i-do). However, the child debugger from that moment on will act independently. As such, any property changes made to the parent debugger will not affect the child debugger, and vice versa.

In terms of registered [Stopping Events](/stopping_events/stopping_events), the new debugger will be a *blank slate*. This means the debugger will not inherit [breakpoints](/stopping_events/breakpoints/), [watchpoints](/stopping_events/watchpoints/), [syscall handlers](/stopping_events/syscalls/), or [signal catchers](/stopping_events/signals/).

## :fontawesome-solid-eye-low-vision: Focusing on the Main Process
Some applications may spawn a large number of children processes, and you may only be interested in debugging the main process. In this case, you can disable the automatic monitoring of children processes by setting the `follow_children` parameter to `False` when creating the [Debugger](/from_pydoc/generated/debugger/debugger/) object.

!!! ABSTRACT "Usage Example"
    ```python
    d = debugger("test", follow_children=False)
    d.run()
    ```
    In this example, **libdebug** will only monitor the main process and ignore any child processes spawned by the tracee.

However, you can also decide to stop monitoring child processes at any time during debugging by setting the `follow_children` attribute to `False` in a certain [Debugger](/from_pydoc/generated/debugger/debugger/) object.

## :fontawesome-regular-file-zipper: Snapshot Behavior
When creating a snapshot of a process from the corresponding [Debugger](/from_pydoc/generated/debugger/debugger/) object, the snapshot will not include children processes, but only children threads. Read more about snapshots in the [Save States](/save_states) section.

## :material-pipe-leak: Pipe Redirection
By default, **libdebug** will redirect the standard input, output, and error of the child processes to pipes. This is how you can interact with these file descriptors using [I/O commands](/basics/running_an_executable/#interactive-io). If you keep this parameter enabled, you will be able to interact with the child processes's standard I/O using the same [PipeManager](/from_pydoc/generated/commlink/pipe_manager) object that is provided upon creation of the root [Debugger](/from_pydoc/generated/debugger/debugger/) object. This is consistent with limitations of forking in the POSIX standard, where the child process inherits the file descriptors of the parent process.

Read more about disabling pipe redirection in the [dedicated section](/basics/running_an_executable/#disabling-pipe-redirection).