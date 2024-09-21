---
icon: material/location-exit
search:
    boost: 4
---
# :material-location-exit: Detach and GDB Migration

In **libdebug**, you can detach from the debugged process and continue execution with the `detach()` method.

!!! ABSTRACT "Syntax"
    ```python
    d.detach()
    ```

!!! WARNING "Detaching from a running process"
    Remember that detaching from a process is meant to be used when the process is stopped. If the process is running, the command will wait for a [stopping event](../../stopping_events/stopping_events). To forcibly stop the process, you can use the `interrupt()` method before migrating.

## :simple-gnu: GDB Migration

and switch to GDB using the `gdb()` method:

!!! ABSTRACT "Syntax"
    ```python
    d.gdb(open_in_new_process = True)
    ```

To detach completely from the program and continue execution:

!!! WARNING "Migrating from a running process"
    Remember that GDB Migration is meant to be used when the process is stopped. If the process is running, the command will wait for a [stopping event](../../stopping_events/stopping_events). To forcibly stop the process, you can use the `interrupt()` method before migrating.

# :material-power: Graceful Termination
If you are finished working with a [Debugger](../../from_pydoc/generated/debugger/debugger/) object and wish to deallocate it, you can terminate it using the `terminate()` command.

!!! ABSTRACT "Syntax"
    ```python
    d.terminate()
    ```

!!! WARNING "What happens to the running process?"
    When you terminate a [Debugger](../../from_pydoc/generated/debugger/debugger/) object, the process is forcibly killed. If you wish to detach from the process and continue execution before terminating it, you should use the `detach()` command before.