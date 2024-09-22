---
icon: material/location-exit
search:
    boost: 4
---
# :material-location-exit: Detach and GDB Migration

In **libdebug**, you can detach from the debugged process and continue execution with the `detach()` method.

!!! ABSTRACT "Function Signature"
    ```python
    d.detach()
    ```

!!! WARNING "Detaching from a running process"
    Remember that detaching from a process is meant to be used when the process is stopped. If the process is running, the command will wait for a [stopping event](../../stopping_events/stopping_events). To forcibly stop the process, you can use the `interrupt()` method before migrating.

## :simple-gnu: GDB Migration
If at any time during your script you want to take a more traditional approach to debugging, you can seamlessly switch to [GDB](https://www.sourceware.org/gdb/). This will temporarily detach libdebug from the program and give you control over the program using GDB. Quitting GDB will return control to libdebug. 

By default, the behavior of this command is to open GDB in a new terminal window. For this to work, it is necessary to specify your terminal emulator in the [libcontext](../../from_pydoc/generated/utils/libcontext) parameters.

!!! ABSTRACT "Example of setting the terminal with tmux"
    ```python
    from libdebug import libcontext

    libcontext.terminal = ['tmux', 'splitw', '-h']
    ```

Once the terminal is set, you can use the `gdb()` method to open GDB in a new terminal window.

!!! ABSTRACT "Function Signature"
    ```python
    d.gdb(open_in_new_process = True)
    ```

If instead of opening GDB in a new terminal window you want to use the current terminal, you can simply set the `open_in_new_process` parameter to `False`.

!!! WARNING "Migrating from a running process"
    Remember that GDB Migration is meant to be used when the process is stopped. If the process is running, the command will wait for a [stopping event](../../stopping_events/stopping_events). To forcibly stop the process, you can use the `interrupt()` method before migrating.

## :material-power: Graceful Termination
If you are finished working with a [Debugger](../../from_pydoc/generated/debugger/debugger/) object and wish to deallocate it, you can terminate it using the `terminate()` command.

!!! ABSTRACT "Function Signature"
    ```python
    d.terminate()
    ```

!!! WARNING "What happens to the running process?"
    When you terminate a [Debugger](../../from_pydoc/generated/debugger/debugger/) object, the process is forcibly killed. If you wish to detach from the process and continue execution before terminating it, you should use the `detach()` command before.