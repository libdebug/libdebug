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
If at any time during your script you want to take a more traditional approach to debugging, you can seamlessly switch to [GDB](https://www.sourceware.org/gdb/). This will temporarily detach **libdebug** from the program and give you control over the program using GDB. Quitting GDB or using the `goback` command will return control to **libdebug**. 

!!! ABSTRACT "Function Signature"
    ```python
    d.gdb(
        migrate_breakpoints: bool = True,
        open_in_new_process: bool = True,
        blocking: bool = True,
    ) -> GdbResumeEvent:
    ```

| Parameter | Description |
| --- | --- |
| `migrate_breakpoints` | If set to `True`, **libdebug** will migrate the breakpoints to GDB. |
| `open_in_new_process` | If set to `True`, **libdebug** will open GDB in a new process. |
| `blocking` | If set to `True`, **libdebug** will wait for the user to terminate the GDB session to continue the script. |

Setting the `blocking` to `False` is useful when you want to continue using the pipe interaction and other parts of your script as you take control of the debugging process.

When `blocking` is set to `False`, the `gdb()` method will return instantly, and allow you to continue executing your script while GDB is running.
To wait for the GDB session to finish, you can use the `wait_for_gdb()` method of the Debugger.
When in non-blocking mode, executing any debugger-related commands will raise an exception, as the debugger is not in control of the process anymore.

!!! ABSTRACT "Example of using non-blocking GDB migration"
    ```python
    from libdebug import debugger
    d = debugger("program")
    pipe = d.run()

    # Reach interesting point in the program
    [...]

    d.gdb(blocking = False)

    pipe.sendline(b"dump interpret")

    with open("dump.bin", "r") as f:
        pipe.send(f.read())

    d.wait_for_gdb() # (1)!

    ```
    
    1. This will wait for the GDB session to finish before continuing the script.

Please consider a few requirements when opening GDB in a new process. For this mode to work, **libdebug** needs to know which terminal emulator you are using. If not set, **libdebug** will try to detect this automatically. In some cases, detection may fail. You can manually set the terminal command in [libcontext](../../from_pydoc/generated/utils/libcontext). If instead of opening GDB in a new terminal window you want to use the current terminal, you can simply set the `open_in_new_process` parameter to `False`.

!!! ABSTRACT "Example of setting the terminal with tmux"
    ```python
    from libdebug import libcontext

    libcontext.terminal = ['tmux', 'splitw', '-h']
    ```

!!! WARNING "Migrating from a running process"
    Remember that GDB Migration is meant to be used when the process is stopped. If the process is running, the command will wait for a [stopping event](../../stopping_events/stopping_events). To forcibly stop the process, you can use the `interrupt()` method before migrating.

Migrating to GDB is possible even inside callbacks:

!!! ABSTRACT "Example of GDB migration inside a callback"
    ```python
    def important_check(t, bp):
        if t.regs.rax == 0:
            d.gdb()
            print(hex(r.regs.rbx)) # (1)!

    d.bp("important_function", callback=important_check)

    d.cont()
    d.wait()
    ```

    1. This line will be executed once the GDB session is finished, as the `gdb()` method is blocking by default.

!!! ABSTRACT "Example of non-blocking GDB migration inside a callback"
    ```python
    def important_check(t, bp):
        if t.regs.rax == 0:
            d.gdb(blocking = False)
            io.sendline(b"1234")
            d.wait_for_gdb() # (1)!
            print(hex(r.regs.rbx)) # (2)!

    d.bp("important_function", callback=important_check)

    d.cont()
    d.wait()
    ```

    1. This method must be called inside the callback, otherwise an exception will be raised. It will block until the GDB session is finished.
    2. This line will be executed once the debugging has resumed.

## :material-power: Graceful Termination
If you are finished working with a [Debugger](../../from_pydoc/generated/debugger/debugger/) object and wish to deallocate it, you can terminate it using the `terminate()` command.

!!! ABSTRACT "Function Signature"
    ```python
    d.terminate()
    ```

!!! WARNING "What happens to the running process?"
    When you terminate a [Debugger](../../from_pydoc/generated/debugger/debugger/) object, the process is forcibly killed. If you wish to detach from the process and continue the execution before terminating the debugger, you should use the `detach()` command before.
