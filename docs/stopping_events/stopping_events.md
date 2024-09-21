---
icon: octicons/stop-24
search:
    boost: 4
---
# :octicons-stop-24: Stopping Events
Debugging a process involves stopping the execution at specific points to inspect the state of the program. **libdebug** provides several ways to stop the execution of a program, such as breakpoints, syscalls and signals. This section covers the different stopping events available in **libdebug**.

## :material-progress-question: Is the process running?
Before we dive into the different stopping events, it is important to understand how to check if the process is running. The `running` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object returns `True` if the process is running and `False` otherwise.

!!! ABSTRACT "Example"
    ```python
    from libdebug import debugger

    d = debugger("program")

    d.run()

    if d.running:
        print("The process is running")
    else:
        print("The process is not running")
    ```

    In this example, the script should print `The process is not running`, since the `run()` command gives you control over a stopped process, ready to be debugged.

To know more on how to wait for the process to stop or forcibly cause it to stop, please read about [control flow](../../basics/control_flow_commands/#continuing) commands.