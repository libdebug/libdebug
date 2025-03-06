---
icon: material/queue-first-in-last-out
search:
    boost: 4
---
# :material-queue-first-in-last-out: Default VS ASAP Mode
For most commands that can be issued in **libdebug**, it is necessary that the traced process stops running. When the traced process stops running as a result of a [stopping event](../../stopping_events/stopping_events), **libdebug** can inspect the state and intervene in its control flow. When one of these commands is used in the script as the process is still running, **libdebug** will wait for the process to stop before executing the command.

In the following example, the content of the `RAX` register is printed after the program hits the breakpoint or stops for any other reason:

```python
from libdebug import debugger

d = debugger("program")
d.run()

d.breakpoint("func")

d.cont()

print(f"RAX: {hex(d.regs.rax)}")
```

!!! INFO "Script execution"
    Please note that, after resuming execution of the tracee process, the script will continue to run. This means that the script will not wait for the process to stop before continuing with the rest of the script. If the next command is a **libdebug** command that requires the process to be stopped, the script will then wait for a [stopping event](../../stopping_events/stopping_events) before executing that command.

In the following example, we make a similar scenario, but show how you can inspect the state of the process by arbitrarily stopping it in the default mode.

```python
d = debugger("program")

d.run()

d.breakpoint("func")

d.cont()

print(f"RAX: {hex(d.regs.rax)}") # (1)!

d.cont()
d.interrupt() # (2)!

print(f"RAX: {hex(d.regs.rax)}") # (3)!

d.cont()

[...]
```

1. This is the value of RAX at the breakpoint.
2. Stop the process shortly after the process resumes.
3. This is the value of RAX at the arbitrary stop (shortly after the breakpoint). 

## :material-run-fast: ASAP Mode
If you want the command to be executed As Soon As Possible (ASAP) instead of waiting for a [stopping event](../../stopping_events/stopping_events), you can specify it when creating the [Debugger](../../from_pydoc/generated/debugger/debugger/) object. In this mode, the debugger will stop the process and issue the command as it runs your script without waiting. The following script has the same behavior as the previous one, using the corresponding option:

```python
d = debugger("program", auto_interrupt_on_command=True)

d.run()

d.breakpoint("func")

d.cont()
d.wait()

print(f"RAX: {hex(d.regs.rax)}") # (1)!

d.cont()

print(f"RAX: {hex(d.regs.rax)}") # (2)!

d.cont()

[...]
```

1. This is the value of RAX at the breakpoint.
2. This is the value of RAX shortly after the breakpoint. The process is forcibly stopped to read the register.

For the sake of this example the `wait()` method is used to wait for the [stopping event](../../stopping_events/stopping_events) (in this case, a breakpoint). This enforces the syncronization of the execution to the stopping point that we want to reach. Read more about the `wait()` method in the section dedicated to [control flow](../control_flow) commands.

!!! TIP "Pwning with **libdebug**"
    Respectable pwners in the field find that the ASAP polling mode is particularly useful when writing exploits.
