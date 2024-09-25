---
icon: material/queue-first-in-last-out
search:
    boost: 4
---
# :material-queue-first-in-last-out: The Command Queue
All internal **libdebug** operations resulting from a command are inserted into a queue and executed according to a first-in-first-out (FIFO) policy. This ensures that commands are executed in the order they are issued. The command queue is automatically polled for new commands when the process is not running as a result of a [stopping event](../../stopping_events/stopping_events).

In the following example, the content of the `RAX` register is printed after the program hits the breakpoint or stops for any other reason:

```python
from libdebug import debugger

d = debugger("program")

d.breakpoint("func")

d.cont()

print(f"RAX: {hex(d.regs.rax)}")
```

## :material-run-fast: ASAP Polling
If you want the command in the queue to be polled As Soon As Possible (ASAP) instead of waiting for a [stopping event](../../stopping_events/stopping_events), you can specify it when creating the [Debugger](../../from_pydoc/generated/debugger/debugger/) object. In this mode, the debugger will stop the process and issue the command as it runs your script. The following script has the same behavior as the previous one, using the ASAP polling option:

```python
d = debugger("program", auto_interrupt_on_command=True)

d.run()

d.breakpoint("func")

d.cont()
d.wait()

print(f"RAX: {hex(d.regs.rax)}") # (1)

d.cont()

print(f"RAX: {hex(d.regs.rax)}") # (2)
```

1. This is the value of RAX at the breakpoint.
2. This is the value of RAX shortly after the breakpoint. The process is forcibly stopped to read the register.

In this case, the `wait()` method is used to wait for the [stopping event](../../stopping_events/stopping_events) (in this case, a breakpoint). Read more about the `wait()` method in the section dedicated to [control flow](../control_flow) commands.

!!! TIP "Pwning with **libdebug**"
    Respectable pwners in the field find that the ASAP polling mode is particularly useful when writing exploits.
