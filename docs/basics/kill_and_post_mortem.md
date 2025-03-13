---
icon: material/emoticon-dead-outline
search:
    boost: 4
---

# :material-emoticon-dead-outline: Process Death (and afterlife)
The default behavior in **libdebug** is to kill the debugged process when the script exits. This is done to prevent the process from running indefinitely if the debugging script terminates or you forget to kill it manually. When creating a [Debugger](/from_pydoc/generated/debugger/debugger/) object, you can set the `kill_on_exit` attribute to `False` to prevent this behavior:

```python
from libdebug import Debugger

d = debugger("test", kill_on_exit=False)
```

You can also change this attribute in an existing [Debugger](/from_pydoc/generated/debugger/debugger/) object at runtime:  

```python
d.kill_on_exit = False
```

!!! INFO "Behavior when attaching to a process"
    When debugging is initiated by attaching to an existing process, the `kill_on_exit` policy is enforced in the same way as when starting a new process.

## :material-knife: Killing the Process

You can kill the process any time the process is stopped using the `kill()` method:

!!! ABSTRACT "Function Signature"
    ```python
    d.kill()
    ```

The method sends a `SIGKILL` signal to the process, which terminates it immediately. If the process is already dead, **libdebug** will throw an exception. When multiple threads are running, the `kill()` method will kill all threads under the parent process.

!!! INFO "Process Stop"
    The `kill()` method will not stop a running process, unless **libdebug** is operating in [ASAP Mode](/basics/command_queue). Just like other commands, in the default mode, the `kill()` method will wait for the process to stop before executing.

# :material-robot-dead: Post Mortem Analysis
You can check if the process is dead using the `dead` property:

```python
if not d.dead:
    print("The process is not dead")
else:
    print("The process is dead")
```

!!! WARNING "The `running` property"
    The [Debugger](/from_pydoc/generated/debugger/debugger/) object also exposes the `running` property. This is not the opposite of `dead`. The `running` property is `True` when the process is not stopped and `False` otherwise. If execution was stopped by a [stopping event](/stopping_events/stopping_events), the `running` property will be equal to `False`. However, in this case the process can still be alive.

### :material-grave-stone: Cause of Death
Has your process passed away unexpectedly? We are sorry to hear that. If your process is indeed defunct, you can access the exit code and signal using `exit_code` and `exit_signal`. When there is no valid exit code or signal, these properties will return `None`.

```python
if d.dead:
    print(f"The process exited with code {d.exit_code}")

if d.dead:
    print(f"The process exited with signal {d.exit_signal}")
```