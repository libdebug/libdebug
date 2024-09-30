---
icon: octicons/file-binary-24
search:
    boost: 4
---
# :octicons-file-binary-24: Running an Executable
You have created your first debugger object, and now you want to run an executable. Calling the `run()` method will start execution on a new child process and, unless otherwise specified, continue to the binary entry point.

```python
from libdebug import debugger

d = debugger("program")
d.run()
```
At this point, the process execution is stopped, waiting for your commands.

!!! INFO "A few things to keep in mind"
    - Please remember that the process you are debugging (the tracee) and the debugger itself are running in different threads. 
    - Also note that breakpoints and other [stopping events](../../stopping_events/stopping_events) set by the user are not kept between different runs of the program. If you want to place them, you should do so after each call to `d.run()`.

## :material-harddisk: Process I/O

When execution is resumed, chances are that your process will need to take input and produce output. To interact with the standard input and output of the process, you can use the [PipeManager](../../from_pydoc/generated/utils/pipe_manager) returned by the `run()` function.

```python
from libdebug import debugger

d = debugger("program")
pipe = d.run()

d.cont()
d.wait()

print(pipe.recvline().decode())
```

You can interact with the process's pipe manager using the following commands:

| Method        | Description                                                                 |
| ------------- | --------------------------------------------------------------------------- |
| `recv`      | Receives `numb` bytes from the target.<br><br>**Parameters**:<br>- `numb` (int \| None) \| default = None <br>- `timeout` (int) \| default = timeout_default |
| `recverr`   | Receives `numb` bytes from the target's standard error.<br><br>**Parameters**:<br>- `numb` (int \| None) \| default = None<br>- `timeout` (int) \| default = timeout_default |
| `recvline`  | Receives `numlines` lines of data from the target.<br><br>**Parameters**:<br>- `numlines` (int) \| default = 1 <br>- `drop` (bool) \| default = True<br>- `timeout` (int) \| default = timeout_default |
| `recverrline`| Receives `numlines` lines of data from the target's standard error.<br><br>**Parameters**:- `numlines` (int) \| default = 1<br>- `drop` (bool) \| default = True<br>- `timeout` (int) \| default = timeout_default |
| `recvuntil` | Receives data from the target until a specified delimiter is encountered for a certain number of occurrences. <br><br>**Parameters**:<br>- `delims` (bytes)<br>- `occurrences` (int) \| default = 1<br>- `drop` (bool) \| default = True<br>- `timeout` (int) \| default = timeout_default |
| `recverruntil`| Receives data from the target's standard error until a specified delimiter is encountered for a certain number of occurrences.<br><br>**Parameters**:<br>- `delims` (bytes)<br>- `occurrences` (int) \| default = 1<br>- `drop` (bool) \| default = True<br>-`timeout` (int) \| default = timeout_default |
| `send`      | Sends data to the target<br><br>**Parameters**:<br>- `data` (bytes)                    |
| `sendafter` | Sends data to the target after receiving a specified number of occurrences of the delimiter.<br><br>**Parameters**:<br>- `delims` (bytes)<br>- `data` (bytes)<br>- `occurrences` (int) \| default = 1<br>- `drop` (bool) \| default = False<br>- `timeout` (int) \| default = timeout_default |
| `sendline`  | Sends a single line of data to the target.<br><br>**Parameters**:<br>- `data` (bytes)   |
| `sendlineafter`| Sends a single line of data to the target after receiving a specified number of occurrences of the delimiter.<br><br>**Parameters**:<br>- `delims` (bytes)<br>- `data` (bytes)<br>- `occurrences` (int) \| default = 1<br>- `drop` (bool) \| default = False<br>- `timeout` (int) \| default = timeout_default |
| `close`     | Closes the connection to the target.                                        |
| `interactive`| Enters an interactive mode where you can send and receive data from the target. Read more in the next section. |

!!! INFO "When process is stopped"
    When the process is stopped, the pipe manager will not be able to receive data from the target. Any recv-like instruction (including `sendafter` and `sendlineafter`) will fail with an exception. Operations on stdin like `send` and `sendline` are not affected by this limitation, since the kernel will buffer the data until the process is resumed.

### :material-keyboard: Interactive I/O
The pipe manager contains a method called `interactive()` that allows you to directly interact with the process's standard I/O. This method will print characters from standard output and read your inputs, letting you interact naturally with the process. The `interactive()` method is blocking, so the execution of the script will wait for the user to terminate the interactive session. To do so, you can press `Ctrl+C` or `Ctrl+D`.

!!! ABSTRACT "Function Signature"
    ```python
    pipe.interactive(prompt: str = prompt_default):
    ```

The `prompt` parameter is optional and will be printed before each input. By default, it is set to `"$ "`.

There are two edge cases to consider when using the `interactive()` method:

- If during the interactive session the process stops as a result of a [stopping event](../../stopping_events/stopping_events), the interactive session will be interrupted with a warning, and the script will continue its execution.
- If any of the file descriptors of standard input, output, or error are closed, a warning will be printed.

## :fontawesome-solid-syringe: Attaching to a Running Process
If you want to attach to a running process instead of spawning a child, you can use the `attach()` method in the [Debugger](../../from_pydoc/generated/debugger/debugger/) object. This method will attach to the process with the specified PID.

```python
from libdebug import debugger

d = debugger("test")

pid = 1234

d.attach(pid)
```

The process will stop upon attachment, waiting for your commands.

!!! WARNING "Ptrace Scope"
    On POSIX systems, **libdebug** uses the `ptrace` system call to interact with the process. This system call is limited by the kernel according to a [`ptrace_scope`](https://www.kernel.org/doc/Documentation/security/Yama.txt) parameter. Different systems have different default values for this parameter. If the `ptrace` system call is not allowed, the `attach()` method will raise an exception notifying you of this issue.