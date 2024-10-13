---
icon: octicons/file-binary-24
search:
    boost: 4
---
# :octicons-file-binary-24: Running an Executable
You have created your first debugger object, and now you want to run the executable. Calling the `run()` method will spawn a new child process and prepare it for the execution of your binary.

```python
from libdebug import debugger

d = debugger("program")
d.run()
```
At this point, the process execution is stopped, waiting for your commands.

!!! INFO "A few things to keep in mind"
    - Please remember that the process you are debugging (the tracee) and the debugger itself are running in different threads. 
    - Also note that breakpoints and other [stopping events](../../stopping_events/stopping_events) set by the user are not kept between different runs of the program. If you want to place them again, you should redo so after each call to `d.run()`. You cannot set breakpoints before calling `d.run()`.

## :material-harddisk: Process I/O

When execution is resumed, chances are that your process will need to take input and produce output. To interact with the standard input and output of the process, you can use the [PipeManager](../../from_pydoc/generated/commlink/pipe_manager) returned by the `run()` function.

```python
from libdebug import debugger

d = debugger("program")
pipe = d.run()

d.cont()
print(pipe.recvline().decode())
d.wait()
```

All pipe receive-like methods have a timeout parameter that you can set. The default value, `timeout_default`, can be set globally as a parameter of the [PipeManager](../../from_pydoc/generated/commlink/pipe_manager) object. By default, this value is set to 2 seconds.

!!! TIP "Changing the global timeout"
    ```python
    pipe = d.run()

    pipe.timeout_default = 10 # (1)
    ```

    1. This sets the default timeout for all pipe receive-like methods to 10 seconds.

You can interact with the process's pipe manager using the following methods:

| Method         | Description |
| -------------- | ----------- |
| `recv`         | Receives at most `numb` bytes from the target's stdout.<br><br>**Parameters**:<br>- `numb` (int) &nbsp;&nbsp;&nbsp; \[default = 4096\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\] |
| `recverr`      | Receives at most `numb` bytes from the target's stderr.<br><br>**Parameters**:<br>- `numb` (int) &nbsp;&nbsp;&nbsp; \[default = 4096\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\] |
| `recvuntil`    | Receives data from stdout until a specified delimiter is encountered for a certain number of occurrences.<br><br>**Parameters**:<br>- `delims` (bytes)<br>- `occurrences` (int) &nbsp;&nbsp;&nbsp; \[default = 1\]<br>- `drop` (bool) &nbsp;&nbsp;&nbsp; \[default = False\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\]<br>- `optional` (bool) &nbsp;&nbsp;&nbsp; \[default = False\] |
| `recverruntil` | Receives data from stderr until a specified delimiter is encountered for a certain number of occurrences.<br><br>**Parameters**:<br>- `delims` (bytes)<br>- `occurrences` (int) &nbsp;&nbsp;&nbsp; \[default = 1\]<br>- `drop` (bool) &nbsp;&nbsp;&nbsp; \[default = False\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\]<br>- `optional` (bool) &nbsp;&nbsp;&nbsp; \[default = False\] |
| `recvline`     | Receives `numlines` lines from the target's stdout.<br><br>**Parameters**:<br>- `numlines` (int) &nbsp;&nbsp;&nbsp; \[default = 1\]<br>- `drop` (bool) &nbsp;&nbsp;&nbsp; \[default = True\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\]<br>- `optional` (bool) &nbsp;&nbsp;&nbsp; \[default = False\] |
| `recverrline`  | Receives `numlines` lines from the target's stderr.<br><br>**Parameters**:<br>- `numlines` (int) &nbsp;&nbsp;&nbsp; \[default = 1\]<br>- `drop` (bool) &nbsp;&nbsp;&nbsp; \[default = True\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\]<br>- `optional` (bool) &nbsp;&nbsp;&nbsp; \[default = False\] |
| `send`         | Sends `data` to the target's stdin.<br><br>**Parameters**:<br>- `data` (bytes)                                                                                   |
| `sendafter`    | Sends `data` after receiving a specified number of occurrences of a delimiter from stdout.<br><br>**Parameters**:<br>- `delims` (bytes)<br>- `data` (bytes)<br>- `occurrences` (int) &nbsp;&nbsp;&nbsp; \[default = 1\]<br>- `drop` (bool) &nbsp;&nbsp;&nbsp; \[default = False\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\]<br>- `optional` (bool) &nbsp;&nbsp;&nbsp; \[default = False\] |
| `sendline`     | Sends `data` followed by a newline to the target's stdin.<br><br>**Parameters**:<br>- `data` (bytes)                                                              |
| `sendlineafter`| Sends a line of `data` after receiving a specified number of occurrences of a delimiter from stdout.<br><br>**Parameters**:<br>- `delims` (bytes)<br>- `data` (bytes)<br>- `occurrences` (int) &nbsp;&nbsp;&nbsp; \[default = 1\]<br>- `drop` (bool) &nbsp;&nbsp;&nbsp; \[default = False\]<br>- `timeout` (int) &nbsp;&nbsp;&nbsp; \[default = timeout_default\]<br>- `optional` (bool) &nbsp;&nbsp;&nbsp; \[default = False\] |
| `close`        | Closes the connection to the target.                                                                                                                             |
| `interactive`  | Enters interactive mode, allowing manual send/receive operations with the target. Read more in the [dedicated section](#interactive-io).<br><br>**Parameters**:<br>- `prompt` (str) &nbsp;&nbsp;&nbsp; \[default = "$ "\]<br>- `auto_quit` (bool) &nbsp;&nbsp;&nbsp; \[default = False\] |

!!! INFO "When process is stopped"
    When the process is stopped, the [PipeManager](../../from_pydoc/generated/commlink/pipe_manager) will not be able to receive new (unbuffered) data from the target. For this reason, the API includes a parameter called `optional`.
    
    When set to `True`, **libdebug** will not necessarily expect to receive data from the process when it is stopped. When set to `False`, any recv-like instruction (including `sendafter` and `sendlineafter`) will fail with an exception when the process is not running.
    
    Operations on stdin like `send` and `sendline` are not affected by this limitation, since the kernel will buffer the data until the process is resumed.

### :material-keyboard: Interactive I/O
The [PipeManager](../../from_pydoc/generated/commlink/pipe_manager) contains a method called `interactive()` that allows you to directly interact with the process's standard I/O. This method will print characters from standard output and error and read your inputs, letting you interact naturally with the process. The `interactive()` method is blocking, so the execution of the script will wait for the user to terminate the interactive session. To quit an interactive session, you can press `Ctrl+C` or `Ctrl+D`.

!!! ABSTRACT "Function Signature"
    ```python
    pipe.interactive(prompt: str = prompt_default, auto_quit: bool = False):
    ```

The `prompt` parameter sets the line prefix in the terminal (e.g. `"$ "` and `"> "` will produce `$ cat flag` and `> cat flag` respectively). By default, it is set to `"$ "`. The `auto_quit` parameter, when set to `True`, will automatically quit the interactive session when the process is stopped.

If any of the file descriptors of standard input, output, or error are closed, a warning will be printed.

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
    **libdebug** uses the `ptrace` system call to interact with the process. For security reasons, this system call is limited by the kernel according to a [`ptrace_scope`](https://www.kernel.org/doc/Documentation/security/Yama.txt) parameter. Different systems have different default values for this parameter. If the `ptrace` system call is not allowed, the `attach()` method will raise an exception notifying you of this issue.