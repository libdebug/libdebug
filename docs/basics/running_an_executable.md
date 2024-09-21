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

When execution is resumed, chances are that your process will need to take input and produce output. To interact with the standard input and output of the process, you can use the [pipe handle](../../from_pydoc/utils/pipe_manager) returned by the `run()` function.

You can interact with the process's pipe handle using the following commands:

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

