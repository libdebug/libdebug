---
icon: material/note-text
search:
    boost: 4
---
# :material-note-text: Logging
Debugging an application with the freedom of a rich API can lead to flows which are hard to unravel. To aid the user in the debugging process, **libdebug** provides logging. The logging system is implemented in the submodule [`liblog`](/from_pydoc/generated/liblog) and adheres to the [Python logging system](https://docs.python.org/3/library/logging.html).

## Event Logging
By default, **libdebug** only prints critical logs such as warnings and errors. However, the user can enable more verbose logging by setting the `argv` parameter of the script.

The available logging modes for events are:

| Mode | Description |
| --- | --- |
| `debugger` | Logs related to the debugging operations performed on the process by **libdebug**. |
| `pipe` | Logs related to interactions with the process pipe: bytes received and bytes sent. |
| `dbg` | Combination of the `pipe` and `debugger` options. |

!!! WARNING "pwntools compatibility"
    As reported in this documentation, the `argv` parameters passed to **libdebug** are *lowercase*. This choice is made to avoid conflicts with [pwntools](https://github.com/Gallopsled/pwntools), which intercepts all uppercase arguments.

### :octicons-bug-24: Debugger Logging
The `debugger` option displays all logs related to the debugging operations performed on the process by libdebug.

<img src="https://github.com/libdebug/libdebug/blob/main/media/debugger_argv.png?raw=true" alt="debugger argv option" />

### :material-pipe: Pipe Logging
The `pipe` option, on the other hand, displays all logs related to interactions with the process pipe: bytes received and bytes sent.
 
<img src="/assets/pipe_logging.jpeg" alt="pipe argv option" />

### :material-vector-union: The best of both worlds
The `dbg` option is the combination of the `pipe` and `debugger` options. It displays all logs related to the debugging operations performed on the process by libdebug, as well as interactions with the process pipe: bytes received and bytes sent.

## :fontawesome-solid-person-military-pointing: Changing logging levels at runtime
**libdebug** defines logging levels and information types to allow the user to filter the granularity of the the information they want to see. Logger levels for each event type can be changed at runtime using the [`libcontext`](/from_pydoc/generated/utils/libcontext) module.

!!! ABSTRACT "Example of setting logging levels"
    ```python
    from libdebug import libcontext

    libcontext.general_logger = 'DEBUG'
    libcontext.pipe_logger = 'DEBUG'
    libcontext.debugger_logger = 'DEBUG'
    ```

| Logger | Description | Supported Levels | Default Level |
| --- | --- | --- | --- |
| `general_logger` | Logger used for general **libdebug** logs, different from the `pipe` and `debugger` logs. | `DEBUG`, `INFO`, `WARNING`, `SILENT` | `INFO` |
| `pipe_logger` | Logger used for pipe logs. | `DEBUG`, `SILENT` | `SILENT` |
| `debugger_logger` | Logger used for debugger logs. | `DEBUG`, `SILENT` | `SILENT` |

Let's see what each logging level actually logs:

| Log Level | Debug Logs | Information Logs | Warnings |
|-----------|------------|------------------|----------|
| DEBUG     | :material-check: | :material-check: | :material-check: |
| INFO      |                | :material-check: | :material-check: |
| WARNING   |                |                  | :material-check: |
| SILENT    |                |                  |            |


### :material-script-text-play-outline: Temporary logging level changes
Logger levels can be temporarily changed at runtime using a `with` statement, as shown in the following example.

```python
from libdebug import libcontext

with libcontext.tmp(pipe_logger='SILENT', debugger_logger='DEBUG'):
    r.sendline(b'gimme the flag')
```