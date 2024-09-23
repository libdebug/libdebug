---
icon: material/flower-tulip-outline
search:
    boost: 4
---
## :material-flower-tulip-outline: Pretty Printing
**libdebug** offers utilities to visualize the process's state in a human-readable format and with color highlighting. This can be especially useful when debugging complex binaries or when you need to quickly understand the behavior of a program.

### :material-hexadecimal: Registers Pretty Printing
There are two functions available to print the registers of a thread: `pprint_registers()` and `print_registers_all()`. The former will print the current values of general-purpose registers, while the latter will print all available registers.

<img src="../../assets/pprint_regs.jpeg" alt="Pretty Printing Registers" width="100%"/>

!!! TIP "Aliases"
    If you don't like long function names, you can use aliases for the two register pretty print functions. The shorter aliases are `pprint_regs()` and `print_regs_all()`.


### :fontawesome-solid-terminal: Syscall Trace Pretty Printing
When debugging a binary, it is often much faster to guess what the intended functionality is by looking at the syscalls that are being invoked. libdebug offers a function that will intercept any syscall and print its arguments and return value. This can be done by setting the property `pprint_syscalls = True` in the debugger object and resuming execution.

!!! ABSTRACT "Syscall Trace PPrint Syntax"
    ```python
    d.pprint_syscalls = True
    d.cont()
    ```

The output will be printed to the console in color accoring to the following coding:

| Format | Description |
| --- | --- |
| <span style="color: #51A1FF">blue</span> | Syscall name |
| <span style="color: #E03239">red</span> | Syscall was intercepted and handled by a callback (either a basic handler or a hijack) |
| <span style="color: #EAD858">yellow</span> | Value given to a syscall argument in hexadecimal |
| <del>strikethrough</del> | Syscall was hijacked, the next line contains the syscall executed in its place |

Handled syscalls with a callback associated with them will be listed as such. Additionally, syscalls hijacked through the libdebug API will be highlighted as striken through, allowing you to monitor both the original behavior and your own changes to the flow.

<img src="https://github.com/libdebug/libdebug/blob/dev/media/pprint_syscalls.png?raw=true" alt="Pretty Printing Syscalls" width="`100%"/>

### :material-map-search: Memory Maps Pretty Printing
To pretty print the memory maps of a process, you can simply use the `pprint_maps()` function. This will print the memory maps of the process in a human-readable format, with color highlighting to distinguish between different memory regions.

| Format | Description |
| --- | --- |
| <span style="color: #50C97B">green</span> | Memory map with read permission only |
| <span style="color: #EAD858">yellow</span> | Memory map with read and write permissions |
| <span style="color: #E03239">red</span> | Memory map with read and execute permissions |
| <span style="color: #E03239"><u>underlined</u></span> | Memory map with read, write, and execute permissions |

<img src="../../assets/pprint_maps.jpeg" alt="Pretty Printing Memory Maps" width="100%"/>


### :octicons-stack-24: Stack Trace Pretty Printing
To pretty print the stack trace (backtrace) of a process, you can use the `pprint_backtrace()` function. This will print the stack trace of the process in a human-readable format.

<img src="../../assets/pprint_backtrace.jpeg" alt="Pretty Printing Stack Trace" width="100%"/>