---
icon: material/flower-tulip-outline
search:
    boost: 4
---
## :material-flower-tulip-outline: Pretty Printing
**libdebug** offers utilities to visualize the process's state in a human-readable format and with color highlighting. This can be especially useful when debugging complex binaries or when you need to quickly understand the behavior of a program.

### :material-hexadecimal: Registers Pretty Printing
There are two functions available to print the registers of a thread: `pprint_registers()` and `print_registers_all()`. The former will print the current values of general-purpose registers, while the latter will print all available registers.

!!! TIP "Aliases"
    If you don't like long function names, you can use aliases for the two register pretty print functions. The shorter aliases are `pprint_regs()` and `print_regs_all()`.

```
rax	0x3c
rbx	0x0
rcx	0x7fffffffdb58
rdx	0x7ffff7fcb200
rdi	0x7ffff7ffe2e0
rsi	0x7ffff7ffe8b8
r8	0x0
r9	0x7ffff7ffb380
r10	0xffffffffffffff88
r11	0x246
r12	0x555555559130
r13	0x7fffffffdb40
r14	0x0
r15	0x0
rbp	0x0
rsp	0x7fffffffdb40
rip	0x555555559130
{
  mm0	0x0
  st0	0.0
}
{
  mm1	0x0
  st1	0.0
}
```

### :fontawesome-solid-terminal: Syscall Trace Pretty Printing
When debugging a binary, it is often much faster to guess what the intended functionality is by looking at the syscalls that are being invoked. libdebug offers a function that will intercept any syscall and print its arguments and return value. This can be done by setting the property `pprint_syscalls = True` in the debugger object.

The output will be printed to the console in color. Handled syscalls with a callback associated with them will be listed as such. Additionally, syscalls hijacked through the libdebug API will be highlighted as striken through, allowing you to monitor both the original behavior and your own changes to the flow.

<img src="https://github.com/libdebug/libdebug/blob/dev/media/pprint_syscalls.png?raw=true" alt="Pretty Printing Syscalls" width="`100%"/>

### :material-map-search: Memory Maps Pretty Printing
