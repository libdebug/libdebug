## Registers
- floating points (get ymm register using PTRACE_GETREGSET)
- rip read and write with pie support
## Memory Access
- check if allignement is really needed
## Control Flow
- run until ret
- break point hw
- watch points
- catch syscall
## Signals
- set mask
- get mask
## MultiThread

## GDB
- Implement go back gdb command
- set current breakpoints into gdb

## MultiArch
- x86
- arm?

## Ideas
### Snapshotting
 Can I snapshot the program? 
 I see 2 options. (1) Copy and store all registers and memory. (2) fork the process and keep the new process as snapshot backup.

### GDBServer
Support GDBServer as backend instead of using ptrace directly.
