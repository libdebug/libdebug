## Registers
- floating points
- rip read and write with pie support
## Memory Access
- check if allignement is really needed
## Control Flow
- run until ret
- finish
- break point hw
- watch points
- catch syscall
## MultiThread

## GDB
- implement gdb auto remove of STOP
- Implement go back gdb command
## Ideas
### Snapshotting
 Can I snapshot the program? 
 I see 2 options. (1) Copy and store all registers and memory. (2) fork the process and keep the new process as snapshot backup.
