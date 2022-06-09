# libdebug
libdebug is a python library to automate the debugging of a binary executable.

## Install
```bash
pip install git+https://github.com/JinBlack/libdebug
```

## Attach/Detach
You can use the method `run` to start a binary using the path to the binary
```python
from libdebug import Debugger
d = Debugger()
d.run("./test")
```

You can attach to a running pid using `attach`
```python
d = Debugger()
d.attach(1234)
```
or

```python
d = Debugger(1234)
```
`detach` is used to unleash the process. `stop` is used to terminate a process executed with `run`. You can use `reattach` to attach back to a process after `detach`

## Register
you can access register as property of the cluss `Debugger`. You can user the property to read and write registers.
```python
d = Debugger()
d.run("./test")
print(d.rax)
d.rax = 0
```
## Memory
`mem` is used to access memory of the debugged program. You can use `d.mem` with the array-link python syntax both for read and write.

```python
d = Debugger()
d.run("./test")
print("[rsp]: ", d.mem[d.rsp])
print("[rsp]: ", d.mem[d.rsp:d.rsp+0x10])
d.mem[d.rsp:d.rsp+0x10] = b"AAAAAAABC"
```

## Control Flow
`step()` will execute a single instruction stepping into function calls

`step_until(<addr>)` keep executing `step()` untill `rip == <addr>` .

`cont()` will continue the execution.

`next()` will execute a single instruction but wil step over the function calls. Indeed, this is implemented checking id the next instruction is a `call` instruction and setting a beakpoints on the return address of the called function.

`finish()` will continue the execution until the return from the current function. (The return is computed retriving the return address from `rbp+8`)


`breakpoint(<address>, [name=<libname>], [hw=False])` to set a breakpoint, name is part of the string to search for relative breakpoints, hw is a bool to specify if you want to use hardware breakpoint. 

`del_bp(<address>)` to remove the break point.

```python
bp = d.breakpoint(0x1234, "libc")
d.cont()
d.del_bp(dp)
```

### Non Blocking Continue
`cont` can be nonblocking. In this case the waitpid is avoided. The library will stop the process when there is an operation that require the process to be stopped.
```python
for i in range(10):
    d.cont(blocking=False)
    time.sleep(0.1)
    print("rip: %#x" % d.rip)
```

## GDB
Migrate debugging to gdb

```python
d.gdb()
```

with default option gdb is executed using `execve`. This means that the python script does not exists anymore after the spawn of gdb.

It is possible to spwn gdb in a differen shell keeping the script alive:
```python
d.gdb(spawn=True)
```
`spawn=True` option will execute gdb without eliminating the current process. In this case the library will use the content of `d.terminal` to spawn a new terminal emulator to handle the new gdb process. The default option fo `d.terminal` is `['tmux', 'splitw', '-h']`. This option will create a vertical separation in a `tmux` shell.



