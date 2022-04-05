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
`step()` will execute a single instruction `cont()` wil continue the execution.

`breakpoint(<address>, [<libname>])` to set a breakpoint. 

`del_bp(<address>)` to remove the break point.

```python
bp = d.breakpoint(0x1234, "libc")
d.cont()
d.del_bp(dp)
```

## GDB
Migrate debugging to gdb

```python
d.gdb()
```