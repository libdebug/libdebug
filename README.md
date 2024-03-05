# libdebug
libdebug is a Python library to automate the debugging of a binary executable.

## Installation
```bash
python3 -m pip install git+https://github.com/io-no/libdebug.git@threading
```

## Attach
After providing the path to the executable, you can use the methdo `run` to start it
```python
from libdebug import debugger

d = debugger("./test")

d.run()
```

You can attach to an already running process using `attach`
```python
d = debugger("./test")

d.attach(1234)
```

## Register Access
Registers are provided as properties of the class `Debugger`. You can read from and write to them when the process is interrupted.
```python
d = debugger("./test")

d.run()

print(d.rax)
d.rax = 0
```

## Memory Access
`memory` is used to access the memory of the debugged program. You can use the `d.memory` property to read from and write to it.
We provide multiple elegant ways of accessing it, such as:

```python
d = debugger("./test")

d.run()

print("[rsp]: ", d.memory[d.rsp])
print("[rsp]: ", d.memory[d.rsp:d.rsp+0x10])
print("[rsp]: ", d.memory[d.rsp, 0x10])

print("[main_arena]: ", d.memory["main_arena"])
print("[main_arena+8:main_arena+18]: ", d.memory["main_arena+8", 0x10])

d.memory[d.rsp, 0x10] = b"AAAAAAABC"
d.memory["main_arena"] = b"12345678"
```

## Control Flow
`step()` will execute a single instruction stepping into function calls

`cont()` will continue the execution, without blocking the main Python script.

`wait()` will block the execution of the Python script until the debugging process interrupts.

`breakpoint(<address | symbol>, [hardware=False])` to set a breakpoint, which can be hardware-assisted. 

```python
bp = d.breakpoint(0x1234)

d.cont()
d.wait()

assert d.rip == bp.address
```

## Asynchronous Callbacks
Breakpoints can be asynchronous: instead of interrupting the main Python script, they can register a small callback function that gets run on hitting the breakpoint, and then the execution is continued automatically.
```python
d = debugger("./test")
d.run()

def callback(d, bp):
    print(hex(d.rip))
    assert d.rip == bp.address
    print(hex(d.memory[d.rax, 0x10]))

d.breakpoint(0x1234, callback=callback)

d.cont()
d.wait()
```

## Multithreading Support
Libdebug supports multithreaded applications: each time the process clones itself, the new thread is automatically traced and registered in the `threads` property of the `debugger`.

Each thread exposes its own set of register access properties. Control flow is synchronous between threads: they either are all stopped or all running, and every time a thread stops all the others get stopped. This is done to avoid concurrency issues.

```python
d = debugger("./threaded_test")
d.run()
d.cont()

for _ in range(15):
    d.wait()

    for thread_id, thread in d.threads.items():
        print(hex(thread.rip))

    d.cont()

d.kill()
```

## Breakpoints
The `Breakpoint` class automatically counts the number of times the breakpoint has been it: this is accessible though the `hit_count` property:

```python
bp = d.breakpoint(0x1234)
d.cont()

for i in range(15):
    d.wait()

    assert d.rip == bp.address
    assert bp.hit_count == i

    d.cont()
```
