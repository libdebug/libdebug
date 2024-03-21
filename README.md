# libdebug
libdebug is a Python library to automate the debugging of a binary executable.

## Installation
```bash
python3 -m pip install git+https://github.com/io-no/libdebug.git@threading
```
PyPy3 is supported but not recommended, as it performs worse.

### Installation Requirements:
Ubuntu: `sudo apt-get install -y python3 python3-dev python3-pip libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`  
Debian: `sudo apt-get install -y python3 python3-dev python3-pip python3-venv libdwarf-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`  
Fedora: `sudo dnf install -y python3 python3-devel kernel-devel pypy3 pypy3-devel binutils-devel libdwarf-devel`  
Arch Linux: `sudo pacman -S --noconfirm python python-pip pypy3 libelf libdwarf gcc make debuginfod`  

## Run and Attach
The first step of a libdebug script is creating a debugger object. This can be done with the function `debugger(argv,...)`. You can either provide a path or an array of arguments. Once your debugger object has been created, you can use the method `run` to start it
```python
from libdebug import debugger

d = debugger("./test")

d.run()
```

Alternatively, you can attach to an already running process using `attach` and specifying the PID.
```python
d = debugger("./test")

d.attach(1234)
```

The debugger has many more options that can be configured by the user:
```python
d = debugger(argv=<"./test" | ["./test", ...]>,
    [enable_aslr=<True | False>], # defaults to False
    [env={...}], # defaults to the same environment in which the debugging script is run
    [continue_to_binary_entrypoint=<True | False>], # defaults to True
    [auto_interrupt_on_command=<True | False>], #defaults to True
)
```
By setting `continue_to_binary_entrypoint` to False, the `run()` command will stop at the first instruction executed by the loader instead of reaching the entrypoint of the binary.

---

The flag `auto_interrupt_on_command` fundamentally changes the way you use libdebug. By default it is set to True. In this setting, every debugging command transparenty stops the execution of the program to perform the requested action as soon as possible. This is an example extract of code in the default mode:

```python
d = debugger("./binary")

bp = d.breakpoint("function")

d.run()
d.cont()

# If you do not call d.wait() here, the register access will be performed
# shortly after the process is allowed to continue
d.wait()
print(hex(d.rip))

d.kill()
```

Instead, when set to False, issued commands will not be performed until a breakpoint is hit or any other tracing signal stops the process (e.g, SIGSEGV).

```python
d = debugger("./binary")

bp = d.breakpoint("function")

d.run()
d.cont()

# Here the register access is performed after the breakpoint is hit
print(hex(d.rip))

d.kill()
```

## Register Access
Registers are provided as properties of the debugger object. You can perform read and write operations on them, which by default are handled when the process is stopped by a breakpoint or another tracing signal.
```python
d = debugger("./test")

d.run()

print(d.rax)
d.rax = 0
```

## Memory Access
The debugger property `memory` is used to read and write a memory address or range in the virtual memory of the debugged program.
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

`step_until(<address | symbol>, [max_steps=-1])` will step until the desired address is reached or for `max_steps` steps, whichever comes first.

`breakpoint(<address | symbol>, [hardware=False])` will set a breakpoint, which can be hardware-assisted.

`watchpoint(<address | symbol>, [condition='w'])`
will set a watchpoint for the requested stopping condition: on write (`w`), on read and write (`rw`) or on execution (`x`, which basically corresponds to a hardware breakpoint).
```python
bp = d.breakpoint(0x1234)

d.cont()
d.wait()

assert d.rip == bp.address
```

## Asynchronous Callbacks
Breakpoints can be asynchronous: instead of interrupting the main Python script, they can register a small callback function that is run upon hitting the breakpoint. Execution of the debugged process is continued automatically.
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

Each thread exposes its own set of register access properties. Control flow is synchronous between threads: they either are all stopped or all running, and every time a thread stops, all the others are stopped. This is done to avoid concurrency issues.

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
The `Breakpoint` class represents a breakpoint for the traced process. It can be created with a function of the debugger object in the following way:
```python
bp = d.breakpoint(position=0x1234, hardware=False, condition=None, length=1, callback=None)
```
`position` represents a memory address or a symbol of the ELF. The `hardware` flag trivially controls whether or not the breakpoint is hardware assisted (a maximum of 4 hardware breakpoints are allowed). `condition`and `length`are used to specify properties of hardware watchpoints (see next section). For any type of breakpoint, a `callback` function can be specified. When set, a breakpoint hit will trigger the callback and automatically resume the execution of the program.

For your convenience, a Breakpoint object counts the number of times the breakpoint has been hit. The current count can be accessed though the `hit_count` property:
```python
bp = d.breakpoint(0x1234)
d.cont()

for i in range(15):
    d.wait()

    assert d.rip == bp.address
    assert bp.hit_count == i

    d.cont()
```

Since breakpoints in the program text are shared between threads, you can check if a breakpoint was hit on a specific thread with the `hit_on` function:
```python
# Assuming to have thread n.3
chosen_thread = d.threads[3]

bp = d.breakpoint(0x1234)
d.cont()

for i in range(15):
    d.wait()

    assert d.rip == bp.address
    assert bp.hit_on(chosen_thread)

    if bp.hit_on(chosen_thread):
        ...

    d.cont()
```

## Watchpoints
The suggested way to insert a watchpoint is the following:

```python
wp = d.watchpoint(position=0x1234, condition='rw', length=8, callback=None)
```
The function returns a `Breakpoint` object, which can be interacted with in the same manner as traditional breakpoints. Valid conditions for the breakpoint are `w`, `rw` and `x` (default is `w`). It is also possible to specify the length of the word being watched (default is 1 byte).