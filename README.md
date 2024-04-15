# libdebug
libdebug is a Python library to automate the debugging of a binary executable.

## Installation
```bash
python3 -m pip install git+https://github.com/libdebug/libdebug.git
```
PyPy3 is supported but not recommended, as it performs worse on most of our tests.

### Installation Requirements:
Ubuntu: `sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`
Debian: `sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`
Fedora: `sudo dnf install -y python3 python3-devel kernel-devel binutils-devel libdwarf-devel`
Arch Linux: `sudo pacman -S python libelf libdwarf gcc make debuginfod`

## Run and Attach
The first step of a libdebug script is creating a debugger object. This can be done with the function `debugger(argv,...)`. You can either provide a path or an array of arguments. Once your debugger object has been created, you can use the method `run` to start it
```python
from libdebug import debugger

d = debugger("./test")

d.run()
```

Alternatively, you can attach to an already running process using `attach` and specifying the PID.
```python
d = debugger()

d.attach(1234)
```

The debugger has many more options that can be configured by the user:
```python
d = debugger(argv=<"./test" | ["./test", ...]>,
    [enable_aslr=<True | False>], # defaults to False
    [env={...}], # defaults to the same environment in which the debugging script is run
    [continue_to_binary_entrypoint=<True | False>], # defaults to True
    [auto_interrupt_on_command=<True | False>], #defaults to False
)
```
By setting `continue_to_binary_entrypoint` to False, the `run()` command will stop at the first instruction executed by the loader instead of reaching the entrypoint of the binary.

---

The flag `auto_interrupt_on_command` fundamentally changes the way you use libdebug. By default it is set to False. In this setting, issued commands will not be performed until a breakpoint is hit or any other tracing signal stops the process (e.g, SIGSEGV).
This is an example extract of code in the default mode:

```python
d = debugger("./binary")

bp = d.breakpoint("function")

d.run()
d.cont()

# Here the register access is performed after the breakpoint is hit
print(hex(d.rip))

d.kill()
```

Instead, when set to True, every debugging command transparenty stops the execution of the program to perform the requested action as soon as possible.

```python
d = debugger("./binary", auto_interrupt_on_command=True)

bp = d.breakpoint("function")

d.run()
d.cont()

# If you do not call d.wait() here, the register access will be performed
# shortly after the process is allowed to continue
d.wait()
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
The debugger property `memory` is used read to and write from a memory address or range in the virtual memory of the debugged program.
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
```

## Multithreading Support
Libdebug supports multithreaded applications: each time the process clones itself, the new thread is automatically traced and registered in the `threads` property of the `debugger`.

Each thread exposes its own set of register access properties. Control flow is synchronous between threads: they either are all stopped or all running, and every time a thread stops, all the others are stopped. This is done to avoid concurrency issues.

```python
d = debugger("./threaded_test")
d.run()
d.cont()

for _ in range(15):
    for thread in d.threads:
        print(thread.thread_id, hex(thread.rip))

    d.cont()

d.kill()
```

## Breakpoints
The `Breakpoint` class represents a breakpoint for the traced process. It can be created with a function of the debugger object in the following way:
```python
bp = d.breakpoint(position=0x1234, hardware=False, condition=None, length=1, callback=None)
```
`position` represents a memory address or a symbol of the ELF. The `hardware` flag trivially controls whether or not the breakpoint is hardware assisted (a maximum of 4 hardware breakpoints are allowed). `condition` and `length` are used to specify properties of hardware watchpoints (see next section). For any type of breakpoint, a `callback` function can be specified. When set, a breakpoint hit will trigger the callback and automatically resume the execution of the program.

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

## Syscall Hooking
libdebug supports hooking system calls in the debugged binary in the following way:
```python
def on_enter_open(d: ThreadContext, syscall_number: int):
    print("entering open")
    d.syscall_arg0 = 0x1

def on_exit_open(d: ThreadContext, syscall_number: int):
    print("exiting open")
    d.syscall_return = 0x0

sys_hook = d.hook_syscall(syscall="open", on_enter=on_enter_open, on_exit=on_exit_open)
```
`hook_syscall` accepts either a number or a string.
If the user provides a string, a syscall definition list is downloaded from [syscalls.mebeim.net](https://syscalls.mebeim.net/?table=x86/64/x64/latest) and cached internally in order to convert it into the corresponding syscall number.
`on_enter` and `on_exit` are optional: they are called only if present. At least one callback is required between `on_enter` and `on_exit` to make the hook meaningful.

Syscall hooks, just like breakpoints, can be enabled and disabled, and automatically count the number of invocations:
```py
sys_hook.disable()
sys_hook.enable()

print(sys_hook.hit_count)
```
Note: there can be at most one hook for each syscall.

## Builtin Hooks
libdebug provides some easy-to-use builtin hooks for syscalls:
- antidebug_escaping
Automatically patches binaries which use the return value of `ptrace(PTRACE_TRACEME, 0, 0, 0)` to verify that no external debugger is present.
Usage:
```py
from libdebug import debugger
from libdebug.builtin import antidebug_escaping

d = debugger(...)
d.run()

antidebug_escaping(d)

d.cont()
[...]
```

- pretty_print_syscall
Installs a hook on any syscall that automatically prints the input arguments and the corresponding return values, just like strace does.
By default, it hooks every syscall. The user can specify either a list of syscalls to hook onto, or a list of syscalls to exclude from hooking.
Usage:
```py
from libdebug import debugger
from libdebug.builtin import pretty_print_syscall

d = debugger("/usr/bin/ls")
d.run()

pretty_print_syscall(d,
    # syscalls = ["execve", "open", "getcwd"],
    # exclude = ["fork", "vfork", "exit_group"]
)

d.cont()
[...]
```
This results in an output similar to:
```
openat(int dfd = 0xffffff9c, const char *filename = 0x7ffff7f241b0, int flags = 0x80000, umode_t mode = 0x0) = 0x3
newfstatat(int dfd = 0x3, const char *filename = 0x7ffff7f1abd5, struct stat *statbuf = 0x7ffff7f53840, int flag = 0x1000) = 0x0
mmap(unsigned long addr = 0x0, unsigned long len = 0xd5f8ef0, unsigned long prot = 0x1, unsigned long flags = 0x2, unsigned long fd = 0x3, unsigned long off = 0x0) = 0x7fffea600000
close(unsigned int fd = 0x3) = 0x0
ioctl(unsigned int fd = 0x1, unsigned int cmd = 0x5401, unsigned long arg = 0x7fffffffd3a0) = 0x0
ioctl(unsigned int fd = 0x1, unsigned int cmd = 0x5413, unsigned long arg = 0x7fffffffd4c0) = 0x0
openat(int dfd = 0xffffff9c, const char *filename = 0x5555555806c0, int flags = 0x90800, umode_t mode = 0x0) = 0x3
newfstatat(int dfd = 0x3, const char *filename = 0x7ffff7f1abd5, struct stat *statbuf = 0x7fffffffd070, int flag = 0x1000) = 0x0
getdents64(unsigned int fd = 0x3, struct linux_dirent64 *dirent = 0x555555580710, unsigned int count = 0x8000) = 0x50
getdents64(unsigned int fd = 0x3, struct linux_dirent64 *dirent = 0x555555580710, unsigned int count = 0x8000) = 0x0
[...]
```
