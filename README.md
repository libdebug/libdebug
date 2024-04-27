# libdebug
libdebug is a Python library to automate the debugging of a binary executable.

## Installation
```bash
python3 -m pip install git+https://github.com/libdebug/libdebug.git
```
PyPy3 is supported but not recommended, as it performs worse on most of our tests.

### Installation Requirements:
Ubuntu: `sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`\
Debian: `sudo apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`\
Arch Linux: `sudo pacman -S python libelf libdwarf gcc make debuginfod` \
Fedora: `sudo dnf install -y python3 python3-devel kernel-devel binutils-devel libdwarf-devel`

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

## Interaction with the Process
When libdebug spawns a process using `d.run()`, it returns an object that allows interaction with the process. \
For clarity and simplicity, the APIs provided are similar to those offered by [pwntools](https://github.com/Gallopsled/pwntools).

#### recv
Receives at most numb bytes from the child process stdout.
```
Args:
    numb (int, optional): number of bytes to receive. Defaults to None.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received bytes from the child process stdout.
```
Example:
```py
r = d.run()

output = r.recv(
    numb = 4, 
    timeout = 2
)
```

#### recverr
Receives at most numb bytes from the child process stderr.

```
Args:
    numb (int, optional): number of bytes to receive. Defaults to None.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received bytes from the child process stdout.
```
Example:
```py
r = d.run()

error = r.recverr(
    numb = 4, 
    timeout = 2
)
```

#### recvuntil
Receives data from the child process stdout until the delimiters are found.
```
Args:
    delims (bytes): delimiters where to stop.
    occurences (int, optional): number of delimiters to find. Defaults to 1.
    drop (bool, optional): drop the delimiter. Defaults to False.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received data from the child process stdout.
```
Example:
```py
r = d.run()

output = r.recvuntil(
    delims = b'> ',
    occurences = 1,
    drop = False,
    timeout = 2
)
```

#### recverruntil
Receives data from the child process stderr until the delimiters are found.
```
Args:
    delims (bytes): delimiters where to stop.
    occurences (int, optional): number of delimiters to find. Defaults to 1.
    drop (bool, optional): drop the delimiter. Defaults to False.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received data from the child process stdout.
```
Example:
```py
r = d.run()

error = r.recerrvuntil(
    delims = b'> ',
    occurences = 1,
    drop = False,
    timeout = 2
)
```

#### recvline
Receives numlines lines from the child process stdout.
```
Args:
    numlines (int, optional): number of lines to receive. Defaults to 1.
    drop (bool, optional): drop the line ending. Defaults to True.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received lines from the child process stdout
```
Example:
```py
r = d.run()

output = r.recvline(
    numlines = 1,
    drop = False,
    timeout = 5,
)
```

#### recverrline
Receives numlines lines from the child process stderr.
```
Args:
    numlines (int, optional): number of lines to receive. Defaults to 1.
    drop (bool, optional): drop the line ending. Defaults to True.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received lines from the child process stdout
```
Example:
```py
r = d.run()

error = r.recverrline(
    numlines = 1,
    drop = False,
    timeout = 5,
)
```

#### send
Sends data to the child process stdin.
```
Args:
    data (bytes): data to send.

Returns:
    int: number of bytes sent.
```
Example:

```py
r = d.run()

r.send(b"gimme the flag")
```


#### sendline
Sends data to the child process stdin and append a newline.
```
Args:
    data (bytes): data to send.

Returns:
    int: number of bytes sent.
```
Example:

```py
r = d.run()

r.sendline(b"gimme the flag")
```

#### sendafter
Sends data to the child process stdin after the delimiters are found.
```
Args:
    delims (bytes): delimiters where to stop.
    data (bytes): data to send.
    occurences (int, optional): number of delimiters to find. Defaults to 1.
    drop (bool, optional): drop the delimiter. Defaults to False.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received data from the child process stdout.
    int: number of bytes sent.
```
Example:
```py
r = d.run()
r.sendafter(
    delims=b"> ",
    data=b"gimme the flag",
    occurences: 1,
    drop: False,
    timeout = 2,
    )
```

#### sendlineafter
Sends line to the child process stdin after the delimiters are found.
```
Args:
    delims (bytes): delimiters where to stop.
    data (bytes): data to send.
    occurences (int, optional): number of delimiters to find. Defaults to 1.
    drop (bool, optional): drop the delimiter. Defaults to False.
    timeout (int, optional): timeout in seconds. Defaults to 2 seconds.

Returns:
    bytes: received data from the child process stdout.
    int: number of bytes sent.
```
Example:
```py
r = d.run()
r.sendlineafter(
    delims=b"> ",
    data=b"gimme the flag",
    occurences: 1,
    drop: False,
    timeout = 2,
    )
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
Note: There can be at most one user-defined hook for each syscall. \
The pretty print function (described below) is not considered a user-defined hook. Therefore, it is possible to hook/hijack and pretty print the same syscall simultaneously. \
If a new hook is defined for a syscall that is already hooked or hijacked, the new hook replaces the old one, and a warning is shown.

For example, the following code

```python
def on_enter_open_1(d: ThreadContext, syscall_number: int):
    print("entering open 1")
    d.syscall_arg0 = 0x1

def on_exit_open_1(d: ThreadContext, syscall_number: int):
    print("exiting open 1")
    d.syscall_return = 0x0

def on_enter_open_2(d: ThreadContext, syscall_number: int):
    print("entering open 2")
    d.syscall_arg0 = 0x4

def on_exit_open_2(d: ThreadContext, syscall_number: int):
    print("exiting open 2")
    d.syscall_return = 0xffffffffffffffff

sys_hook_1 = d.hook_syscall(syscall="open", on_enter=on_enter_open_1, on_exit=on_exit_open_1)

sys_hook_2 = d.hook_syscall(syscall="open", on_enter=on_enter_open_2, on_exit=on_exit_open_2)
```
will override `sys_hook_1` with `sys_hook_2` showing the following warning

![alt text](media/syscall_hook_override_warning.png)

## Syscall Hijacking
libdebug also facilitates easy hijacking of syscalls, as shown in the following example:
```py
from libdebug import debugger

d = debugger("/usr/bin/ls")
d.run()

hook = d.hijack_syscall("read", "write")
# hook = d.hijack_syscall("read", 0x1)
# hook = d.hijack_syscall(0x0, 0x1)

d.cont()
[...]
```
#### Syscall Hijacking Loop Detection
During execution, libdebug checks for loops in syscall hijacking and raises an exception if infinite loops are detected. \
For example, the following code
```py
from libdebug import debugger

d = debugger("/usr/bin/ls")
d.run()

hook = d.hijack_syscall("read", "write")
hook = d.hijack_syscall("write", "read")

d.cont()
[...]
```
raises the following execption

![alt text](media/syscall_hijacking_loop_detection.png)

#### Hook on hijack
After a syscall is hijacked, the user can choose whether to execute the hook or hijacking installed in the newly executed syscall, if any. \

For example, if we hijack the syscall `read` with the syscall `write`, and the `write` is also hooked or hijacked, `hook_hijack` allows us to choose whether to execute the hook/hijack installed on the `write` when the read becomes a `write`. This helps reduce loops during hijacking and behaviors that are difficult to track

The syscall hijacking loop detection takes this choice into account.
```py
from libdebug import debugger

def on_enter_write(d: ThreadContext, syscall_number: int):
    print("entering write")

d = debugger("/usr/bin/ls")
d.run()

d.hook_syscall(syscall="write", on_enter=on_enter_write)

"""We want to change the read in write but we do not want to execute on_enter_write during hijacking"""
d.hijack_syscall("read", "write", hook_hijack=False)


d.cont()
[...]
```
The deafult value is True.


## Builtin Hooks
libdebug provides some easy-to-use builtin hooks for syscalls.
#### Antidebug Escaping
Automatically patches binaries which use the return value of `ptrace(PTRACE_TRACEME, 0, 0, 0)` to verify that no external debugger is present.
Usage:
```py
from libdebug import debugger

d = debugger("binary", escape_antidebug=True)
d.run()

antidebug_escaping(d)

d.cont()
[...]
```

#### Pretty Print of Syscalls
Installs a hook on any syscall that automatically prints the input arguments and the corresponding return values, just like strace does. \
By default, it hooks every syscall. The user can specify either a list of syscalls to hook onto, or a list of syscalls to exclude from hooking. These lists can contain syscall names, syscall numbers, or both. If one of the lists is modified after pretty print has been enabled, the changes are automatically applied as soon as the process stops. \
The pretty print output also indicates whether a syscall has been hooked, hijacked, or if its return value has been modified. \
Usage:
```py
from libdebug import debugger

d = debugger("/usr/bin/ls")
d.run()

d.pprint_syscalls = True

d.cont()
[...]
```

```py
from libdebug import debugger

d = debugger("/usr/bin/ls")
d.run()

with d.pprint_syscalls_context(True):
    d.cont()
[...]
```

This results in an output similar to:

![alt text](media/pprint_syscalls.png)

## Symbol Resolution
As anticipated, libdebug can accept ELF symbols as an alternative to addresses, thanks to its capability to parse the ELF file to find debugging symbols. libdebug offers five different levels for symbol resolutions, as follows:

- 0: Symbol resolution is disabled.
- 1: Parses the ELF symbol table (.symtab) and dynamic symbol table (.dynsym).
- 2: Parses the ELF DWARF.
- 3: Follows the external debug file link in the .gnu_debuglink and/or .gnu_debugaltlink sections, and if the file is present in the system, reads its .symtab and .dynsym.
- 4: Parses the external debug file DWARF, if the file exists in the system.
- 5: Downloads the external debug file using debuginfod. The file is cached in the debuginfod default folder.

The default values is 4 and it can be modified at runtime in the following way:
```py
from libdebug import debugger, libcontext
[...]
libcontext.sym_lvl = 5
d.breakpoint('main')
[...]
```
or also
```py
from libdebug import debugger, libcontext
[...]
with libcontext.tmp(sym_lvl = 5):
    d.breakpoint('main')
[...]
```
Lastly, libdebug automatically demangles the C++ symbols.

## Logging Levels
libdebug also helps debug scripts by providing two loggers, accessible through two argv parameters, both of which must be written in lowercase. This choice is made to avoid conflicts with [pwntools](https://github.com/Gallopsled/pwntools), which uses uppercase arguments.

#### debugger
The `debugger` option displays all logs related to the debugging operations performed on the process by libdebug.

![alt text](media/debugger_argv.png)

#### pipe
The `pipe` option, on the other hand, displays all logs related to interactions with the process, such as bytes received and sent.

![alt text](media/pipe_argv.png)

Both logger levels can be modified at runtime using a `with` statement, as shown in the following example.
```py
from libdebug import debugger, libcontext
[...]
with libcontext.tmp(pipe_logger='INFO', debugger_logger='DEBUG'):
    r.sendline(b'gimme the flag')
[...]
```

####
The `dbg` option, on the other hand, displays all logs shown with the `debugger` option as well as those displayed with the `pipe` option.

![alt text](media/dbg_argv.png)