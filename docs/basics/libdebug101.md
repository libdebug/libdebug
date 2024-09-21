---
icon: material/school-outline
search:
    boost: 4
---
# :material-school-outline: **libdebug** 101
Welcome to **libdebug**! When writing a script to debug a program, the first step is to create a [Debugger](../../from_pydoc/generated/debugger/debugger/) object. This object will be your main interface for debugging commands.

```python
from libdebug import debugger

debugger = debugger(argv=["./program", "arg1", "arg2"]) # (1)
```

1. You can either pass the name of the executable as a positional string argument, or a list of argv parameters for the execution.

!!! INFO "Am I already debugging?"
    Creating a [Debugger](../../from_pydoc/generated/debugger/debugger/) object will not start the execution automatically. You can reuse the same debugger to iteratively run multiple instances of the program. This is particularly useful for smart bruteforcing or fuzzing scripts.

    To run the executable, refer to [Running an Executable](../running_an_executable)

### Environment
Just as you would expect, you can also pass environment variables to the program using the `env` parameter. Here, the variables are passed as a string-string dictionary.

```python
from libdebug import debugger

debugger = debugger("test", env = {"LD_PRELOAD": "musl_libc.so"})
```

### Address Space Layout Randomization (ASLR)
Modern operating system kernels implement mitigations against predictable addresses in binary exploitation scenarios. One such feature is [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), which randomizes the base address of mapped virtual memory pages (e.g., binary, libraries, stack). When debugging, this feature can become a nuisance for the user.

For your convenience, the default behavior on **libdebug** is to disable ASLR. The debugger `aslr` parameter can be used to change this behavior.

```python
from libdebug import debugger

debugger = debugger("test", aslr=True)
```

### Binary Entry Point
When a child process is spawned on the Linux kernel through the [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html) system call, it is possible to trace it as soon as the loader has set up your executable. Debugging these first instructions inside the loader library is generally uninteresting.

For this reason, the default behavior for **libdebug** is to continue until the binary entry point (1) is reached. When you need to start debugging from the very beginning, you can simply disable this behavior in the following way:
{ .annotate }

1. In Linux, the binary entry point corresponds to the `_start` / `__rt_entry` symbol in your binary executable. This function is the initial stub that calls the `main()` function in your executable, through a call to the standard library of your system (e.g., [`__libc_start_main`](https://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/baselib---libc-start-main-.html), [`__rt_lib_init`](https://developer.arm.com/documentation/dui0475/m/the-c-and-c---library-functions-reference/--rt-entry))

```python
from libdebug import debugger

debugger = debugger("test", continue_to_binary_entrypoint=False)
```

!!! WARNING "What the hell are you debugging?"
    Please note that this feature assumes the binary is well-formed. If the ELF header is corrupt, the binary entrypoint will not be resolved correctly. As such, setting this parameter to `False` is a good practice when you don't want **libdebug** to rely on this information.

### What else can I do?
The [Debugger](../../from_pydoc/generated/debugger/debugger/) object has many more parameters it can take. Since they are associated to other features, we will mention them later in the documentation.