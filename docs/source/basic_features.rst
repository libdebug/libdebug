
Basic Features
==============
When writing a script to debug a program, the first step is to create a Debugger object :class:`libdebug.debugger.debugger.Debugger`:

.. code-block:: python

    from libdebug import debugger
    debugger = debugger(argv=["./program", "arg1", "arg2"])


This will be your main interface to the debugger. You can either pass the name of the executable as a string, or a list of argv parameters for the execution.

Just as you would expect, you can also pass environment variables to the program using the env parameter. Here, the variables are passed as a string-string dictionary.

By default, debugged programs are run with ASLR disabled. If you want to enable it, you can set the `aslr` parameter to True.

You can also choose to debug the program starting from the just after the *execve* call, following the flow of the loader. By default, the debugger will continue to the entry point of the binary before giving you control. You can change this behavior by setting the `continue_to_binary_entrypoint` parameter to False. 

Please note that this feature assumes the binary is well-formed. If the ELF header is corrupt, the binary entrypoint will not be resolved correctly. As such, setting this parameter to False is a good practice when you don't want libdebug to rely on that information.

Creating a debugger object will not start the execution automatically. In fact, you can reuse the same debugger to iteratively run multiple instances of the program. This is particularly useful for smart bruteforcing or fuzzing scripts. 

As for the other parameters of the debugger, we will mention them later in the documentation.

Running the program
-------------------

After creating the debugger object, you can start the execution of the program using the `run()` method. This method will start execution on a child process and, unless otherwise specified, continue to the entry point.

.. code-block:: python

    d = debugger("program")
    pipes = d.run()


The `run()` command returns a `PipeManager` object, which you can use to interact with the program's standard input, output, and error. To read more about the PipeManager interface, please refer to the PipeManager documentation :class:`libdebug.utils.pipe_manager.PipeManager`. Please note that breakpoints are not kept between different runs of the program. If you want to set a breakpoint again, you should do so after the program has restarted.

Any process will be automatically killed when the debugging script exits. If you want to prevent this behavior, you can set the `kill_on_exit` parameter to False when creating the debugger object, or set the companion attribute `kill_on_exit` to False at runtime.

The command queue
-----------------
Control flow commands, register access and memory access are all done through the command queue. This is a FIFO queue of commands that are executed in order. 

While the inner workings of the command queue are transparent to the user, it is important to understand how its handling impacts the flow of the debugging script:

By default, a command is polled from the queue when the execution stops, either as a result of handling a breakpoint, a signal, or other similar events.
In the following example, the content of the RAX register is printed after the program hits the breakpoint or stops for any other reason:

.. code-block:: python

    d = debugger("program")

    d.breakpoint("func")

    d.cont()

    print(f"RAX: {hex(d.regs.rax)}")

This flow is similar to how a GDB script would work, allowing for a more intuitive starting point. If you would like to have more control, however, you can disable this behavior to make sure the command queue is polled as soon as possible.

This can be done by setting the `auto_interrupt_on_command` parameter to True when creating the debugger object. In this new scenario, we would have to modify the script to recreate the previous flow.

.. code-block:: python

    d = debugger("program", auto_interrupt_on_command=True)

    d.breakpoint("func")

    d.cont()
    d.wait()

    print(f"RAX: {hex(d.regs.rax)}")

The `wait()` method waits for the running process to stop before going forward with the script. Adding the `d.wait()` command will make sure the register access doesn't happen before hitting the breakpoint or any other stopping event. If the `wait()` method is omitted, the register access will happen as soon as possible after the continue command is issued. Please remember that accessing a property like registers will stop the process. Sending a continue command afterwards will make the process run again.


You can manually send a stopping signal to the program using the `interrupt()` method. This will stop the execution of the program and allow you to access the registers and memory. The syntax is as follows:

.. code-block:: python

    d.interrupt()

Register Access
===============
.. _register-access-paragraph:

libdebug offers a simple register access interface for supported architectures. The registers are accessed through the `regs`` attribute of the debugger object. The field includes both general purpose and special registers, as well as the flags register. Effectively, any register that can be accessed by an assembly instruction, can also be accessed through the regs attribute. The debugger specifically exposes properties of the main thread, including the registers. See :doc:`multithreading` to learn how to access registers and other properties from different threads.

Floating point and vector registers are available as well. The syntax is identical to the one used for integer registers.
For amd64, the list of available AVX registers is determined during installation by checking the CPU capabilities, thus special registers, such as `zmm0` to `zmm31`, are available only on CPUs that support the specific ISA extension.
If you believe that your target CPU supports AVX registers, but they are not available during debugging, please file an issue on the GitHub repository and include your precise hardware details, so that we can investigate and resolve the issue.

Memory Access
====================================

Memory access is done through the memory attribute of the debugger object or the ThreadContext. Since virtual memory is shared between threads, accessing one or the other makes no difference.
When reading from memory, a *bytes-like* object is returned. The memory API is flexible, allowing you to access memory in different ways. The following methods are available:

- **Single byte access**
You can access a single byte of memory by providing the address as an integer. For example, to access the byte at address 0x1000, you would use the following code:

.. code-block:: python

    d.memory[0x1000]

- **Slice access**
You can access a range of bytes by providing the start and end addresses as integers. For example, to access the bytes from 0x1000 to 0x1010, you would use the following code:

.. code-block:: python

    d.memory[0x1000:0x1010]

- **Base and length**
You can access a range of bytes by providing the base address and the length as integers. For example, to access the bytes from 0x1000 to 0x1010, you would use the following code:

.. code-block:: python

    d.memory[0x1000, 0x10]

- **Symbol access**
You can access memory by providing a symbol name. For example, to access the bytes from the address of the symbol `main_arena` to the address of the symbol `main_arena+8`, you would use the following code:

.. code-block:: python

    d.memory["main_arena", 0x8]

or 

.. code-block:: python

    d.memory["main_arena":"main_arena+8"]


Writing to memory works in a similar way. You can write a *bytes-like* object to memory using the addressing methods you already know:

.. code-block:: python

    d.memory[d.rsp, 0x10] = b"AAAAAAABC"
    d.memory["main_arena"] = b"12345678"

Please note that proving a shorter byte-like object than the length you are trying to write will result in zero padding.
If the byte-like object is longer than the length you are trying to write, the FULL object will be written to memory ignoring the range you provided. A warning is printed in this case.

Absolute and Relative Addressing
-------------------

When accessing memory, you can use both absolute and relative addressing. Absolute addressing is the most common way to access memory, where you provide the exact address you want to access. Relative addressing is a more advanced way to access memory, where you provide an address relative to a base address.
By default, the memory access in libdebug is done using an hybrid addressing mode. This means that libdebug will try to resolve the address as an absolute address first. If the address is not found, libdebug will try to resolve the address as a relative address, using as base the one of the binary. In this case, a warning will be printed.
You can force the addressing mode by using the following syntax:

.. code-block:: python

    d.memory[0x1000, 0x10, "absolute"]
    d.memory[0x1000, 0x10, "hybrid"]

If you specify a full or a substring of a file name, libdebug will search for the memory map of the file and use the base address of the file as the base address for the relative addressing. If the file is not found or multiple matches are found, an exception is raised.

.. code-block:: python
    
    d.memory[0x1000, 0x10, "file_name"]
    d.memory[0x1000, 0x10, "other_file_name"]

You can also use the wildcard string "binary" to use the base address of the binary as the base address for the relative addressing. The same behavior is applied if you pass a string corresponding to the binary name.

Faster Memory Access
-------------------

By default, libdebug uses the kernel's ptrace interface to access memory. This is guaranteed to work, but it might be slow during large memory transfers.
To speed up memory access, we provide a secondary system that relies on /proc/$pid/mem for read and write operations. You can enable this feature by setting `fast_memory` to True when instancing the debugger.
The final behavior is identical, but the speed is significantly improved.

Additionally, you can mix the two memory access methods by changing the `fast_memory` attribute of the debugger at runtime:

.. code-block:: python

    d.fast_memory = True

    # ...

    d.fast_memory = False

Control Flow Commands
====================================

The control flow commands are the main way to interact with the debugger. They allow you to set breakpoints, step through the program, and control the execution flow. The following commands are available:

Stepping
--------

When debuggin an executable, it is sometimes useful to step through the program one assembly instruction at a time. Just like in other debuggers, libdebug offers the step commands to help you with this task.

Single Step
^^^^^^^^^^^

The `step` command will execute the next instruction and stop the execution. The syntax is as follows:

.. code-block:: python

    d.step()

Step Until
^^^^^^^^^^

Sometimes, you may want to step through the program until a specific address is reached. The `step_until` command will execute steps (hardware step if available) until the program counter reaches the specified address.

Optionally, you can specify a maximum number of steps that are performed before returning. The syntax is as follows:

.. code-block:: python
    
    d.step_until(position=0x40003b, max_steps=1000)

Continuing
----------

Exactly as you would expect, the `cont()` command will continue the execution of the program until a breakpoint is hit or the program stops for any other reason. The syntax is as follows:

.. code-block:: python

    d.cont()

Finish
^^^^^^

The `finish` command is a more advanced version of the continue command. It will continue the execution of the program until the current function returns, a breakpoint is hit or the program stop for any other reason.

Please note that the concept of "current function" is not as simple as it may seem. Boundaries between functions can become nuanced as a result of compiler optimizations, packing and inlining.

Because of this, the finish command needs to use one of the available heuristics to resolve the end of the function. 

Remember that some cases may not be handled correctly by any of the heuristics, causing unexpected behavior. The syntax is as follows:

.. code-block:: python

    d.finish(heuristic="backtrace")

The available heuristics are:

- **backtrace**: This heuristic uses the saved return address found on the stack or on a dedicated register to find the return address of the current function. A breakpoint is applied to the resolved address and execution is continued. This is the fastest heuristic and is fairly reliable, but it may not work in the presence of self-modifying code.
- **step-mode**: This heuristic steps one instruction at a time until the ret instruction is executed in the current frame (nested calls are handled). This is a reliable heuristic, but is slow and fails in the case of internal tailcalls or similar optimizations.

The default heuristic when none is specified is "backtrace".

Next
^^^^

The `next` command is similar to the `step` command, but when a ``call`` instruction is found, it will continue until the end of the function being called or until the process stops for other reasons. The syntax is as follows:

.. code-block:: python

    d.next()

Detach and GDB Migration
====================================

If at any time during your script you want to take a more interactive approach to debugging, you can use the ``gdb()`` method. This will temporarily detach libdebug from the program and give you control over the program using GDB. Quitting GDB will return control to libdebug. 

By default, the behavior of this command is to open GDB in a new terminal window. For this to work, it is necessary to specify your terminal emulator in the libcontext parameters. The following example shows how to set the terminal to tmux:

.. code-block:: python

    from libdebug import libcontext

    libcontext.terminal = ['tmux', 'splitw', '-h']

Remember that GDB Migration is meant to be used when the process is stopped. If the process is running, the command will hang, waiting for the process to stop. To forcibly stop the process, you can use the `interrupt()` method.

.. code-block:: python

    d.interrupt()
    # Now the process is stopped
    [...]

Once the terminal is set, you can use the ``gdb()`` method.

.. code-block:: python

    d.gdb()

Optionally, you can specify `open_in_new_process=False` to execute GDB on the same process as the script. This way you can have gdb inlined in the same terminal session. You will be able to return to your script by using the command `goback`. The syntax is as follows:

.. code-block:: python

    d.gdb(open_in_new_process=False)

Depending on your use case, you may want to detach from the program and continue execution without either libdebug or GDB. The `detach()` method will detach libdebug from the program and continue execution. The syntax is as follows:

.. code-block:: python

    d.detach()

An alternative to running the program from the beginning and to resume libdebug control after detaching is to use the `attach()` method. The syntax is as follows:

.. code-block:: python

    d.attach(pid)

Do note that libdebug automatically kills any running process when the debugging script exits, even if the debugger has detached from it.
If you want to prevent this behavior, you can set the `kill_on_exit` parameter to False when creating the debugger object, or set the companion attribute `kill_on_exit` to False at runtime.

Graceful Termination
====================

If you want to kill the process being debugged, you can use the `kill()` method. When repeatedly running new instances of debugged program, remember to call the `kill()` command on old instances to avoid large memory usage. The syntax is as follows:

.. code-block:: python

    d.kill()

When you are done with the debugger object, you can terminate the background thread using the `terminate()` method. This will free up resources and should be used only when the debugger object is no longer needed. The syntax is as follows:

.. code-block:: python

    d.terminate()


Post Mortem Analysis
====================
You can check at every moment if the whole process (or a specific thread) is dead by using the `dead` property. The syntax is as follows:

.. code-block:: python

    if not d.dead:
        print("The process is not dead")
    else:
        print("The process is dead")

Moreover, after the process has died, you can check the exit code and the exit signal by using the `exit_code` and `exit_signal` properties, respectively. The syntax is as follows:

.. code-block:: python

    if d.dead:
        print(f"The process exited with code {d.exit_code}")

.. code-block:: python

    if d.dead:
        print(f"The process exited with signal {d.exit_signal}")

You can also access registers after the process has died. This is useful for *post-mortem* analysis.


Supported Architectures
=======================

libdebug currently only supports Linux under the x86_64 (AMD64) and AArch64 (ARM64) architectures. Support for other architectures is planned for future releases. Stay tuned.
