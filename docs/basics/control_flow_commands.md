---
icon: material/arrow-down-right
search:
    boost: 4
---
# :material-arrow-down-right: Control Flow Commands

Control flow commands allow you to set step through the code, stop execution and resume it at your pleasure. 

## :material-ray-end-arrow: Stepping
A basic feature of any debugger is the ability to step through the code. **libdebug** provides several methods to step, some of which will be familiar to users of other debuggers.

### :material-debug-step-into: Single Step
The `step()` command executes the instruction at the instruction pointer and stops the process. When possible, it uses the hardware single-step feature of the CPU for better performance.

!!! ABSTRACT "Function Signature"
    ```python
    d.step()
    ```

### :material-debug-step-over: Next
The `next()` command executes the current instruction at the instruction pointer and stops the process. If the instruction is a function call, it will execute the whole function and stop at the instruction following the call. In other debuggers, this command is known as "step over".

Please note that the `next()` command resumes the execution of the program if the instruction is a function call. This means that the debugger can encounter [stopping events](../../stopping_events/stopping_events) in the middle of the function, causing the command to return before the function finishes.

!!! ABSTRACT "Function Signature"
    ```python
    d.next()
    ```

!!! WARNING "Damn heuristics!"
    The `next()` command uses heuristics to determine if the instruction is a function call and to find the stopping point. This means that the command may not work as expected in some cases (e.g. functions called with a jump, non-returning calls).

### :material-debug-step-over::material-debug-step-over: Step Until

The `step_until()` command executes single steps until a specific address is reached. Optionally, you can also limit steps to a maximum count (default value is -1, meaning no limit).

!!! ABSTRACT "Function Signature"
    ```python
    d.step_until(position, max_steps=-1, file='hybrid') 
    ```

The file parameter can be used to specify the choice on relative addressing. Refer to the [memory access](../memory_access/#absolute-and-relative-addressing) section for more information on addressing modes.

## :material-step-forward: Continuing

The `cont()` command continues the execution.

!!! ABSTRACT "Function Signature"
    ```python
    d.cont()
    ```

    For example, in the following script, **libdebug** will not wait for the process to stop before checking d.dead. To change this behavior, you can use the `wait()` command right after the `cont()`.
    ```python
    from libdebug import debugger

    d = debugger("program_that_dies_tragically")

    d.run()

    d.cont()

    if d.dead:
        print("The program is dead!")

    ```

### :material-clock-alert-outline: The `wait()` Method

The `wait()` command is likely the most important in **libdebug**. Loved by most and hated by many, it instructs the debugger to wait for a [stopping event](../../stopping_events/stopping_events) before continuing with the execution of the script.

!!! ABSTRACT "Example"
    In the following script, **libdebug** will wait for the process to stop before printing "provola".
    ```python
    from libdebug import debugger

    d = debugger("program_that_dies_tragically")

    d.run()

    d.cont()
    d.wait()

    print("provola")
    ```

### :material-stop: Interrupt
You can manually issue a stopping signal to the program using the `interrupt()` command. Clearly, this command is issued as soon as it is executed within the script.

!!! ABSTRACT "Function Signature"
    ```python
    d.interrupt()
    ```

## :material-debug-step-out: Finish

The `finish()` command continues execution until the current function returns or a breakpoint is hit. In other debuggers, this command is known as "step out".

!!! ABSTRACT "Function Signature"
    ```python
    d.finish(heuristic='backtrace')
    ```

!!! WARNING "Damn heuristics!"
    The `finish()` command uses heuristics to determine the end of a function. While **libdebug** allows to choose the heuristic, it is possible that none of the available options work in some specific cases. (e.g. tail-calls, non-returning calls).

### Available Heuristics
The `finish()` command allows you to choose the heuristic to use. If you don't specify any, the `"backtrace"` heuristic will be used. The following heuristics are available:

| Heuristic | Description |
|-----------|-------------|
| `backtrace` | The `backtrace` heuristic uses the return address on the function stack frame to determine the end of the function. This is the default heuristic but may fail in case of broken stack, rare execution flows, and obscure compiler optimizations. |
| `step-mode` | The `step-mode` heuristic uses repeated single steps to execute instructions until a `ret` instruction is reached. Nested calls are handled, when the calling convention is respected. This heuristic is slower and may fail in case of rare execution flows and obscure compiler optimizations. |
