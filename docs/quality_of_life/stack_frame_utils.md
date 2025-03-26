---
icon: octicons/stack-24
search:
    boost: 4
---
# :octicons-stack-24: Stack Frame Utils
Function calls in a binary executable are made according to a system calling convention. One constant in these conventions is the use of a stack frame to store the return addresses to resume at the end of the function.

Different architectures have slightly different ways to retrieve the return address (for example, in AArch64, the latest return address is stored in `x30`, the Link Register). To abstract these differences, **libdebug** provides common utilities to resolve the stack trace (*backtrace*) of the running process (or thread).

<div style="text-align: center;">
    <img src="/assets/backtrace_plot.png#only-light" loading="lazy" width="85%" />
    <img src="/assets/backtrace_plot_dark.png#only-dark" loading="lazy" width="85%" />
</div>

**libdebug**'s *backtrace* is structured like a LIFO stack, with the top-most value being the current instruction pointer. Subsequent values are the return addresses of the functions that were called to reach the current instruction pointer.

!!! ABSTRACT "Backtrace usage example"
    ```python
    from libdebug import debugger

    d = debugger("test_backtrace")
    d.run()

    # A few calls later...
    [...]

    current_ip = d.backtrace()[0]
    return_address = d.backtrace()[1]
    other_return_addresses = d.backtrace()[2:]
    ```

Additionally, the field `saved_ip` of the [Debugger](../../from_pydoc/generated/debugger/debugger/) or [ThreadContext](../../from_pydoc/generated/state/thread_context/) objects will contain the return address of the current function.