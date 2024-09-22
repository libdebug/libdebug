---
icon: fontawesome/solid/terminal
search:
    boost: 4
---
# :fontawesome-solid-terminal: Syscalls
System calls (a.k.a. syscalls or software interrupts) are the interface between user space and kernel space. They are used to request services from the kernel, such as reading from a file or creating a new process. **libdebug** allows you to trace syscalls invoked by the debugged program. Specifically, you can choose to **handle** or **hijack** a specific syscall (read more on [hijacking](../stopping_events/#hijacking)).

## :material-format-align-middle: Syscall Handlers
Syscall handlers can be created to register [stopping events](../stopping_events/) for when a syscall is entered and exited.

!!! QUESTION "Do I have to handle both on enter and on exit?"
    When using [asynchronous](../debugging_flow) syscall handlers, you can choose to handle both or only one of the two events. However, when using synchronous handlers, both events will stop the process.

!!! INFO "Multiple handlers for the same syscall"
    Please note that there can be at most **one** user-defined handler or hijack for each syscall. If a new handler is defined for a syscall that is already handled or hijacked, the new handler will replace the old one, and a warning will be printed.


## **libdebug** API for Syscall Handlers
The `handle_syscall()` function in the [Debugger](../../from_pydoc/generated/debugger/debugger/) object registers a handler for the specified syscall.

!!! ABSTRACT "Function Signature"
    ```python
    d.handle_syscall(syscall, on_enter=None, on_exit=None, recursive=False) 
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `syscall` | `int` \| `str` | The syscall number or name to be handled. |
| `on_enter` | `Callable` (see callback signature [here](#callback-signature)) | The callback function to be executed when the syscall is entered. |
| `on_exit` | `Callable` (see callback signature [here](#callback-signature)) | The callback function to be executed when the syscall is exited. |
| `recursive` | `bool` | If set to `True`, the handler's callback will be executed even if the syscall was triggered by a hijack. |

**Returns**:

| Return | Type | Description |
| --- | --- | --- |
| `SyscallHandler` | [SyscallHandler](../../from_pydoc/generated/data/syscall_handler) | The handler object created. |

### Callback Signature

!!! ABSTRACT "Callback Signature"
    ```python
    def callback(t: ThreadContext, handler: HandledSyscall) -> None:
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `t` | [ThreadContext](../../from_pydoc/generated/state/thread_context) | The thread that hit the syscall. |
| `handler` | [SyscallHandler](../../from_pydoc/generated/data/syscall_handler) | The SyscallHandler object that triggered the callback. |

!!! INFO "Nuances of Syscall Handling"
    The syscall handler is the only [stopping event](../stopping_events/) that can be triggered by the same syscall twice in a row. This is because the handler is triggered both when the syscall is entered and when it is exited. As a result the `hit_on()` function does not exist in the [SyscallHandler](../../from_pydoc/generated/data/syscall_handler) object.

    Instead, you can use the `hit_on_enter()` and `hit_on_exit()` functions to check if cause of the process stop was the syscall entering or exiting, respectively.

    As for the `hit_count` attribute, it stores the number of times the syscall was *exited*.

---

!!! ABSTRACT "Example usage of asynchronous syscall handlers"
    ```python
    def on_enter_open(t: ThreadContext, handler: SyscallHandler):
        print("entering open")
        t.syscall_arg0 = 0x1

    def on_exit_open(t: ThreadContext, handler: SyscallHandler):
        print("exiting open")
        t.syscall_return = 0x0

    handler = d.handle_syscall(syscall="open", on_enter=on_enter_open, on_exit=on_exit_open)
    ```

!!! ABSTRACT "Example of synchronous syscall handling"
    ```python
    from libdebug import debugger

    d = debugger("./test_program")
    d.run()

    handler = d.handle_syscall(syscall="open")
    d.cont()

    if handler.hit_on_enter(d):
        print("open syscall was entered")
    elif handler.hit_on_exit(d):
        print("open syscall was exited")
    ```

    The script above will print "open syscall was entered".

## :octicons-number-24: Resolution of Syscall Numbers
Syscall handlers can be created with the identifier number of the syscall or by the syscall's common name. In the second case, syscall names are resolved from a definition list for Linux syscalls on the target architecture. The list is fetched from [mebeim's syscall table](https://syscalls.mebeim.net). We thank him for hosting such a precious resource. Once downloaded, the list cached internally. 

## :material-arrow-decision: Hijacking
When hijacking a syscall, the user can provide an alternative syscall to be executed in place of the original one. Internally, the hijack is implemented by registering a handler for the syscall and replacing the syscall number with the new one.

!!! ABSTRACT "Function Signature"
    ```python
    d.hijack_syscall(original_syscall, new_syscall, recursive=False, **kwargs) 
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `original_syscall` | `int` \| `str` | The syscall number or name to be hijacked. |
| `new_syscall` | `int` \| `str` | The syscall number or name to be executed instead. |
| `recursive` | `bool` | If set to `True`, the handler's callback will be executed even if the syscall was triggered by a hijack. |
| `**kwargs` | `(int, optional)` | Additional arguments to be passed to the new syscall. |

**Returns**:

| Return | Type | Description |
| --- | --- | --- |
| `SyscallHandler` | [SyscallHandler](../../from_pydoc/generated/data/syscall_handler) | The handler object created. |


!!! ABSTRACT "Example of hijacking a syscall"
    <div class="grid cards" markdown>

    ```C
    #include <unistd.h>

    char secretBuffer[32] = "The password is 12345678";

    int main(int argc, char** argv)
    {
        [...]

        read(0, secretBuffer, 31);
        
        [...]
        return 0;
    }
    ```

    ```python
    from libdebug import debugger

    d = debugger("./test_program")
    d.run()

    handler = d.hijack_syscall("read", "write")
    
    d.cont()
    d.wait()

    out = pipe.recvline()
    print(out.decode())
    ```

    </div>
    In this case, the secret will be leaked to the standard output instead of being overwritten with content from the standard input.

For your convenience, you can also easily provide the syscall parameters to be used when the hijacked syscall is executed:

!!! ABSTRACT "Example of hijacking a syscall with parameters"
    <div class="grid cards" markdown>

    ```C
    #include <unistd.h>

    char manufacturerName[32] = "libdebug";
    char secretKey[32] = "provola";

    int main(int argc, char** argv)
    {
        [...]

        read(0, manufacturerName, 31);
        
        [...]
        return 0;
    }
    ```

    ```python
    from libdebug import debugger

    d = debugger("./test_program")
    d.run()

    manufacturerBuffer = [...]

    handler = d.hijack_syscall("read", "write",
        syscall_arg0=0x1,
        syscall_arg1=manufacturerBuffer,
        syscall_arg2=0x100
    )
        
    d.cont()
    d.wait()

    out = pipe.recvline()
    print(out.decode())
    ```

    </div>

    Again, the secret will be leaked to the standard output.

