---
icon: octicons/git-pull-request-draft-24
search:
    boost: 4
---
# :octicons-git-pull-request-draft-24: Debugging Flow of Stopping Events
Before diving into each **libdebug** stopping event, it's crucial to understand the debugging flow that these events introduce, based on the mode selected by the user.

The flow of all stopping events is similar and adheres to a mostly uniform API structure. Upon placing a stopping event, the user is allowed to specify a callback function for the stopping event. If a callback is passed, the event will trigger **asynchronously**. Otherwise, if the callback is not passed, the event will be **synchronous**. The following flowchart shows the difference between the two flows.

---

<figure markdown="span">
  ![Syncronous and Asyncronous Flow](../../assets/sync_async.webp#only-light){ width="90%" }
  ![Syncronous and Asyncronous Flow](../../assets/sync_async_dark.webp#only-dark){ width="90%" }
  <figcaption>Flowchart of different handling modes for stopping events</figcaption>
</figure>

When a **synchronous** event is hit, the process will stop, awaiting further commands. When an **asynchronous** event is hit, **libdebug** temporarily stops the process and invokes the user callback. Process execution is automatically resumed right after.

!!! TIP "Tip: Use cases of asynchronous stopping events"
    The asynchronous mode for stopping events is particularly useful for events being repeated as a result of a loop in the executed code.

    When attempting side-channel reverse engineering, this mode can save a lot of your time.

## :material-format-list-bulleted-type: Types of Stopping Events

**libdebug** supports the following types of stopping events:

| Event Type | Description                          | Notes                                |
|------------|--------------------------------------|--------------------------------------|
| [Breakpoint](../breakpoints) | Stops the process when a certain address is executed | Can be a software or a hardware breakpoint    |
| [Watchpoint](../watchpoints) | Stops the process when a memory area is read or written | Alias for a hardware breakpoint |
| [Syscall](../syscalls)    | Stops the process when a syscall is made | Two events are supported: syscall start and end |
| [Signal](../signals)     | Stops the process when a signal is received |  |

## Common APIs of Stopping Events
All **libdebug** stopping events share some common attributes that can be employed in debugging scripts.

### :material-power: Enable/Disable
All stopping events can be enabled or disabled at any time. You can read the `enabled` attribute to check the current state of the event. To enable or disable the event, you can call the `enable()` or `disable()` methods respectively.

### :material-lambda: Callback
The callback function of the event can be set, changed or removed (set to `None`) at any time. Please be mindful of the event mode resulting from the change on the callback parameter. Additionally, you can set the callback to `True` to register an empty callback.

### :simple-ticktick: Hit Records
Stopping events have attributes that can help you keep track of hits. For example, the `hit_count` attribute stores the number of times the event has been triggered.

The `hit_on()` function is used to check if the stopping event was the cause of the process stopping. It is particularly useful when debugging multithreaded applications, as it takes a [ThreadContext](../../from_pydoc/generated/state/thread_context) as a parameter. Refer to [multithreading](../../multithreading/multithreading) for more information.

### :material-arrow-decision: Hijacking
Hijacking is a powerful feature that allows you to change the flow of the process when a stopping event is hit. It is available for both syscalls and signals, but currently not for other stopping events. When registering an hijack for a compatible stopping event, that execution flow will be replaced with another.

<figure markdown="span">
  ![Hijack of a Signal](../../assets/hijack.webp#only-light){ width="90%" }
  ![Hijack of a Signal](../../assets/hijack-dark.webp#only-dark){ width="90%" }
  <figcaption>Example hijacking of a SIGALRM to a SIGUSR1</figcaption>
</figure>

For example, in the case of a signal, you can specify that a received `SIGALRM` signal should be replaced with a `SIGUSR1` signal. This can be useful when you want to prevent a process from executing a certain code path. In fact, you can even use the hijack feature to "NOP" the syscall or signal altogether, avoiding it to be executed / forwarded to the processed. More information on how to use this feature in each stopping event can be found in their respective documentation.


!!! WARNING "Hijacking Loop Detection"
    When carelessly hijacking stopping events, it could happen that loops are created. **libdebug** automatically performs checks to avoid these situations and raises an exception if an infinite loop is detected.

    For example, the following code raises a `RuntimeError`:

    ```python
    handler = d.hijack_syscall("read", "write")
    handler = d.hijack_syscall("write", "read")
    ```

### :fontawesome-solid-arrows-rotate: Recursion
Mixing asynchronous callbacks and hijacking can become messy. Because of this, **libdebug** provides users with the choice of whether to execute the callback for an event that was triggered *by* a hijack.

This behavior is enabled by the parameter `recursive`, available when instantiating a syscall handler, a signal catcher, or their respective hijackers. By default, recursion is disabled.