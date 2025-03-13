---
icon: material/traffic-light-outline
search:
    boost: 4
---
# :material-traffic-light-outline: Signals
[Signals](https://man7.org/linux/man-pages/man7/signal.7.html) are a feature of POSIX systems like (e.g., the Linux kernel) that provide a mechanism for asynchronous communication between processes and the operating system. When certain events occur (e.g., hardware interrupts, illegal operations, or termination requests) the kernel can send a signal to a process to notify it of the event. Each signal is identified by a unique integer and corresponds to a specific type of event. For example, `SIGINT` (usually triggered by pressing `Ctrl+C`) is used to interrupt a process, while `SIGKILL` forcefully terminates a process without cleanup. 

Processes can handle these signals in different ways: they may catch and define custom behavior for certain signals, ignore them, or allow the default action to occur.

!!! WARNING "Restrictions on Signal Catching"
    **libdebug** does not support catching `SIGSTOP` and `SIGKILL`, since kernel-level restrictions prevent these signals from being caught or ignored. While `SIGTRAP` can be caught, it is used internally by **libdebug** to implement stopping events and should be used with caution.

**libdebug** allows you to intercept signals sent to the tracee. Specifically, you can choose to **catch** or **hijack** a specific signal (read more on [hijacking](../stopping_events/#hijacking)).

## :material-bucket-outline: Signal Catchers
Signal catchers can be created to register [stopping events](../stopping_events/) for when a signal is received.

!!! INFO "Multiple catchers for the same signal"
    Please note that there can be at most **one** user-defined catcher or hijack for each signal. If a new catcher is defined for a signal that is already caught or hijacked, the new catcher will replace the old one, and a warning will be printed.

## **libdebug** API for Signal Catching
The `catch_signal()` function in the [Debugger](../../from_pydoc/generated/debugger/debugger/) object registers a catcher for the specified signal.

!!! ABSTRACT "Function Signature"
    ```python
    d.catch_signal(signal, callback=None, recursive=False) 
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `signal` | `int` \| `str` | The signal number or name to catch. If set to `"*"` or `"all"`, all signals will be caught. |
| `callback` |  `Callable` \| `bool` (see callback signature [here](#callback-signature)) | The callback function to be executed when the signal is received. |
| `recursive` | `bool` | If set to `True`, the catcher's callback will be executed even if the signal was triggered by a hijack. |

**Returns**:

| Return | Type | Description |
| --- | --- | --- |
| `SignalCatcher` | [SignalCatcher](../../from_pydoc/generated/data/signal_catcher) | The catcher object created. |

### :material-code-json: Callback Signature

!!! ABSTRACT "Callback Signature"
    ```python
    def callback(t: ThreadContext, catcher: SignalCatcher):
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `t` | [ThreadContext](../../from_pydoc/generated/state/thread_context) | The thread that received the signal. |
| `catcher` | [SignalCatcher](../../from_pydoc/generated/data/signal_catcher) | The SignalCatcher object that triggered the callback. |

!!! WARNING "Signals in multi-threaded applications"
    In the Linux kernel, an incoming signal could be delivered to any thread in the process. Please do not assume that the signal will be delivered to a specific thread in your scripts.

---

!!! ABSTRACT "Example usage of asynchronous signal catchers"
    ```python
    from libdebug import debugger

    d = debugger("./test_program")
    d.run()

    # Define the callback function
    def catcher_SIGUSR1(t, catcher):
        t.signal = 0x0
        print("Look mum, I'm catching a signal")

    def catcher_SIGINT(t, catcher):
        print("Look mum, I'm catching another signal")

    # Register the signal catchers
    catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1)
    catcher2 = d.catch_signal('SIGINT', callback=catcher_SIGINT)

    d.cont()
    d.wait()
    ```

!!! ABSTRACT "Example of synchronous signal catching"
    ```python
    from libdebug import debugger

    d = debugger("./test_program")
    d.run()

    catcher = d.catch_signal(10)
    d.cont()

    if catcher.hit_on(d):
        print("Signal 10 was caught")
    ```

    The script above will print "Signal 10 was entered".

## :material-arrow-decision: Hijacking
When hijacking a signal, the user can provide an alternative signal to be executed in place of the original one. Internally, the hijack is implemented by registering a catcher for the signal and replacing the signal number with the new one.

!!! ABSTRACT "Function Signature"
    ```python
    d.hijack_signal(original_signal, new_signal, recursive=False) 
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `original_signal` | `int` \| `str` | The signal number or name to be hijacked. If set to `"*"` or `"all"`, all signals except the restricted ones will be hijacked. |
| `new_signal` | `int` \| `str` | The signal number or name to be delivered instead. |
| `recursive` | `bool` | If set to `True`, the catcher's callback will be executed even if the signal was dispached by a hijack. |

**Returns**:

| Return | Type | Description |
| --- | --- | --- |
| `SignalCatcher` | [SignalCatcher](../../from_pydoc/generated/data/signal_catcher) | The catcher object created. |


!!! ABSTRACT "Example of hijacking a signal"
    <div class="grid cards" markdown>

    ```C
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <signal.h>

    // Handler for SIGALRM
    void handle_sigalrm(int sig) {
        printf("You failed. Better luck next time\n");
        exit(1);
    }

    // Handler for SIGUSR1
    void handle_sigusr1(int sig) {
        printf("Congrats: flag{pr1nt_pr0vol4_1s_th3_w4y}\n");
        exit(0);
    }

    int main() {
        // Set up the SIGALRM handler
        struct sigaction sa_alrm;
        sa_alrm.sa_handler = handle_sigalrm;
        sigemptyset(&sa_alrm.sa_mask);
        sa_alrm.sa_flags = 0;
        sigaction(SIGALRM, &sa_alrm, NULL);

        // Set up the SIGUSR1 handler
        struct sigaction sa_usr1;
        sa_usr1.sa_handler = handle_sigusr1;
        sigemptyset(&sa_usr1.sa_mask);
        sa_usr1.sa_flags = 0;
        sigaction(SIGUSR1, &sa_usr1, NULL);

        // Set an alarm to go off after 10 seconds
        alarm(10);

        printf("Waiting for a signal...\n");

        // Infinite loop, waiting for signals
        while (1) {
            pause(); // Suspend the program until a signal is caught
        }

        return 0;
    }

    ```

    ```python
    from libdebug import debugger

    d = debugger("./test_program")
    d.run()

    handler = d.hijack_signal("SIGALRM", "SIGUSR1")
    
    d.cont()

    # Will print "Waiting for a signal..."
    out = pipe.recvline()
    print(out.decode())

    d.wait()

    # Will print the flag
    out = pipe.recvline()
    print(out.decode())
    ```

    </div>

## :material-filter: Signal Filtering
Instead of setting a catcher on signals, you might want to filter which signals are not to be forwarded to the debugged process during execution.

!!! ABSTRACT "Example of signal filtering"
    ```python
    d.signals_to_block = [10, 15, 'SIGINT', 3, 13]
    ```

## :material-mail: Arbitrary Signals
You can also send an arbitrary signal to the process. The signal will be forwarded upon resuming execution. As always, you can specify the signal number or name.

!!! ABSTRACT "Example of sending an arbitrary signal"
    ```python
    d.signal = 10
    d.cont()
    ```

In [multithreaded](../../multithreading/multithreading) applications, the same syntax applies when using a [ThreadContext](../../from_pydoc/generated/state/thread_context) object instead of the [Debugger](../../from_pydoc/generated/debugger/debugger) object.