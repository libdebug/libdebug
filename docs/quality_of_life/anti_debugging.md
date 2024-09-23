---
icon: material/run-fast
search:
    boost: 4
---
## :material-run-fast: Automatic Evasion of Anti-Debugging Techniques
A common anti-debugging technique for Linux ELF binaries is to invoke the `ptrace` syscall with the `PTRACE_TRACEME` argument. The syscall will fail if the binary is currently being traced by a debugger, as the kernel forbids a process from being traced by multiple debuggers.

Bypassing this technique involves intercepting such syscalls and altering the return value to make the binary believe that it is not being traced. While this can absolutely be performed manually, **libdebug** comes with a pre-made implementation that can save you precious time.

To enable this feature, set the `escape_antidebug` property to `True` when creating the debugger object. The debugger will take care of the rest.

!!! ABSTRACT "Example"
    \> C source code
    ```C
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/ptrace.h>

    int main()
    {

        if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) // (1)
        {
            puts("No cheating! Debugger detected.\n"); // (2)
            exit(1);
        }

        puts("Congrats! Here's your flag:\n"); // (3)
        puts("flag{y0u_sn3aky_guy_y0u_tr1ck3d_m3}\n");

        return 0;
    }
    ```

    1. Call ptrace with `PTRACE_TRACEME` to detect if we are being debugged
    2. If the call fails, it means the program is being debugged
    3. If the program is not being debugged, print the flag

    \> **libdebug** script
    ```python
    from libdebug import debugger

    d = debugger("evasive_binary",
        escape_antidebug=True)

    pipe = d.run()
    
    d.cont()
    d.wait()

    out = pipe.recvline(numlines=2)
    print(out.decode())
    ```
    
    Execution of the script will print the flag, even if the binary is being debugged.