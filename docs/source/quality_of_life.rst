Quality of Life Functions
=======================
For your convenience, libdebug offers a few functions that will speed up your debugging process.

Automatic Evasion of Anti-Debugging Techniques
---------------------------------------------

A common anti-debugging technique for Linux ELF binaries is to invoke the `ptrace` syscall with the `PTRACE_TRACEME` argument. The syscall will fail if the binary is currently being traced by a debugger. Bypassing this technique involves intercepting such syscalls and altering the return value to make the binary believe that it is not being traced. While this can absolutely be performed manually in libdebug, there is also the possibility of passing `escape_antidebug=True` when creating the debugger object. The debugger will take care of the rest.

Syscall Trace Pretty Print
--------------------------

When debugging a binary, it is often much faster to guess what the intended functionality is by looking at the syscalls that are being invoked. libdebug offers a function that will intercept any syscall and print its arguments and return value. This can be done by setting the property `pprint_syscalls = True` in the debugger object. The output will be printed to the console in color. Additionally, syscalls hijacked through the libdebug API will be highlighted as striken through, allowing you to monitor both the original behavior and your own changes to the flow.

TODO: Put an example here @Io_no, you certainly have one