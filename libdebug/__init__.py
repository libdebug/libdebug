"""libdebug: A Python library for programmatic debugging of binary executables.

libdebug provides a comprehensive set of building blocks designed to facilitate the development
of debugging tools for different purposes, including reverse engineering and exploitation.

With libdebug you have full control of your debugged executable:
- Access process memory and registers
- Control the execution flow of the process
- Handle and hijack syscalls
- Catch and hijack signals
- Interact with stdin, stdout, and stderr of the debugged process
- Debug multithreaded and multiprocess applications with ease
- Seamlessly switch to GDB for interactive analysis
- Debug on Linux systems based on AMD64, AArch64, and i386

Classes:
    Debugger: The main debugger class, composed of mixins, that provides all methods to run and interact with processes.
    Breakpoint: Represents a breakpoint that can be set in the debugged process.
    SignalCatcher: Handles signal catching and hijacking functionality.
    SyscallHandler: Manages system call handling and hijacking.
    ThreadContext: Provides access to thread-specific information and state.

Functions:
    debugger: Factory function to create a Debugger instance (or subclass via `cls`) with the specified configuration. Prefer this over instantiating Debugger directly (constructor expects an InternalDebugger for mixin composition).

Objects:
    libcontext: Singleton configuration object for libdebug settings and terminal configuration.

Example:
    Basic usage for debugging a binary:

    >>> from libdebug import debugger
    >>> d = debugger("/path/to/binary")
    >>> io = d.run()
    >>> bp = d.breakpoint("main")
    >>> d.cont()
    >>> d.wait()
    >>> print(f"RAX: {d.regs.rax:#x}")
    >>> d.cont()

    Advanced usage with signal and syscall handling:

    >>> from libdebug import debugger
    >>> d = debugger("./binary", aslr=False)
    >>> io = d.run()
    >>> catcher = d.catch_signal("SIGINT", lambda t, c: print("Caught SIGINT!"))
    >>> handler = d.handle_syscall("write", on_enter=lambda t, h: print("write() called"))
    >>> d.cont()

For more information, visit: https://docs.libdebug.org
"""

try:
    from rich.traceback import install
except ImportError:
    pass
else:
    install()

from libdebug.data.breakpoint import Breakpoint
from libdebug.data.signal_catcher import SignalCatcher
from libdebug.data.syscall_handler import SyscallHandler
from libdebug.debugger.debugger import Debugger
from libdebug.libdebug import debugger
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.libcontext import libcontext

__all__ = ["Breakpoint", "Debugger", "SignalCatcher", "SyscallHandler", "ThreadContext", "debugger", "libcontext"]
