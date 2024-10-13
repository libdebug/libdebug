from collections.abc import Sequence


class LibdebugPtraceInterface:
    """The native binding for ptrace on Linux."""

    def __init__(self) -> None:
        """Initializes a new ptrace interface for debugging."""

    def cleanup(self) -> None:
        """Cleans up the instance from any previous state."""

    def register_thread(self, tid: int) -> tuple[PtraceRegsStruct, PtraceFPRegsStruct]:
        """
        Registers a new thread that must be debugged.

        Args:
            tid (int): The thread id to be registered.

        Returns:
            tuple: A tuple containing a reference to the registers, integer and floating point.
        """

    def unregister_thread(self, tid: int) -> None:
        """
        Unregisters a thread that was previously registered.

        Args:
            tid (int): The thread id to be unregistered.
        """

    def attach(self, tid: int) -> int:
        """
        Attaches to a process for debugging.

        Args:
            tid (int): The thread id to be attached to.

        Returns:
            int: The error code of the operation, if any.
        """

    def detach_for_migration(self) -> None:
        """Detaches from the process for migration to another debugger."""

    def detach_and_cont(self) -> None:
        """Detaches from the process and continues its execution."""

    def set_ptrace_options(self) -> None:
        """Sets the ptrace options for the process."""

    def get_event_msg(self, tid: int) -> int:
        """
        Gets an event message for a thread.

        Args:
            tid (int): The thread id to get the event message for.

        Returns:
            int: The event message.
        """

    def wait_all_and_update_regs(self) -> list[tuple[int, int]]:
        """
        Waits for any thread to stop, interrupts all the others and updates the registers.

        Returns:
            list: A list of tuples containing the thread id and the corresponding waitpid result.
        """

    def cont_all_and_set_bps(self, handle_syscalls: bool) -> None:
        """
        Sets the breakpoints and continues all the threads.

        Args:
            handle_syscalls (bool): A flag to indicate if the debuggee should stop on syscalls.
        """

    def step(self, tid: int) -> None:
        """
        Steps a thread by one instruction.

        Args:
            tid (int): The thread id to step.
        """

    def step_until(self, tid: int, addr: int, max_steps: int) -> None:
        """
        Steps a thread until a specific address is reached, or for a maximum amount of steps.

        Args:
            tid (int): The thread id to step.
            addr (int): The address to step until.
            max_steps (int): The maximum amount of steps to take, or -1 if unlimited.
        """

    def stepping_finish(self, tid: int, use_trampoline_heuristic: bool) -> None:
        """
        Runs a thread until the end of the current function call, by single-stepping it.

        Args:
            tid (int): The thread id to step.
            use_trampoline_heuristic (bool): A flag to indicate if the trampoline heuristic for i386 should be used.
        """

    def forward_signals(self, signals: Sequence[tuple[int, int]]) -> None:
        """
        Forwards signals to the threads.

        Args:
            signals (list): A list of tuples containing the thread id and the signal to forward.
        """

    def get_remaining_hw_breakpoint_count(self, tid: int) -> int:
        """
        Gets the remaining hardware breakpoint count for a thread.

        Args:
            tid (int): The thread id to get the remaining hardware breakpoint count for.
        """

    def get_remaining_hw_watchpoint_count(self, tid: int) -> int:
        """
        Gets the remaining hardware watchpoint count for a thread.

        Args:
            tid (int): The thread id to get the remaining hardware watchpoint count for.
        """

    def register_hw_breakpoint(self, tid: int, address: int, type: int, len: int) -> None:
        """
        Registers a hardware breakpoint for a thread.

        Args:
            tid (int): The thread id to register the hardware breakpoint for.
            address (int): The address to set the hardware breakpoint at.
            type (int): The type of the hardware breakpoint.
            len (int): The length of the hardware breakpoint.
        """

    def unregister_hw_breakpoint(self, tid: int, address: int) -> None:
        """
        Unregisters a hardware breakpoint for a thread.

        Args:
            tid (int): The thread id to unregister the hardware breakpoint for.
            address (int): The address to remove the hardware breakpoint from.
        """

    def get_hit_hw_breakpoint(self, tid: int) -> int:
        """
        Gets the address of the hardware breakpoint hit by a specific thread, if any.

        Args:
            tid (int): The thread id to get the hit hardware breakpoint for.

        Returns:
            int: The address of the hit hardware breakpoint.
        """

    def register_breakpoint(self, address: int) -> None:
        """
        Registers a software breakpoint at a specific address.

        Args:
            address (int): The address to set the software breakpoint at.
        """

    def unregister_breakpoint(self, address: int) -> None:
        """
        Unregisters a software breakpoint at a specific address.

        Args:
            address (int): The address to remove the software breakpoint from.
        """

    def enable_breakpoint(self, address: int) -> None:
        """
        Enables a previously registered software breakpoint at a specific address.

        Args:
            address (int): The address to enable the software breakpoint at.
        """

    def disable_breakpoint(self, address: int) -> None:
        """
        Disables a previously registered software breakpoint at a specific address.

        Args:
            address (int): The address to disable the software breakpoint at.
        """

    def detach_for_kill(self) -> None:
        """Detaches from the process and kills it."""

    def get_fp_regs(self, tid: int) -> None:
        """
        Refreshes the floating point registers for a thread.

        Args:
            tid (int): The thread id to refresh the floating point registers for.
        """

    def peek_data(self, addr: int) -> int:
        """
        Peeks memory from a specific address.

        Args:
            addr (int): The address to peek memory from.

        Returns:
            int: The memory value at the address.
        """

    def poke_data(self, addr: int, data: int) -> None:
        """
        Pokes memory at a specific address.

        Args:
            addr (int): The address to poke memory at.
            data (int): The data to poke at the address.
        """

class PtraceFPRegsStruct:
    @property
    def type(self) -> int: ...

    @property
    def dirty(self) -> bool: ...

    @dirty.setter
    def dirty(self, arg: bool, /) -> None: ...

    @property
    def fresh(self) -> bool: ...

    @fresh.setter
    def fresh(self, arg: bool, /) -> None: ...

    @property
    def mmx(self) -> list[Reg128]: ...

    @property
    def xmm0(self) -> list[Reg128]: ...

    @property
    def ymm0(self) -> list[Reg128]: ...

class PtraceRegsStruct:
    @property
    def r15(self) -> int: ...

    @r15.setter
    def r15(self, arg: int, /) -> None: ...

    @property
    def r14(self) -> int: ...

    @r14.setter
    def r14(self, arg: int, /) -> None: ...

    @property
    def r13(self) -> int: ...

    @r13.setter
    def r13(self, arg: int, /) -> None: ...

    @property
    def r12(self) -> int: ...

    @r12.setter
    def r12(self, arg: int, /) -> None: ...

    @property
    def rbp(self) -> int: ...

    @rbp.setter
    def rbp(self, arg: int, /) -> None: ...

    @property
    def rbx(self) -> int: ...

    @rbx.setter
    def rbx(self, arg: int, /) -> None: ...

    @property
    def r11(self) -> int: ...

    @r11.setter
    def r11(self, arg: int, /) -> None: ...

    @property
    def r10(self) -> int: ...

    @r10.setter
    def r10(self, arg: int, /) -> None: ...

    @property
    def r9(self) -> int: ...

    @r9.setter
    def r9(self, arg: int, /) -> None: ...

    @property
    def r8(self) -> int: ...

    @r8.setter
    def r8(self, arg: int, /) -> None: ...

    @property
    def rax(self) -> int: ...

    @rax.setter
    def rax(self, arg: int, /) -> None: ...

    @property
    def rcx(self) -> int: ...

    @rcx.setter
    def rcx(self, arg: int, /) -> None: ...

    @property
    def rdx(self) -> int: ...

    @rdx.setter
    def rdx(self, arg: int, /) -> None: ...

    @property
    def rsi(self) -> int: ...

    @rsi.setter
    def rsi(self, arg: int, /) -> None: ...

    @property
    def rdi(self) -> int: ...

    @rdi.setter
    def rdi(self, arg: int, /) -> None: ...

    @property
    def orig_rax(self) -> int: ...

    @orig_rax.setter
    def orig_rax(self, arg: int, /) -> None: ...

    @property
    def rip(self) -> int: ...

    @rip.setter
    def rip(self, arg: int, /) -> None: ...

    @property
    def cs(self) -> int: ...

    @cs.setter
    def cs(self, arg: int, /) -> None: ...

    @property
    def eflags(self) -> int: ...

    @eflags.setter
    def eflags(self, arg: int, /) -> None: ...

    @property
    def rsp(self) -> int: ...

    @rsp.setter
    def rsp(self, arg: int, /) -> None: ...

    @property
    def ss(self) -> int: ...

    @ss.setter
    def ss(self, arg: int, /) -> None: ...

    @property
    def fs_base(self) -> int: ...

    @fs_base.setter
    def fs_base(self, arg: int, /) -> None: ...

    @property
    def gs_base(self) -> int: ...

    @gs_base.setter
    def gs_base(self, arg: int, /) -> None: ...

    @property
    def ds(self) -> int: ...

    @ds.setter
    def ds(self, arg: int, /) -> None: ...

    @property
    def es(self) -> int: ...

    @es.setter
    def es(self, arg: int, /) -> None: ...

    @property
    def fs(self) -> int: ...

    @fs.setter
    def fs(self, arg: int, /) -> None: ...

    @property
    def gs(self) -> int: ...

    @gs.setter
    def gs(self, arg: int, /) -> None: ...

class Reg128:
    """A 128-bit register."""

    @property
    def data(self) -> list[int]:
        """The data of the register, as a byte array."""

    @data.setter
    def data(self, arg: Sequence[int], /) -> None: ...

class Reg256:
    """A 256-bit register."""

    @property
    def data(self) -> list[int]:
        """The data of the register, as a byte array."""

    @data.setter
    def data(self, arg: Sequence[int], /) -> None: ...

class Reg512:
    """A 512-bit register."""

    @property
    def data(self) -> list[int]:
        """The data of the register, as a byte array."""

    @data.setter
    def data(self, arg: Sequence[int], /) -> None: ...

class ThreadStatus:
    """The waitpid result of a specific thread."""

    @property
    def tid(self) -> int:
        """The thread id."""

    @property
    def status(self) -> int:
        """The waitpid result."""
