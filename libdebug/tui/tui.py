from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger.debugger import Debugger


def draw_registers(dbg: Debugger) -> None:
    """Render the registers in a reader-friendly format."""
    print("┌─[ registers ]")
    dbg.pprint_registers()
    print("└─")


def draw_stack(dbg: Debugger) -> None:
    """Draw the stack in a reader-friendly format."""
    sp = dbg.regs.__getattribute__("rsp")  # stack pointer
    mem = dbg.mem[sp, 8 * 8]  # top 8 qwords
    print("┌─[ stack ]")
    dbg.pprint_memory(sp, sp + 64, file="absolute", integer_mode="hex")
    print("└─")


# ── pretty printer ────────────────────────────────────────────────────
def draw_context(dbg: Debugger) -> None:
    """Draw the context of the debugger."""
    # Clear screen + home cursor
    print("\x1b[2J\x1b[H", end="")

    # Render the registers and stack
    draw_registers(dbg)
    draw_stack(dbg)


def start_tui(dbg: Debugger) -> None:
    """Tiny TUI for libdebug."""
    while True:
        draw_context(dbg)
        try:
            line = input("libdebug> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if line in ("q", "quit", "exit"):
            break
