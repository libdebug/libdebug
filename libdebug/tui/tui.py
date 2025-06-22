from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.utils.libcontext import libcontext

if TYPE_CHECKING:
    from libdebug.debugger.debugger import Debugger

from libdebug.utils.pprint_primitives import pprint_backtrace_util, pprint_memory_util, pprint_registers_util

# TODO: select the right thread to display registers and stack


def draw_registers(dbg: Debugger) -> None:
    """Render the registers in a reader-friendly format."""
    print("┌─[ registers ]")
    pprint_registers_util(
        dbg.regs,
        dbg.maps,
        dbg.threads[0]._register_holder.provide_regs(),
        start_char="│ ",
    )
    print("└─")


def draw_backtrace(dbg: Debugger) -> None:
    """Draw the backtrace of the current thread."""
    print("┌─[ backtrace ]")
    # We do not want annoying warning about broken backtrace here
    with libcontext.tmp(general_logger="SILENT"):
        backtrace = dbg.backtrace()
        maps = dbg.maps
        pprint_backtrace_util(backtrace=backtrace, maps=maps, external_symbols=dbg.symbols, start_char="│ ")
    print("└─")


def draw_stack(dbg: Debugger) -> None:
    """Draw the stack in a reader-friendly format."""
    sp = dbg.regs.__getattribute__("rsp")  # stack pointer
    mem = dbg.mem[sp, 8 * 8]  # top 8 qwords
    print("┌─[ stack ]")
    pprint_memory_util(
        address_start=sp,
        extract=dbg.mem[sp, 8 * 8],
        word_size=8,
        maps=dbg.maps,
        integer_mode=True,
        start_char="│ ",
    )
    print("└─")


# ── pretty printer ────────────────────────────────────────────────────
def draw_context(dbg: Debugger) -> None:
    """Draw the context of the debugger."""
    # Clear screen + home cursor
    print("\x1b[2J\x1b[H", end="")

    # Render the registers, stack, and backtrace
    draw_registers(dbg)
    draw_stack(dbg)
    draw_backtrace(dbg)


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
