from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from IPython import embed

from libdebug.utils.libcontext import libcontext

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger

from libdebug.utils.pprint_primitives import pprint_backtrace_util, pprint_memory_util, pprint_registers_util

# TODO: select the right thread to display registers and stack


def draw_registers(dbg: InternalDebugger) -> None:
    """Render the registers in a reader-friendly format."""
    print("┌─[ registers ]")
    pprint_registers_util(
        dbg.threads[0].regs,
        dbg.maps,
        dbg.threads[0]._register_holder.provide_regs(),
        start_char="│ ",
    )
    print("└─")


def draw_backtrace(dbg: InternalDebugger) -> None:
    """Draw the backtrace of the current thread."""
    print("┌─[ backtrace ]")
    # We do not want annoying warning about broken backtrace here
    with libcontext.tmp(general_logger="SILENT"):
        backtrace = dbg.threads[0].backtrace()
        maps = dbg.maps
        pprint_backtrace_util(backtrace=backtrace, maps=maps, external_symbols=dbg.symbols, start_char="│ ")
    print("└─")


def draw_stack(dbg: InternalDebugger) -> None:
    """Draw the stack in a reader-friendly format."""
    sp = dbg.threads[0].regs.__getattribute__("rsp")  # stack pointer
    print("┌─[ stack ]")
    pprint_memory_util(
        address_start=sp,
        extract=dbg.memory[sp, 8 * 8],
        word_size=8,
        maps=dbg.maps,
        integer_mode=True,
        start_char="│ ",
    )
    print("└─")


# ── pretty printer ────────────────────────────────────────────────────
def draw_context(dbg: InternalDebugger) -> None:
    """Draw the context of the devugger."""
    # Clear screen + home cursor
    print("\x1b[2J\x1b[H", end="")

    # Render the registers, stack, and backtrace
    draw_registers(dbg)
    draw_stack(dbg)
    draw_backtrace(dbg)


def start_tui(dbg: InternalDebugger) -> None:
    """Tiny TUI for libdebug."""
    dbg.is_in_tui = True
    draw_context(dbg)
    try:
        # Start an IPython shell with the context of the user script
        # TODO: what if libdebug is not run in the main module?
        g = sys.modules["__main__"].__dict__
        embed(user_ns=g, banner1="", banner2="", exit_msg="")
    except (EOFError, KeyboardInterrupt):
        dbg.is_in_tui = False
        return
