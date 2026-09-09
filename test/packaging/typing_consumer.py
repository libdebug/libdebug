"""Type-check against an installed wheel, with no checkout on the import path."""

from typing_extensions import assert_type

from libdebug.native.libdebug_debug_sym_parser import (
    HAS_SYMBOL_SUPPORT,
    ElfInfo,
    SymbolInfo,
    SymbolVector,
    collect_external_symbols,
    read_elf_info,
)
from libdebug.native.libdebug_linux_binding import disable_aslr, enable_aslr
from libdebug.ptrace.native.libdebug_ptrace_binding import (
    LibdebugPtraceInterface,
    PtraceFPRegsStruct,
    PtraceFPRegsStructDefinition,
    PtraceRegsStruct,
    Reg128,
    ThreadStatus,
)


def symbols(path: str) -> None:
    assert_type(HAS_SYMBOL_SUPPORT, bool)
    info = read_elf_info(path, 1)
    assert_type(info, ElfInfo)
    assert_type(info.symbols, SymbolVector)
    assert_type(collect_external_symbols(path, 1), SymbolVector)
    for symbol in info.symbols:
        assert_type(symbol, SymbolInfo)
        assert_type(symbol.name, str)
        assert_type(symbol.low_pc, int)
        assert_type(symbol.high_pc, int)


def registers(interface: LibdebugPtraceInterface, definition: PtraceFPRegsStructDefinition, reg: Reg128) -> None:
    assert_type(LibdebugPtraceInterface(definition), LibdebugPtraceInterface)
    pair = interface.register_thread(1)
    assert_type(pair, tuple[PtraceRegsStruct, PtraceFPRegsStruct])
    assert_type(reg.data, list[int])
    reg.data = [0] * 16
    assert_type(interface.wait_all_and_update_regs(False), list[tuple[int, int]])
    assert_type(interface.peek_data(0), int)
    interface.poke_data(0, 0)
    disable_aslr()
    enable_aslr()


def status(value: ThreadStatus) -> None:
    assert_type(value.tid, int)
    assert_type(value.status, int)
