"""Check the indexed AArch64 FP bindings in the installed architecture-specific stub."""

from typing_extensions import assert_type

from libdebug.ptrace.native.libdebug_ptrace_binding import PtraceFPRegsStruct


def registers(fp: PtraceFPRegsStruct) -> None:
    assert_type(fp.get_vregs(0), bytes)
    fp.set_vregs(0, bytes(16))
