"""Check the indexed x86 FP bindings in the installed architecture-specific stub."""

from typing_extensions import assert_type

from libdebug.ptrace.native.libdebug_ptrace_binding import PtraceFPRegsStruct


def registers(fp: PtraceFPRegsStruct) -> None:
    assert_type(fp.get_mmx(0), bytes)
    fp.set_mmx(0, bytes(16))
    assert_type(fp.get_legacy_st_space(0), bytes)
    fp.set_legacy_st_space(0, bytes(10))
    assert_type(fp.get_xmm0(0), bytes)
    fp.set_xmm0(0, bytes(16))
    assert_type(fp.get_ymm0(0), bytes)
    fp.set_ymm0(0, bytes(16))
    assert_type(fp.get_zmm0(0), bytes)
    fp.set_zmm0(0, bytes(32))
    assert_type(fp.get_zmm1(0), bytes)
    fp.set_zmm1(0, bytes(64))
