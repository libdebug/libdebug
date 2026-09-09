"""Exercise an installed wheel using its actual interpreter (including i686/musl)."""

import ast
import importlib
import platform
import sys
from pathlib import Path

from libdebug import debugger
from libdebug.native import libdebug_debug_sym_parser as symbols

for name in (
    "libdebug.native.libdebug_linux_binding",
    "libdebug.native.libdebug_debug_sym_parser",
    "libdebug.ptrace.native.libdebug_ptrace_binding",
):
    module = importlib.import_module(name)
    directory = Path(module.__file__).parent
    stub = directory / (name.rsplit(".", 1)[1] + ".pyi")
    ast.parse(stub.read_text(), feature_version=(3, 10))
    print(name, module.__file__)

assert symbols.HAS_SYMBOL_SUPPORT
info = symbols.read_elf_info(sys.executable, 1)
assert isinstance(info.symbols, symbols.SymbolVector)
d = debugger([sys.executable, "-c", "print('nanobind-wheel')"])
try:
    pipe = d.run()
    assert d.instruction_pointer > 0
    fp = d.threads[0]._register_holder.fp_register_file
    bank = "vregs" if platform.machine() == "aarch64" else (
        "xmm0" if fp.has_xsave else "legacy_st_space"
    )
    read = getattr(fp, f"get_{bank}")
    write = getattr(fp, f"set_{bank}")
    width = len(getattr(fp, bank)[0].data)
    value = bytes(range(width))
    write(0, value)
    assert read(0) == value
    # This tests the native buffer without flushing synthetic state to the process.
    assert not fp.dirty
    d.cont()
    assert pipe.recvline() == b"nanobind-wheel"
    d.wait()
    assert d.exit_code == 0
finally:
    d.terminate()
