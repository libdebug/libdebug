"""Exercise an installed wheel using its actual interpreter (including i686/musl)."""

import ast
import importlib
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
    d.cont()
    assert pipe.recvline() == b"nanobind-wheel"
    d.wait()
    assert d.exit_code == 0
finally:
    d.terminate()
