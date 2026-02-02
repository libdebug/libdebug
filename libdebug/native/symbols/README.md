# Symbol Parser Native Module

This directory contains the C++ implementation of libdebug's symbol parsing backend.

## File Structure

| File | Purpose |
|------|---------|
| `debug_sym_parser_v2.cpp` | Main symbol parsing (ELF symbols, TLS, PLT/GOT detection) |
| `debug_sym_parser_dwarf.cpp` | DWARF parsing (new libdwarf API) |
| `debug_sym_parser_legacy.cpp` | DWARF parsing (legacy libdwarf API) |
| `debug_sym_parser_shared.cpp` | Nanobind Python bindings |
| `debug_sym_parser_dummy.cpp` | Stub when built without symbol support |
| `debug_sym_structs.h` | Data structures (`SymbolInfo`, `TlsModuleInfo`, `ElfInfo`) |
| `debug_sym_structs.cpp` | Implementation of SymbolInfo methods |
| `debug_sym_parser.h` | Function declarations |
| `debug_sym_parser_shared.h` | Shared header for bindings |
