---
icon: material/alphabetical
search:
    boost: 4
---
## :material-alphabetical: Symbol Resolution
As described in the [memory access](../../basics/memory_access/#absolute-and-relative-addressing) section, many functions in **libdebug** accept symbols as an alternative to actual addresses or offsets.

You can list all resolved symbols in the binary and shared libraries using the `symbols` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object. This attribute returns a [SymbolList](../../from_pydoc/generated/data/symbol_list/) object.

This object grants the user hybrid access to the symbols: as a dict or as a list. Tor example, the following lines of code all have a valid syntax:

```python
d.symbols['printf'] #(1)
d.symbols[0] #(2)
d.symbols['printf'][0] #(3)
```

1. Returns a list of symbols that match the string `printf` exactly.
2. Returns the first symbol in the list.
3. Returns the first symbol that matches the string `printf` exactly.

Please note that the dict-like access returns exact matches with the symbol name. If you want to filter for symbols that contain a specific string, read [the dedicated section](#symbol-filtering).

!!! INFO "C++ Demangling"
    Reverse-engineering of C++ binaries can be a struggle. To help out, **libdebug** automatically demangles C++ symbols.

### :material-pyramid: Symbol Resolution Levels
With large binaries and libraries, parsing symbols can become an expensive operation. Because of this, **libdebug** offers the possibility of choosing among 5 levels of symbol resolution. To set the symbol resolution level, you can use the `sym_lvl` property of the [`libcontext`](../../from_pydoc/generated/utils/libcontext) module. The default value is level 5.

| Level | Description |
|-------|-------------|
| 0     | Symbol resolution is disabled. |
| 1     | Parse the ELF symbol table (.symtab) and dynamic symbol table (.dynsym). |
| 2     | Parse the ELF DWARF. |
| 3     | Follow the external debug file link in the .gnu_debuglink and/or .gnu_debugaltlink sections. If the file is present in the system, read its .symtab and .dynsym. |
| 4     | Parse the external debug file DWARF, if the file exists in the system. |
| 5     | Download the external debug file using `debuginfod`. The file is cached in the default folder for `debuginfod`. |

Upon searching for symbols, **libdebug** will proceed from the lowest level to the set maximum.

!!! ABSTRACT "Example of setting the symbol resolution level"
    ```python
    from libdebug import libcontext

    libcontext.sym_lvl = 3
    d.breakpoint('main')
    ```

If you want to change the symbol resolution level temporarily, you can use a `with` statement along with the `tmp` method of the `libcontext` module.

!!! ABSTRACT "Example of temporary resolution level change"
    ```python
    from libdebug import libcontext

    with libcontext.tmp(sym_lvl = 5):
        d.breakpoint('main')
    ```

## :material-filter: Symbol Filtering
The `symbols` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object allows you to filter symbols in the binary and shared libraries.

!!! ABSTRACT "Function Signature"
    ```python
    d.symbols.filter(value: int | str) -> SymbolList[Symbol]
    ```

Given a symbol name or address, this function returns a [SymbolList](../../from_pydoc/generated/data/symbol_list/). The list will contain all symbols that match the given value.

[Symbol](../../from_pydoc/generated/data/symbol/) objects contain the following attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `start`   | `int` | The start offset of the symbol. |
| `end`     | `int` | The end offset of the symbol. |
| `name`    | `str` | The name of the symbol. |
| `backing_file` | `str` | The file where the symbol is defined (e.g., binary, libc, ld). |

!!! INFO "Slow Symbol Resolution"
    Please keep in mind that symbol resolution can be an expensive operation on large binaries and shared libraries. If you are experiencing performance issues, you can set the [symbol resolution level](#symbol-resolution-levels) to a lower value.