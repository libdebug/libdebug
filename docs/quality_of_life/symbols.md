---
icon: material/alphabetical
search:
    boost: 4
---
## :material-alphabetical: Symbol Resolution
As described in the [memory access](../memory_access/#absolute-and-relative-addressing) section, many functions in **libdebug** accept symbols as an alternative to actual addresses.

!!! INFO "C++ Demangling"
    Reverse-engineering of C++ binaries can be a struggle. To help out, **libdebug** automatically demangles C++ symbols.

### Symbol Resolution Levels
With large binaries and libraries, parsing symbols can become an expensive operation. Because of this, **libdebug** offers the possibility of choosing among 6 levels of symbol resolution. To set the symbol resolution level, you can use the `sym_lvl` property of the [`libcontext`](../../from_pydoc/generated/utils/libcontext) module.

| Level | Description |
|-------|-------------|
| 0     | Symbol resolution is disabled. |
| 1     | Parse the ELF symbol table (.symtab) and dynamic symbol table (.dynsym). |
| 2     | Parse the ELF DWARF. |
| 3     | Follow the external debug file link in the .gnu_debuglink and/or .gnu_debugaltlink sections. If the file is present in the system, read its .symtab and .dynsym. |
| 4     | Parse the external debug file DWARF, if the file exists in the system. |
| 5     | Download the external debug file using `debuginfod`. The file is cached in the default folder for `debuginfod`. |

The default value is level 4.

!!! ABSTRACT "Example of setting the symbol resolution level"
    ```python
    from libdebug import libcontext

    libcontext.sym_lvl = 5
    d.breakpoint('main')
    ```

If you want to change the symbol resolution level temporarily, you can use a `with` statement along with the `tmp` method of the `libcontext` module.

!!! ABSTRACT "Example of temporary resolution level change"
    ```python
    from libdebug import libcontext

    with libcontext.tmp(sym_lvl = 5):
        d.breakpoint('main')
    ```