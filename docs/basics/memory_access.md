---
icon: fontawesome/solid/memory
search:
    boost: 4
---
# :fontawesome-solid-memory: Memory Access
In **libdebug**, memory access is performed via the `memory` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object or the [Thread Context](../../from_pydoc/generated/state/thread_context). When reading from memory, a [*bytes-like*](https://docs.python.org/3/glossary.html#term-bytes-like-object) object is returned. The following methods are available:

=== "Single byte access"
    Access a single byte of memory by providing the address as an integer.
    ```python
    d.memory[0x1000]
    ```

=== "Slice access"
    Access a range of bytes by providing the start and end addresses as integers.
    ```python
    d.memory[0x1000:0x1010]
    ```

=== "Base and length"
    Access a range of bytes by providing the base address and length as integers.
    ```python
    d.memory[0x1000, 0x10]
    ```

=== "Symbol access"
    Access memory using a symbol name.
    ```python
    d.memory["function", 0x8]
    ```

    When specifying a symbol, you can also provide an offset. Contrary to what happens in GDB, the offset is always interpreted as hexadecimal.
    ```python
    d.memory["function+a8"]
    ```
    
=== "Symbol Range"
    Access a range of bytes using a symbol name.
    ```python
    d.memory["function":"function+0f"]
    ```
    Please note that contrary to what happens in GDB, the offset is always interpreted as hexadecimal.

---

!!! INFO "Accessing memory with symbols"
    Please note that, unless otherwise specified, symbols are resolved in the debugged binary only. To resolve symbols in shared libraries, you need to indicate it in the third parameter of the function.

    ```python
    d.memory["__libc_start_main", 0x8, "libc"]
    ```

Writing to memory works similarly. You can write a [*bytes-like*](https://docs.python.org/3/glossary.html#term-bytes-like-object) object to memory using the same addressing methods:

```python
d.memory[d.rsp, 0x10] = b"AAAAAAABC"
d.memory["main_arena", 16, "libc"] = b"12345678"
```

!!! WARNING "Length/Slice when writing"
    When writing to memory, slices and length are ignored in favor of the length of the specified [*bytes-like*](https://docs.python.org/3/glossary.html#term-bytes-like-object) object.

    In the following example, only 4 bytes are written:
    
    ```python
    d.memory["main_arena", 50] = b"\x0a\xeb\x12\xfc"
    ```

## :material-relative-scale: Absolute and Relative Addressing

Just like with symbols, memory addresses can also be accessed relative to a certain file base. **libdebug** uses `"hybrid"` addressing by default. This means it first attempts to resolve addresses as absolute. If the address does not correspond to an absolute one, it considers it relative to the base of the binary.

You can use the third parameter of the memory access method to select the file you want to use as base (e.g., libc, ld, binary). If you want to force **libdebug** to use absolute addressing, you can specify `"absolute"` instead.

!!! ABSTRACT "Examples of relative and absolute addressing"
    ```python
    # Absolute addressing
    d.memory[0x7ffff7fcb200, 0x10, "absolute"]

    # Hybrid addressing
    d.memory[0x1000, 0x10, "hybrid"]

    # Relative addressing
    d.memory[0x1000, 0x10, "binary"]
    d.memory[0x1000, 0x10, "libc"]
    ```

## :octicons-search-24: Searching inside Memory
The `memory` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object also allows you to search for specific values in the memory of the process. You can search for integers, strings, or [bytes-like](https://docs.python.org/3/glossary.html#term-bytes-like-object) objects.

!!! ABSTRACT "Function Signature"
    ```python
    d.memory.find(
        value: int | bytes | str,
        file: str = "all",
        start: int | None = None,
        end: int | None = None,
    ) -> list[int]:
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `value` | `int` \| `bytes` \| `str` | The value to search for. |
| `file` | `str` | The backing file to search in (e.g, binary, libc, stack). |
| `start` | `int` (optional) | The start address of the search (works with both relative and absolute). |
| `end` | `int` (optional) | The end address of the search (works with both relative and absolute). |

**Returns**:

| Return | Type | Description |
| --- | --- | --- |
| `Addresses` | `list[int]` | List of memory addresses where the value was found. |

!!! ABSTRACT "Usage Example"
    ```python
    bish_string_addr = d.memory.find("/bin/sh", file="libc")

    value_address = d.memory.find(0x1234, file="stack", start=d.regs.rsp)
    ```

## :material-clock-fast: Faster Memory Access
!!! EXAMPLE "Warning: This feature is Experimental!"
    This feature is experimental and may not work as expected. Please report any issues you encounter [:octicons-issue-opened-24: here](https://github.com/libdebug/libdebug/issues).

By default, **libdebug** reads and writes memory using the [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html) system call interface. However, this is not the most efficient way to access memory and will likely be changed in future versions.

To speed up memory access, you can already enable a faster system that relies on Linux's [procfs](https://docs.kernel.org/filesystems/proc.html). To use it, simply set the `fast_memory` parameter to `True` when creating the [Debugger](../../from_pydoc/generated/debugger/debugger/) object. You can also enable and disable this feature at runtime by accessing the debugger's attribute.

=== "When creating the Debugger object"
    ```python
    d = debugger("test", fast_memory=True)
    ```
=== "At runtime"
    ```python
    d.fast_memory = True
    ```