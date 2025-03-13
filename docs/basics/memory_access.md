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
    binsh_string_addr = d.memory.find("/bin/sh", file="libc")

    value_address = d.memory.find(0x1234, file="stack", start=d.regs.rsp)
    ```

### :fontawesome-solid-droplet: Leaker API
The `memory` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object also allows you to search for pointers between two memory maps. This is useful for finding leaks of memory addresses when **libdebug** is used for exploitation tasks.

!!! ABSTRACT "Function Signature"
    ```py
    def find_pointers(
            where: int | str = "*",
            target: int | str = "*",
            step: int = 1,
        ) -> list[tuple[int, int]]:
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `where` | `int` \| `str` | The memory map where we want to search for references. Defaults to `"*"`, which means all memory maps. |
| `target` | `int` \| `str` | The memory map whose pointers we want to find. Defaults to `"*"`, which means all memory maps. |
| `step` | `int` | The interval step size while iterating over the memory buffer. Defaults to `1`. |

**Returns**:

| Return | Type | Description |
| --- | --- | --- |
| `Pointers` | `list[tuple[int, int]]` | A list of tuples containing the address where the pointer was found and the pointer itself. |

!!! ABSTRACT "Usage Example"
    ```python
    pointers = d.memory.find_pointers("stack", "heap")

    for src, dst in pointers:
        print(f"Heap leak to {dst} found at {src} points")
    ```

## :material-clock-fast: Fast and Slow Memory Access
**libdebug** supports two different methods to access memory on Linux, controlled by the `fast_memory` parameter of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object. The two methods are:

- `fast_memory=False` uses the [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html) system call interface, requiring a context switch from user space to kernel space for each architectural word-size read.
- `fast_memory=True` reduces the access latency by relying on Linux's [procfs](https://docs.kernel.org/filesystems/proc.html), which contains a virtual as an interface to the process memory.

As of version **0.8** :sushi: *Chutoro Nigiri* :sushi:, `fast_memory=True` is the default. The following examples show how to change the memory access method when creating the [Debugger](../../from_pydoc/generated/debugger/debugger/) object or at runtime.

=== "When creating the Debugger object"
    ```python
    d = debugger("test", fast_memory=False)
    ```
=== "At runtime"
    ```python
    d.fast_memory = False
    ```