---
icon: material/map-plus
search:
    boost: 4
---
# :material-map-plus: Memory Maps
Virtual memory is a fundamental concept in operating systems. It allows the operating system to provide each process with its own address space, which is isolated from other processes. This isolation is crucial for security and stability reasons. The memory of a process is divided into regions called *memory maps*. Each memory map has a starting address, an ending address, and a set of permissions (read, write, execute).

In **libdebug**, you can access the memory maps of a process using the `maps` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object.

The `maps` attribute returns a list of [MemoryMap](../../from_pydoc/generated/data/memory_map/) objects, which contain the following attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `start`   | `int` | The start address of the memory map. |
| `end`     | `int` | The end address of the memory map. |
| `permissions` | `str` | The permissions of the memory map. |
| `size` | `int` | The size of the memory map. |
| `offset` | `int` | The offset of the memory map relative to the backing file. |
| `backing_file` | `str` | The backing file of the memory map, or the symbolic name of the memory map. |

## :material-filter: Filtering Memory Maps
You can filter memory maps based on their attributes using the `filter()` method of the `maps` attribute. The `filter()` method accepts a value that can be either a memory address (`int`) or a symbolic name (`str`) and returns a list of [MemoryMap](../../from_pydoc/generated/data/memory_map/) objects that match the criteria.

!!! ABSTRACT "Function Signature"
    ```python
    d.maps.filter(value: int | str) -> MemoryMapList[MemoryMap]:
    ```

The behavior of the memory map filtering depends on the type of the `value` parameter:

| Queried Value | Return Value |
|-------------| ------------|
| Integer (memory address)     | Map that contains the address  |
| String (symbolic map name)     | List of maps that match the symbolic name |
