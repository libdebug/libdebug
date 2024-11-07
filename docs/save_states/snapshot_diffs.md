---
icon: octicons/diff-24
search:
    boost: 4
---
# :octicons-diff-24: Snapshot Diffs
[Snapshot](../snapshots) diffs are objects that represent what changed between two snapshots. They are created through the [`diff()`](../snapshot#resolving-diffs) method of a snapshot.

The level of a diff is resolved as the lowest level of the two snapshots being compared. For example, if a diff is created between a `full` snapshot and a `base` snapshot, their diff will be of `base` level. For more information on the different levels of snapshots, see the [Snapshots](../snapshots) page.

## :octicons-code-24: API
Just like snapshots themselves, diffs try to mimic the API of the [Debugger](../../from_pydoc/generated/debugger/debugger) and [ThreadContext](../../from_pydoc/generated/state/thread_context) objects. The main difference is that returned objects represent a change in state, rather than the state itself.

### :material-hexadecimal: Register Diffs
The `regs` attribute of a diff object (aliased as `registers`) is a [RegisterDiffAccessor](../../from_pydoc/generated/snapshots/registers/register_diff_accessor) object that allows you to access the register values of the snapshot. The accessor will return a [RegisterDiff](../../from_pydoc/generated/snapshots/registers/register_diff) object that represents the difference between the two snapshots.

You can access each diff with any of the architecture-specific register names. For a full list, refer to the [Register Access](../../basics/register_access) page.

!!! ABSTRACT "Example usage"
    ```python
    print(ts_diff.regs.rip)
    ```
    Output:
    ```plaintext
    RegisterDiff(old_value=0x56148d577130, new_value=0x56148d577148, has_changed=True)
    ```

Each register diff is an object with the following attributes:

| Attribute | Data Type | Description |
| --------- | --------- | ----------- |
| `old_value` | `int | float` | The value of the register in the first snapshot. |
| `new_value` | `int | float` | The value of the register in the second snapshot. |
| `has_changed` | `bool` | Whether the register value has changed. |

### :material-map-plus: Memory Map Diffs
The `maps` attribute of a diff object is a [MemoryMapDiffList](../../from_pydoc/generated/snapshots/memory/memory_map_diff_list) object that contains the memory maps of the process in each of the snapshots.

Here is what a [MemoryMapDiff](../../from_pydoc/generated/snapshots/memory/memory_map_diff) object looks like:

!!! ABSTRACT "Example usage"
    ```python
    print(ts_diff.maps[-2])
    ```
    Output (indented for readability):
    ```plaintext
    MemoryMapDiff(
        old_map_state=MemoryMap(
            start=0x7fff145ea000,
            end=0x7fff1460c000,
            permissions=rw-p,
            size=0x22000,
            offset=0x0,
            backing_file=[stack]
        )   [snapshot with content],
        new_map_state=MemoryMap(
            start=0x7fff145ea000,
            end=0x7fff1460c000,
            permissions=rw-p,
            size=0x22000,
            offset=0x0,
            backing_file=[stack]
        )   [snapshot with content],
        has_changed=True,
        _cached_diffs=None
    )
    ```

The map diff contains the following attributes:

| Attribute | Data Type | Description |
| --------- | --------- | ----------- |
| `old_map_state` | [`MemoryMap`](../../from_pydoc/generated/data/memory_map) | The memory map in the first snapshot. |
| `new_map_state` | [`MemoryMap`](../../from_pydoc/generated/data/memory_map) | The memory map in the second snapshot. |
| `has_changed` | `bool` | Whether the memory map has changed. |

!!! INFO "Memory Map Diff Levels"
    If the diff is of `base` level, the `has_changed` attribute will only consider _superficial changes_ in the memory map (e.g., permissions, end address). Under the `writable` and `full` levels, the diff will also consider the contents of the memory map.

#### :material-tape-drive: Memory Content Diffs
If the diff is of `full` or `writable` level, the [MemoryMapDiff](../../from_pydoc/generated/snapshots/memory/memory_map_diff) object exposes a useful utility to track blocks of differing memory contents in a certain memory map: the `content_diff` attribute.

!!! ABSTRACT "Example usage"
    ```python
    stack_page_diff = ts_diff.maps.filter("stack")[0]

    for current_slice in stack_page_diff.content_diff:
        print(f"Memory diff slice: {hex(current_slice.start)}:{hex(current_slice.stop)}")
    ```
    Output:
    ```plaintext
    Memory diff slice: 0x20260:0x20266
    Memory diff slice: 0x20268:0x2026e
    ```

The attribute will return a list of [slice](https://docs.python.org/3/c-api/slice.html) objects that represent the blocks of differing memory contents in the memory map. Each slice will contain the start and end addresses of the differing memory block relative to the memory map.

### :material-flower-tulip-outline: Pretty Printing

[Pretty Printing](../../quality_of_life/pretty_printing) is a feature of some **libdebug** objects that allows you to print the contents of a snapshot in a colorful and eye-catching format. This is useful when you want to inspect the state of the process at a glance.

[Diff](../../from_pydoc/generated/snapshots/diff) objects have the following pretty printing functions:

| Function | Description |
| -------- | ----------- |
| `pprint_registers()` | Prints all changed register values (including special and vector registers) |
| `pprint_maps()` | Prints memory maps which have changed between snapshots (highlights if only the content or the end address have changed). |
| `pprint_memory()` | Prints the memory content diffs of the snapshot. See next section for more information |

Here are some visual examples of the pretty printing functions:

=== "Register Diff"

    ![Register Diff](../../assets/pprint_reg_diff.jpeg)

=== "Memory Map Diff"

    ![Memory Map Diff](../../assets/pprint_map_diff.jpeg)

#### :material-format-columns: Memory Content Diff Pretty Printing

The `pprint_memory()` function of a diff object will print the content diffs within a certain range of memory addresses.

!!! ABSTRACT "Function signature"
    ```python
    ts_diff.pprint_memory(
        start: int,
        end: int,
        file: str = "hybrid",
        override_word_size: int = None,
        endianness_mode: bool = False,
    ) -> None:
    ```

| Parameter | Data Type | Description |
| --------- | --------- | ----------- |
| `start` | `int` | The start address of the memory range to print. |
| `end` | `int` | The end address of the memory range to print. |
| `file` | `str` (optional) | The file to use for the memory content. Defaults to `hybrid` mode (see [memory access](../../basics/memory_access/)). |
| `override_word_size` | `int` (optional) | The word size to use to align memory contents. By default, it uses the ISA register size. |
| `endianness_mode` | `bool` (optional) | Whether to print the memory content in endianness mode. Defaults to False |

!!! TIP "Start after End"
    For your convenience, if the `start` address is greater than the `end` address, the function will **swap** the values.

Here is a visual example of the memory content diff pretty printing (with and without endianness mode):

=== "Endianness mode disabled"

    ![Memory Content Diff](../../assets/pprint_memory_base.jpeg)

=== "Endianness mode enabled"

    ![Memory Content Diff Endianness](../../assets/pprint_memory_endianness.jpeg)

## :material-code-json: Attributes

| Attribute | Data Type | Level | Description | Aliases |
| ---------- | --------- | ----- | ----------- | ------- |
| **Common** |
| `snapshot1` | [`Snapshot`](../../from_pydoc/generated/snapshots/snapshot) | All | The earliest snapshot being compared (recency is determined by id ordering). | |
| `snapshot2` | [`Snapshot`](../../from_pydoc/generated/snapshots/snapshot) | All | The latest snapshot being compared (recency is determined by id ordering). | |
| `level` | `str` | All | The diff level. | |
| `maps` | [`MemoryMapDiffList`](../../from_pydoc/generated/snapshots/memory/memory_map_diff_list) | All | The memory maps of the process. Each map will also have the contents of the memory map under the appropriate snapshot level. | |
| **Thread Snapshot Diff** |
| `regs` | [`RegisterDiffAccessor`](../../from_pydoc/generated/snapshots/registers/register_diff_accessor) | All | The register values of the thread. | `registers` |
| **Process Snapshot Diff** |
| `born_threads` | [`list[LightweightThreadSnapshot]`](../../from_pydoc/generated/snapshots/thread/lw_thread_snapshot) | All | Snapshots of all threads of the process. | |
| `dead_threads` | [`list[LightweightThreadSnapshot]`](../../from_pydoc/generated/snapshots/thread/lw_thread_snapshot) | All | Snapshots of all threads of the process. | |
| `threads` | [`list[LightweightThreadSnapshotDiff]`](../../from_pydoc/generated/snapshots/thread/lw_thread_snapshot_diff) | All | Snapshots of all threads of the process. | |
| `regs` | [`RegsterDiffAccessor`](../../from_pydoc/generated/snapshots/registers/register_diff_accessor) | All | The register values of the main thread of the process. | `registers` |