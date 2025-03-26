---
icon: fontawesome/regular/file-zipper
search:
    boost: 4
---
# :fontawesome-regular-file-zipper: Snapshots
Snapshots are a _static_ type of save state in **libdebug**. They allow you to save the current state of the process in terms of registers, memory, and other process properties. Snapshots can be saved to disk as a file and loaded for future use. Finally, snapshots can be diffed to compare the differences between the state of the process at two different moments or executions.

!!! INFO "Snapshots are static"
    Snapshots are static in the sense that they capture the state of the process at a single moment in time. They can be loaded and inspected at any time and across different architectures. They _do not_, however, allow to restore their state to the process.

There are three available levels of snapshots in **libdebug**, which differ in the amount of information they store:

| Level | Registers | Memory Pages | Memory Contents |
| ----- | --------- | ------ | --------------- |
| `base` | :octicons-check-24: | :octicons-check-24: | :octicons-x-24: |
| `writable` | :octicons-check-24: | :octicons-check-24: | writable pages only |
| `full` | :octicons-check-24: | :octicons-check-24: | :octicons-check-24: |

Since memory content snapshots can be large, the default level is `base`.

You can create snapshots of [single threads](../../from_pydoc/generated/snapshots/thread/thread_snapshot) or [the entire process](../../from_pydoc/generated/snapshots/process/process_snapshot).

## :octicons-code-24: API

<div class="grid cards" markdown>

-   :material-hexadecimal:{ .lg .middle } __Register Access__

    ---

    You can access a snapshot's registers using the `regs` attribute, just like you would when debugging the process.

    [:octicons-arrow-right-24: API Reference](../../basics/register_access)

-   :fontawesome-solid-memory:{ .lg .middle } __Memory Access__

    ---

    When the snapshot level is appropriate, you can access the memory of the process using the `memory` attribute.

    [:octicons-arrow-right-24: API Reference](../../basics/memory_access)

-   :material-map-plus:{ .lg .middle } __Memory Maps__

    ---

    Memory maps are always available. When the snapshot level is appropriate, you can access the contents as a [bytes-like object](https://docs.python.org/3/library/stdtypes.html#bytes).

    [:octicons-arrow-right-24: API Reference](../../quality_of_life/memory_maps)

-   :octicons-stack-24:{ .lg .middle } __Stack Trace__

    ---

    When the snapshot level is appropriate, you can access the backtrace of the process or thread.

    [:octicons-arrow-right-24: API Reference](../../quality_of_life/stack_frame_utils)

</div>

### :octicons-plus-24: Creating Snapshots

The function used to create a snapshot is `create_snapshot()`. It behaves differently depending on the object it is called from.

| Calling Object | Snapshot Type | Description |
| -------------- | ------------- | ----------- |
| [ThreadContext](../../from_pydoc/generated/state/thread_context) | [ThreadSnapshot](../../from_pydoc/generated/snapshots/thread/thread_snapshot) | Creates a snapshot of the specific thread. |
| [Debugger](../../from_pydoc/generated/debugger/debugger/) | [ProcessSnapshot](../../from_pydoc/generated/snapshots/process/process_snapshot) | Creates a snapshot of the entire process. This includes snapshots _for all threads_. |

The following is the signature of the function:

!!! ABSTRACT "Function Signature"
    ```python
    d.create_snapshot(level: str = "base", name: str = None) -> ProcessSnapshot
    ```
    or
    ```python
    t.create_snapshot(level: str = "base", name: str = None) -> ThreadSnapshot
    ```
    Where `d` is a [Debugger](../../from_pydoc/generated/debugger/debugger/) object and `t` is a [ThreadContext](../../from_pydoc/generated/state/thread_context) object.

The following is an example usage of the function in both cases:

```python
d = debugger("program")

my_thread = d.threads[1]

# Thread Snapshot
ts = my_thread.create_snapshot(level="full", name="cool snapshot") #(1)!

# Process Snapshot
ps = d.create_snapshot(level="writable", name="very cool snapshot") #(2)!
```

1. This will create a full-level snapshot of the thread `my_thread` and name it "cool snapshot".
2. This will create a writable-level snapshot of the entire process and name it "very cool snapshot".

!!! TIP "Naming Snapshots"
    When creating a snapshot, you can optionally specify a name for it. The name will be useful when comparing snapshots in diffs or when saving them to disk.

### :material-content-save-outline: Saving and Loading Snapshots
You can save a snapshot to disk using the [`save()`](../../from_pydoc/generated/snapshots/snapshot/#libdebug.snapshots.snapshot.Snapshot.save) method of the [Snapshot](../../from_pydoc/generated/snapshots/snapshot) object. The method will create a serializable version of the snapshot and export a json file to the specified path.

!!! ABSTRACT "Example usage"
    ```python
    ts = d.threads[1].create_snapshot(level="full")
    ts.save("path/to/save/snapshot.json")
    ```

---

You can load a snapshot from disk using the [`load_snapshot()`](../../from_pydoc/generated/debugger/debugger#libdebug.debugger.debugger.Debugger.load_snapshot) method of the [Debugger](../../from_pydoc/generated/debugger/debugger) object. The method will read the json file from the specified path and create a [Snapshot](../../from_pydoc/generated/snapshots/snapshot) object from it.

!!! ABSTRACT "Example usage"
    ```python
    ts = d.load_snapshot("path/to/load/snapshot.json")
    ```

The snapshot type will be inferred from the json file, so you can easily load both thread and process snapshots from the same method.

### :octicons-diff-24: Resolving Diffs
Thanks to their static nature, snapshots can be easily compared to find differences in saved properties.

You can diff a snapshot against another using the [`diff()`](../../from_pydoc/generated/snapshots/snapshot#libdebug.snapshots.snapshot.Snapshot.diff) method. The method will return a [Diff](../../from_pydoc/generated/snapshots/diff) object that represents the differences between the two snapshots. The diff will be of the lowest level of the two snapshots being compared in terms.

!!! ABSTRACT "Example usage"
    ```python
    ts1 = d.threads[1].create_snapshot(level="full")

    [...] # (1)!
    
    ts2 = d.threads[1].create_snapshot(level="full")

    ts_diff = ts1.diff(ts2) # (2)!
    ```

    1. Do some operations that change the state of the process.
    2. Compute the diff between the two snapshots

Diffs have a rich and detailed API that allows you to inspect the differences in registers, memory, and other properties. Read more in the [dedicated section](../snapshot_diffs).

### :material-flower-tulip-outline: Pretty Printing

[Pretty Printing](../../quality_of_life/pretty_printing) is a feature of some **libdebug** objects that allows you to print the contents of a snapshot in a colorful and eye-catching format. This is useful when you want to inspect the state of the process at a glance.

Pretty printing utilities of snapshots are "mirrors" of pretty pretting functions available for the [Debugger](../../from_pydoc/generated/debugger/debugger/) and [ThreadContext](../../from_pydoc/generated/state/thread_context). Here is a list of available pretty printing functions and their equivalent for the running process:

| Function | Description | Reference |
| -------- | ----------- | --------- |
| `pprint_registers()` | Prints the general-purpose registers of the snapshot. | [:octicons-arrow-right-24: API Reference](../../quality_of_life/pretty_printing#registers-pretty-printing) |
| `pprint_registers_all()` | Prints all registers of the snapshot. | [:octicons-arrow-right-24: API Reference](../../quality_of_life/pretty_printing#registers-pretty-printing) |
| `pprint_maps()` | Prints the memory of the snapshot. | [:octicons-arrow-right-24: API Reference](../../quality_of_life/pretty_printing#memory-maps-pretty-printing) |
| `pprint_backtrace()` | Prints the backtrace of the snapshot. | [:octicons-arrow-right-24: API Reference](../../quality_of_life/pretty_printing#stack-trace-pretty-printing) |


## :material-code-json: Attributes

| Attribute | Data Type | Level | Description | Aliases |
| ---------- | --------- | ----- | ----------- | ------- |
| **Common** |
| `name` | `str` (optional) | All | The name of the snapshot. | |
| `arch` | `str` | All | The ISA under which the snapshot process was running. | |
| `snapshot_id` | int | All | Progressive id counted from 0. Process and Thread snapshots have separate counters. | |
| `level` | `str` | All | The snapshot level. | |
| `maps` | [`MemoryMapSnapshotList`](../../from_pydoc/generated/snapshots/memory/memory_map_snapshot_list) | All | The memory maps of the process. Each map will also have the contents of the memory map under the appropriate snapshot level. | |
| `memory` | [`SnapshotMemoryView`](../../from_pydoc/generated/snapshots/memory/snapshot_memory_view) | `writable` / `full` | Interface to the memory of the process. | `mem` |
| `aslr_enabled` | `bool` | All | Whether ASLR was enabled at the time of the snapshot. | |
| **Thread Snapshot** |
| `thread_id` | `int` | All | The ID of the thread the snapshot was taken from. | `tid` |
| `regs` | [`SnapshotRegisters`](../../from_pydoc/generated/snapshots/registers/snapshot_registers) | All | The register values of the thread. | `registers` |
| **Process Snapshot** |
| `process_id` | `int` | All | The ID of the process the snapshot was taken from. | `pid` |
| `threads` | [`list[LightweightThreadSnapshot]`](../../from_pydoc/generated/snapshots/thread/lw_thread_snapshot) | All | Snapshots of all threads of the process. | |
| `regs` | [`SnapshotRegisters`](../../from_pydoc/generated/snapshots/registers/snapshot_registers) | All | The register values of the main thread of the process. | `registers` |