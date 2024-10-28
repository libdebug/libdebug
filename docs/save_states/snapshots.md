---
icon: fontawesome/regular/file-zipper
search:
    boost: 4
---
# :fontawesome-regular-file-zipper: Snapshots
Snapshots are a _static_ type of save state in **libdebug**. They allow you to save the current state of the process in terms of registers, memory, and other process properties. Snapshots can be saved to disk as a file and loaded for future use. Finally, snapshots can be diffed to compare the differences between the state of the process at two different moments or executions.

!!! TIP "Snapshots are static"
    Snapshots are static in the sense that they capture the state of the process at a single moment in time. They can be loaded and inspected at any time and across different architectures. They do not, however, allow to restore their state to the process.

There are three available levels of snapshots in **libdebug**, which differ in the amount of information they store:

| Level | Registers | Memory Pages | Memory Contents |
| ----- | --------- | ------ | --------------- |
| `base` | :octicons-check-24: | :octicons-check-24: | :octicons-x-24: |
| `writable` | :octicons-check-24: | :octicons-check-24: | writable pages only |
| `full` | :octicons-check-24: | :octicons-check-24: | :octicons-check-24: |

Additionally, you can create snapshots of [single threads](../../from_pydoc/generated/snapshots/thread/thread_snapshot) or [the entire process](../../from_pydoc/generated/snapshots/process/process_snapshot).

## :octicons-code-24: API

## :material-code-json: Attributes
Snaphots expose most of the useful attributes that you would expect from a **libdebug** [Debugger](../../from_pydoc/generated/debugger/debugger/) or [ThreadContext](../../from_pydoc/generated/state/thread_context) objects.

## :octicons-diff-24: Resolving Diffs

## :material-flower-tulip-outline: Pretty Printing

## :material-content-save-outline: Saving and Loading Snapshots
