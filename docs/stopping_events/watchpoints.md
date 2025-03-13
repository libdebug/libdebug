---
icon: material/track-light
search:
    boost: 4
---
# :material-track-light: Watchpoints
Watchpoints are a special type of [hardware breakpoint](../breakpoints#hardware-breakpoints) that triggers when a specific memory location is accessed. You can set a watchpoint to trigger on certain memory access conditions, or upon execution (equivalent to a hardware breakpoint).

Features of watchpoints are shared with breakpoints, so you can set [asynchronous](../debugging_flow) watchpoints and use properties in the same way.

## **libdebug** API for Watchpoints
The `watchpoint()` function in the [Debugger](../../from_pydoc/generated/debugger/debugger/) object sets a watchpoint at a specific address. While you can also use the [breakpoint API](../breakpoints/#libdebug-api-for-breakpoints) to set up a watchpoint, a specific API is provided for your convenience:

!!! ABSTRACT "Function Signature"
    ```python
    d.watchpoint(position, condition='w', length=1, callback=None, file='hybrid') 
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `position` | `int` \| `str` | The address or symbol where the watchpoint will be set. |
| `condition` | `str` | The type of access (see [later section](#valid-access-conditions)). |
| `length` | `int` | The size of the word being watched (see [later section](#valid-word-lengths)). |
| `callback` |  `Callable` \| `bool` (see callback signature [here](#callback-signature)) | Used to create asyncronous watchpoints (read more on the [debugging flow of stopping events](../debugging_flow)). |
| `file` | `str` | The backing file for relative addressing. Refer to the [memory access](../../basics/memory_access/#absolute-and-relative-addressing) section for more information on addressing modes. |

**Returns**:

| Return | Type | Description |
| --- | --- | --- |
| `Breakpoint` | [Breakpoint](../../from_pydoc/generated/data/breakpoint) | The breakpoint object created. |

### Valid Access Conditions
The `condition` parameter specifies the type of access that triggers the watchpoint. Default is write access.

| Condition | Description | Supported Architectures |
| --- | --- | --- |
| `"r"` | Read access | AArch64 |
| `"w"` | Write access | AMD64, AArch64 |
| `"rw"` | Read/write access | AMD64, AArch64 |
| `"x"` | Execute access | AMD64 |

### Valid Word Lengths
The `length` parameter specifies the size of the word being watched. By default, the watchpoint is set to watch a single byte.

| Architecture | Supported Lengths |
| --- | --- |
| AMD64 | 1, 2, 4, 8 |
| AArch64 | Any length from 1 to 8 bytes |

!!! INFO "Watchpoint alignment in AArch64"
    The address of the watchpoint on AArch64-based CPUs needs to be aligned to 8 bytes. Instead, basic hardware breakpoints have to be aligned to 4 bytes (which is the size of an ARM instruction).

### :material-code-json: Callback Signature
If you wish to create an [asynchronous](../debugging_flow) watchpoint, you will have to provide a callback function. Since internally watchpoints are implemented as hardware breakpoints, the callback signature is the same as for [breakpoints](../breakpoints#callback-signature). As for breakpoints, if you want to leave the callback empty, you can set callback to `True`.

!!! ABSTRACT "Callback Signature"
    ```python
    def callback(t: ThreadContext, bp: Breakpoint):
    ```

**Parameters**:

| Argument | Type | Description |
| --- | --- | --- |
| `t` | [ThreadContext](../../from_pydoc/generated/state/thread_context) | The thread that hit the breakpoint. |
| `bp` | [Breakpoint](../../from_pydoc/generated/data/breakpoint) | The breakpoint object that triggered the callback. |

---

!!! ABSTRACT "Example usage of asynchronous watchpoints"
    ```python
    def on_watchpoint_hit(t, bp):
        print(f"RAX: {t.regs.rax:#x}")

        if bp.hit_count == 100:
            print("Hit count reached 100")
            bp.disable()

    d.watchpoint(0x11f0, condition="rw", length=8, callback=on_watchpoint_hit, file="binary")
    ```

