---
icon: material/robot-happy
search:
    boost: 4
---
# :material-robot-happy: Quality of Life Features
For your convenience, **libdebug** offers a few functions that will speed up your debugging process.

### [:material-flower-tulip-outline: Pretty Printing](../pretty_printing/)
Visualizing the state of the process you are debugging can be a daunting task. **libdebug** offers utilities to print registers, memory maps, syscalls, and more in a human-readable format and with color highlighting.

### [:material-alphabetical: Symbol Resolution](../symbols/)
**libdebug** can resolve symbols in the binary and shared libraries. With big binaries, this can be a computationally intensive, especially if your script needs to be run multiple types. You can set symbol resolution levels and specify where to look for symbols according to your needs.

### [:material-map-plus: Memory Maps](../memory_maps/)
**libdebug** offers utilities to retrieve the memory maps of a process. This can be useful to understand the memory layout of the process you are debugging.

### [:octicons-stack-24: Stack Frame Utils](../stack_frame_utils/)
**libdebug** offers utilities to resolve the return addresses of a process.

### [:fontawesome-solid-wand-magic-sparkles: Arbitrary Code Execution](../arbitrary_code_execution/)
**libdebug** offers a few functions that will help you execute arbitrary code in the context of the process you are debugging. Beware though, this features can significantly change the intended behavior of the process and may cause unexpected behaviors.

### [:material-run-fast: Evasion of Anti-Debugging](../anti_debugging/)
**libdebug** offers a few functions that will help you evade simple anti-debugging techniques. These functions can be used to bypass checks for the presence of a debugger.