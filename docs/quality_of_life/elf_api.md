---
icon: octicons/file-binary-16
search:
    boost: 4
---
# :octicons-file-binary-16: ELF API

The [Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) (ELF) is a common standard file format for executables, object code, shared libraries, and core dumps. It is widely used on Unix-like operating systems, including Linux. By design, the ELF format is cross-platform and supports different architectures.

Since version 0.10 TBD, **libdebug** offers a simple API to parse some of the most useful information contained in an ELF file. Here are the properties that you can access in an [ELF](../../from_pydoc/generated/data/elf/elf) object:

| Attribute | Type | Description |
| --- | --- | --- |
| `path` | `str` | Relative path to the ELF file. |
| `absolute_path` | `str` | Absolute path to the ELF file. |
| `entry_point` | `int` | Entry point address (relative) of the ELF binary. |
| `is_pie` | `bool` | Whether the ELF file is position-independent (PIE). See [Linux Runtime Mitigations](#linux-runtime-mitigations) |
| `architecture` | `str` | CPU architecture (e.g., `amd64`, `i386`, `aarch64`). Alias: `arch`. |
| `arch` | `str` | Alias for `architecture`. |
| `endianness` | `str` | Endianness of the ELF file (`little`, `big`). |
| `size` | `int` | Size of the ELF file in bytes (cached; uses filesystem). |
| `sections` | [`SectionList`](../../from_pydoc/generated/data/elf/section_list) | List of ELF sections; see [Sections](#sections). |
| `program_headers` | [`ProgramHeaderList`](../../from_pydoc/generated/data/elf/program_header_list) | Program headers (segments); see [Program Headers (Segments)](#program-headers-segments). |
| `dynamic_sections` | [`DynamicSectionList`](../../from_pydoc/generated/data/elf/dynamic_section_list) | Entries from the dynamic section; see [Dynamic Sections](#dynamic-sections). |
| `gnu_properties` | [`GNUPropertyList`](../../from_pydoc/generated/data/elf/gnu_property_list) | GNU properties/notes; see [GNU Properties](#gnu-properties). |
| `build_id` | `str` | Build ID extracted from the ELF (if present). |
| `base_address` | `int` | Base load address of the ELF in memory. Will be 0 if the process is not yet traced. |
| `symbols` | `SymbolList` | Symbols defined/exported by the ELF; see [Symbols](#symbols). |
| `soname()` | `str | None` | Returns the SONAME from the dynamic section, or `None` if not present (not a shared object). |
| `runtime_mitigations` | [`LinuxRuntimeMitigations`](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) | Kernel/runtime mitigations inferred from the ELF; see [Linux Runtime Mitigations](#linux-runtime-mitigations). |

!!! INFO "SONAMEs"
    The soname of a shared library is the name specified in the `DT_SONAME` entry of the [dynamic section](#dynamic-sections) of the ELF file. If the entry is not present, the library will not be included in the `libraries` dictionary.

    Example: For `/usr/lib/x86_64-linux-gnu/libc.so.6`, the soname is `libc.so.6`.

The [Debugger](../../from_pydoc/generated/debugger/debugger) object exposes two properties that you can use to access ELF files.

### :material-apps: Binary
This property returns an instance of the [ELF](../../from_pydoc/generated/data/elf/elf) class representing the ELF file of the main binary of the process you are debugging.

```python
elf = d.binary
```

Most useful information is right here in the binary. However, to interact with the operating system, a binary needs shared libraries. Let's see how to access them as well.

### :material-library-shelves: Libraries
This property returns an [ELFList](../../from_pydoc/generated/data/elf/elf_list) object containing instances of the [ELF](../../from_pydoc/generated/data/elf/elf) class representing the ELF files of all the shared libraries loaded in the process. There is also an alias for this property called `libs`.

<!--- TODO: Review the caching policy of d.libraries so that every time it is called it checks for new maps? -->

!!! WARNING "Traced Process Required"
    Since the list of libraries is retrieved from the memory maps of the process, the `libraries` property is only available once the process is being traced (i.e., after a `d.run()` or `d.attach()` call).

    On the other hand, the list will also include libraries that were dynamically loaded with `dlopen()` during execution, even if not listed as needed dependencies of the binary. Be sure to access the `libraries` property after the process has loaded all the libraries you are interested in.

<!--- TODO: Change library search to make it by SONAME instead... -->

The [ELFList](../../from_pydoc/generated/data/elf/elf_list) object offers two methods to filter the libraries: `filter()` and the `[]` operator. While the first allows to find elves by name or path, the `[]` operator expects the exact match of the filename, whereas the `filter()` method can handle partial matches.

!!! ABSTRACT "Function Signature"
    ```python
    d.libraries.filter(name_or_path: str) -> ELFList
    ```

!!! ABSTRACT "Examples"
    Partial matching with `filter()`:
    ```python
    libc = d.libraries.filter('libc')[0] # (1)!
    ```

    1. Careful! Since the `filter()` method returns all partial matches, this could return `libc.so.6`, `libcurl.so.4`, `libcrypto.so.3`, `libcapstone.so.5`, etc.

    Exact matching with `[]`:
    ```python
    libs = d.libraries # or d.libs
    libc = libs['libc.so.6'][0] # (1)!
    ```

    1. Both the `filter()` method and the `[]` operator return a [ELFList](../../from_pydoc/generated/data/elf/elf_list) object. As such, the result should be indexed to get the actual [ELF](../../from_pydoc/generated/data/elf/elf) object.

## :material-page-next-outline: Sections
Sections define the logical structure of an ELF file. Each section has a specific purpose, such as holding code, data, or metadata. Common sections include `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), and `.rodata` (read-only data).

You can access the sections of an ELF file using the `sections` property, which returns a [SectionList](../../from_pydoc/generated/data/elf/section_list) object. Each section is represented by a [Section](../../from_pydoc/generated/data/elf/section) object.

The Section object exposes the following attributes:

| Attribute | Type | Description |
| --- | --- | --- |
| `name` | `str` | Name of the section (e.g., `.text`, `.data`). |
| `section_type` | `str` | Section type mnemonic (e.g., `PROGBITS`, `SYMTAB`). |
| `flags` | `int` | Flags parsed from bitmask describing section attributes (e.g., executable, writable, readable). |
| `address` | `int` | Virtual address of the section in memory. |
| `offset` | `int` | Offset of the section within the file. |
| `size` | `int` | Size of the section in bytes. |
| `address_align` | `int` | Required alignment of the section in memory. |
| `reference_file` | `str` | Path to the ELF file that contains this section. |

The `flags` attibute, parsed from a bitmask, can have one or more of the following values:

| &lt;elf.h&gt; Definition | Notation | Description |
| --- | --- | --- |
| `SHF_WRITE` | `'W'` | Section is writable. |
| `SHF_ALLOC` | `'A'` | Section is allocated in memory at runtime. |
| `SHF_EXECINSTR` | `'X'` | Section contains executable instructions. |
| `SHF_MERGE` | `'M'` | Section may be merged (contains data that can be combined). |
| `SHF_STRINGS` | `'S'` | Section contains null-terminated strings. |
| `SHF_INFO_LINK` | `'I'` | Section holds information that indexes another section (sh_info). |
| `SHF_LINK_ORDER` | `'L'` | Section order matters relative to other sections (link-order). |
| `SHF_OS_NONCONFORMING` | `'O'` | OS-specific nonconforming section. |
| `SHF_GROUP` | `'G'` | Section is a member of a section group. |
| `SHF_TLS` | `'T'` | Section describes thread-local storage (TLS). |
| `SHF_COMPRESSED` | `'C'` | Section data is compressed. |
| `SHF_EXCLUDE` | `'E'` | Section should be excluded from the final output (GNU extension). |
| `SHF_GNU_RETAIN` | `' RETAIN'` | GNU-specific: instructs the linker/loader to retain the section. |
| `SHF_ORDERED` | `' ORDERED'` | GNU-specific: section has ordering constraints. |
| `SHF_X86_64_LARGE` | `' LARGE'` | Processor-specific: large section on x86_64. |
| `SHF_ENTRYSECT` | `' ENTRYSECT'` | Processor-specific: marks an entry-section. |
| `SHF_COMDEF` | `' COMDEF'` | Processor-specific: common definitions (COMDEF). |

### Searching Sections
You can search sections in a [SectionList](../../from_pydoc/generated/data/elf/section_list) object using the `filter()` method or the `[]` operator.

!!! ABSTRACT "Function Signature"
    ```python
    d.binary.sections.filter(value: int | str) -> SectionList:
    ```

The `filter()` method allows you to search for sections either by relative address (int) or by pattern in the name (str). The method returns a [SectionList](../../from_pydoc/generated/data/elf/section_list) object containing all matching sections.

!!! ABSTRACT "Example of Filtering Registers"
    ```python
    note_sections = d.binary.sections.filter('.note')

    for section in note_sections:
        print(f"Found note section at {section.address:#x} of size {section.size} bytes")
    ```

You can also use the `[]` operator to look up sections by exact name. Because section names always begin with a `.`, you may omit the leading dot when matching. The `[]` operator returns a [SectionList](../../from_pydoc/generated/data/elf/section_list) object.

!!! ABSTRACT "Example of Exact Match"
    ```python
    text_section = d.binary.sections['text'][0]  # or d.binary.sections['.text'][0]

    print(f".text section is at {text_section.address:#x} of size {text_section.size} bytes")
    ```

## :material-page-layout-header: Program Headers (Segments)
Program headers contain the information that the loader uses to setup the process. Each entry describes either a loadable segment or auxiliary information the runtime needs (for example, interpreter path, dynamic linking info, TLS, program header table location, or notes). Loadable segments (type `LOAD`) tell the loader which parts of the file to map into memory and how, so that the segments are placed and protected correctly at runtime.

Segments are a higher-level view than sections: one segment may encompass multiple sections (or parts of sections), and sections do not have to align one-to-one with segments.

Common program header types you will encounter include:

- LOAD — loadable segment (mapped into memory)
- DYNAMIC — dynamic linking information
- INTERP — path to the program interpreter (ld.so)
- NOTE — auxiliary notes (e.g., build IDs)
- PHDR — location of the program header table itself
- TLS — thread-local storage template

| Attribute | Type | Description |
| --- | --- | --- |
| `header_type` | `str` | Type of the program header (e.g., `LOAD`, `DYNAMIC`, `INTERP`). |
| `offset` | `int` | Offset of the segment in the file. |
| `vaddr` | `int` | Virtual address of the segment in memory. |
| `paddr` | `int` | Ignored by System V. Used in systems for which physical addressing is relevant. [Read More](https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html). |
| `filesz` | `int` | Size of the segment in the file (bytes). |
| `memsz` | `int` | Size of the segment in memory (bytes). |
| `flags` | `str` | Flags associated with the segment (e.g., `R`, `W`, `X`). |
| `align` | `int` | Alignment of the segment in memory. |
| `reference_file` | `str` | Path to the ELF file containing this program header. |

### Searching Program Headers
You can search program headers by type in a [ProgramHeaderList](../../from_pydoc/generated/data/elf/program_header_list) object using the `filter()` method or the `[]` operator.

!!! ABSTRACT "Function Signature"
    ```python
    d.binary.program_headers.filter(value: str) -> ProgramHeaderList:
    ```

As always, the `filter()` method allows partial matching, while the `[]` operator requires an exact match. Both return a [ProgramHeaderList](../../from_pydoc/generated/data/elf/program_header_list) object.

## :material-library-shelves: Dynamic Sections
Dynamic sections contain information used for dynamic linking. They include entries that specify needed shared libraries, symbol hash tables, relocation entries, and other data required by the dynamic linker at runtime.

You can access the dynamic sections of an ELF file using the `dynamic_sections` property, which returns a [DynamicSectionList](../../from_pydoc/generated/data/elf/dynamic_section_list) object. Each entry is represented by a [DynamicSection](../../from_pydoc/generated/data/elf/dynamic_section) object.

The DynamicSection object exposes the following attributes:

| Attribute | Type | Description |
| --- | --- | --- |
| `tag` | `int` | The tag of the dynamic section. |
| `value` | `int | str` | The value of the dynamic section. |
| `is_value_address` | `bool` | Whether the value is an address. |
| `reference_file` | `str` | Path to the ELF file containing this section. |

### Searching Dynamic Sections
You can search dynamic sections by tag in a [DynamicSectionList](../../from_pydoc/generated/data/elf/dynamic_section_list) object using the `filter()` method or the `[]` operator.

!!! ABSTRACT "Function Signature"
    ```python
    d.binary.dynamic_sections.filter(value: str) -> DynamicSectionList:
    ```

As always, the `filter()` method allows partial matching, while the `[]` operator requires an exact match. Both return a [DynamicSectionList](../../from_pydoc/generated/data/elf/dynamic_section_list) object.

## :simple-gnu: GNU Properties
GNU properties are a set of attributes that provide additional information about the ELF file, such as security features, required hardware extensions, and other metadata. They can be stored as notes in the `.note.gnu.property` section, or in a program header of type `GNU_PROPERTY`.

You can access the GNU properties of an ELF file using the `gnu_properties` property, which returns a [GNUPropertyList](../../from_pydoc/generated/data/elf/gnu_property_list) object. Each property is represented by a [GNUProperty](../../from_pydoc/generated/data/elf/gnu_property) object.

The GNUProperty object exposes the following attributes:

| Attribute | Type | Description |
| --- | --- | --- |
| `pr_type` | `str` | The type of the GNU property. |
| `value` | `str | int | bytes` | Data of the GNU property. Depending on the property type, this could be a string, an integer, or raw bytes. |
| `reference_file` | `str` | Path to the ELF file that contains this GNU property. |

### Searching GNU Properties
You can search GNU properties by type in a [GNUPropertyList](../../from_pydoc/generated/data/elf/gnu_property_list) object using the `filter()` method or the `[]` operator.

!!! ABSTRACT "Function Signature"
    ```python
    d.binary.gnu_properties.filter(value: str) -> GNUPropertyList:
    ```

As always, the `filter()` method allows partial matching, while the `[]` operator requires an exact match. Both return a [GNUPropertyList](../../from_pydoc/generated/data/elf/gnu_property_list) object.

## :material-alphabetical: Symbols
The `symbols` property of an [ELF](../../from_pydoc/generated/data/elf/elf) object returns a [SymbolList](../../from_pydoc/generated/data/symbol_list) object containing all symbols defined or exported by the ELF file. A deep dive into symbol resolution and filtering can be found in the [:material-alphabetical: Symbol Resolution](../symbols/) documentation.

## :material-security: Linux Runtime Mitigations
The ELF API also includes the parsing of Linux runtime security mitigations supported by the binary. To those who are used to [pwntools](https://github.com/Gallopsled/pwntools), this is similar to the `checksec` functionality. Before seeing how to access mitigation information, let's make a brief introduction to each mitigation htat **libdebug** can parse.

!!! WARNING "Damn Heuristics"
    Note that many mitigation checks are heuristic and may not be completely reliable. Some detections depend on runtime configuration or hardware, and others can be intentionally concealed.

    For example, symbol-based checks will miss mitigations if symbols are stripped or renamed. Each mitigation section below documents the exact checks performed so you can assess whether they are adequate for your use case.

### 🧱 RELocation Read-Only (RELRO)
Relocation Read-Only (RELRO) is a security feature that alters the relocation strategy of dynamically-linked ELFS to prevent attacks that rely on overwriting Global Offset Table (GOT) entries.

There are three levels of RELRO:

- <span style="color:#e53935;">:material-shield-off: No RELRO</span>: Lazy binding via `.got.plt`. `.got` section and `.got.plt` are writable, and are placed right after the `.bss` section (allows exploitation of overflows from BSS into GOT).
- <span style="color:#fb8c00;">:material-shield-half: Partial RELRO</span>: Some symbols (e.g. `__libc_start_main`) are resolved at startup, and the `.got` section is made read-only. However, `.got.plt` section remains writable for lazy binding of other symbols. These sections are placed before `.data` and `.bss` to prevent exploitation of overflows.
- <span style="color:#43a047;">:material-shield: Full RELRO</span>: All symbols are resolved at startup, and both `.got` and `.got.plt` sections are made read-only. This is the most secure option, as it prevents any modification of GOT entries after the program has started.

**libdebug** checks for RELRO in the following way:
- If there is no `PT_GNU_RELRO` program header, RELRO is considered `NONE`.
- If there is a `PT_GNU_RELRO` program header but no `BIND_NOW` flag in the `DT_FLAGS` or `DT_FLAGS_1` dynamic section entries, RELRO is considered `PARTIAL`.
- If there is a `PT_GNU_RELRO` program header and the `BIND_NOW` flag is present, RELRO is considered `FULL`.

You can check the [RelroStatus](../../from_pydoc/generated/data/elf/linux_runtime_mitigations#libdebug.data.elf.linux_runtime_mitigations.RelroStatus) of the ELF using the `relro` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object.

### 🛡 Stack Canary (Stack Guard)
[Stack Guard](https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard) is a security mechanism implemented in [GCC](https://gcc.gnu.org/) and [Clang](https://clang.llvm.org/) that helps protect against stack-based buffer overflow attacks. It works by placing a small, random value called a "canary" between the local variables and the control data (such as the return address) on the stack. Before a function returns, the canary value is checked to see if it has been altered. If it has, the program calls `__stack_chk_fail`, which typically results in the program terminating with a `SIGABRT` signal.

**libdebug** simply checks for the presence of the `__stack_chk_fail` string in the ELF to determine if Stack Guard is enabled.

You can check if Stack Guard is enabled using the `stack_guard` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object.

### 👾 NX (Non-eXecutable) Protection
Non-eXecutable (NX) is a security feature that marks some segment of a process as non-executable. This helps mitigate code injection as a result of buffer overflows.

**libdebug** follows the same approach as [pwntools](https://docs.pwntools.com/en/stable/elf/elf.html#pwnlib.elf.elf.ELF.nx) to determine if NX is enabled: if there is a `PT_GNU_STACK` program header with the executable flag (`PF_X`) unset, NX is considered enabled, otherwise architecture-specific checks are done.

You can check if NX is enabled using the `nx` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object. Other than a boolean value, this attribute may also be `None`, indicating that the check depends on whether the process has `READ_IMPLIES_EXEC` in its [personality](https://man7.org/linux/man-pages/man2/personality.2.html). In this case, the [Binary Report](#binary-report) will s`Depends` for NX.

Read more about NX checks in [pwntools' documentation](https://docs.pwntools.com/en/stable/elf/elf.html#pwnlib.elf.elf.ELF.nx).

### 🧩 Position-Independent Executable
Position-Independent Executable (PIE) is a security feature that allows the operating system to load an executable at any address in memory, rather than at a fixed address. This is achieved by compiling the executable with position-independent code (PIC), which uses relative addressing instead of absolute addressing. PIE is often used in conjunction with [Address Space Layout Randomization (ASLR)](https://en.wikipedia.org/wiki/Address_space_layout_randomization) to make it more difficult for attackers to predict the location of code and data in memory.

**libdebug** checks if an ELF is compiled as PIE by examining the ELF type: if the type is `ET_DYN`, it is considered PIE; otherwise, it is not.

You can check if PIE is enabled using the `pie` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object.

### 🏰 Fortify Source
[Fortify Source](https://www.redhat.com/en/blog/enhance-application-security-fortifysource) is a set of compile-time and runtime security checks provided by [Glibc](https://www.gnu.org/software/libc/) to detect and prevent buffer overflows and other memory-related vulnerabilities. When enabled, Fortify Source replaces certain standard library functions (like `strcpy`, `sprintf`, etc.) with safer versions that perform additional checks on the size of the destination buffer before performing the operation.

There are two levels of Fortify Source:

- Level 1 (`-D_FORTIFY_SOURCE=1`): Doesn't change the behavior of functions, but adds checks for some functions when optimization is enabled.
- Level 2 (`-D_FORTIFY_SOURCE=2`): Adds more extensive checks and may change the behavior of some functions, making them non-conforming to the standard.

**libdebug** checks for Fortify Source by looking for strings with names of fortified function symbols (e.g., `__strcpy_chk`, `__sprintf_chk`, etc.) in the ELF.

You can check if Fortify Source is enabled using the `fortify` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object.

### ☰ Shadow Stack
A Shadow Stack is a security feature that provides protection against control-flow hijacking attacks, such as return-oriented programming (ROP). It works by maintaining a separate, protected stack (the shadow stack) that stores return addresses. When a function is called, the return address is pushed onto both the regular stack and the shadow stack. Upon function return, the return address from the regular stack is compared with the one on the shadow stack. If they do not match, it indicates a potential attack, and the program can take appropriate action (e.g., terminate).

Implementations of Shadow Stacks include [Intel's Control-flow Enforcement Technology (CET)](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html) and [ARM's Guarded Control Stack (GCS)](https://developer.arm.com/documentation/109697/2025_09/Feature-descriptions/The-Armv9-4-architecture-extension#md461-tRM's Guarded Control Stack (GCS)](https://developer.arm.com/documentation/109697/2025_09/Feature-descriptions/The-Armv9-4-architecture-extension#md461-the-armv94-architecture-extension__feat_FEAT_GCS) on ARMv9.4-a.

On i386 and amd64 architectures, **libdebug** checks for Intel CET Shadow Stack support by looking for the `SHSTK` flag in the `X86_FEATURE_1_AND` GNU property. On aarch64 architecture, it checks for ARM GCS support by looking for the `GCS` flag in the `AARCH64_FEATURE_1_AND` GNU property.

You can check if Shadow Stack is supported using the `shstk` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object.

!!! INFO "Intel CET and ARM GCS Availability"
    Note that even if Shadow Stack support is indicated in the binary, the actual availability of this feature also depends on the CPU and kernel configuration. For example, Intel CET requires both hardware support (a compatible CPU) and OS support (e.g., a recent Linux kernel with CET **explicitly** enabled).

### 🧭 Indirect Branch Tracking / Branch Target Identification
Indirect Branch Tracking (IBT) is a security feature that helps protect against control-flow hijacking attacks by ensuring that indirect branches (like function pointers or virtual method calls) only target valid locations. This is achieved by marking valid branch targets with special instructions, and the CPU checks these instructions before allowing the branch to occur.

It is implemented as part of [Intel's Control-flow Enforcement Technology (CET)](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html). ARM architecture has a similar feature called [Branch Target Identification (BTI)](https://developer.arm.com/documentation/109576/0100/Branch-Target-Identification).

On i386 and amd64 architectures, **libdebug** checks for Intel CET IBT support by looking for the `IBT` flag in the `X86_FEATURE_1_AND` GNU property. On aarch64 architecture, it checks for ARM BTI support by looking for the `BTI` flag in the `AARCH64_FEATURE_1_AND` GNU property.

You can check if Indirect Branch Tracking / Branch Target Identification is supported using the `ibt` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object. You can also use the alias `bti` for this attribute.

!!! INFO "Intel CET and ARM BTI Availability"
    Note that even if IBT/BTI support is indicated in the binary, the actual availability of this feature also depends on the CPU and kernel configuration. For example, Intel CET requires both hardware support (a compatible CPU) and OS support (e.g., a recent Linux kernel with CET **explicitly** enabled).

### 🧪 GCC Sanitizers
Sanitizers are runtime instrumentation tools that help detect various types of bugs and vulnerabilities in programs during development. In this sense, they are not strictly a mitigation, but may be used in CTF challenges to harden binaries.

Common sanitizers include:

For more information on sanitizers in GCC, read [here](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html).

- Address Sanitizer (ASAN): Detects memory errors such as buffer overflows, use-after-free, and memory leaks.
- Memory Sanitizer (MSAN): Detects uninitialized memory reads.
- Undefined Behavior Sanitizer (UBSAN): Detects undefined behavior in C/C++ programs, such as integer overflows, null pointer dereferences, and type mismatches.

**libdebug** checks for the presence of sanitizer-specific stings (e.g., `__asan_*`, `__msan_*`, `__ubsan_*`) in the ELF's symbol table to determine if a binary was built with a specific sanitizer.

You can check if a binary was built with a specific sanitizer using the `asan`, `msan`, and `ubsan` attributes of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object.

!!! WARNING "Specificity of Sanitizers Detection"
    Note that the detection of sanitizers is based on the presence of specific symbols in the ELF's symbol table. These symbols are introduced by GCC when the sanitizers are enabled during compilation. However, different sanitizers may use different sets of symbols.

### ARM Architectural Hardening
In recent years, ARM has introduced several architectural extensions to enhance security and mitigate common attack vectors. For the following mitigations, remember that their actual availability also depends on the CPU and kernel configuration.

#### 🔐 Pointer Authentication Codes (PAC)
As part of the ARMv8.3-A architecture, [Pointer Authentication Codes (PAC)](https://developer.arm.com/documentation/109576/0100/Pointer-Authentication-Code/Introduction-to-PAC) were introduced as a security feature to protect against control-flow hijacking attacks by cryptographically signing pointers. PAC works by generating a Pointer Authentication Code (PAC) for each pointer using a secret key and additional context information (such as the pointer's address). When the pointer is used, the hardware verifies the PAC to ensure that the pointer has not been tampered with. If the PAC verification fails, it indicates a potential attack, and the program can take appropriate action (e.g., terminate).

**libdebug** checks for ARM PAC support by looking for the `PAC` flag in the `AARCH64_FEATURE_1_AND` GNU property or specific PAC instructions in the `.text` section (e.g., `PACG`, `AUT`, etc.). This is because unlike BTI, the PAC GNU property is optional, as it is callee ABI in Linux with no changes to memory permissions \[[Source](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64#Bill'sdraftpost:EnablingPACandBTIonAArch64onLinux-PAC)\]. 

You can check if Pointer Authentication Codes are supported using the `pac` attribute of the [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object.

## Mitigations API

The `runtime_mitigations` property of an [ELF](../../from_pydoc/generated/data/elf/elf) object returns a [LinuxRuntimeMitigations](../../from_pydoc/generated/data/elf/linux_runtime_mitigations) object, containing the following properties:

| Attribute | Type | Description |
| --- | --- | --- |
| `relro` | [RelroStatus](../../from_pydoc/generated/data/elf/linux_runtime_mitigations#libdebug.data.elf.linux_runtime_mitigations.RelroStatus) | Value of RELRO (FULL, PARTIAL, NONE). |
| `stack_guard` | `bool` | Whether a stack canary (stack guard) is present (heuristic: `__stack_chk_fail` symbol). |
| `nx` | `bool | None` | Whether NX (non-executable stack) is enabled. May be `None` when detection depends on process personality. |
| `stack_executable` | `bool` | Whether the stack is executable. |
| `pie` | `bool` | Whether the binary is a Position-Independent Executable (PIE). |
| `shstk` | `bool` | Shadow Stack support (Intel CET SHSTK / ARM GCS). |
| `ibt` | `bool` | Indirect Branch Tracking / Branch Target Identification support (Intel CET IBT / ARM BTI). Alias: `bti`. |
| `fortify` | `bool` | Whether glibc _FORTIFY_SOURCE is in effect (heuristic via fortified symbols). |
| `pac` | `bool` | ARM Pointer Authentication Codes (PAC) supported. |
| `asan` | `bool` | Binary built with AddressSanitizer (ASAN). |
| `msan` | `bool` | Binary built with MemorySanitizer (MSAN). |
| `ubsan` | `bool` | Binary built with UndefinedBehaviorSanitizer (UBSAN). |

## :material-flower-tulip-outline: Pretty Printing of ELF Information
You can pretty print the most relevant information of an ELF file using the following `pprint_...` methods of the [ELF](../../from_pydoc/generated/data/elf/elf) object:

- `d.binary.pprint_sections()` — Pretty print ELF sections.

![pprint_sections output](../../assets/pprint_sections.png)

- `d.binary.pprint_program_headers()` — Pretty print ELF program headers (segments).

![pprint_program_headers output](../../assets/pprint_program_headers.png)

- `d.binary.pprint_dynamic_sections()` — Pretty print ELF dynamic sections.

![pprint_dynamic_sections output](../../assets/pprint_dynamic_sections.png)

- `d.binary.pprint_gnu_properties()` — Pretty print ELF GNU properties.

![pprint_gnu_properties output](../../assets/pprint_gnu_properties.png)

### :material-file-code-outline: Binary Report
The binary report is a pretty-printed summary of the most relevant information about an ELF file. You can generate it using the `pprint_binary_report()` method of the [Debugger](../../from_pydoc/generated/debugger/debugger) object.

!!! ABSTRACT "Usage"
    ```python
    d.pprint_binary_report()
    ```

The report will include different information based on whether the process is being traced or not. For example, when the process is traced, the base address of the binary and paths to the libraries will be included.

Finally, the report will also include the runtime mitigations supported by the binary, color-coded for better readability.

Here are two examples of binary reports, one on AMD64 and another on AArch64:

Example on AMD64:

=== "Not Traced"
    ![AMD64 Binary Report - Not Traced Process](../../assets/amd64_binary_report.png)

=== "Traced"
    ![AMD64 Binary Report - Traced Process](../../assets/amd64_binary_report_running.png)

Example on AArch64:

=== "Not Traced"
    ![AArch64 Binary Report - Not Traced Process](../../assets/aarch64_binary_report.png)

=== "Traced"
    ![AArch64 Binary Report - Traced Process](../../assets/aarch64_binary_report_running.png)
