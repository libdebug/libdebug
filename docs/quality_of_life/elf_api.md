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
| `path` | `str` | Path to the ELF file. |
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
| `flags` | `int` | Flags bitmask describing section attributes (e.g., executable, writable, readable). |
| `address` | `int` | Virtual address of the section in memory. |
| `offset` | `int` | Offset of the section within the file. |
| `size` | `int` | Size of the section in bytes. |
| `address_align` | `int` | Required alignment of the section in memory. |
| `reference_file` | `str` | Path to the ELF file that contains this section. |

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