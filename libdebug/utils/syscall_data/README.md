## Authorship and Attribution

The base syscall definitions used in this library were adapted from the excellent resources provided by [**Mebeim**](https://github.com/mebeim). We extend our sincere gratitude for their comprehensive and well-maintained data.

Specifically, the original data was downloaded and adapted from:

* **Systrack:**

  * GitHub Repository: <https://github.com/mebeim/systrack>

  * Interactive Syscall Table: <https://syscalls.mebeim.net/>

Their work has been invaluable in compiling accurate and up-to-date syscall information, which forms the foundation of the JSON definitions included here.
We have processed and adapted these definitions to fit the specific needs and format of our library.

## Updating Syscall Definitions (`update.py`)

The `update.py` script in this directory is used to manage and maintain these syscall definition files.

### Purpose

This script performs two key functions:

1. **Fetches Syscall Definitions**: Downloads the latest syscall tables for supported architectures (x86/64, ARM64, i386) directly from `syscalls.mebeim.net`.

2. **Compresses Syscall Data**: Processes existing syscall JSON files, removing unnecessary fields and retaining only essential information (`name`, `number`, `signature`) to optimize them for the `libdebug` library.

### Usage

To update the syscall definitions for your current platform's architecture by fetching the latest data:
```bash
./update.py --remote
```

You can also specify the architecture explicitly:
```bash
./update.py --remote --arch i386
```

Alternatively, to compress a locally available syscall data file:
```bash
./update.py --input_file /path/to/your/syscall_data.json
```

The script automatically saves the processed data as a `{architecture}.json` file (e.g., `amd64.json`) in the correct directory.