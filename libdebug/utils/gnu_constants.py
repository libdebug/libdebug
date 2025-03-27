#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

# Mapping of error codes to their short names and descriptions
# From /usr/include/asm-generic/errno-base.h
err_code = {
    1: {"short_name": "EPERM", "description": "Operation not permitted"},
    2: {"short_name": "ENOENT", "description": "No such file or directory"},
    3: {"short_name": "ESRCH", "description": "No such process"},
    4: {"short_name": "EINTR", "description": "Interrupted system call"},
    5: {"short_name": "EIO", "description": "I/O error"},
    6: {"short_name": "ENXIO", "description": "No such device or address"},
    7: {"short_name": "E2BIG", "description": "Argument list too long"},
    8: {"short_name": "ENOEXEC", "description": "Exec format error"},
    9: {"short_name": "EBADF", "description": "Bad file number"},
    10: {"short_name": "ECHILD", "description": "No child processes"},
    11: {"short_name": "EAGAIN", "description": "Try again"},
    12: {"short_name": "ENOMEM", "description": "Out of memory"},
    13: {"short_name": "EACCES", "description": "Permission denied"},
    14: {"short_name": "EFAULT", "description": "Bad address"},
    15: {"short_name": "ENOTBLK", "description": "Block device required"},
    16: {"short_name": "EBUSY", "description": "Device or resource busy"},
    17: {"short_name": "EEXIST", "description": "File exists"},
    18: {"short_name": "EXDEV", "description": "Cross-device link"},
    19: {"short_name": "ENODEV", "description": "No such device"},
    20: {"short_name": "ENOTDIR", "description": "Not a directory"},
    21: {"short_name": "EISDIR", "description": "Is a directory"},
    22: {"short_name": "EINVAL", "description": "Invalid argument"},
    23: {"short_name": "ENFILE", "description": "File table overflow"},
    24: {"short_name": "EMFILE", "description": "Too many open files"},
    25: {"short_name": "ENOTTY", "description": "Not a typewriter"},
    26: {"short_name": "ETXTBSY", "description": "Text file busy"},
    27: {"short_name": "EFBIG", "description": "File too large"},
    28: {"short_name": "ENOSPC", "description": "No space left on device"},
    29: {"short_name": "ESPIPE", "description": "Illegal seek"},
    30: {"short_name": "EROFS", "description": "Read-only file system"},
    31: {"short_name": "EMLINK", "description": "Too many links"},
    32: {"short_name": "EPIPE", "description": "Broken pipe"},
    33: {"short_name": "EDOM", "description": "Math argument out of domain of func"},
    34: {"short_name": "ERANGE", "description": "Math result not representable"},
    35: {"short_name": "EDEADLK", "description": "Resource deadlock would occur"},
    36: {"short_name": "ENAMETOOLONG", "description": "File name too long"},
    37: {"short_name": "ENOLCK", "description": "No record locks available"},
    38: {"short_name": "ENOSYS", "description": "Invalid system call number"},
    39: {"short_name": "ENOTEMPTY", "description": "Directory not empty"},
    40: {"short_name": "ELOOP", "description": "Too many symbolic links encountered"},
    42: {"short_name": "ENOMSG", "description": "No message of desired type"},
    43: {"short_name": "EIDRM", "description": "Identifier removed"},
    44: {"short_name": "ECHRNG", "description": "Channel number out of range"},
    45: {"short_name": "EL2NSYNC", "description": "Level 2 not synchronized"},
    46: {"short_name": "EL3HLT", "description": "Level 3 halted"},
    47: {"short_name": "EL3RST", "description": "Level 3 reset"},
    48: {"short_name": "ELNRNG", "description": "Link number out of range"},
    49: {"short_name": "EUNATCH", "description": "Protocol driver not attached"},
    50: {"short_name": "ENOCSI", "description": "No CSI structure available"},
    51: {"short_name": "EL2HLT", "description": "Level 2 halted"},
    52: {"short_name": "EBADE", "description": "Invalid exchange"},
    53: {"short_name": "EBADR", "description": "Invalid request descriptor"},
    54: {"short_name": "EXFULL", "description": "Exchange full"},
    55: {"short_name": "ENOANO", "description": "No anode"},
    56: {"short_name": "EBADRQC", "description": "Invalid request code"},
    57: {"short_name": "EBADSLT", "description": "Invalid slot"},
    59: {"short_name": "EBFONT", "description": "Bad font file format"},
    60: {"short_name": "ENOSTR", "description": "Device not a stream"},
    61: {"short_name": "ENODATA", "description": "No data available"},
    62: {"short_name": "ETIME", "description": "Timer expired"},
    63: {"short_name": "ENOSR", "description": "Out of streams resources"},
    64: {"short_name": "ENONET", "description": "Machine is not on the network"},
    65: {"short_name": "ENOPKG", "description": "Package not installed"},
    66: {"short_name": "EREMOTE", "description": "Object is remote"},
    67: {"short_name": "ENOLINK", "description": "Link has been severed"},
    68: {"short_name": "EADV", "description": "Advertise error"},
    69: {"short_name": "ESRMNT", "description": "Srmount error"},
    70: {"short_name": "ECOMM", "description": "Communication error on send"},
    71: {"short_name": "EPROTO", "description": "Protocol error"},
    72: {"short_name": "EMULTIHOP", "description": "Multihop attempted"},
    73: {"short_name": "EDOTDOT", "description": "RFS specific error"},
    74: {"short_name": "EBADMSG", "description": "Not a data message"},
    75: {"short_name": "EOVERFLOW", "description": "Value too large for defined data type"},
}

# File access modes
# From /usr/include/uapi/asm-generic/fcntl.h
file_access_modes = {
    0o00000003: {"short_name": "O_ACCMODE", "description": "Bit mask for the file access modes"},
    0o00000000: {"short_name": "O_RDONLY", "description": "Open for reading only"},
    0o00000001: {"short_name": "O_WRONLY", "description": "Open for writing only"},
    0o00000002: {"short_name": "O_RDWR", "description": "Open for reading and writing"},
    0o00000100: {"short_name": "O_CREAT", "description": "Create file if it does not exist"},
    0o00000200: {"short_name": "O_EXCL", "description": "Error if O_CREAT and the file exists"},
    0o00000400: {"short_name": "O_NOCTTY", "description": "Do not assign controlling terminal"},
    0o00001000: {"short_name": "O_TRUNC", "description": "Truncate file to zero length"},
    0o00002000: {"short_name": "O_APPEND", "description": "Append on each write"},
    0o00004000: {"short_name": "O_NONBLOCK", "description": "Non-blocking mode"},
    0o00010000: {"short_name": "O_DSYNC", "description": "Synchronized I/O data integrity completion"},
    0o00020000: {"short_name": "FASYNC", "description": "Enable signal-driven I/O"},
    0o00040000: {"short_name": "O_DIRECT", "description": "Minimize cache effects of I/O"},
    0o00100000: {"short_name": "O_LARGEFILE", "description": "Allow files larger than 2GB"},
    0o00200000: {"short_name": "O_DIRECTORY", "description": "Must be a directory"},
    0o00400000: {"short_name": "O_NOFOLLOW", "description": "Do not follow symbolic links"},
    0o01000000: {"short_name": "O_NOATIME", "description": "Do not update file access time"},
    0o02000000: {"short_name": "O_CLOEXEC", "description": "Set the close-on-exec flag"},
    0o04000000: {"short_name": "__O_SYNC", "description": "Internal synchronous writes flag"},
    (0o04000000 | 0o00010000): {"short_name": "O_SYNC", "description": "Synchronous writes flag (O_DSYNC combined with __O_SYNC)"},
    0o010000000: {"short_name": "O_PATH", "description": "Obtain a file descriptor for path-level operations and fstat()"},
    0o020000000: {"short_name": "__O_TMPFILE", "description": "Internal temporary file flag"},
    (0o020000000 | 0o00200000): {"short_name": "O_TMPFILE", "description": "Open a temporary file (combines __O_TMPFILE with O_DIRECTORY)"},
    # 0o00004000: {"short_name": "O_NDELAY", "description": "Historical alias for O_NONBLOCK"},
}


# File status flags
file_status_flags = {
    0: {"short_name": "F_DUPFD", "description": "Duplicate file descriptor"},
    1: {"short_name": "F_GETFD", "description": "Get file descriptor flags"},
    2: {"short_name": "F_SETFD", "description": "Set file descriptor flags"},
    3: {"short_name": "F_GETFL", "description": "Get file status flags"},
    4: {"short_name": "F_SETFL", "description": "Set file status flags"},
    5: {"short_name": "F_GETLK", "description": "Get record locking information"},
    6: {"short_name": "F_SETLK", "description": "Set record locking information"},
    7: {"short_name": "F_SETLKW", "description": "Set record locking info and wait if blocked"},
    8: {"short_name": "F_SETOWN", "description": "Set the process/group ID to receive SIGIO"},
    9: {"short_name": "F_GETOWN", "description": "Get the process/group ID receiving SIGIO"},
    10: {"short_name": "F_SETSIG", "description": "Set the signal sent when I/O is possible"},
    11: {"short_name": "F_GETSIG", "description": "Get the signal sent when I/O is possible"},
    12: {"short_name": "F_GETLK64", "description": "Get record locking info (64-bit)"},
    13: {"short_name": "F_SETLK64", "description": "Set record locking info (64-bit)"},
    14: {"short_name": "F_SETLKW64", "description": "Set record locking info and wait (64-bit)"},
    15: {"short_name": "F_SETOWN_EX", "description": "Set extended process/group ID for SIGIO"},
    16: {"short_name": "F_GETOWN_EX", "description": "Get extended process/group ID for SIGIO"},
    17: {"short_name": "F_GETOWNER_UIDS", "description": "Get UIDs responsible for file lock ownership"},
}

# File status flags for OFD locks
ofd_lock_status_flags = {
    36: {"short_name": "F_OFD_GETLK", "description": "Get OFD lock status"},
    37: {"short_name": "F_OFD_SETLK", "description": "Set OFD lock"},
    38: {"short_name": "F_OFD_SETLKW", "description": "Set OFD lock and wait if blocked"},
}

# File owner types
file_owner_types = {
    0: {"short_name": "F_OWNER_TID", "description": "Thread ID owner"},
    1: {"short_name": "F_OWNER_PID", "description": "Process ID owner"},
    2: {"short_name": "F_OWNER_PGRP", "description": "Process group owner"},
}

# File descriptor flags
file_descriptor_flags = {
    1: {"short_name": "FD_CLOEXEC", "description": "Close-on-exec flag"},
}

# File lock types
file_lock_types = {
    0: {"short_name": "F_RDLCK", "description": "Read lock"},
    1: {"short_name": "F_WRLCK", "description": "Write lock"},
    2: {"short_name": "F_UNLCK", "description": "Unlock"},
}

# File lock operations
file_lock_operations = {
    4: {"short_name": "F_EXLCK", "description": "Exclusive lock operation"},
    8: {"short_name": "F_SHLCK", "description": "Shared lock operation"},
}

# File lock types for OFD locks
ofd_lock_types = {
    1: {"short_name": "LOCK_SH", "description": "OFD shared lock"},
    2: {"short_name": "LOCK_EX", "description": "OFD exclusive lock"},
    4: {"short_name": "LOCK_NB", "description": "OFD non-blocking lock"},
    8: {"short_name": "LOCK_UN", "description": "OFD unlock"},
}

# File lock operations for OFD locks
ofd_lock_operations = {
    32: {"short_name": "LOCK_MAND", "description": "OFD mandatory lock operation"},
    64: {"short_name": "LOCK_READ", "description": "OFD read lock operation"},
    128: {"short_name": "LOCK_WRITE", "description": "OFD write lock operation"},
    192: {"short_name": "LOCK_RW", "description": "OFD read/write lock operation"},
}

# Chmod modes
chmod_modes = {
    0o0170000: {"short_name": "S_IFMT", "description": "File type mask"},
    0o0140000: {"short_name": "S_IFSOCK", "description": "Socket"},
    0o0120000: {"short_name": "S_IFLNK", "description": "Symbolic link"},
    0o0100000: {"short_name": "S_IFREG", "description": "Regular file"},
    0o0060000: {"short_name": "S_IFBLK", "description": "Block device"},
    0o0040000: {"short_name": "S_IFDIR", "description": "Directory"},
    0o0020000: {"short_name": "S_IFCHR", "description": "Character device"},
    0o0010000: {"short_name": "S_IFIFO", "description": "FIFO"},
    0o0004000: {"short_name": "S_ISUID", "description": "Set user ID on execution"},
    0o0002000: {"short_name": "S_ISGID", "description": "Set group ID on execution"},
    0o0001000: {"short_name": "S_ISVTX", "description": "Sticky bit"},
    0o00700: {"short_name": "S_IRWXU", "description": "Owner has read, write, and execute permission"},
    0o00400: {"short_name": "S_IRUSR", "description": "Owner has read permission"},
    0o00200: {"short_name": "S_IWUSR", "description": "Owner has write permission"},
    0o00100: {"short_name": "S_IXUSR", "description": "Owner has execute permission"},
    0o00070: {"short_name": "S_IRWXG", "description": "Group has read, write, and execute permission"},
    0o00040: {"short_name": "S_IRGRP", "description": "Group has read permission"},
    0o00020: {"short_name": "S_IWGRP", "description": "Group has write permission"},
    0o00010: {"short_name": "S_IXGRP", "description": "Group has execute permission"},
    0o00007: {"short_name": "S_IRWXO", "description": "Others have read, write, and execute permission"},
    0o00004: {"short_name": "S_IROTH", "description": "Others have read permission"},
    0o00002: {"short_name": "S_IWOTH", "description": "Others have write permission"},
    0o00001: {"short_name": "S_IXOTH", "description": "Others have execute permission"},
}

# Memory protection constants
memory_protection_constants = {
    0x1: {"short_name": "PROT_READ", "description": "Page can be read"},
    0x2: {"short_name": "PROT_WRITE", "description": "Page can be written"},
    0x4: {"short_name": "PROT_EXEC", "description": "Page can be executed"},
    0x8: {"short_name": "PROT_SEM", "description": "Page may be used for atomic operations"},
    0x0: {"short_name": "PROT_NONE", "description": "Page cannot be accessed"},
    0x01000000: {"short_name": "PROT_GROWSDOWN", "description": "Extend change to start of growsdown VMA"},
    0x02000000: {"short_name": "PROT_GROWSUP", "description": "Extend change to end of growsup VMA"},
}

# Memory mapping constants
memory_mapping_constants = {
    0x0f: {"short_name": "MAP_TYPE", "description": "Mask for type of mapping"},
    0x10: {"short_name": "MAP_FIXED", "description": "Interpret address exactly"},
    0x20: {"short_name": "MAP_ANONYMOUS", "description": "Do not use a file"},
    0x008000: {"short_name": "MAP_POPULATE", "description": "Prefault pagetables"},
    0x010000: {"short_name": "MAP_NONBLOCK", "description": "Do not block on IO"},
    0x020000: {"short_name": "MAP_STACK", "description": "Address suited for process/thread stacks"},
    0x040000: {"short_name": "MAP_HUGETLB", "description": "Create a huge page mapping"},
    0x080000: {"short_name": "MAP_SYNC", "description": "Perform synchronous page faults"},
    0x100000: {"short_name": "MAP_FIXED_NOREPLACE", "description": "MAP_FIXED without unmapping underlying mapping"},
    0x4000000: {"short_name": "MAP_UNINITIALIZED", "description": "Anonymous mmap with uninitialized memory"},
}

# Memory locking constants
memory_locking_constants = {
    0x01: {"short_name": "MLOCK_ONFAULT", "description": "Lock pages after they are faulted in"},
}

# Memory synchronization constants
memory_sync_constants = {
    1: {"short_name": "MS_ASYNC", "description": "Sync memory asynchronously"},
    2: {"short_name": "MS_INVALIDATE", "description": "Invalidate the caches"},
    4: {"short_name": "MS_SYNC", "description": "Synchronous memory sync"},
}

# Memory advice constants
memory_advice_constants = {
    0: {"short_name": "MADV_NORMAL", "description": "No special treatment"},
    1: {"short_name": "MADV_RANDOM", "description": "Expect random page references"},
    2: {"short_name": "MADV_SEQUENTIAL", "description": "Expect sequential page references"},
    3: {"short_name": "MADV_WILLNEED", "description": "Will need these pages"},
    4: {"short_name": "MADV_DONTNEED", "description": "Don't need these pages"},
    8: {"short_name": "MADV_FREE", "description": "Free pages only if memory pressure"},
    9: {"short_name": "MADV_REMOVE", "description": "Remove these pages and resources"},
    10: {"short_name": "MADV_DONTFORK", "description": "Don't inherit across fork"},
    11: {"short_name": "MADV_DOFORK", "description": "Inherit across fork"},
    12: {"short_name": "MADV_MERGEABLE", "description": "KSM may merge identical pages"},
    13: {"short_name": "MADV_UNMERGEABLE", "description": "KSM may not merge identical pages"},
    14: {"short_name": "MADV_HUGEPAGE", "description": "Worth backing with hugepages"},
    15: {"short_name": "MADV_NOHUGEPAGE", "description": "Not worth backing with hugepages"},
    16: {"short_name": "MADV_DONTDUMP", "description": "Exclude from core dump"},
    17: {"short_name": "MADV_DODUMP", "description": "Clear the MADV_DONTDUMP flag"},
    18: {"short_name": "MADV_WIPEONFORK", "description": "Zero memory on fork (child only)"},
    19: {"short_name": "MADV_KEEPONFORK", "description": "Undo MADV_WIPEONFORK"},
    20: {"short_name": "MADV_COLD", "description": "Deactivate these pages"},
    21: {"short_name": "MADV_PAGEOUT", "description": "Reclaim these pages"},
    22: {"short_name": "MADV_POPULATE_READ", "description": "Prefault page tables readable"},
    23: {"short_name": "MADV_POPULATE_WRITE", "description": "Prefault page tables writable"},
    24: {"short_name": "MADV_DONTNEED_LOCKED", "description": "Drop locked pages too"},
    25: {"short_name": "MADV_COLLAPSE", "description": "Synchronous hugepage collapse"},
    100: {"short_name": "MADV_HWPOISON", "description": "Poison a page for testing"},
    101: {"short_name": "MADV_SOFT_OFFLINE", "description": "Soft offline page for testing"},
    102: {"short_name": "MADV_GUARD_INSTALL", "description": "Fatal signal on access to range"},
    103: {"short_name": "MADV_GUARD_REMOVE", "description": "Unguard range"},
}

# Compatibility flags
compatibility_flags = {
    0: {"short_name": "MAP_FILE", "description": "Compatibility flag"},
}

# Protection key constants
protection_key_constants = {
    0x1: {"short_name": "PKEY_DISABLE_ACCESS", "description": "Disable access"},
    0x2: {"short_name": "PKEY_DISABLE_WRITE", "description": "Disable write"},
    0x3: {"short_name": "PKEY_ACCESS_MASK", "description": "Mask for access and write disable"},
}

at_flags = {
    0x100: {"short_name": "AT_SYMLINK_NOFOLLOW", "description": "Do not follow symbolic links"},
    0x200: {"short_name": "AT_SYMLINK_FOLLOW", "description": "Follow symbolic links"},
    0x400: {"short_name": "AT_NO_AUTOMOUNT", "description": "Suppress terminal automount traversal"},
    0x800: {"short_name": "AT_EMPTY_PATH", "description": "Allow empty relative pathname to operate on dirfd directly"},
    0x1000: {"short_name": "AT_RECURSIVE", "description": "Apply to the entire subtree"},
}

at_statx_flags = {
    0x6000: {"short_name": "AT_STATX_SYNC_TYPE", "description": "Type of synchronisation required from statx()"},
    0x0000: {"short_name": "AT_STATX_SYNC_AS_STAT", "description": "- Do whatever stat() does"},
    0x2000: {"short_name": "AT_STATX_FORCE_SYNC", "description": "- Force the attributes to be sync'd with the server"},
    0x4000: {"short_name": "AT_STATX_DONT_SYNC", "description": "- Don't sync attributes with the server"},
}

at_rename_flags = {
    0x0001: {"short_name": "AT_RENAME_NOREPLACE", "description": "Do not replace existing file"},
    0x0002: {"short_name": "AT_RENAME_EXCHANGE", "description": "Exchange two files"},
    0x0004: {"short_name": "AT_RENAME_WHITEOUT", "description": "Create a whiteout entry"},
}

faccess_at_flags = at_flags | {
    0x200: {"short_name": "AT_EACCESS", "description": "Test access permitted for effective IDs, not real IDs"},
}

unlink_at_flags = at_flags | {
    0x200: {"short_name": "AT_REMOVEDIR", "description": "Remove directory instead of unlinking file"},
}

name_to_handle_at_flags = at_flags | {
    0x200: {"short_name": "AT_HANDLE_FID", "description": "File handle is needed to compare object identity and may not be usable with open_by_handle_at(2)"},
    0x001: {"short_name": "AT_HANDLE_MNT_ID_UNIQUE", "description": "Return the u64 unique mount ID"},
    0x002: {"short_name": "AT_HANDLE_CONNECTABLE", "description": "Request a connectable file handle"},
}
