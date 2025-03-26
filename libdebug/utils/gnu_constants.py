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
    "O_ACCMODE": {"value": 0o00000003, "description": "Bit mask for the file access modes"},
    "O_RDONLY": {"value": 0o00000000, "description": "Open for reading only"},
    "O_WRONLY": {"value": 0o00000001, "description": "Open for writing only"},
    "O_RDWR": {"value": 0o00000002, "description": "Open for reading and writing"},
    "O_CREAT": {"value": 0o00000100, "description": "Create file if it does not exist"},
    "O_EXCL": {"value": 0o00000200, "description": "Error if O_CREAT and the file exists"},
    "O_NOCTTY": {"value": 0o00000400, "description": "Do not assign controlling terminal"},
    "O_TRUNC": {"value": 0o00001000, "description": "Truncate file to zero length"},
    "O_APPEND": {"value": 0o00002000, "description": "Append on each write"},
    "O_NONBLOCK": {"value": 0o00004000, "description": "Non-blocking mode"},
    "O_DSYNC": {"value": 0o00010000, "description": "Synchronized I/O data integrity completion"},
    "FASYNC": {"value": 0o00020000, "description": "Enable signal-driven I/O"},
    "O_DIRECT": {"value": 0o00040000, "description": "Minimize cache effects of I/O"},
    "O_LARGEFILE": {"value": 0o00100000, "description": "Allow files larger than 2GB"},
    "O_DIRECTORY": {"value": 0o00200000, "description": "Must be a directory"},
    "O_NOFOLLOW": {"value": 0o00400000, "description": "Do not follow symbolic links"},
    "O_NOATIME": {"value": 0o01000000, "description": "Do not update file access time"},
    "O_CLOEXEC": {"value": 0o02000000, "description": "Set the close-on-exec flag"},
    "__O_SYNC": {"value": 0o04000000, "description": "Internal synchronous writes flag"},
    "O_SYNC": {"value": 0o04000000 | 0o00010000, "description": "Synchronous writes flag (O_DSYNC combined with __O_SYNC)"},
    "O_PATH": {"value": 0o010000000, "description": "Obtain a file descriptor that can be used for two purposes: to indicate the file for operations that act purely at the file descriptor level and as input to fstat()"},
    "__O_TMPFILE": {"value": 0o020000000, "description": "Internal temporary file flag"},
    "O_TMPFILE": {"value": (0o020000000 | 0o00200000), "description": "Open a temporary file (combines __O_TMPFILE with O_DIRECTORY)"},
    "O_NDELAY": {"value": 0o00004000, "description": "Historical alias for O_NONBLOCK"},
}

# File status flags
file_status_flags = {
    "F_DUPFD": {"value": 0, "description": "Duplicate file descriptor"},
    "F_GETFD": {"value": 1, "description": "Get file descriptor flags"},
    "F_SETFD": {"value": 2, "description": "Set file descriptor flags"},
    "F_GETFL": {"value": 3, "description": "Get file status flags"},
    "F_SETFL": {"value": 4, "description": "Set file status flags"},
    "F_GETLK": {"value": 5, "description": "Get record locking information"},
    "F_SETLK": {"value": 6, "description": "Set record locking information"},
    "F_SETLKW": {"value": 7, "description": "Set record locking info and wait if blocked"},
    "F_SETOWN": {"value": 8, "description": "Set the process/group ID to receive SIGIO"},
    "F_GETOWN": {"value": 9, "description": "Get the process/group ID receiving SIGIO"},
    "F_SETSIG": {"value": 10, "description": "Set the signal sent when I/O is possible"},
    "F_GETSIG": {"value": 11, "description": "Get the signal sent when I/O is possible"},
    "F_GETLK64": {"value": 12, "description": "Get record locking info (64-bit)"},
    "F_SETLK64": {"value": 13, "description": "Set record locking info (64-bit)"},
    "F_SETLKW64": {"value": 14, "description": "Set record locking info and wait (64-bit)"},
    "F_SETOWN_EX": {"value": 15, "description": "Set extended process/group ID for SIGIO"},
    "F_GETOWN_EX": {"value": 16, "description": "Get extended process/group ID for SIGIO"},
    "F_GETOWNER_UIDS": {"value": 17, "description": "Get UIDs responsible for file lock ownership"},
}

# File status flags for OFD locks
ofd_lock_status_flags = {
    "F_OFD_GETLK": {"value": 36, "description": "Get OFD lock status"},
    "F_OFD_SETLK": {"value": 37, "description": "Set OFD lock"},
    "F_OFD_SETLKW": {"value": 38, "description": "Set OFD lock and wait if blocked"},
}

# File owner types
file_owner_types = {
    "F_OWNER_TID": {"value": 0, "description": "Thread ID owner"},
    "F_OWNER_PID": {"value": 1, "description": "Process ID owner"},
    "F_OWNER_PGRP": {"value": 2, "description": "Process group owner"},
}

# File descriptor flags
file_descriptor_flags = {
    "FD_CLOEXEC": {"value": 1, "description": "Close-on-exec flag"},
}

# File lock types
file_lock_types = {
    "F_RDLCK": {"value": 0, "description": "Read lock"},
    "F_WRLCK": {"value": 1, "description": "Write lock"},
    "F_UNLCK": {"value": 2, "description": "Unlock"},
}

# File lock operations
file_lock_operations = {
    "F_EXLCK": {"value": 4, "description": "Exclusive lock operation"},
    "F_SHLCK": {"value": 8, "description": "Shared lock operation"},
}

# File lock types for OFD locks
ofd_lock_types = {
    "LOCK_SH": {"value": 1, "description": "OFD shared lock"},
    "LOCK_EX": {"value": 2, "description": "OFD exclusive lock"},
    "LOCK_NB": {"value": 4, "description": "OFD non-blocking lock"},
    "LOCK_UN": {"value": 8, "description": "OFD unlock"},
}

# File lock operations for OFD locks
ofd_lock_operations = {
    "LOCK_MAND": {"value": 32, "description": "OFD mandatory lock operation"},
    "LOCK_READ": {"value": 64, "description": "OFD read lock operation"},
    "LOCK_WRITE": {"value": 128, "description": "OFD write lock operation"},
    "LOCK_RW": {"value": 192, "description": "OFD read/write lock operation"},
}

