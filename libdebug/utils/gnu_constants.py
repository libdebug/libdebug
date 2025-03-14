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
O_ACCMODE = 0o00000003
O_RDONLY = 0o00000000
O_WRONLY = 0o00000001
O_RDWR = 0o00000002
O_CREAT = 0o00000100
O_EXCL = 0o00000200
O_NOCTTY = 0o00000400
O_TRUNC = 0o00001000
O_APPEND = 0o00002000
O_NONBLOCK = 0o00004000
O_DSYNC = 0o00010000
FASYNC = 0o00020000
O_DIRECT = 0o00040000
O_LARGEFILE = 0o00100000
O_DIRECTORY = 0o00200000
O_NOFOLLOW = 0o00400000
O_NOATIME = 0o01000000
O_CLOEXEC = 0o02000000
__O_SYNC = 0o04000000
O_SYNC = (__O_SYNC | O_DSYNC)
O_PATH = 0o010000000
__O_TMPFILE = 0o020000000
O_TMPFILE = (__O_TMPFILE | O_DIRECTORY)
O_NDELAY = O_NONBLOCK

# File status flags
F_DUPFD = 0
F_GETFD = 1
F_SETFD = 2
F_GETFL = 3
F_SETFL = 4
F_GETLK = 5
F_SETLK = 6
F_SETLKW = 7
F_SETOWN = 8
F_GETOWN = 9
F_SETSIG = 10
F_GETSIG = 11
F_GETLK64 = 12
F_SETLK64 = 13
F_SETLKW64 = 14
F_SETOWN_EX = 15
F_GETOWN_EX = 16
F_GETOWNER_UIDS = 17

# File status flags for OFD locks
F_OFD_GETLK = 36
F_OFD_SETLK = 37
F_OFD_SETLKW = 38

# File owner types
F_OWNER_TID = 0
F_OWNER_PID = 1
F_OWNER_PGRP = 2

# File descriptor flags
FD_CLOEXEC = 1

# File lock types
F_RDLCK = 0
F_WRLCK = 1
F_UNLCK = 2

# File lock operations
F_EXLCK = 4
F_SHLCK = 8

# File lock types for OFD locks
LOCK_SH = 1
LOCK_EX = 2
LOCK_NB = 4
LOCK_UN = 8

# File lock operations for OFD locks
LOCK_MAND = 32
LOCK_READ = 64
LOCK_WRITE = 128
LOCK_RW = 192

