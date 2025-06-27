#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

# ruff: noqa: RUF012

# !!! Parsing Values are up to date with Linux Kernel 6.15 !!!

from __future__ import annotations

from dataclasses import dataclass

from libdebug.architectures.syscall_arg_parser import or_parse, sequential_parse


@dataclass(frozen=True)
class GnuConstants:
    """
    A class that provides constants used in GNU/Linux syscall parsing.

    This class contains mappings of numeric values to human-readable names
    for various Linux kernel constants, including error codes, syscall flags,
    file modes, socket options, and other system-specific values.
    """

    # Mapping of error codes to their short names and descriptions
    # From /usr/include/asm-generic/errno-base.h
    ERRNOS = {
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

    # Common flags flags across syscalls
    OPEN_FLAGS = {
        0o00002000: "O_APPEND",
        0o00020000: "O_ASYNC",
        0o02000000: "O_CLOEXEC",
        0o00000100: "O_CREAT",
        0o00040000: "O_DIRECT",
        0o00200000: "O_DIRECTORY",
        0o00010000: "O_DSYNC",
        0o00000200: "O_EXCL",
        0o00100000: "O_LARGEFILE",
        0o00000400: "O_NOCTTY",
        0o00004000: "O_NOFOLLOW / O_NONBLOCK",
        0o010000000: "O_PATH",
        0o00000000: "O_RDONLY",
        0o00000002: "O_RDWR",
        0o04000000: "O_SYNC",
        0o01000000: "O_TMPFILE / O_NOATIME",
        0o00001000: "O_TRUNC",
        0o00000001: "O_WRONLY",
    }

    OPEN_MODES = {
        0o00700: "S_IRWXU",
        0o00400: "S_IRUSR",
        0o00200: "S_IWUSR",
        0o00100: "S_IXUSR",
        0o00070: "S_IRWXG",
        0o00040: "S_IRGRP",
        0o00020: "S_IWGRP",
        0o00010: "S_IXGRP",
        0o00007: "S_IRWXO",
        0o00004: "S_IROTH",
        0o00002: "S_IWOTH",
        0o00001: "S_IXOTH",
        0o0004000: "S_ISUID",
        0o0002000: "S_ISGID",
        0o0001000: "S_ISVTX",
    }

    SIGNALS = {
        1: "SIGHUP",
        2: "SIGINT",
        3: "SIGQUIT",
        4: "SIGILL",
        5: "SIGTRAP",
        6: "SIGABRT / SIGIOT",
        7: "SIGBUS",
        8: "SIGFPE",
        9: "SIGKILL",
        10: "SIGUSR1",
        11: "SIGSEGV",
        12: "SIGUSR2",
        13: "SIGPIPE",
        14: "SIGALRM",
        15: "SIGTERM",
        16: "SIGSTKFLT",
        17: "SIGCHLD",
        18: "SIGCONT",
        19: "SIGSTOP",
        20: "SIGTSTP",
        21: "SIGTTIN",
        22: "SIGTTOU",
        23: "SIGURG",
        24: "SIGXCPU",
        25: "SIGXFSZ",
        26: "SIGVTALRM",
        27: "SIGPROF",
        28: "SIGWINCH",
        29: "SIGIO / SIGPOLL",
        30: "SIGPWR",
        31: "SIGSYS",
        "parsing_mode": "sequential",
    }

    WHICH_CLOCK = {
        0: "CLOCK_REALTIME",
        1: "CLOCK_MONOTONIC",
        2: "CLOCK_PROCESS_CPUTIME_ID",
        3: "CLOCK_THREAD_CPUTIME_ID",
        4: "CLOCK_MONOTONIC_RAW",
        5: "CLOCK_REALTIME_COARSE",
        6: "CLOCK_MONOTONIC_COARSE",
        7: "CLOCK_BOOTTIME",
        8: "CLOCK_REALTIME_ALARM",
        9: "CLOCK_BOOTTIME_ALARM",
        10: "CLOCK_SGI_CYCLE",
        11: "CLOCK_TAI",
        "parsing_mode": "sequential",
    }

    OPENAT_DFD = {
        0xFFFFFF9C: "AT_FDCWD",
    }

    SPLICE_FLAGS = {
        0x01: "SPLICE_F_MOVE",
        0x02: "SPLICE_F_NONBLOCK",
        0x04: "SPLICE_F_MORE",
    }

    VMSPLICE_FLAGS = {
        0x02: "SPLICE_F_NONBLOCK",
        0x04: "SPLICE_F_MORE",
        0x08: "SPLICE_F_GIFT",
    }

    ADVISE_BEHAVIORS = {
        0: "MADV_NORMAL",
        1: "MADV_RANDOM",
        2: "MADV_SEQUENTIAL",
        3: "MADV_WILLNEED",
        4: "MADV_DONTNEED",
        8: "MADV_FREE",
        9: "MADV_REMOVE",
        10: "MADV_DONTFORK",
        11: "MADV_DOFORK",
        12: "MADV_MERGEABLE",
        13: "MADV_UNMERGEABLE",
        14: "MADV_HUGEPAGE",
        15: "MADV_NOHUGEPAGE",
        16: "MADV_DONTDUMP",
        17: "MADV_DODUMP",
        18: "MADV_WIPEONFORK",
        19: "MADV_KEEPONFORK",
        20: "MADV_COLD",
        21: "MADV_PAGEOUT",
        22: "MADV_POPULATE_READ",
        23: "MADV_POPULATE_WRITE",
        24: "MADV_DONTNEED_LOCKED",
        25: "MADV_COLLAPSE",
        100: "MADV_HWPOISON",
        101: "MADV_SOFT_OFFLINE",
        102: "MADV_GUARD_INSTALL",
        103: "MADV_GUARD_REMOVE",
        "parsing_mode": "sequential",
    }

    FCNTL_CMDS = {
        0: "F_DUPFD",
        1: "F_GETFD",
        2: "F_SETFD",
        3: "F_GETFL",
        4: "F_SETFL",
        5: "F_GETLK",
        6: "F_SETLK",
        7: "F_SETLKW",
        8: "F_SETOWN",
        9: "F_GETOWN",
        10: "F_SETSIG",
        11: "F_GETSIG",
        15: "F_SETOWN_EX",
        16: "F_GETOWN_EX",
        17: "F_GETOWNER_UIDS",
        36: "F_OFD_GETLK",
        37: "F_OFD_SETLK",
        38: "F_OFD_SETLKW",
        1024: "F_SETLEASE",
        1025: "F_GETLEASE",
        1026: "F_NOTIFY",
        1027: "F_DUPFD_QUERY",
        1028: "F_CREATED_QUERY",
        1029: "F_CANCELLK",
        1030: "F_DUPFD_CLOEXEC",
        1031: "F_SETPIPE_SZ",
        1032: "F_GETPIPE_SZ",
        1033: "F_ADD_SEALS",
        1034: "F_GET_SEALS",
        1035: "F_GET_RW_HINT",
        1036: "F_SET_RW_HINT",
        1037: "F_GET_FILE_RW_HINT",
        1038: "F_SET_FILE_RW_HINT",
        "parsing_mode": "sequential",
    }

    FCNTL64_CMDS = FCNTL_CMDS + {
        12: "F_GETLK64",
        13: "F_SETLK64",
        14: "F_SETLKW64",
    }

    LSEEK_WHENCE = {
        0: "SEEK_SET",
        1: "SEEK_CUR",
        2: "SEEK_END",
        3: "SEEK_DATA",
        4: "SEEK_HOLE",
    }

    MMAP_PROT = {
        0x0: "PROT_NONE",
        0x1: "PROT_READ",
        0x2: "PROT_WRITE",
        0x4: "PROT_EXEC",
    }

    MMAP_FLAGS_COMMON = {
        0x00000000: "MAP_FILE",
        0x00000001: "MAP_SHARED",
        0x00000003: "MAP_SHARED_VALIDATE",
        0x00000002: "MAP_PRIVATE",
        # 0x00000040: "MAP_32BIT" 32-bit only
        0x00000020: "MAP_ANONYMOUS",
        0x00000800: "MAP_DENYWRITE",
        0x00001000: "MAP_EXECUTABLE",
        0x00000010: "MAP_FIXED",
        0x00100000: "MAP_FIXED_NOREPLACE",
        0x00000100: "MAP_GROWSDOWN",
        0x00040000: "MAP_HUGETLB",
        0x54000000: "MAP_HUGE_2MB",
        0x78000000: "MAP_HUGE_1GB",
        0x00002000: "MAP_LOCKED",
        0x00010000: "MAP_NONBLOCK",
        0x00004000: "MAP_NORESERVE",
        0x00008000: "MAP_POPULATE",
        0x00020000: "MAP_STACK",
        0x00080000: "MAP_SYNC",
        0x04000000: "MAP_UNINITIALIZED",
    }

    MPROTECT_PROT = {
        0x0: "PROT_NONE",
        0x1: "PROT_READ",
        0x2: "PROT_WRITE",
        0x4: "PROT_EXEC",
        0x8: "PROT_SEM",
        0x01000000: "PROT_GROWSDOWN",
        0x02000000: "PROT_GROWSUP",
    }

    RT_SIGPROCMASK_HOW = {
        0: "SIG_BLOCK",
        1: "SIG_UNBLOCK",
        2: "SIG_SETMASK",
        "parsing_mode": "sequential",
    }

    ACCESS_MODES = {
        0: "F_OK",
        1: "X_OK",
        2: "W_OK",
        4: "R_OK",
    }

    MREMAP_FLAGS = {
        1: "MREMAP_MAYMOVE",
        2: "MREMAP_FIXED",
        4: "MREMAP_DONTUNMAP",
    }

    MSYNC_FLAGS = {
        1: "MS_ASYNC",
        2: "MS_INVALIDATE",
        4: "MS_SYNC",
    }

    SHMGET_FLAGS = {
        0o00001000: "IPC_CREAT",
        0o00002000: "IPC_EXCL",
        0o00010000: "SHM_NORESERVE",
        0x54000000: "SHM_HUGE_2MB",
        0x78000000: "SHM_HUGE_1GB",
        0o0004000: "SHM_HUGETLB",
        0o0000032: "SHM_HUGE_SHIFT",
    }

    SHMAT_FLAGS = {
        0o00001000: "IPC_CREAT",
        0o00002000: "IPC_EXCL",
        0o00010000: "SHM_NORESERVE",
        0x54000000: "SHM_HUGE_2MB",
        0x78000000: "SHM_HUGE_1GB",
        0o0004000: "SHM_HUGETLB",
        0o0000032: "SHM_HUGE_SHIFT",
    }

    SHMCTL_CMDS = {
        0: "IPC_RMID",
        1: "IPC_SET",
        2: "IPC_STAT",
        3: "IPC_INFO",
        11: "SHM_LOCK",
        12: "SHM_UNLOCK",
        13: "SHM_STAT",
        14: "SHM_INFO",
        15: "SHM_STAT_ANY",
        "parsing_mode": "sequential",
    }

    ITIMER_WHICH = {
        0: "ITIMER_REAL",
        1: "ITIMER_VIRTUAL",
        2: "ITIMER_PROF",
        "parsing_mode": "sequential",
    }

    SOCKET_FAMILIES = {
        0: "AF_UNSPEC",
        1: "AF_UNIX / AF_LOCAL",
        2: "AF_INET",
        3: "AF_AX25",
        4: "AF_IPX",
        5: "AF_APPLETALK",
        6: "AF_NETROM",
        7: "AF_BRIDGE",
        8: "AF_ATMPVC",
        9: "AF_X25",
        10: "AF_INET6",
        11: "AF_ROSE",
        12: "AF_DECnet",
        13: "AF_NETBEUI",
        14: "AF_SECURITY",
        15: "AF_KEY",
        16: "AF_NETLINK / AF_ROUTE",
        17: "AF_PACKET",
        18: "AF_ASH",
        19: "AF_ECONET",
        20: "AF_ATMSVC",
        21: "AF_RDS",
        22: "AF_SNA",
        23: "AF_IRDA",
        24: "AF_PPPOX",
        25: "AF_WANPIPE",
        26: "AF_LLC",
        27: "AF_IB",
        28: "AF_MPLS",
        29: "AF_CAN",
        30: "AF_TIPC",
        31: "AF_BLUETOOTH",
        32: "AF_IUCV",
        33: "AF_RXRPC",
        34: "AF_ISDN",
        35: "AF_PHONET",
        36: "AF_IEEE802154",
        37: "AF_CAIF",
        38: "AF_ALG",
        39: "AF_NFC",
        40: "AF_VSOCK",
        41: "AF_KCM",
        42: "AF_QIPCRTR",
        43: "AF_SMC",
        44: "AF_XDP",
        45: "AF_MCTP",
        "parsing_mode": "sequential",
    }

    SOCKET_TYPES = {
        "sequential_flags": {
            0x000001: "SOCK_STREAM",
            0x000002: "SOCK_DGRAM",
            0x000003: "SOCK_RAW",
            0x000004: "SOCK_RDM",
            0x000005: "SOCK_SEQPACKET",
            0x00000A: "SOCK_PACKET",
        },
        "or_flags": {
            0x000800: "SOCK_NONBLOCK",
            0x080000: "SOCK_CLOEXEC",
        },
        "parsing_mode": "mixed",
    }

    SENDTO_FLAGS = {
        0x00000800: "MSG_CONFIRM",
        0x00000004: "MSG_DONTROUTE",
        0x00000040: "MSG_DONTWAIT",
        0x00000080: "MSG_EOR",
        0x00008000: "MSG_MORE",
        0x00004000: "MSG_NOSIGNAL",
        0x00000001: "MSG_OOB",
        0x20000000: "MSG_FASTOPEN",
    }

    RECV_FLAGS = {
        0x40000000: "MSG_CMSG_CLOEXEC",
        0x00000040: "MSG_DONTWAIT",
        0x00002000: "MSG_ERRQUEUE",
        0x00000001: "MSG_OOB",
        0x00000002: "MSG_PEEK",
        0x00000020: "MSG_TRUNC",
        0x00000100: "MSG_WAITALL",
    }

    SENDMSG_FLAGS = {
        0x00000800: "MSG_CONFIRM",
        0x00000004: "MSG_DONTROUTE",
        0x00000040: "MSG_DONTWAIT",
        0x00000080: "MSG_EOR",
        0x00008000: "MSG_MORE",
        0x00004000: "MSG_NOSIGNAL",
        0x00000001: "MSG_OOB",
        0x20000000: "MSG_FASTOPEN",
    }

    SHUTDOWN_HOW = {
        0: "SHUT_RD",
        1: "SHUT_WR",
        2: "SHUT_RDWR",
        "parsing_mode": "sequential",
    }

    CLONE_FLAGS_COMMON = {
        0x00000100: "CLONE_VM",
        0x00000200: "CLONE_FS",
        0x00000400: "CLONE_FILES",
        0x00000800: "CLONE_SIGHAND",
        0x00001000: "CLONE_PIDFD",
        0x00002000: "CLONE_PTRACE",
        0x00004000: "CLONE_VFORK",
        0x00008000: "CLONE_PARENT",
        0x00010000: "CLONE_THREAD",
        0x00020000: "CLONE_NEWNS",
        0x00040000: "CLONE_SYSVSEM",
        0x00080000: "CLONE_SETTLS",
        0x00100000: "CLONE_PARENT_SETTID",
        0x00200000: "CLONE_CHILD_CLEARTID",
        0x00400000: "CLONE_DETACHED",
        0x00800000: "CLONE_UNTRACED",
        0x01000000: "CLONE_CHILD_SETTID",
        0x02000000: "CLONE_NEWCGROUP",
        0x04000000: "CLONE_NEWUTS",
        0x08000000: "CLONE_NEWIPC",
        0x10000000: "CLONE_NEWUSER",
        0x20000000: "CLONE_NEWPID",
        0x40000000: "CLONE_NEWNET",
        0x80000000: "CLONE_IO",
    }

    WAIT4_OPTIONS = {
        0x00000001: "WNOHANG",
        0x00000002: "WUNTRACED / WSTOPPED",
        0x00000004: "WEXITED",
        0x00000008: "WCONTINUED",
        0x01000000: "WNOWAIT",
        0x20000000: "__WNOTHREAD",
        0x40000000: "__WALL",
        0x80000000: "__WCLONE",
    }

    SEMGET_KEYS = {
        0: "IPC_PRIVATE",
    }

    SEMGET_FLAGS = {
        0o0001000: "IPC_CREAT",
        0o0002000: "IPC_EXCL",
        0o0004000: "IPC_NOWAIT",
    }

    SEMCTL_CMDS = {
        0: "IPC_RMID",
        1: "IPC_SET",
        2: "IPC_STAT",
        3: "IPC_INFO",
        18: "SEM_STAT",
        19: "SEM_INFO",
        20: "SEM_STAT_ANY",
        11: "GETPID",
        12: "GETVAL",
        13: "GETALL",
        14: "GETNCNT",
        15: "GETZCNT",
        16: "SETVAL",
        17: "SETALL",
        "parsing_mode": "sequential",
    }

    FLOCK_CMDS = {
        1: "LOCK_SH",
        2: "LOCK_EX",
        4: "LOCK_NB",
        8: "LOCK_UN",
    }

    RLIMIT_RESOURCES = {
        0: "RLIMIT_CPU",
        1: "RLIMIT_FSIZE",
        2: "RLIMIT_DATA",
        3: "RLIMIT_STACK",
        4: "RLIMIT_CORE",
        5: "RLIMIT_RSS",
        6: "RLIMIT_NPROC",
        7: "RLIMIT_NOFILE",
        8: "RLIMIT_MEMLOCK",
        9: "RLIMIT_AS",
        10: "RLIMIT_LOCKS",
        11: "RLIMIT_SIGPENDING",
        12: "RLIMIT_MSGQUEUE",
        13: "RLIMIT_NICE",
        14: "RLIMIT_RTPRIO",
        15: "RLIMIT_RTTIME",
        "parsing_mode": "sequential",
    }

    RUSAGE_WHO = {
        0: "RUSAGE_SELF",
        0xFFFFFFFF: "RUSAGE_CHILDREN",
        0xFFFFFFFE: "RUSAGE_BOTH",
        1: "RUSAGE_THREAD",
        "parsing_mode": "sequential",
    }

    PTRACE_COMMON_REQUESTS = {
        # Arch-independent
        0x4200: "PTRACE_SETOPTIONS",
        0x4201: "PTRACE_GETEVENTMSG",
        0x4202: "PTRACE_GETSIGINFO",
        0x4203: "PTRACE_SETSIGINFO",
        0x4204: "PTRACE_GETREGSET",
        0x4205: "PTRACE_SETREGSET",
        0x4206: "PTRACE_SEIZE",
        0x4207: "PTRACE_INTERRUPT",
        0x4208: "PTRACE_LISTEN",
        0x4209: "PTRACE_PEEKSIGINFO",
        0x420A: "PTRACE_GETSIGMASK",
        0x420B: "PTRACE_SETSIGMASK",
        0x420C: "PTRACE_SECCOMP_GET_FILTER",
        0x420D: "PTRACE_SECCOMP_GET_METADATA",
        0x420E: "PTRACE_GET_SYSCALL_INFO",
        0x420F: "PTRACE_GET_RSEQ_CONFIGURATION",
        0x4210: "PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG",
        0x4211: "PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG",
        "parsing_mode": "sequential",
    }

    SYSLOG_TYPES = {
        0: "SYSLOG_ACTION_CLOSE",
        1: "SYSLOG_ACTION_OPEN",
        2: "SYSLOG_ACTION_READ",
        3: "SYSLOG_ACTION_READ_ALL",
        4: "SYSLOG_ACTION_READ_CLEAR",
        5: "SYSLOG_ACTION_CLEAR",
        6: "SYSLOG_ACTION_CONSOLE_OFF",
        7: "SYSLOG_ACTION_CONSOLE_ON",
        8: "SYSLOG_ACTION_CONSOLE_LEVEL",
        9: "SYSLOG_ACTION_SIZE_UNREAD",
        10: "SYSLOG_ACTION_SIZE_BUFFER",
        "parsing_mode": "sequential",
    }

    MKNOD_MODES = {
        # Permissions
        0o00700: "S_IRWXU",
        0o00400: "S_IRUSR",
        0o00200: "S_IWUSR",
        0o00100: "S_IXUSR",
        0o00070: "S_IRWXG",
        0o00040: "S_IRGRP",
        0o00020: "S_IWGRP",
        0o00010: "S_IXGRP",
        0o00007: "S_IRWXO",
        0o00004: "S_IROTH",
        0o00002: "S_IWOTH",
        0o00001: "S_IXOTH",
        0o0004000: "S_ISUID",
        0o0002000: "S_ISGID",
        0o0001000: "S_ISVTX",
        # File type
        0o100000: "S_IFREG",
        0o020000: "S_IFCHR",
        0o060000: "S_IFBLK",
        0o010000: "S_IFIFO",
        0o140000: "S_IFSOCK",
    }

    PROCESS_PERSONALITIES = {
        0x0200000: "ADDR_COMPAT_LAYOUT",
        0x0040000: "ADDR_NO_RANDOMIZE",
        0x0800000: "PER_LINUX_32BIT | ADDR_LIMIT_32BIT",
        0x8000000: "ADDR_LIMIT_3GB",
        0x0100000: "MMAP_PAGE_ZERO",
        0x0400000: "READ_IMPLIES_EXEC",
        0x1000000: "SHORT_INODE",
        0x4000000: "STICKY_TIMEOUTS",
        0x0020000: "UNAME26",
        0x2000000: "WHOLE_SECONDS",
        0x0006: "PER_BSD",
        0x0010: "PER_HPUX",
        0x4000009: "PER_IRIX32",
        0x400000B: "PER_IRIX64",
        0x400000A: "PER_IRIXN32",
        0x4000005: "PER_ISCR4",
        0x0000000: "PER_LINUX",
        0x0000008: "PER_LINUX32",
        0x8000008: "PER_LINUX32_3GB",
        0x000F: "PER_OSF4",
        0x0000000C: "PER_RISCOS",
        0x07000003: "PER_SCOSVR3",
        0x0400000D: "PER_SOLARIS",
        0x04000006: "PER_SUNOS",
        0x05000002: "PER_SVR3",
        0x04100001: "PER_SVR4",
        0x0410000E: "PER_UW7",
        0x05000004: "PER_WYSEV386",
        0x05000007: "PER_XENIX",
    }

    PRIORITY_WHICH = {
        0: "PRIO_PROCESS",
        1: "PRIO_PGRP",
        2: "PRIO_USER",
        "parsing_mode": "sequential",
    }

    SCHEDULER_POLICIES = {
        0: "SCHED_NORMAL",
        1: "SCHED_FIFO",
        2: "SCHED_RR",
        3: "SCHED_BATCH",
        5: "SCHED_IDLE",
        6: "SCHED_DEADLINE",
        7: "SCHED_EXT",
        "parsing_mode": "sequential",
    }

    MLOCKALL_FLAGS = {
        0x00000001: "MCL_CURRENT",
        0x00000002: "MCL_FUTURE",
        0x00000004: "MCL_ONFAULT",
    }

    PRCTL_OPTIONS = {
        0x0000002F: "PR_CAP_AMBIENT",
        0x00000017: "PR_CAPBSET_READ",
        0x00000018: "PR_CAPBSET_DROP",
        0x00000024: "PR_SET_CHILD_SUBREAPER",
        0x00000025: "PR_GET_CHILD_SUBREAPER",
        0x00000004: "PR_SET_DUMPABLE",
        0x00000003: "PR_GET_DUMPABLE",
        0x00000014: "PR_SET_ENDIAN",
        0x00000013: "PR_GET_ENDIAN",
        0x0000002D: "PR_SET_FP_MODE",
        0x0000002E: "PR_GET_FP_MODE",
        0x0000000A: "PR_SET_FPEMU",
        0x00000009: "PR_GET_FPEMU",
        0x0000000C: "PR_SET_FPEXC",
        0x0000000B: "PR_GET_FPEXC",
        0x00000039: "PR_SET_IO_FLUSHER",
        0x0000003A: "PR_GET_IO_FLUSHER",
        0x00000008: "PR_SET_KEEPCAPS",
        0x00000007: "PR_GET_KEEPCAPS",
        0x00000021: "PR_MCE_KILL",
        0x00000022: "PR_MCE_KILL_GET",
        0x00000023: "PR_SET_MM",
        0x53564D41: "PR_SET_VMA",
        0x0000002B: "PR_MPX_ENABLE_MANAGEMENT",
        0x0000002C: "PR_MPX_DISABLE_MANAGEMENT",
        0x0000000F: "PR_SET_NAME",
        0x00000010: "PR_GET_NAME",
        0x00000026: "PR_SET_NO_NEW_PRIVS",
        0x00000027: "PR_GET_NO_NEW_PRIVS",
        0x00000036: "PR_PAC_RESET_KEYS",
        0x00000001: "PR_SET_PDEATHSIG",
        0x00000002: "PR_GET_PDEATHSIG",
        0x59616D61: "PR_SET_PTRACER",
        0x00000016: "PR_SET_SECCOMP",
        0x00000015: "PR_GET_SECCOMP",
        0x0000001C: "PR_SET_SECUREBITS",
        0x0000001B: "PR_GET_SECUREBITS",
        0x00000034: "PR_GET_SPECULATION_CTRL",
        0x00000035: "PR_SET_SPECULATION_CTRL",
        0x00000032: "PR_SVE_SET_VL",
        0x00000033: "PR_SVE_GET_VL",
        0x0000003B: "PR_SET_SYSCALL_USER_DISPATCH",
        0x00000037: "PR_SET_TAGGED_ADDR_CTRL",
        0x00000038: "PR_GET_TAGGED_ADDR_CTRL",
        0x0000001F: "PR_TASK_PERF_EVENTS_DISABLE",
        0x00000020: "PR_TASK_PERF_EVENTS_ENABLE",
        0x00000029: "PR_SET_THP_DISABLE",
        0x0000002A: "PR_GET_THP_DISABLE",
        0x00000028: "PR_GET_TID_ADDRESS",
        0x0000001D: "PR_SET_TIMERSLACK",
        0x0000001E: "PR_GET_TIMERSLACK",
        0x0000000E: "PR_SET_TIMING",
        0x0000000D: "PR_GET_TIMING",
        0x0000001A: "PR_SET_TSC",
        0x00000019: "PR_GET_TSC",
        0x00000006: "PR_SET_UNALIGN",
        0x00000005: "PR_GET_UNALIGN",
        0x41555856: "PR_GET_AUXV",
        0x00000041: "PR_SET_MDWE",
        0x00000042: "PR_GET_MDWE",
        0x00000047: "PR_RISCV_SET_ICACHE_FLUSH_CTX",
        "parsing_mode": "sequential",
    }

    MOUNT_FLAGS = {
        0x00000001: "MS_RDONLY",
        0x00000002: "MS_NOSUID",
        0x00000004: "MS_NODEV",
        0x00000008: "MS_NOEXEC",
        0x00000010: "MS_SYNCHRONOUS",
        0x00000020: "MS_REMOUNT",
        0x00000040: "MS_MANDLOCK",
        0x00000080: "MS_DIRSYNC",
        0x00000100: "MS_NOSYMFOLLOW",
        0x00000400: "MS_NOATIME",
        0x00000800: "MS_NODIRATIME",
        0x00001000: "MS_BIND",
        0x00002000: "MS_MOVE",
        0x00004000: "MS_REC",
        # 0x00008000: "MS_VERBOSE", /* War is peace. Verbosity is silence. MS_VERBOSE is deprecated. */
        0x00008000: "MS_SILENT",
        0x00010000: "MS_POSIXACL",
        0x00020000: "MS_UNBINDABLE",
        0x00040000: "MS_PRIVATE",
        0x00080000: "MS_SLAVE",
        0x00100000: "MS_SHARED",
        0x00200000: "MS_RELATIME",
        0x00400000: "MS_KERNMOUNT",
        0x00800000: "MS_I_VERSION",
        0x01000000: "MS_STRICTATIME",
        0x02000000: "MS_LAZYTIME",
    }

    UMOUNT_FLAGS = {
        0x00000001: "MNT_FORCE",
        0x00000002: "MNT_DETACH",
        0x00000004: "MNT_EXPIRE",
        0x00000008: "UMOUNT_NOFOLLOW",
        0x80000000: "UMOUNT_UNUSED",
    }

    SWAPON_FLAGS = {
        0x8000: "SWAP_FLAG_PREFER",
        0x10000: "SWAP_FLAG_DISCARD",
    }

    REBOOT_MAGIC1 = {
        0xFEE1DEAD: "LINUX_REBOOT_MAGIC1",
        "parsing_mode": "sequential",
    }

    REBOOT_MAGIC2 = {
        672274793: "LINUX_REBOOT_MAGIC2",
        85072278: "LINUX_REBOOT_MAGIC2A",
        369367448: "LINUX_REBOOT_MAGIC2B",
        537993216: "LINUX_REBOOT_MAGIC2C",
        "parsing_mode": "sequential",
    }

    REBOOT_CMDS = {
        0x01234567: "LINUX_REBOOT_CMD_RESTART",
        0xCDEF0123: "LINUX_REBOOT_CMD_HALT",
        0x89ABCDEF: "LINUX_REBOOT_CMD_CAD_ON",
        0x00000000: "LINUX_REBOOT_CMD_CAD_OFF",
        0x4321FEDC: "LINUX_REBOOT_CMD_POWER_OFF",
        0xA1B2C3D4: "LINUX_REBOOT_CMD_RESTART2",
        0xD000FCE2: "LINUX_REBOOT_CMD_SW_SUSPEND",
        0x45584543: "LINUX_REBOOT_CMD_KEXEC",
        "parsing_mode": "sequential",
    }

    DELETE_MODULE_FLAGS = {
        0o0004000: "O_NONBLOCK",
        0o0001000: "O_TRUNC",
    }

    QUOTACTL_CMDS = {
        0: "USRQUOTA",
        1: "GRPQUOTA",
        2: "PRJQUOTA",
        0x80000100: "Q_SYNC",
        0x80000200: "Q_QUOTAON",
        0x80000300: "Q_QUOTAOFF",
        0x80000400: "Q_GETFMT",
        0x80000500: "Q_GETINFO",
        0x80000600: "Q_SETINFO",
        0x80000700: "Q_GETQUOTA",
        0x80000800: "Q_SETQUOTA",
        0x80000900: "Q_GETNEXTQUOTA",
    }

    XATTR_FLAGS = {
        0x00000001: "XATTR_CREATE",
        0x00000002: "XATTR_REPLACE",
        "parsing_mode": "sequential",
    }

    FUTEX_OPS = {
        "sequential_flags": {
            0: "FUTEX_WAIT",
            1: "FUTEX_WAKE",
            2: "FUTEX_FD",
            3: "FUTEX_REQUEUE",
            4: "FUTEX_CMP_REQUEUE",
            5: "FUTEX_WAKE_OP",
            6: "FUTEX_LOCK_PI",
            7: "FUTEX_UNLOCK_PI",
            8: "FUTEX_TRYLOCK_PI",
            9: "FUTEX_WAIT_BITSET",
            10: "FUTEX_WAKE_BITSET",
            11: "FUTEX_WAIT_REQUEUE_PI",
            12: "FUTEX_CMP_REQUEUE_PI",
            13: "FUTEX_LOCK_PI2",
        },
        "or_flags": {
            128: "FUTEX_PRIVATE_FLAG",
            256: "FUTEX_CLOCK_REALTIME",
        },
        "parsing_mode": "mixed",
    }

    REMAP_FILE_PAGES_FLAGS = {
        # All flags other that MAP_NONBLOCK are ignored
        0x00010000: "MAP_NONBLOCK",
    }

    FADVISE_ADVICE = {
        0: "POSIX_FADV_NORMAL",
        1: "POSIX_FADV_RANDOM",
        2: "POSIX_FADV_SEQUENTIAL",
        3: "POSIX_FADV_WILLNEED",
        4: "POSIX_FADV_DONTNEED",
        5: "POSIX_FADV_NOREUSE",
        "parsing_mode": "sequential",
    }

    TIMER_SETTIME_FLAGS = {
        1: "TIMER_ABSTIME",
    }

    CLOCK_NANOSLEEP_FLAGS = {
        1: "TIMER_ABSTIME",
    }

    EPOLL_CTL_OPS = {
        1: "EPOLL_CTL_ADD",
        2: "EPOLL_CTL_DEL",
        3: "EPOLL_CTL_MOD",
        "parsing_mode": "sequential",
    }

    MBIND_MODES = {
        "sequential_flags": {
            0: "MPOL_DEFAULT",
            1: "MPOL_PREFERRED",
            2: "MPOL_BIND",
            3: "MPOL_INTERLEAVE",
            4: "MPOL_LOCAL",
            5: "MPOL_PREFERRED_MANY",
            6: "MPOL_WEIGHTED_INTERLEAVE",
            7: "MPOL_MAX",
        },
        "or_flags": {
            0b1000000000000000: "MPOL_F_STATIC_NODES",
            0b0100000000000000: "MPOL_F_RELATIVE_NODES",
            0b0010000000000000: "MPOL_F_NUMA_BALANCING",
        },
        "parsing_mode": "mixed",
    }

    MBIND_FLAGS = {
        0b00000001: "MPOL_MF_STRICT",
        0b00000010: "MPOL_MF_MOVE",
        0b00000100: "MPOL_MF_MOVE_ALL",
        0b00001000: "MPOL_MF_LAZY",
        0b00010000: "MPOL_MF_INTERNAL",
    }

    SETMEMPOLICY_MODES = {
        "sequential_flags": {
            0: "MPOL_DEFAULT",
            1: "MPOL_PREFERRED",
            2: "MPOL_BIND",
            3: "MPOL_INTERLEAVE",
            4: "MPOL_LOCAL",
            5: "MPOL_PREFERRED_MANY",
            6: "MPOL_WEIGHTED_INTERLEAVE",
            7: "MPOL_MAX",
        },
        "or_flags": {
            0b1000000000000000: "MPOL_F_STATIC_NODES",
            0b0100000000000000: "MPOL_F_RELATIVE_NODES",
            0b0010000000000000: "MPOL_F_NUMA_BALANCING",
        },
        "parsing_mode": "mixed",
    }

    GETMEMPOLICY_FLAGS = {
        0b0001: "MPOL_F_NODE",
        0b0010: "MPOL_F_ADDR",
        0b0100: "MPOL_F_MEMS_ALLOWED",
    }

    MQ_OPEN_FLAGS = {
        0o02000000: "O_CLOEXEC",
        0o00000100: "O_CREAT",
        0o00000200: "O_EXCL",
        0o00004000: "O_NOFOLLOW / O_NONBLOCK",
        0o00000000: "O_RDONLY",
        0o00000002: "O_RDWR",
        0o00000001: "O_WRONLY",
    }

    KEXEC_LOAD_FLAGS = {
        "or_flags": {
            0x00000001: "KEXEC_ON_CRASH",
            0x00000002: "KEXEC_PRESERVE_CONTEXT",
            0x00000004: "KEXEC_UPDATE_ELFCOREHDR",
            0x00000008: "KEXEC_CRASH_HOTPLUG_SUPPORT",
            0xFFFF0000: "KEXEC_ARCH_MASK",
        },
        "sequential_flags": {
            0x0: "KEXEC_ARCH_DEFAULT",
            0x30000: "KEXEC_ARCH_386",
            0x40000: "KEXEC_ARCH_68K",
            0xF0000: "KEXEC_ARCH_PARISC",
            0x3E0000: "KEXEC_ARCH_X86_64",
            0x140000: "KEXEC_ARCH_PPC",
            0x150000: "KEXEC_ARCH_PPC64",
            0x320000: "KEXEC_ARCH_IA_64",
            0x280000: "KEXEC_ARCH_ARM",
            0x160000: "KEXEC_ARCH_S390",
            0x2A0000: "KEXEC_ARCH_SH",
            0xA0000: "KEXEC_ARCH_MIPS_LE",
            0x80000: "KEXEC_ARCH_MIPS",
            0xB70000: "KEXEC_ARCH_AARCH64",
            0xF30000: "KEXEC_ARCH_RISCV",
            0x1020000: "KEXEC_ARCH_LOONGARCH",
        },
        "parsing_mode": "mixed",
    }

    WAITID_WHICH = {
        0: "P_ALL",
        1: "P_PID",
        2: "P_PGID",
        "parsing_mode": "sequential",
    }

    WAITID_OPTIONS = {
        0x00000001: "WNOHANG",
        0x00000002: "WUNTRACED / WSTOPPED",
        0x00000004: "WEXITED",
        0x00000008: "WCONTINUED",
        0x01000000: "WNOWAIT",
        0x20000000: "__WNOTHREAD",
        0x40000000: "__WALL",
        0x80000000: "__WCLONE",
    }

    KEYCTL_OPTIONS = {
        0: "KEYCTL_GET_KEYRING_ID",
        1: "KEYCTL_JOIN_SESSION_KEYRING",
        2: "KEYCTL_UPDATE",
        3: "KEYCTL_REVOKE",
        4: "KEYCTL_CHOWN",
        5: "KEYCTL_SETPERM",
        6: "KEYCTL_DESCRIBE",
        7: "KEYCTL_CLEAR",
        8: "KEYCTL_LINK",
        9: "KEYCTL_UNLINK",
        10: "KEYCTL_SEARCH",
        11: "KEYCTL_READ",
        12: "KEYCTL_INSTANTIATE",
        13: "KEYCTL_NEGATE",
        14: "KEYCTL_SET_REQKEY_KEYRING",
        15: "KEYCTL_SET_TIMEOUT",
        16: "KEYCTL_ASSUME_AUTHORITY",
        17: "KEYCTL_GET_SECURITY",
        18: "KEYCTL_SESSION_TO_PARENT",
        19: "KEYCTL_REJECT",
        20: "KEYCTL_INSTANTIATE_IOV",
        21: "KEYCTL_INVALIDATE",
        22: "KEYCTL_GET_PERSISTENT",
        23: "KEYCTL_DH_COMPUTE",
        24: "KEYCTL_PKEY_QUERY",
        25: "KEYCTL_PKEY_ENCRYPT",
        26: "KEYCTL_PKEY_DECRYPT",
        27: "KEYCTL_PKEY_SIGN",
        28: "KEYCTL_PKEY_VERIFY",
        29: "KEYCTL_RESTRICT_KEYRING",
        30: "KEYCTL_MOVE",
        31: "KEYCTL_CAPABILITIES",
        32: "KEYCTL_WATCH_KEY",
        "parsing_mode": "sequential",
    }

    IOPRIO_WHICH = {
        1: "IOPRIO_WHO_PROCESS",
        2: "IOPRIO_WHO_PGRP",
        3: "IOPRIO_WHO_USER",
        "parsing_mode": "sequential",
    }

    FCHOWNAT_FLAGS = {
        0x1000: "AT_EMPTY_PATH",
        0x100: "AT_SYMLINK_NOFOLLOW",
    }

    NEWSTATFS_FLAGS = {
        0x1000: "AT_EMPTY_PATH",
        0x100: "AT_SYMLINK_NOFOLLOW",
        0x800: "AT_NO_AUTOMOUNT",
    }

    UNLINKAT_FLAGS = {
        0x200: "AT_REMOVEDIR",
    }

    LINKAT_FLAGS = {
        0x1000: "AT_EMPTY_PATH",
        0x400: "AT_SYMLINK_FOLLOW",
    }

    UNSHARE_FLAGS = {
        0x00000400: "CLONE_FILES",
        0x00000200: "CLONE_FS",
        0x02000000: "CLONE_NEWCGROUP",
        0x08000000: "CLONE_NEWIPC",
        0x40000000: "CLONE_NEWNET",
        0x00020000: "CLONE_NEWNS",
        0x20000000: "CLONE_NEWPID",
        0x00000080: "CLONE_NEWTIME",
        0x10000000: "CLONE_NEWUSER",
        0x04000000: "CLONE_NEWUTS",
        0x00040000: "CLONE_SYSVSEM",
        0x00000100: "CLONE_VM",
        0x00010000: "CLONE_THREAD",
        0x00000800: "CLONE_SIGHAND",
    }

    SYNC_FILE_RANGE_FLAGS = {
        1: "SYNC_FILE_RANGE_WAIT_BEFORE",
        2: "SYNC_FILE_RANGE_WRITE",
        4: "SYNC_FILE_RANGE_WAIT_AFTER",
    }

    MOVEPAGES_FLAGS = {
        0b10: "MPOL_MF_MOVE",
        0b100: "MPOL_MF_MOVE_ALL",
    }

    UTIMENSAT_FLAGS = {
        0x1000: "AT_EMPTY_PATH",
        0x100: "AT_SYMLINK_NOFOLLOW",
    }

    TIMERFD_CREATE_CLOCKS = {
        0: "CLOCK_REALTIME",
        1: "CLOCK_MONOTONIC",
        7: "CLOCK_BOOTTIME",
        8: "CLOCK_REALTIME_ALARM",
        9: "CLOCK_BOOTTIME_ALARM",
        "parsing_mode": "sequential",
    }

    TIMERFD_CREATE_FLAGS = {
        0o02000000: "TFD_CLOEXEC",
        0o00004000: "TFD_NONBLOCK",
    }

    FALLOCATE_MODES = {
        0x00: "FALLOC_FL_ALLOCATE_RANGE",
        0x01: "FALLOC_FL_KEEP_SIZE",
        0x02: "FALLOC_FL_PUNCH_HOLE",
        0x04: "FALLOC_FL_NO_HIDE_STALE",
        0x08: "FALLOC_FL_COLLAPSE_RANGE",
        0x10: "FALLOC_FL_ZERO_RANGE",
        0x20: "FALLOC_FL_INSERT_RANGE",
        0x40: "FALLOC_FL_UNSHARE_RANGE",
    }

    TIMERFD_SETTIME_FLAGS = {
        0x00000001: "TFD_TIMER_ABSTIME",
        0x00000002: "TFD_TIMER_CANCEL_ON_SET",
    }

    ACCEPT_FLAGS = {
        0o02000000: "SOCK_CLOEXEC",
        0o00004000: "SOCK_NONBLOCK",
    }

    SIGNALFD_FLAGS = {
        0o02000000: "SFD_CLOEXEC",
        0o00004000: "SFD_NONBLOCK",
    }

    EVENTFD_FLAGS = {
        0o00000001: "EFD_SEMAPHORE",
        0o02000000: "EFD_CLOEXEC",
        0o00004000: "EFD_NONBLOCK",
    }

    EPOLL_CREATE_FLAGS = {
        0o02000000: "EPOLL_CLOEXEC",
    }

    DUP3_FLAGS = {
        0o02000000: "O_CLOEXEC",
    }

    PIPE2_FLAGS = {
        0o02000000: "O_CLOEXEC",
        0o00004000: "O_NONBLOCK",
        0o00040000: "O_DIRECT",
        0o00000200: "O_EXCL",
    }

    INOTIFY_INIT_FLAGS = {
        0o02000000: "IN_CLOEXEC",
        0o00004000: "IN_NONBLOCK",
    }

    PERF_EVENT_OPEN_FLAGS = {
        0b0001: "PERF_FLAG_FD_NO_GROUP",
        0b0010: "PERF_FLAG_FD_OUTPUT",
        0b0100: "PERF_FLAG_PID_CGROUP",
        0b1000: "PERF_FLAG_FD_CLOEXEC",
    }

    RECVMMSG_FLAGS = {
        0x40000000: "MSG_CMSG_CLOEXEC",
        0x00000040: "MSG_DONTWAIT",
        0x00002000: "MSG_ERRQUEUE",
        0x00000001: "MSG_OOB",
        0x00000002: "MSG_PEEK",
        0x00000020: "MSG_TRUNC",
        0x00000100: "MSG_WAITALL",
    }

    FANOTIFY_INIT_FLAGS = {
        "sequential_flags": {
            0x00000000: "FAN_CLASS_NOTIF",
            0x00000004: "FAN_CLASS_CONTENT",
            0x00000008: "FAN_CLASS_PRE_CONTENT",
        },
        "or_flags": {
            0x00000001: "FAN_CLOEXEC",
            0x00000002: "FAN_NONBLOCK",
            0x00000010: "FAN_UNLIMITED_QUEUE",
            0x00000020: "FAN_UNLIMITED_MARKS",
            0x00000040: "FAN_ENABLE_AUDIT",
            0x00000100: "FAN_REPORT_TID",
            0x00000200: "FAN_REPORT_FID",
            0x00000400: "FAN_REPORT_DIR_FID",
            0x00000800: "FAN_REPORT_NAME",
            0x00001000: "FAN_REPORT_TARGET_FID",
            0x00000080: "FAN_REPORT_PIDFD",
        },
        "parsing_mode": "mixed",
    }

    FANOTIFY_EVENT_F_FLAGS = {
        0o00000000: "O_RDONLY",
        0o00000001: "O_WRONLY",
        0o00000002: "O_RDWR",
        0o00100000: "O_LARGEFILE",
        0o02000000: "O_CLOEXEC",
        0o00002000: "O_APPEND",
        0o00010000: "O_DSYNC",
        0o01000000: "O_NOATIME",
        0o00004000: "O_NONBLOCK",
    }

    FANOTIFY_MARK_FLAGS = {
        "sequential_flags": {
            0x00000001: "FAN_MARK_ADD",
            0x00000002: "FAN_MARK_REMOVE",
            0x00000080: "FAN_MARK_FLUSH",
        },
        "or_flags": {
            0x00000004: "FAN_MARK_DONT_FOLLOW",
            0x00000008: "FAN_MARK_ONLYDIR",
            0x00000010: "FAN_MARK_MOUNT",
            0x00000100: "FAN_MARK_FILESYSTEM",
            0x00000020: "FAN_MARK_IGNORED_MASK",
            0x00000400: "FAN_MARK_IGNORE",
            0x00000040: "FAN_MARK_IGNORED_SURV_MODIFY",
            0x00000200: "FAN_MARK_EVICTABLE",
        },
        "parsing_mode": "mixed",
    }

    FANOTIFY_MARK_MASK = {
        0x00000001: "FAN_ACCESS",
        0x00000002: "FAN_MODIFY",
        0x00000004: "FAN_ATTRIB",
        0x00000008: "FAN_CLOSE_WRITE",
        0x00000010: "FAN_CLOSE_NOWRITE",
        0x00000020: "FAN_OPEN",
        0x00000040: "FAN_MOVED_FROM",
        0x00000080: "FAN_MOVED_TO",
        0x00000100: "FAN_CREATE",
        0x00000200: "FAN_DELETE",
        0x00000400: "FAN_DELETE_SELF",
        0x00000800: "FAN_MOVE_SELF",
        0x00001000: "FAN_OPEN_EXEC",
        0x00008000: "FAN_FS_ERROR",
        0x10000000: "FAN_RENAME",
        0x00020000: "FAN_ACCESS_PERM",
        0x00040000: "FAN_OPEN_EXEC_PERM",
        0x40000000: "FAN_ONDIR",
        0x08000000: "FAN_EVENT_ON_CHILD",
    }

    PRLIMIT_RESOURCES = {
        0: "RLIMIT_CPU",
        1: "RLIMIT_FSIZE",
        2: "RLIMIT_DATA",
        3: "RLIMIT_STACK",
        4: "RLIMIT_CORE",
        5: "RLIMIT_RSS",
        6: "RLIMIT_NPROC",
        7: "RLIMIT_NOFILE",
        8: "RLIMIT_MEMLOCK",
        9: "RLIMIT_AS",
        10: "RLIMIT_LOCKS",
        11: "RLIMIT_SIGPENDING",
        12: "RLIMIT_MSGQUEUE",
        13: "RLIMIT_NICE",
        14: "RLIMIT_RTPRIO",
        15: "RLIMIT_RTTIME",
        0xFFFFFFFF: "RLIM_INFINITY",
        "parsing_mode": "sequential",
    }

    NAME_TO_HANDLE_FLAGS = {
        0x200: "AT_HANDLE_FID",
        0x1000: "AT_EMPTY_PATH",
        0x400: "AT_SYMLINK_FOLLOW",
    }

    SETNS_FLAGS = {
        0x02000000: "CLONE_NEWCGROUP",
        0x04000000: "CLONE_NEWUTS",
        0x08000000: "CLONE_NEWIPC",
        0x40000000: "CLONE_NEWNET",
        0x00000080: "CLONE_NEWTIME",
        0x00020000: "CLONE_NEWNS",
        0x20000000: "CLONE_NEWPID",
        0x10000000: "CLONE_NEWUSER",
    }

    KCMP_TYPES = {
        0: "KCMP_FILE",
        1: "KCMP_VM",
        2: "KCMP_FILES",
        3: "KCMP_FS",
        4: "KCMP_SIGHAND",
        5: "KCMP_IO",
        6: "KCMP_SYSVSEM",
        7: "KCMP_EPOLL_TFD",
        "parsing_mode": "sequential",
    }

    FINIT_MODULE_FLAGS = {
        1: "MODULE_INIT_IGNORE_MODVERSIONS",
        2: "MODULE_INIT_IGNORE_VERMAGIC",
        4: "MODULE_INIT_COMPRESSED_FILE",
    }

    RENAMEAT_FLAGS = {
        0b001: "RENAME_NOREPLACE",
        0b010: "RENAME_EXCHANGE",
        0b100: "RENAME_WHITEOUT",
    }

    SECCOMP_OPS = {
        0: "SECCOMP_SET_MODE_STRICT",
        1: "SECCOMP_SET_MODE_FILTER",
        2: "SECCOMP_GET_ACTION_AVAIL",
        3: "SECCOMP_GET_NOTIF_SIZES",
    }

    SECCOMP_FLAGS = {
        0b000001: "SECCOMP_FILTER_FLAG_TSYNC",
        0b000010: "SECCOMP_FILTER_FLAG_LOG",
        0b000100: "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
        0b001000: "SECCOMP_FILTER_FLAG_NEW_LISTENER",
        0b010000: "SECCOMP_FILTER_FLAG_TSYNC_ESRCH",
        0b100000: "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV",
    }

    GETRANDOM_FLAGS = {
        0x0001: "GRND_NONBLOCK",
        0x0002: "GRND_RANDOM",
        0x0004: "GRND_INSECURE",
    }

    MEMFD_CREATE_FLAGS = {
        0x1: "MFD_CLOEXEC",
        0x2: "MFD_ALLOW_SEALING",
        0x4: "MFD_HUGETLB",
        0x8: "MFD_NOEXEC_SEAL",
        0x10: "MFD_EXEC",
        0x40000000: "MFD_HUGE_64KB",
        0x4C000000: "MFD_HUGE_512KB",
        0x50000000: "MFD_HUGE_1MB",
        0x54000000: "MFD_HUGE_2MB",
        0x5C000000: "MFD_HUGE_8MB",
        0x60000000: "MFD_HUGE_16MB",
        0x64000000: "MFD_HUGE_32MB",
        0x70000000: "MFD_HUGE_256MB",
        0x74000000: "MFD_HUGE_512MB",
        0x78000000: "MFD_HUGE_1GB",
        0x7C000000: "MFD_HUGE_2GB",
        0x88000000: "MFD_HUGE_16GB",
    }

    KEXEC_FILE_LOAD_FLAGS = {
        0x00000001: "KEXEC_FILE_UNLOAD",
        0x00000002: "KEXEC_FILE_ON_CRASH",
        0x00000004: "KEXEC_FILE_NO_INITRAMFS",
        0x00000008: "KEXEC_FILE_DEBUG",
    }

    BPF_CMDS = {
        0: "BPF_MAP_CREATE",
        1: "BPF_MAP_LOOKUP_ELEM",
        2: "BPF_MAP_UPDATE_ELEM",
        3: "BPF_MAP_DELETE_ELEM",
        4: "BPF_MAP_GET_NEXT_KEY",
        5: "BPF_PROG_LOAD",
        6: "BPF_OBJ_PIN",
        7: "BPF_OBJ_GET",
        8: "BPF_PROG_ATTACH",
        9: "BPF_PROG_DETACH",
        10: "BPF_PROG_RUN",
        11: "BPF_PROG_GET_NEXT_ID",
        12: "BPF_MAP_GET_NEXT_ID",
        13: "BPF_PROG_GET_FD_BY_ID",
        14: "BPF_MAP_GET_FD_BY_ID",
        15: "BPF_OBJ_GET_INFO_BY_FD",
        16: "BPF_PROG_QUERY",
        17: "BPF_RAW_TRACEPOINT_OPEN",
        18: "BPF_BTF_LOAD",
        19: "BPF_BTF_GET_FD_BY_ID",
        20: "BPF_TASK_FD_QUERY",
        21: "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
        22: "BPF_MAP_FREEZE",
        23: "BPF_BTF_GET_NEXT_ID",
        24: "BPF_MAP_LOOKUP_BATCH",
        25: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
        26: "BPF_MAP_UPDATE_BATCH",
        27: "BPF_MAP_DELETE_BATCH",
        28: "BPF_LINK_CREATE",
        29: "BPF_LINK_UPDATE",
        30: "BPF_LINK_GET_FD_BY_ID",
        31: "BPF_LINK_GET_NEXT_ID",
        32: "BPF_ENABLE_STATS",
        33: "BPF_ITER_CREATE",
        34: "BPF_LINK_DETACH",
        35: "BPF_PROG_BIND_MAP",
        36: "BPF_TOKEN_CREATE",
        "parsing_mode": "sequential",
    }

    EXECVEAT_FLAGS = {
        0x1000: "AT_EMPTY_PATH",
        0x100: "AT_SYMLINK_NOFOLLOW",
    }

    USERFAULTFD_FLAGS = {
        0x00000001: "UFFD_USER_MODE_ONLY",
        0o02000000: "O_CLOEXEC",
        0o00004000: "O_NONBLOCK",
    }

    MEMBARRIER_CMDS = {
        0b0000000000: "MEMBARRIER_CMD_QUERY",
        0b0000000001: "MEMBARRIER_CMD_GLOBAL",
        0b0000000010: "MEMBARRIER_CMD_GLOBAL_EXPEDITED",
        0b0000000100: "MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED",
        0b0000001000: "MEMBARRIER_CMD_PRIVATE_EXPEDITED",
        0b0000010000: "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED",
        0b0000100000: "MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE",
        0b0001000000: "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE",
        0b0010000000: "MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ",
        0b0100000000: "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ",
        0b1000000000: "MEMBARRIER_CMD_GET_REGISTRATIONS",
    }

    MEMBARRIER_FLAGS = {
        0x00000001: "MEMBARRIER_CMD_FLAG_CPU",
    }

    MLOCK_FLAGS = {
        1: "MCL_CURRENT",
        2: "MCL_FUTURE",
        4: "MCL_ONFAULT",
    }

    PREADV_FLAGS = {
        0x00000001: "RWF_HIPRI",
        0x00000002: "RWF_DSYNC",
        0x00000004: "RWF_SYNC",
        0x00000008: "RWF_NOWAIT",
        0x00000010: "RWF_APPEND",
        0x00000020: "RWF_NOAPPEND",
        0x00000040: "RWF_ATOMIC",
        0x00000080: "RWF_DONTCACHE",
    }

    PKEY_MPROTECT_PROTS = {
        0x0: "PROT_NONE",
        0x1: "PROT_READ",
        0x2: "PROT_WRITE",
        0x4: "PROT_EXEC",
        0x8: "PROT_SEM",
        0x10: "PROT_SAO",
        0x01000000: "PROT_GROWSDOWN",
        0x02000000: "PROT_GROWSUP",
    }

    PKEY_ALLOC_INIT_VALS = {
        0x1: "PKEY_DISABLE_ACCESS",
        0x2: "PKEY_DISABLE_WRITE",
    }

    STATX_FLAGS = {
        0x1000: "AT_EMPTY_PATH",
        0x800: "AT_NO_AUTOMOUNT",
        0x100: "AT_SYMLINK_NOFOLLOW",
        0x6000: "AT_STATX_SYNC_TYPE",
        0x0000: "AT_STATX_SYNC_AS_STAT",
        0x2000: "AT_STATX_FORCE_SYNC",
        0x4000: "AT_STATX_DONT_SYNC",
    }

    STATX_MASKS = {
        0x00000001: "STATX_TYPE",
        0x00000002: "STATX_MODE",
        0x00000004: "STATX_NLINK",
        0x00000008: "STATX_UID",
        0x00000010: "STATX_GID",
        0x00000020: "STATX_ATIME",
        0x00000040: "STATX_MTIME",
        0x00000080: "STATX_CTIME",
        0x00000100: "STATX_INO",
        0x00000200: "STATX_SIZE",
        0x00000400: "STATX_BLOCKS",
        0x000007FF: "STATX_BASIC_STATS",
        0x00000800: "STATX_BTIME",
        0x00001000: "STATX_MNT_ID",
        0x00002000: "STATX_DIOALIGN",
        0x00004000: "STATX_MNT_ID_UNIQUE",
        0x00008000: "STATX_SUBVOL",
        0x00010000: "STATX_WRITE_ATOMIC",
        0x00020000: "STATX_DIO_READ_ALIGN",
    }

    RSEQ_FLAGS = {
        0x00000001: "RSEQ_FLAG_UNREGISTER",
    }

    PIDFD_SEND_SIGNAL_FLAGS = {
        0b0001: "PIDFD_SIGNAL_THREAD",
        0b0010: "PIDFD_SIGNAL_THREAD_GROUP",
        0b0100: "PIDFD_SIGNAL_PROCESS_GROUP",
    }

    OPENTREE_FLAGS = {
        0x1000: "AT_EMPTY_PATH",
        0x800: "AT_NO_AUTOMOUNT",
        0x8000: "AT_RECURSIVE",
        0x100: "AT_SYMLINK_NOFOLLOW",
        0x1: "OPEN_TREE_CLONE",
        0o2000000: "OPEN_TREE_CLOEXEC",
    }

    MOVE_MOUNT_FLAGS = {
        0x00000001: "MOVE_MOUNT_F_SYMLINKS",
        0x00000002: "MOVE_MOUNT_F_AUTOMOUNTS",
        0x00000004: "MOVE_MOUNT_F_EMPTY_PATH",
        0x00000010: "MOVE_MOUNT_T_SYMLINKS",
        0x00000020: "MOVE_MOUNT_T_AUTOMOUNTS",
        0x00000040: "MOVE_MOUNT_T_EMPTY_PATH",
        0x00000100: "MOVE_MOUNT_SET_GROUP",
        0x00000200: "MOVE_MOUNT_BENEATH",
    }

    FSOPEN_FLAGS = {
        0x00000001: "FSOPEN_CLOEXEC",
    }

    FSCONFIG_CMDS = {
        0: "FSCONFIG_SET_FLAG",
        1: "FSCONFIG_SET_STRING",
        2: "FSCONFIG_SET_BINARY",
        3: "FSCONFIG_SET_PATH",
        4: "FSCONFIG_SET_PATH_EMPTY",
        5: "FSCONFIG_SET_FD",
        6: "FSCONFIG_CMD_CREATE",
        7: "FSCONFIG_CMD_RECONFIGURE",
        8: "FSCONFIG_CMD_CREATE_EXCL",
        "parsing_mode": "sequential",
    }

    FSMOUNT_FLAGS = {
        0x00000001: "FSMOUNT_CLOEXEC",
    }

    FSMOUNT_ATTR_FLAGS = {
        0x00000001: "MOUNT_ATTR_RDONLY",
        0x00000002: "MOUNT_ATTR_NOSUID",
        0x00000004: "MOUNT_ATTR_NODEV",
        0x00000008: "MOUNT_ATTR_NOEXEC",
        0x00000070: "MOUNT_ATTR__ATIME",
        0x00000000: "MOUNT_ATTR_RELATIME",
        0x00000010: "MOUNT_ATTR_NOATIME",
        0x00000020: "MOUNT_ATTR_STRICTATIME",
        0x00000080: "MOUNT_ATTR_NODIRATIME",
        0x00100000: "MOUNT_ATTR_IDMAP",
        0x00200000: "MOUNT_ATTR_NOSYMFOLLOW",
    }

    FSPICK_FLAGS = {
        0x00000001: "FSPICK_CLOEXEC",
        0x00000002: "FSPICK_SYMLINK_NOFOLLOW",
        0x00000004: "FSPICK_NO_AUTOMOUNT",
        0x00000008: "FSPICK_EMPTY_PATH",
    }

    PIDFD_OPEN_FLAGS = {
        0o00004000: "PIDFD_NONBLOCK",
        0o00000200: "PIDFD_THREAD",
    }

    CLOSE_RANGE_FLAGS = {
        0b000000010: "CLOSE_RANGE_UNSHARE",
        0b000000100: "CLOSE_RANGE_CLOEXEC",
    }

    FACCESSAT_FLAGS = {
        0x200: "AT_EACCESS",
        0x1000: "AT_EMPTY_PATH",
        0x100: "AT_SYMLINK_NOFOLLOW",
    }

    MOUNT_SETATTR_FLAGS = {
        0x100: "AT_SYMLINK_NOFOLLOW",
        0x800: "AT_NO_AUTOMOUNT",
        0x1000: "AT_EMPTY_PATH",
        0x8000: "AT_RECURSIVE",
    }

    LANDLOCK_CREATE_RULESET_FLAGS = {
        1: "LANDLOCK_CREATE_RULESET_VERSION",
    }

    LANDLOCK_ADD_RULE_TYPES = {
        1: "LANDLOCK_RULE_PATH_BENEATH",
        2: "LANDLOCK_RULE_NET_PORT",
    }

    MEMFD_SECRET_FLAGS = {
        0x00000001: "FD_CLOEXEC",
    }

    FCHMODAT_FLAGS = {
        0x100: "AT_SYMLINK_NOFOLLOW",
    }

    MAP_SHADOW_STACK_FLAGS = {
        1: "SHADOW_STACK_SET_TOKEN",
        2: "SHADOW_STACK_SET_MARKER",
    }

    LISTMOUNT_FLAGS = {
        1: "LISTMOUNT_REVERSE",
    }

    LSM_GET_SELF_ATTR_FLAGS = {
        0x0001: "LSM_FLAG_SINGLE",
    }

    XATTRAT_FLAGS = {
        0x100: "AT_SYMLINK_NOFOLLOW",
        0x1000: "AT_EMPTY_PATH",
    }

    MSGGET_KEYS = {
        0: "IPC_PRIVATE",
    }

    MSGGET_FLAGS = {
        0o0001000: "IPC_CREAT",
        0o0002000: "IPC_EXCL",
    }

    MSGSND_FLAGS = {
        0o0004000: "IPC_NOWAIT",
    }

    MSGRCV_FLAGS = {
        0o010000: "MSG_NOERROR",
        0o020000: "MSG_EXCEPT",
        0o040000: "MSG_COPY",
        0o0004000: "IPC_NOWAIT",
    }

    MSGCTL_CMDS = {
        0: "IPC_RMID",
        1: "IPC_SET",
        2: "IPC_STAT",
        3: "IPC_INFO",
        11: "MSG_STAT",
        12: "MSG_INFO",
        13: "MSG_STAT_ANY",
        "parsing_mode": "sequential",
    }

    IO_URING_ENTER_FLAGS = {
        0b00000001: "IORING_ENTER_GETEVENTS",
        0b00000010: "IORING_ENTER_SQ_WAKEUP",
        0b00000100: "IORING_ENTER_SQ_WAIT",
        0b00001000: "IORING_ENTER_EXT_ARG",
        0b00010000: "IORING_ENTER_REGISTERED_RING",
        0b00100000: "IORING_ENTER_ABS_TIMER",
        0b01000000: "IORING_ENTER_EXT_ARG_REG",
        0b10000000: "IORING_ENTER_NO_IOWAIT",
    }

    IO_URING_REGISTER_OPCODES = {
        "sequential_flags": {
            0: "IORING_REGISTER_BUFFERS",
            1: "IORING_UNREGISTER_BUFFERS",
            2: "IORING_REGISTER_FILES",
            3: "IORING_UNREGISTER_FILES",
            4: "IORING_REGISTER_EVENTFD",
            5: "IORING_UNREGISTER_EVENTFD",
            6: "IORING_REGISTER_FILES_UPDATE",
            7: "IORING_REGISTER_EVENTFD_ASYNC",
            8: "IORING_REGISTER_PROBE",
            9: "IORING_REGISTER_PERSONALITY",
            10: "IORING_UNREGISTER_PERSONALITY",
            11: "IORING_REGISTER_RESTRICTIONS",
            12: "IORING_REGISTER_ENABLE_RINGS",
            13: "IORING_REGISTER_FILES2",
            14: "IORING_REGISTER_FILES_UPDATE2",
            15: "IORING_REGISTER_BUFFERS2",
            16: "IORING_REGISTER_BUFFERS_UPDATE",
            17: "IORING_REGISTER_IOWQ_AFF",
            18: "IORING_UNREGISTER_IOWQ_AFF",
            19: "IORING_REGISTER_IOWQ_MAX_WORKERS",
            20: "IORING_REGISTER_RING_FDS",
            21: "IORING_UNREGISTER_RING_FDS",
            22: "IORING_REGISTER_PBUF_RING",
            23: "IORING_UNREGISTER_PBUF_RING",
            24: "IORING_REGISTER_SYNC_CANCEL",
            25: "IORING_REGISTER_FILE_ALLOC_RANGE",
            26: "IORING_REGISTER_PBUF_STATUS",
            27: "IORING_REGISTER_NAPI",
            28: "IORING_UNREGISTER_NAPI",
            29: "IORING_REGISTER_CLOCK",
            30: "IORING_REGISTER_CLONE_BUFFERS",
            31: "IORING_REGISTER_SEND_MSG_RING",
            32: "IORING_REGISTER_ZCRX_IFQ",
            33: "IORING_REGISTER_RESIZE_RINGS",
            34: "IORING_REGISTER_MEM_REGION",
        },
        "or_flags": {0x80000000: "IORING_REGISTER_USE_REGISTERED_RING"},
        "parsing_mode": "mixed",
    }

    FUTEX2_FLAGS = {
        128: "FUTEX_PRIVATE_FLAG",
        "parsing_mode": "sequential",
    }

    TIMER_CREATE_WHICH_CLOCK = {
        0: "CLOCK_REALTIME",
        1: "CLOCK_MONOTONIC",
        2: "CLOCK_PROCESS_CPUTIME_ID",
        3: "CLOCK_THREAD_CPUTIME_ID",
        5: "CLOCK_REALTIME_COARSE",
        7: "CLOCK_BOOTTIME",
        8: "CLOCK_REALTIME_ALARM",
        9: "CLOCK_BOOTTIME_ALARM",
        11: "CLOCK_TAI",
        "parsing_mode": "sequential",
    },

    def parse_fcntl_arg(self: GnuConstants, cmd: int, arg: int) -> str:
        """
        Parse the fcntl command.

        Args:
            cmd (int): The fcntl command.
            arg (int): The argument to parse.

        Returns:
            str: The parsed command.
        """
        match cmd:
            case 2:  # F_SETFD
                if arg == 1:
                    return "FD_CLOEXEC"
                return f"{arg:#x}"
            case 4:  # F_SETFL
                REDUCED_MAP = {
                    0o00002000: "O_APPEND",
                    0o00020000: "O_ASYNC",
                    0o00040000: "O_DIRECT",
                    0o01000000: "O_NOATIME",
                    0o00004000: "O_NONBLOCK",
                }
                return or_parse(REDUCED_MAP, arg)
            case 10:  # F_SETSIG
                return sequential_parse(GnuConstants.SIGNALS, arg)
            case 1024:  # F_SETLEASE
                LEASES = {
                    0: "F_RDLCK",
                    1: "F_WRLCK",
                    2: "F_UNLCK",
                }
                return sequential_parse(LEASES, arg)
            case 1026:  # F_NOTIFY
                NOTIFY_FLAGS = {
                    0x00000001: "DN_ACCESS",
                    0x00000002: "DN_MODIFY",
                    0x00000004: "DN_CREATE",
                    0x00000008: "DN_DELETE",
                    0x00000010: "DN_RENAME",
                    0x00000020: "DN_ATTRIB",
                    0x80000000: "DN_MULTISHOT",
                }
                return or_parse(NOTIFY_FLAGS, arg)
            case 1033:  # F_ADD_SEALS
                SEALS = {
                    0x0001: "F_SEAL_SEAL",
                    0x0002: "F_SEAL_SHRINK",
                    0x0004: "F_SEAL_GROW",
                    0x0008: "F_SEAL_WRITE",
                    0x0010: "F_SEAL_FUTURE_WRITE",
                    0x0020: "F_SEAL_EXEC",
                }
                return or_parse(SEALS, arg)
            case 1038:  # F_SET_FILE_RW_HINT
                RW_HINTS = {
                    0: "RWH_WRITE_LIFE_NOT_SET",
                    1: "RWH_WRITE_LIFE_NONE",
                    2: "RWH_WRITE_LIFE_SHORT",
                    3: "RWH_WRITE_LIFE_MEDIUM",
                    4: "RWH_WRITE_LIFE_LONG",
                    5: "RWH_WRITE_LIFE_EXTREME",
                }
                return sequential_parse(RW_HINTS, arg)
            case _:
                return f"{arg:#x}"
