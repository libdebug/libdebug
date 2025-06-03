#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.syscall_arg_parser import or_parse, sequential_parse

# !!! Parsing Values are up to date with Linux Kernel 6.15 !!!

def parse_ptrace_data(*args) -> str:
    """
    Parse the ptrace data value into a dictionary.

    Args:
        *args: The arguments passed to the ptrace syscall.
    """
    request, pid, addr, data = args

    # Skip any other parsing it's just 0
    if data == 0:
        return "0x0"

    PTRACE_SETOPTIONS = 0x4200
    PTRACE_SEIZE = 0x4206

    if request in (PTRACE_SETOPTIONS, PTRACE_SEIZE):
        options = {
            0x1: "PTRACE_O_TRACESYSGOOD",
            0x2: "PTRACE_O_TRACEFORK",
            0x4: "PTRACE_O_TRACEVFORK",
            0x8: "PTRACE_O_TRACECLONE",
            0x10: "PTRACE_O_TRACEEXEC",
            0x20: "PTRACE_O_TRACEVFORKDONE",
            0x40: "PTRACE_O_TRACEEXIT",
            0x80: "PTRACE_O_TRACESECCOMP",
            0x100000: "PTRACE_O_EXITKILL",
            0x200000: "PTRACE_O_SUSPEND_SECCOMP",
        }

        masked_bits = 0x0
        out = ""

        for bit, name in options.items():
            if data & bit:
                masked_bits |= bit
                out = out + " | " + name if out else name
                data &= ~bit

                # Early exit if all bits are masked
                if not data:
                    break

        # Unmasked values
        if data:
            return out + f" | {data:#x}" if out else f"{data:#x}"

        return out
    else:
        return f"{data:#x}"

# def parse_fcntl_arg(cmd: int, arg: int) -> str:
#     """
#     Parse the fcntl command.

#     Args:
#         cmd (int): The fcntl command.
#         arg (int): The argument to parse.

#     Returns:
#         str: The parsed command.
#     """
#     match cmd:
#         case 2:  # F_SETFD
#             if arg == 1:
#                 return "FD_CLOEXEC"
#             return f"{arg:#x}"
#         case 4:  # F_SETFL
#             REDUCED_MAP = \
#             {
#                 0o00002000: "O_APPEND",
#                 0o00020000: "O_ASYNC",
#                 0o00040000: "O_DIRECT",
#                 0o01000000: "O_NOATIME",
#                 0o00004000: "O_NONBLOCK",
#             }
#             return or_parse(REDUCED_MAP, arg)
#         case 10:  # F_SETSIG
#             return sequential_parse(SIGNALS, arg)
#         case 1024:  # F_SETLEASE
#             LEASES = \
#             {
#                 0: "F_RDLCK",
#                 1: "F_WRLCK",
#                 2: "F_UNLCK",
#             }
#             return sequential_parse(LEASES, arg)
#         case 1026: # F_NOTIFY
#             NOTIFY_FLAGS = \
#             {
#                 0x00000001: "DN_ACCESS",
#                 0x00000002: "DN_MODIFY",
#                 0x00000004: "DN_CREATE",
#                 0x00000008: "DN_DELETE",
#                 0x00000010: "DN_RENAME",
#                 0x00000020: "DN_ATTRIB",
#                 0x80000000: "DN_MULTISHOT",
#             }
#             return or_parse(NOTIFY_FLAGS, arg)
#         case 1033: # F_ADD_SEALS
#             SEALS = \
#             {
#                 0x0001: "F_SEAL_SEAL",
#                 0x0002: "F_SEAL_SHRINK",
#                 0x0004: "F_SEAL_GROW",
#                 0x0008: "F_SEAL_WRITE",
#                 0x0010: "F_SEAL_FUTURE_WRITE",
#                 0x0020: "F_SEAL_EXEC",
#             }
#             return or_parse(SEALS, arg)
#         case 1038: # F_SET_FILE_RW_HINT
#             RW_HINTS = \
#             {
#                 0: "RWH_WRITE_LIFE_NOT_SET",
#                 1: "RWH_WRITE_LIFE_NONE",
#                 2: "RWH_WRITE_LIFE_SHORT",
#                 3: "RWH_WRITE_LIFE_MEDIUM",
#                 4: "RWH_WRITE_LIFE_LONG",
#                 5: "RWH_WRITE_LIFE_EXTREME",
#             }
#             return sequential_parse(RW_HINTS, arg)
#         case _:
#             return f"{arg:#x}"


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

# Copied from AMD64, to check
# FCNTL_CMDS = {
#     0: "F_DUPFD",
#     1: "F_GETFD",
#     2: "F_SETFD",
#     3: "F_GETFL",
#     4: "F_SETFL",
#     5: "F_GETLK",
#     6: "F_SETLK",
#     7: "F_SETLKW",
#     8: "F_SETOWN",
#     9: "F_GETOWN",
#     10: "F_SETSIG",
#     11: "F_GETSIG",
#     12: "F_GETLK64",
#     13: "F_SETLK64",
#     14: "F_SETLKW64",
#     15: "F_SETOWN_EX",
#     16: "F_GETOWN_EX",
#     17: "F_GETOWNER_UIDS",
#     36: "F_OFD_GETLK",
#     37: "F_OFD_SETLK",
#     38: "F_OFD_SETLKW",
#     1024: "F_SETLEASE",
#     1025: "F_GETLEASE",
#     1026: "F_NOTIFY",
#     1027: "F_DUPFD_QUERY",
#     1028: "F_CREATED_QUERY",
#     1029: "F_CANCELLK",
#     1030: "F_DUPFD_CLOEXEC",
#     1031: "F_SETPIPE_SZ",
#     1032: "F_GETPIPE_SZ",
#     1033: "F_ADD_SEALS",
#     1034: "F_GET_SEALS",
#     1035: "F_GET_RW_HINT",
#     1036: "F_SET_RW_HINT",
#     1037: "F_GET_FILE_RW_HINT",
#     1038: "F_SET_FILE_RW_HINT",
#     "parsing_mode": "sequential",
# }

I386_SYSCALL_PARSER_MAP = \
{
    #open
    5:{
        #int flags
        1: OPEN_FLAGS,
        #umode_t mode
        2: OPEN_MODES,
    },
    #waitpid
    7:{
        #int options
        2: {
            0x00000001: "WNOHANG",
            0x00000002: "WUNTRACED / WSTOPPED",
            0x00000004: "WEXITED",
            0x00000008: "WCONTINUED",
            0x01000000: "WNOWAIT",
            0x20000000: "__WNOTHREAD",
            0x40000000: "__WALL",
            0x80000000: "__WCLONE",
        },
    },
    #creat
    8:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #mknod
    14:{
        #umode_t mode
        1: {
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
        },
    },
    #chmod
    15:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #lseek
    19:{
        #unsigned int whence
        2: {
            0: "SEEK_SET",
            1: "SEEK_CUR",
            2: "SEEK_END",
            3: "SEEK_DATA",
            4: "SEEK_HOLE",
        },
    },
    #mount
    21:{
        #unsigned long flags
        3: {
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
        },
    },
    #ptrace
    26:{
        #long request
        0: {
            0: "PTRACE_TRACEME",
            1: "PTRACE_PEEKTEXT",
            2: "PTRACE_PEEKDATA",
            3: "PTRACE_PEEKUSER",
            4: "PTRACE_POKETEXT",
            5: "PTRACE_POKEDATA",
            6: "PTRACE_POKEUSER",
            7: "PTRACE_CONT",
            8: "PTRACE_KILL",
            9: "PTRACE_SINGLESTEP",
            16: "PTRACE_ATTACH",
            17: "PTRACE_DETACH",
            24: "PTRACE_SYSCALL",
            12: "PTRACE_GETREGS",
            13: "PTRACE_SETREGS",
            14: "PTRACE_GETFPREGS",
            15: "PTRACE_SETFPREGS",
            18: "PTRACE_GETFPXREGS",
            19: "PTRACE_SETFPXREGS",
            21: "PTRACE_OLDSETOPTIONS",
            25: "PTRACE_GET_THREAD_AREA",
            26: "PTRACE_SET_THREAD_AREA",
            31: "PTRACE_SYSEMU",
            32: "PTRACE_SYSEMU_SINGLESTEP",
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
        },
        # unsigned long data
        3: {
            "parsing_mode": "custom",
            "parser": parse_ptrace_data,
        },
    },
    #access
    33:{
        #int mode
        1: {
            0: "F_OK",
            1: "X_OK",
            2: "W_OK",
            4: "R_OK",
        },
    },
    #kill
    37:{
        #int sig
        1: SIGNALS,
    },
    #mkdir
    39:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #signal
    48:{
        #int sig
        0: SIGNALS,
    },
    #umount
    52:{
        #int flags
        1: {
            0x00000001: "MNT_FORCE",
            0x00000002: "MNT_DETACH",
            0x00000004: "MNT_EXPIRE",
            0x00000008: "UMOUNT_NOFOLLOW",
            0x80000000: "UMOUNT_UNUSED",
        },
    },
    #TODO: Fill
    #fcntl
    55:{
        #unsigned int fd
        0: {},
        #unsigned int cmd
        1: {},
        #unsigned long arg
        2: {},
    },
    #umask
    60:{
        #int mask
        0: OPEN_MODES,
    },
    #sigaction
    67:{
        #int sig
        0: SIGNALS,
    },
    #setrlimit
    75:{
        #unsigned int resource
        0: {
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
        },
    },
    #getrlimit
    76:{
        #unsigned int resource
        0: {
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
        },
    },
    #getrusage
    77:{
        #int who
        0: {
            0: "RUSAGE_SELF",
            0xFFFFFFFF: "RUSAGE_CHILDREN",
            0xFFFFFFFE: "RUSAGE_BOTH",
            1: "RUSAGE_THREAD",
            "parsing_mode": "sequential",
        },
    },
    #swapon
    87:{
        #int swap_flags
        1: {
            0x8000: "SWAP_FLAG_PREFER",
            0x10000: "SWAP_FLAG_DISCARD",
        },
    },
    #reboot
    88: {
        # int magic1
        0: {
            0xFEE1DEAD: "LINUX_REBOOT_MAGIC1",
            "parsing_mode": "sequential",
        },
        # int magic2
        1: {
            672274793: "LINUX_REBOOT_MAGIC2",
            85072278: "LINUX_REBOOT_MAGIC2A",
            369367448: "LINUX_REBOOT_MAGIC2B",
            537993216: "LINUX_REBOOT_MAGIC2C",
            "parsing_mode": "sequential",
        },
        # unsigned int cmd
        2: {
            0x01234567: "LINUX_REBOOT_CMD_RESTART",
            0xCDEF0123: "LINUX_REBOOT_CMD_HALT",
            0x89ABCDEF: "LINUX_REBOOT_CMD_CAD_ON",
            0x00000000: "LINUX_REBOOT_CMD_CAD_OFF",
            0x4321FEDC: "LINUX_REBOOT_CMD_POWER_OFF",
            0xA1B2C3D4: "LINUX_REBOOT_CMD_RESTART2",
            0xD000FCE2: "LINUX_REBOOT_CMD_SW_SUSPEND",
            0x45584543: "LINUX_REBOOT_CMD_KEXEC",
            "parsing_mode": "sequential",
        },
    },
    # TODO: Implement struct parsing just for this
    #mmap
    90:{
        #struct mmap_arg_struct *arg
        0: {},
    },
    #fchmod
    94:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #getpriority
    96:{
        #int which
        0: {
            0: "PRIO_PROCESS",
            1: "PRIO_PGRP",
            2: "PRIO_USER",
            "parsing_mode": "sequential",
        },
    },
    #setpriority
    97:{
        #int which
        0: {
            0: "PRIO_PROCESS",
            1: "PRIO_PGRP",
            2: "PRIO_USER",
            "parsing_mode": "sequential",
        },
    },
    #socketcall
    102:{
        #int call
        0: {
            1: "SYS_SOCKET",
            2: "SYS_BIND",
            3: "SYS_CONNECT",
            4: "SYS_LISTEN",
            5: "SYS_ACCEPT",
            6: "SYS_GETSOCKNAME",
            7: "SYS_GETPEERNAME",
            8: "SYS_SOCKETPAIR",
            9: "SYS_SEND",
            10: "SYS_RECV",
            11: "SYS_SENDTO",
            12: "SYS_RECVFROM",
            13: "SYS_SHUTDOWN",
            14: "SYS_SETSOCKOPT",
            15: "SYS_GETSOCKOPT",
            16: "SYS_SENDMSG",
            17: "SYS_RECVMSG",
            18: "SYS_ACCEPT4",
            19: "SYS_RECVMMSG",
            20: "SYS_SENDMMSG",
            "parsing_mode": "sequential",
        },
    },
    #syslog
    103:{
        #int type
        0: {
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
        },
    },
    #setitimer
    104:{
        #int which
        0: {
            0: "ITIMER_REAL",
            1: "ITIMER_VIRTUAL",
            2: "ITIMER_PROF",
            "parsing_mode": "sequential",
        },
    },
    #getitimer
    105:{
        #int which
        0: {
            0: "ITIMER_REAL",
            1: "ITIMER_VIRTUAL",
            2: "ITIMER_PROF",
            "parsing_mode": "sequential",
        },
    },
    #wait4
    114:{
        #int options
        2: {
            0x00000001: "WNOHANG",
            0x00000002: "WUNTRACED / WSTOPPED",
            0x00000004: "WEXITED",
            0x00000008: "WCONTINUED",
            0x01000000: "WNOWAIT",
            0x20000000: "__WNOTHREAD",
            0x40000000: "__WALL",
            0x80000000: "__WCLONE",
        },
    },
    #ipc
    117:{
        #unsigned int call
        0: {
            1: "SEMOP",
            2: "SEMGET",
            3: "SEMCTL",
            4: "SEMTIMEDOP",
            11: "MSGSND",
            12: "MSGRCV",
            13: "MSGGET",
            14: "MSGCTL",
            21: "SHMAT",
            22: "SHMDT",
            23: "SHMGET",
            24: "SHMCTL",
            "parsing_mode": "sequential",
        },
    },
    #clone
    120:{
        #unsigned long clone_flags
        0: {
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
        },
    },
    #mprotect
    125:{
        #unsigned long prot
        2: {
            0x0: "PROT_NONE",
            0x1: "PROT_READ",
            0x2: "PROT_WRITE",
            0x4: "PROT_EXEC",
            0x8: "PROT_SEM",
            0x01000000: "PROT_GROWSDOWN",
            0x02000000: "PROT_GROWSUP",
        },
    },
    #sigprocmask
    126:{
        #int how
        0: {
            0: "SIG_BLOCK",
            1: "SIG_UNBLOCK",
            2: "SIG_SETMASK",
            "parsing_mode": "sequential",
        },
    },
    #delete_module
    129:{
        #unsigned int flags
        1: {
            0o0004000: "O_NONBLOCK",
            0o0001000: "O_TRUNC",
        },
    },
    #quotactl
    131:{
        #unsigned int cmd
        0: {
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
        },
    },
    #fchdir
    133:{
        #unsigned int fd
        0: OPENAT_DFD,
    },
    #personality
    136:{
        #unsigned int personality
        0: {
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
        },
    },
    #llseek
    140:{
        #unsigned int whence
        4: {
            0: "SEEK_SET",
            1: "SEEK_CUR",
            2: "SEEK_END",
            "parsing_mode": "sequential",
        },
    },
    #flock
    143:{
        #unsigned int cmd
        1: {
            1: "LOCK_SH",
            2: "LOCK_EX",
            4: "LOCK_NB",
            8: "LOCK_UN",
        },
    },
    #msync
    144:{
        #int flags
        2: {
            1: "MS_ASYNC",
            2: "MS_INVALIDATE",
            4: "MS_SYNC",
        },
    },
    #mlockall
    152:{
        #int flags
        0: {
            0x00000001: "MCL_CURRENT",
            0x00000002: "MCL_FUTURE",
            0x00000004: "MCL_ONFAULT",
        },
    },
    #sched_setscheduler
    156:{
        #int policy
        1: {
            0: "SCHED_NORMAL",
            1: "SCHED_FIFO",
            2: "SCHED_RR",
            3: "SCHED_BATCH",
            5: "SCHED_IDLE",
            6: "SCHED_DEADLINE",
            7: "SCHED_EXT",
            "parsing_mode": "sequential",
        },
    },
    #sched_get_priority_max
    159:{
        #int policy
        0: {
            0: "SCHED_NORMAL",
            1: "SCHED_FIFO",
            2: "SCHED_RR",
            3: "SCHED_BATCH",
            5: "SCHED_IDLE",
            6: "SCHED_DEADLINE",
            7: "SCHED_EXT",
            "parsing_mode": "sequential",
        },
    },
    #sched_get_priority_min
    160:{
        #int policy
        0: {
            0: "SCHED_NORMAL",
            1: "SCHED_FIFO",
            2: "SCHED_RR",
            3: "SCHED_BATCH",
            5: "SCHED_IDLE",
            6: "SCHED_DEADLINE",
            7: "SCHED_EXT",
            "parsing_mode": "sequential",
        },
    },
    #mremap
    163:{
        #unsigned long flags
        3: {
            1: "MREMAP_MAYMOVE",
            2: "MREMAP_FIXED",
            4: "MREMAP_DONTUNMAP",
        },
    },
    #vm86
    166:{
        #unsigned long cmd
        0: {
            0: "VM86_PLUS_INSTALL_CHECK",
            1: "VM86_ENTER",
            2: "VM86_ENTER_NO_BYPASS",
            3: "VM86_REQUEST_IRQ",
            4: "VM86_FREE_IRQ",
            5: "VM86_GET_IRQ_BITS",
            6: "VM86_GET_AND_RESET_IRQ",
            "parsing_mode": "sequential",
        },
    },
    #prctl
    172:{
        #int option
        0: {
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
        },
    },
    #rt_sigaction
    174:{
        #int sig
        0: SIGNALS,
    },
    #rt_sigprocmask
    175:{
        #int how
        0: {
            0: "SIG_BLOCK",
            1: "SIG_UNBLOCK",
            2: "SIG_SETMASK",
            "parsing_mode": "sequential",
        },
    },
    #getrlimit
    191:{
        #unsigned int resource
        0: {
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
        },
    },
    #mmap_pgoff
    192:{
        #unsigned long prot
        2: {
            0x0: "PROT_NONE",
            0x1: "PROT_READ",
            0x2: "PROT_WRITE",
            0x4: "PROT_EXEC",
        },
        #unsigned long flags
        3: {
            0x00000000: "MAP_FILE",
            0x00000001: "MAP_SHARED",
            0x00000003: "MAP_SHARED_VALIDATE",
            0x00000002: "MAP_PRIVATE",
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
        },
    },
    #madvise
    219:{
        #int behavior
        2: ADVISE_BEHAVIORS,
    },
    #TODO: Fill
    #fcntl64
    221:{
        #unsigned int fd
        0: {},
        #unsigned int cmd
        1: {},
        #unsigned long arg
        2: {},
    },
    #setxattr
    226:{
        #int flags
        4: {
            0x00000001: "XATTR_CREATE",
            0x00000002: "XATTR_REPLACE",
            "parsing_mode": "sequential",
        },
    },
    #lsetxattr
    227:{
        #int flags
        4: {
            0x00000001: "XATTR_CREATE",
            0x00000002: "XATTR_REPLACE",
            "parsing_mode": "sequential",
        },
    },
    #fsetxattr
    228:{
        #int flags
        4: {
            0x00000001: "XATTR_CREATE",
            0x00000002: "XATTR_REPLACE",
            "parsing_mode": "sequential",
        },
    },
    #tkill
    238:{
        #int sig
        1: SIGNALS,
    },
    #futex
    240:{
        #int op
        1: {
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
        },
    },
    #fadvise64
    250:{
        #int advice
        4: {
            0: "POSIX_FADV_NORMAL",
            1: "POSIX_FADV_RANDOM",
            2: "POSIX_FADV_SEQUENTIAL",
            3: "POSIX_FADV_WILLNEED",
            4: "POSIX_FADV_DONTNEED",
            5: "POSIX_FADV_NOREUSE",
            "parsing_mode": "sequential",
        },
    },
    #epoll_ctl
    255:{
        #int op
        1: {
            1: "EPOLL_CTL_ADD",
            2: "EPOLL_CTL_DEL",
            3: "EPOLL_CTL_MOD",
            "parsing_mode": "sequential",
        },
    },
    #remap_file_pages
    257:{
        #unsigned long flags
        4: {
            # All flags other that MAP_NONBLOCK are ignored
            0x00010000: "MAP_NONBLOCK",
        },
    },
    #timer_create
    259:{
        #const clockid_t which_clock
        0: {
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
    },
    #timer_settime
    260:{
        #int flags
        1: {
            1: "TIMER_ABSTIME",
        },
    },
    #clock_settime
    264:{
        #clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #clock_gettime
    265:{
        #clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #clock_getres
    266:{
        #clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #clock_nanosleep
    267:{
        #clockid_t which_clock
        0: WHICH_CLOCK,
        #int flags
        1: {
            1: "TIMER_ABSTIME",
        },
    },
    #tgkill
    270:{
        #int sig
        2: SIGNALS,
    },
    #fadvise64_64
    272:{
        #int advice
        5: {
            0: "POSIX_FADV_NORMAL",
            1: "POSIX_FADV_RANDOM",
            2: "POSIX_FADV_SEQUENTIAL",
            3: "POSIX_FADV_WILLNEED",
            4: "POSIX_FADV_DONTNEED",
            5: "POSIX_FADV_NOREUSE",
            "parsing_mode": "sequential",
        },
    },
    #mbind
    274:{
        #unsigned long mode
        2: {
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
        },
        #unsigned int flags
        5: {
            0b00000001: "MPOL_MF_STRICT",
            0b00000010: "MPOL_MF_MOVE",
            0b00000100: "MPOL_MF_MOVE_ALL",
            0b00001000: "MPOL_MF_LAZY",
            0b00010000: "MPOL_MF_INTERNAL",
        },
    },
    #get_mempolicy
    275:{
        #unsigned long flags
        4: {
            0b0001: "MPOL_F_NODE",
            0b0010: "MPOL_F_ADDR",
            0b0100: "MPOL_F_MEMS_ALLOWED",
        },
    },
    #set_mempolicy
    276:{
        #int mode
        0: {
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
        },
    #mq_open
    277:{
        #int oflag
        1: {
            0o02000000: "O_CLOEXEC",
            0o00000100: "O_CREAT",
            0o00000200: "O_EXCL",
            0o00004000: "O_NOFOLLOW / O_NONBLOCK",
            0o00000000: "O_RDONLY",
            0o00000002: "O_RDWR",
            0o00000001: "O_WRONLY",
        },
        #umode_t mode
        2: OPEN_MODES,
    },
    #kexec_load
    283:{
        #unsigned long flags
        3: {
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
        },
    },
    #waitid
    284:{
        #int which
        0: {
            0: "P_ALL",
            1: "P_PID",
            2: "P_PGID",
            "parsing_mode": "sequential",
        },
        #int options
        3: {
            0x00000001: "WNOHANG",
            0x00000002: "WUNTRACED / WSTOPPED",
            0x00000004: "WEXITED",
            0x00000008: "WCONTINUED",
            0x01000000: "WNOWAIT",
            0x20000000: "__WNOTHREAD",
            0x40000000: "__WALL",
            0x80000000: "__WCLONE",
        },
    },
    #add_key
    286:{
        #key_serial_t ringid
        4: {
            0xFFFFFFFFFFFFFFFF: "KEY_SPEC_THREAD_KEYRING",
            0xFFFFFFFFFFFFFFFE: "KEY_SPEC_PROCESS_KEYRING",
            0xFFFFFFFFFFFFFFFD: "KEY_SPEC_SESSION_KEYRING",
            0xFFFFFFFFFFFFFFFC: "KEY_SPEC_USER_KEYRING",
            0xFFFFFFFFFFFFFFFB: "KEY_SPEC_USER_SESSION_KEYRING",
            0xFFFFFFFFFFFFFFFA: "KEY_SPEC_GROUP_KEYRING",
            0xFFFFFFFFFFFFFF9F: "KEY_SPEC_REQKEY_AUTH_KEY",
            0xFFFFFFFFFFFFFF9E: "KEY_SPEC_REQUESTOR_KEYRING",
            "parsing_mode": "sequential",
        },
    },
    #request_key
    287:{
        #key_serial_t destringid
        3: {
            0xFFFFFFFFFFFFFFFF: "KEY_SPEC_THREAD_KEYRING",
            0xFFFFFFFFFFFFFFFE: "KEY_SPEC_PROCESS_KEYRING",
            0xFFFFFFFFFFFFFFFD: "KEY_SPEC_SESSION_KEYRING",
            0xFFFFFFFFFFFFFFFC: "KEY_SPEC_USER_KEYRING",
            0xFFFFFFFFFFFFFFFB: "KEY_SPEC_USER_SESSION_KEYRING",
            0xFFFFFFFFFFFFFFFA: "KEY_SPEC_GROUP_KEYRING",
            0xFFFFFFFFFFFFFF9F: "KEY_SPEC_REQKEY_AUTH_KEY",
            0xFFFFFFFFFFFFFF9E: "KEY_SPEC_REQUESTOR_KEYRING",
            "parsing_mode": "sequential",
        },
    },
    #keyctl
    288:{
        #int option
        0: {
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
        },
    },
    #ioprio_set
    289:{
        #int which
        0: {
            1: "IOPRIO_WHO_PROCESS",
            2: "IOPRIO_WHO_PGRP",
            3: "IOPRIO_WHO_USER",
            "parsing_mode": "sequential",
        },
    },
    #ioprio_get
    290:{
        #int which
        0: {
            1: "IOPRIO_WHO_PROCESS",
            2: "IOPRIO_WHO_PGRP",
            3: "IOPRIO_WHO_USER",
            "parsing_mode": "sequential",
        },
    },
    #openat
    295:{
        #int dfd
        0: OPENAT_DFD,
        #int flags
        2: OPEN_FLAGS,
        #umode_t mode
        3: OPEN_MODES,
    },
    #mkdirat
    296:{
        #int dfd
        0: OPENAT_DFD,
        #umode_t mode
        2: OPEN_MODES,
    },
    #mknodat
    297:{
        #int dfd
        0: OPENAT_DFD,
        #umode_t mode
        2: {
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
        },
    },
    #fchownat
    298:{
        #int dfd
        0: OPENAT_DFD,
        #int flag
        4: {
            0x1000: "AT_EMPTY_PATH",
            0x100: "AT_SYMLINK_NOFOLLOW",
        },
    },
    #futimesat
    299:{
        #unsigned int dfd
        0: OPENAT_DFD,
    },
    #fstatat64
    300:{
        #int dfd
        0: OPENAT_DFD,
        #int flag
        3: {
            0x1000: "AT_EMPTY_PATH",
            0x100: "AT_SYMLINK_NOFOLLOW",
            0x800: "AT_NO_AUTOMOUNT",
        },
    },
    #unlinkat
    301:{
        #int dfd
        0: OPENAT_DFD,
        #int flag
        2: {
            0x200: "AT_REMOVEDIR",
        },
    },
    #renameat
    302:{
        #int olddfd
        0: OPENAT_DFD,
    },
    #linkat
    303:{
        #int olddfd
        0: OPENAT_DFD,
        #int newdfd
        2: OPENAT_DFD,
        #int flags
        4: {
            0x1000: "AT_EMPTY_PATH",
            0x400: "AT_SYMLINK_FOLLOW",
        },
    },
    #symlinkat
    304:{
        #int newdfd
        1: OPENAT_DFD,
    },
    #readlinkat
    305:{
        #int dfd
        0: OPENAT_DFD,
    },
    #fchmodat
    306:{
        #int dfd
        0: OPENAT_DFD,
        #umode_t mode
        2: OPEN_MODES,
    },
    #faccessat
    307:{
        #int dfd
        0: OPENAT_DFD,
        #int mode
        2: OPEN_MODES,
    },
    #unshare
    310:{
        #unsigned long unshare_flags
        0: {
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
        },
    },
    #splice
    313:{
        #unsigned int flags
        5: SPLICE_FLAGS,
    },
    #sync_file_range
    314:{
        #int flags
        5: {
            1: "SYNC_FILE_RANGE_WAIT_BEFORE",
            2: "SYNC_FILE_RANGE_WRITE",
            4: "SYNC_FILE_RANGE_WAIT_AFTER",
        },
    },
    #tee
    315:{
        #unsigned int flags
        3: SPLICE_FLAGS,
    },
    #vmsplice
    316:{
        #unsigned int flags
        3: SPLICE_FLAGS,
    },
    #move_pages
    317:{
        #int flags
        5: {
            0b10: "MPOL_MF_MOVE",
            0b100: "MPOL_MF_MOVE_ALL",
        },
    },
    #utimensat
    320:{
        #int flags
        3: {
            0x1000: "AT_EMPTY_PATH",
            0x100: "AT_SYMLINK_NOFOLLOW",
        },
    },
    #timerfd_create
    322:{
        #int clockid
        0: {
            0: "CLOCK_REALTIME",
            1: "CLOCK_MONOTONIC",
            7: "CLOCK_BOOTTIME",
            8: "CLOCK_REALTIME_ALARM",
            9: "CLOCK_BOOTTIME_ALARM",
            "parsing_mode": "sequential",
        },
        #int flags
        1: {
            0o02000000: "TFD_CLOEXEC",
            0o00004000: "TFD_NONBLOCK",
        },
    },
    #fallocate
    324:{
        #int mode
        1: {
            0x00: "FALLOC_FL_ALLOCATE_RANGE",
            0x01: "FALLOC_FL_KEEP_SIZE",
            0x02: "FALLOC_FL_PUNCH_HOLE",
            0x04: "FALLOC_FL_NO_HIDE_STALE",
            0x08: "FALLOC_FL_COLLAPSE_RANGE",
            0x10: "FALLOC_FL_ZERO_RANGE",
            0x20: "FALLOC_FL_INSERT_RANGE",
            0x40: "FALLOC_FL_UNSHARE_RANGE",
        },
    },
    #timerfd_settime
    325:{
        #int flags
        1: {
            0x00000001: "TFD_TIMER_ABSTIME",
            0x00000002: "TFD_TIMER_CANCEL_ON_SET",
        },
    },
    #signalfd4
    327:{
        #int flags
        3: {
            0o02000000: "SFD_CLOEXEC",
            0o00004000: "SFD_NONBLOCK",
        },
    },
    #eventfd2
    328:{
        #int flags
        1: {
            0o00000001: "EFD_SEMAPHORE",
            0o02000000: "EFD_CLOEXEC",
            0o00004000: "EFD_NONBLOCK",
        },
    },
    #epoll_create1
    329:{
        #int flags
        0: {
            0o02000000: "EPOLL_CLOEXEC",
        },
    },
    #dup3
    330:{
        #int flags
        2: {
            0o02000000: "O_CLOEXEC",
        },
    },
    #pipe2
    331:{
        #int flags
        1: {
            0o02000000: "O_CLOEXEC",
            0o00004000: "O_NONBLOCK",
            0o00040000: "O_DIRECT",
            0o00000200: "O_EXCL",
        },
    },
    #inotify_init1
    332:{
        #int flags
        0: {
            0o02000000: "IN_CLOEXEC",
            0o00004000: "IN_NONBLOCK",
        },
    },
    #rt_tgsigqueueinfo
    335:{
        #int sig
        2: SIGNALS,
    },
    #perf_event_open
    336:{
        #unsigned long flags
        4: {
            0b0001: "PERF_FLAG_FD_NO_GROUP",
            0b0010: "PERF_FLAG_FD_OUTPUT",
            0b0100: "PERF_FLAG_PID_CGROUP",
            0b1000: "PERF_FLAG_FD_CLOEXEC",
        },
    },
    #recvmmsg
    337:{
        #unsigned int flags
        3: {
            0x40000000: "MSG_CMSG_CLOEXEC",
            0x00000040: "MSG_DONTWAIT",
            0x00002000: "MSG_ERRQUEUE",
            0x00000001: "MSG_OOB",
            0x00000002: "MSG_PEEK",
            0x00000020: "MSG_TRUNC",
            0x00000100: "MSG_WAITALL",
        },
    },
    #fanotify_init
    338:{
        #unsigned int flags
        0: {
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
        },
        #unsigned int event_f_flags
        1: OPEN_FLAGS,
    },
    #fanotify_mark
    339:{
        #unsigned int flags
        1: {
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
        },
        #u32 mask_lo
        2: {
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
        },
        #int dfd
        4: OPENAT_DFD,
    },
    #prlimit64
    340:{
        #unsigned int resource
        1: {
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
            16: "RLIM_NLIMITS",
            0xFFFFFFFF: "RLIM_INFINITY",
            "parsing_mode": "sequential",
        },
    },
    #name_to_handle_at
    341:{
        #int dfd
        0: OPENAT_DFD,
        #int flag
        4: {
            0x200: "AT_HANDLE_FID",
            0x1000: "AT_EMPTY_PATH",
            0x400: "AT_SYMLINK_FOLLOW",
        },
    },
    #open_by_handle_at
    342:{
        #int mountdirfd
        0: OPENAT_DFD,
        #int flags
        2: OPEN_FLAGS,
    },
    #clock_adjtime
    343:{
        #clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #sendmmsg
    345:{
        #unsigned int flags
        3: {
            0x00000800: "MSG_CONFIRM",
            0x00000004: "MSG_DONTROUTE",
            0x00000040: "MSG_DONTWAIT",
            0x00000080: "MSG_EOR",
            0x00008000: "MSG_MORE",
            0x00004000: "MSG_NOSIGNAL",
            0x00000001: "MSG_OOB",
            0x20000000: "MSG_FASTOPEN",
        },
    },
    #setns
    346:{
        #int flags
        1: {
            0x02000000: "CLONE_NEWCGROUP",
            0x04000000: "CLONE_NEWUTS",
            0x08000000: "CLONE_NEWIPC",
            0x40000000: "CLONE_NEWNET",
            0x00000080: "CLONE_NEWTIME",
            0x00020000: "CLONE_NEWNS",
            0x20000000: "CLONE_NEWPID",
            0x10000000: "CLONE_NEWUSER",
        },
    },
    #kcmp
    349:{
        #int type
        2: {
            0: "KCMP_FILE",
            1: "KCMP_VM",
            2: "KCMP_FILES",
            3: "KCMP_FS",
            4: "KCMP_SIGHAND",
            5: "KCMP_IO",
            6: "KCMP_SYSVSEM",
            7: "KCMP_EPOLL_TFD",
            "parsing_mode": "sequential",
        },
    },
    #finit_module
    350:{
        #int flags
        2: {
            1: "MODULE_INIT_IGNORE_MODVERSIONS",
            2: "MODULE_INIT_IGNORE_VERMAGIC",
            4: "MODULE_INIT_COMPRESSED_FILE",
        },
    },
    #renameat2
    353:{
        # int olddfd
        0: OPENAT_DFD,
        #unsigned int flags
        4: {
            0b001: "RENAME_NOREPLACE",
            0b010: "RENAME_EXCHANGE",
            0b100: "RENAME_WHITEOUT",
        },
    },
    #seccomp
    354:{
        # unsigned int op
        0: {
            0: "SECCOMP_SET_MODE_STRICT",
            1: "SECCOMP_SET_MODE_FILTER",
            2: "SECCOMP_GET_ACTION_AVAIL",
            3: "SECCOMP_GET_NOTIF_SIZES",
        },
        # unsigned int flags
        1: {
            0b000001: "SECCOMP_FILTER_FLAG_TSYNC",
            0b000010: "SECCOMP_FILTER_FLAG_LOG",
            0b000100: "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
            0b001000: "SECCOMP_FILTER_FLAG_NEW_LISTENER",
            0b010000: "SECCOMP_FILTER_FLAG_TSYNC_ESRCH",
            0b100000: "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV",
        },
    },
    #getrandom
    355:{
        #unsigned int flags
        2: {
            0x0001: "GRND_NONBLOCK",
            0x0002: "GRND_RANDOM",
            0x0004: "GRND_INSECURE",
        },
    },
    #memfd_create
    356:{
        #unsigned int flags
        1: {
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
        },
    },
    #bpf
    357:{
        #int cmd
        0: {
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
        },
    },
    #execveat
    358:{
        #int fd
        0: OPENAT_DFD,
        #int flags
        4: {
            0x1000: "AT_EMPTY_PATH",
            0x100: "AT_SYMLINK_NOFOLLOW",
        },
    },
    #socket
    359:{
        #int family
        0: {},
        #int type
        1: {},
        #int protocol
        2: {},
    },
    #socketpair
    360:{
        #int family
        0: {},
        #int type
        1: {},
        #int protocol
        2: {},
        #int *usockvec
        3: {},
    },
    #bind
    361:{
        #int fd
        0: {},
        #struct sockaddr *umyaddr
        1: {},
        #int addrlen
        2: {},
    },
    #connect
    362:{
        #int fd
        0: {},
        #struct sockaddr *uservaddr
        1: {},
        #int addrlen
        2: {},
    },
    #listen
    363:{
        #int fd
        0: {},
        #int backlog
        1: {},
    },
    #accept4
    364:{
        #int fd
        0: {},
        #struct sockaddr *upeer_sockaddr
        1: {},
        #int *upeer_addrlen
        2: {},
        #int flags
        3: {},
    },
    #getsockopt
    365:{
        #int fd
        0: {},
        #int level
        1: {},
        #int optname
        2: {},
        #char *optval
        3: {},
        #int *optlen
        4: {},
    },
    #setsockopt
    366:{
        #int fd
        0: {},
        #int level
        1: {},
        #int optname
        2: {},
        #char *optval
        3: {},
        #int optlen
        4: {},
    },
    #getsockname
    367:{
        #int fd
        0: {},
        #struct sockaddr *usockaddr
        1: {},
        #int *usockaddr_len
        2: {},
    },
    #getpeername
    368:{
        #int fd
        0: {},
        #struct sockaddr *usockaddr
        1: {},
        #int *usockaddr_len
        2: {},
    },
    #sendto
    369:{
        #int fd
        0: {},
        #void *buff
        1: {},
        #size_t len
        2: {},
        #unsigned int flags
        3: {},
        #struct sockaddr *addr
        4: {},
        #int addr_len
        5: {},
    },
    #sendmsg
    370:{
        #int fd
        0: {},
        #struct user_msghdr *msg
        1: {},
        #unsigned int flags
        2: {},
    },
    #recvfrom
    371:{
        #int fd
        0: {},
        #void *ubuf
        1: {},
        #size_t size
        2: {},
        #unsigned int flags
        3: {},
        #struct sockaddr *addr
        4: {},
        #int *addr_len
        5: {},
    },
    #recvmsg
    372:{
        #int fd
        0: {},
        #struct user_msghdr *msg
        1: {},
        #unsigned int flags
        2: {},
    },
    #shutdown
    373:{
        #int fd
        0: {},
        #int how
        1: {},
    },
    #userfaultfd
    374:{
        #int flags
        0: {},
    },
    #membarrier
    375:{
        #int cmd
        0: {},
        #unsigned int flags
        1: {},
        #int cpu_id
        2: {},
    },
    #mlock2
    376:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
        #int flags
        2: {},
    },
    #copy_file_range
    377:{
        #int fd_in
        0: {},
        #loff_t *off_in
        1: {},
        #int fd_out
        2: {},
        #loff_t *off_out
        3: {},
        #size_t len
        4: {},
        #unsigned int flags
        5: {},
    },
    #preadv2
    378:{
        #unsigned long fd
        0: {},
        #const struct iovec *vec
        1: {},
        #unsigned long vlen
        2: {},
        #unsigned long pos_l
        3: {},
        #unsigned long pos_h
        4: {},
        #rwf_t flags
        5: {},
    },
    #pwritev2
    379:{
        #unsigned long fd
        0: {},
        #const struct iovec *vec
        1: {},
        #unsigned long vlen
        2: {},
        #unsigned long pos_l
        3: {},
        #unsigned long pos_h
        4: {},
        #rwf_t flags
        5: {},
    },
    #statx
    383:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #unsigned flags
        2: {},
        #unsigned int mask
        3: {},
        #struct statx *buffer
        4: {},
    },
    #arch_prctl
    384:{
        #int option
        0: {
            0x1011: "ARCH_GET_CPUID",
            0x1012: "ARCH_SET_CPUID",
            "parsing_mode": "sequential",
        },
    },
    #io_pgetevents
    385:{
        #aio_context_t ctx_id
        0: {},
        #long min_nr
        1: {},
        #long nr
        2: {},
        #struct io_event *events
        3: {},
        #struct old_timespec32 *timeout
        4: {},
        #const struct __aio_sigset *usig
        5: {},
    },
    #rseq
    386:{
        #struct rseq *rseq
        0: {},
        #u32 rseq_len
        1: {},
        #int flags
        2: {},
        #u32 sig
        3: {},
    },
    #semget
    393:{
        #key_t key
        0: {},
        #int nsems
        1: {},
        #int semflg
        2: {},
    },
    #semctl
    394:{
        #int semid
        0: {},
        #int semnum
        1: {},
        #int cmd
        2: {},
        #unsigned long arg
        3: {},
    },
    #shmget
    395:{
        #key_t key
        0: {},
        #size_t size
        1: {},
        #int shmflg
        2: {},
    },
    #shmctl
    396:{
        #int shmid
        0: {},
        #int cmd
        1: {},
        #struct shmid_ds *buf
        2: {},
    },
    #shmat
    397:{
        #int shmid
        0: {},
        #char *shmaddr
        1: {},
        #int shmflg
        2: {},
    },
    #shmdt
    398:{
        #char *shmaddr
        0: {},
    },
    #msgget
    399:{
        #key_t key
        0: {},
        #int msgflg
        1: {},
    },
    #msgsnd
    400:{
        #int msqid
        0: {},
        #struct msgbuf *msgp
        1: {},
        #size_t msgsz
        2: {},
        #int msgflg
        3: {},
    },
    #msgrcv
    401:{
        #int msqid
        0: {},
        #struct msgbuf *msgp
        1: {},
        #size_t msgsz
        2: {},
        #long msgtyp
        3: {},
        #int msgflg
        4: {},
    },
    #msgctl
    402:{
        #int msqid
        0: {},
        #int cmd
        1: {},
        #struct msqid_ds *buf
        2: {},
    },
    #clock_gettime
    403:{
        #const clockid_t which_clock
        0: {},
        #struct __kernel_timespec *tp
        1: {},
    },
    #clock_settime
    404:{
        #const clockid_t which_clock
        0: {},
        #const struct __kernel_timespec *tp
        1: {},
    },
    #clock_adjtime
    405:{
        #const clockid_t which_clock
        0: {},
        #struct __kernel_timex *utx
        1: {},
    },
    #clock_getres
    406:{
        #const clockid_t which_clock
        0: {},
        #struct __kernel_timespec *tp
        1: {},
    },
    #clock_nanosleep
    407:{
        #const clockid_t which_clock
        0: {},
        #int flags
        1: {},
        #const struct __kernel_timespec *rqtp
        2: {},
        #struct __kernel_timespec *rmtp
        3: {},
    },
    #timer_gettime
    408:{
        #timer_t timer_id
        0: {},
        #struct __kernel_itimerspec *setting
        1: {},
    },
    #timer_settime
    409:{
        #timer_t timer_id
        0: {},
        #int flags
        1: {},
        #const struct __kernel_itimerspec *new_setting
        2: {},
        #struct __kernel_itimerspec *old_setting
        3: {},
    },
    #timerfd_gettime
    410:{
        #int ufd
        0: {},
        #struct __kernel_itimerspec *otmr
        1: {},
    },
    #timerfd_settime
    411:{
        #int ufd
        0: {},
        #int flags
        1: {},
        #const struct __kernel_itimerspec *utmr
        2: {},
        #struct __kernel_itimerspec *otmr
        3: {},
    },
    #utimensat
    412:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #struct __kernel_timespec *utimes
        2: {},
        #int flags
        3: {},
    },
    #pselect6
    413:{
        #int n
        0: {},
        #fd_set *inp
        1: {},
        #fd_set *outp
        2: {},
        #fd_set *exp
        3: {},
        #struct __kernel_timespec *tsp
        4: {},
        #void *sig
        5: {},
    },
    #ppoll
    414:{
        #struct pollfd *ufds
        0: {},
        #unsigned int nfds
        1: {},
        #struct __kernel_timespec *tsp
        2: {},
        #const sigset_t *sigmask
        3: {},
        #size_t sigsetsize
        4: {},
    },
    #io_pgetevents
    416:{
        #aio_context_t ctx_id
        0: {},
        #long min_nr
        1: {},
        #long nr
        2: {},
        #struct io_event *events
        3: {},
        #struct __kernel_timespec *timeout
        4: {},
        #const struct __aio_sigset *usig
        5: {},
    },
    #recvmmsg
    417:{
        #int fd
        0: {},
        #struct mmsghdr *mmsg
        1: {},
        #unsigned int vlen
        2: {},
        #unsigned int flags
        3: {},
        #struct __kernel_timespec *timeout
        4: {},
    },
    #mq_timedsend
    418:{
        #mqd_t mqdes
        0: {},
        #const char *u_msg_ptr
        1: {},
        #size_t msg_len
        2: {},
        #unsigned int msg_prio
        3: {},
        #const struct __kernel_timespec *u_abs_timeout
        4: {},
    },
    #mq_timedreceive
    419:{
        #mqd_t mqdes
        0: {},
        #char *u_msg_ptr
        1: {},
        #size_t msg_len
        2: {},
        #unsigned int *u_msg_prio
        3: {},
        #const struct __kernel_timespec *u_abs_timeout
        4: {},
    },
    #semtimedop
    420:{
        #int semid
        0: {},
        #struct sembuf *tsops
        1: {},
        #unsigned int nsops
        2: {},
        #const struct __kernel_timespec *timeout
        3: {},
    },
    #rt_sigtimedwait
    421:{
        #const sigset_t *uthese
        0: {},
        #siginfo_t *uinfo
        1: {},
        #const struct __kernel_timespec *uts
        2: {},
        #size_t sigsetsize
        3: {},
    },
    #futex
    422:{
        #u32 *uaddr
        0: {},
        #int op
        1: {},
        #u32 val
        2: {},
        #const struct __kernel_timespec *utime
        3: {},
        #u32 *uaddr2
        4: {},
        #u32 val3
        5: {},
    },
    #sched_rr_get_interval
    423:{
        #pid_t pid
        0: {},
        #struct __kernel_timespec *interval
        1: {},
    },
    #pidfd_send_signal
    424:{
        #int pidfd
        0: {},
        #int sig
        1: {},
        #siginfo_t *info
        2: {},
        #unsigned int flags
        3: {},
    },
    #io_uring_setup
    425:{
        #u32 entries
        0: {},
        #struct io_uring_params *params
        1: {},
    },
    #io_uring_enter
    426:{
        #unsigned int fd
        0: {},
        #u32 to_submit
        1: {},
        #u32 min_complete
        2: {},
        #u32 flags
        3: {},
        #const void *argp
        4: {},
        #size_t argsz
        5: {},
    },
    #io_uring_register
    427:{
        #unsigned int fd
        0: {},
        #unsigned int opcode
        1: {},
        #void *arg
        2: {},
        #unsigned int nr_args
        3: {},
    },
    #open_tree
    428:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #unsigned flags
        2: {},
    },
    #move_mount
    429:{
        #int from_dfd
        0: {},
        #const char *from_pathname
        1: {},
        #int to_dfd
        2: {},
        #const char *to_pathname
        3: {},
        #unsigned int flags
        4: {},
    },
    #fsopen
    430:{
        #const char *_fs_name
        0: {},
        #unsigned int flags
        1: {},
    },
    #fsconfig
    431:{
        #int fd
        0: {},
        #unsigned int cmd
        1: {},
        #const char *_key
        2: {},
        #const void *_value
        3: {},
        #int aux
        4: {},
    },
    #fsmount
    432:{
        #int fs_fd
        0: {},
        #unsigned int flags
        1: {},
        #unsigned int attr_flags
        2: {},
    },
    #fspick
    433:{
        #int dfd
        0: {},
        #const char *path
        1: {},
        #unsigned int flags
        2: {},
    },
    #pidfd_open
    434:{
        #pid_t pid
        0: {},
        #unsigned int flags
        1: {},
    },
    #clone3
    435:{
        #struct clone_args *uargs
        0: {},
        #size_t size
        1: {},
    },
    #close_range
    436:{
        #unsigned int fd
        0: {},
        #unsigned int max_fd
        1: {},
        #unsigned int flags
        2: {},
    },
    #openat2
    437:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #struct open_how *how
        2: {},
        #size_t usize
        3: {},
    },
    #pidfd_getfd
    438:{
        #int pidfd
        0: {},
        #int fd
        1: {},
        #unsigned int flags
        2: {},
    },
    #faccessat2
    439:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #int mode
        2: {},
        #int flags
        3: {},
    },
    #process_madvise
    440:{
        #int pidfd
        0: {},
        #const struct iovec *vec
        1: {},
        #size_t vlen
        2: {},
        #int behavior
        3: {},
        #unsigned int flags
        4: {},
    },
    #epoll_pwait2
    441:{
        #int epfd
        0: {},
        #struct epoll_event *events
        1: {},
        #int maxevents
        2: {},
        #const struct __kernel_timespec *timeout
        3: {},
        #const sigset_t *sigmask
        4: {},
        #size_t sigsetsize
        5: {},
    },
    #mount_setattr
    442:{
        #int dfd
        0: {},
        #const char *path
        1: {},
        #unsigned int flags
        2: {},
        #struct mount_attr *uattr
        3: {},
        #size_t usize
        4: {},
    },
    #quotactl_fd
    443:{
        #unsigned int fd
        0: {},
        #unsigned int cmd
        1: {},
        #qid_t id
        2: {},
        #void *addr
        3: {},
    },
    #landlock_create_ruleset
    444:{
        #const struct landlock_ruleset_attr *const attr
        0: {},
        #const size_t size
        1: {},
        #const __u32 flags
        2: {},
    },
    #landlock_add_rule
    445:{
        #const int ruleset_fd
        0: {},
        #const enum landlock_rule_type rule_type
        1: {},
        #const void *const rule_attr
        2: {},
        #const __u32 flags
        3: {},
    },
    #landlock_restrict_self
    446:{
        #const int ruleset_fd
        0: {},
        #const __u32 flags
        1: {},
    },
    #memfd_secret
    447:{
        #unsigned int flags
        0: {},
    },
    #process_mrelease
    448:{
        #int pidfd
        0: {},
        #unsigned int flags
        1: {},
    },
    #futex_waitv
    449:{
        #struct futex_waitv *waiters
        0: {},
        #unsigned int nr_futexes
        1: {},
        #unsigned int flags
        2: {},
        #struct __kernel_timespec *timeout
        3: {},
        #clockid_t clockid
        4: {},
    },
    #set_mempolicy_home_node
    450:{
        #unsigned long start
        0: {},
        #unsigned long len
        1: {},
        #unsigned long home_node
        2: {},
        #unsigned long flags
        3: {},
    },
    #cachestat
    451:{
        #unsigned int fd
        0: {},
        #struct cachestat_range *cstat_range
        1: {},
        #struct cachestat *cstat
        2: {},
        #unsigned int flags
        3: {},
    },
    #fchmodat2
    452:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #umode_t mode
        2: {},
        #unsigned int flags
        3: {},
    },
    #futex_wake
    454:{
        #void *uaddr
        0: {},
        #unsigned long mask
        1: {},
        #int nr
        2: {},
        #unsigned int flags
        3: {},
    },
    #futex_wait
    455:{
        #void *uaddr
        0: {},
        #unsigned long val
        1: {},
        #unsigned long mask
        2: {},
        #unsigned int flags
        3: {},
        #struct __kernel_timespec *timeout
        4: {},
        #clockid_t clockid
        5: {},
    },
    #futex_requeue
    456:{
        #struct futex_waitv *waiters
        0: {},
        #unsigned int flags
        1: {},
        #int nr_wake
        2: {},
        #int nr_requeue
        3: {},
    },
    #statmount
    457:{
        #const struct mnt_id_req *req
        0: {},
        #struct statmount *buf
        1: {},
        #size_t bufsize
        2: {},
        #unsigned int flags
        3: {},
    },
    #listmount
    458:{
        #const struct mnt_id_req *req
        0: {},
        #u64 *mnt_ids
        1: {},
        #size_t nr_mnt_ids
        2: {},
        #unsigned int flags
        3: {},
    },
    #lsm_get_self_attr
    459:{
        #unsigned int attr
        0: {},
        #struct lsm_ctx *ctx
        1: {},
        #u32 *size
        2: {},
        #u32 flags
        3: {},
    },
    #lsm_set_self_attr
    460:{
        #unsigned int attr
        0: {},
        #struct lsm_ctx *ctx
        1: {},
        #u32 size
        2: {},
        #u32 flags
        3: {},
    },
    #lsm_list_modules
    461:{
        #u64 *ids
        0: {},
        #u32 *size
        1: {},
        #u32 flags
        2: {},
    },
    #setxattrat
    463:{
        #int dfd
        0: {},
        #const char *pathname
        1: {},
        #unsigned int at_flags
        2: {},
        #const char *name
        3: {},
        #const struct xattr_args *uargs
        4: {},
        #size_t usize
        5: {},
    },
    #getxattrat
    464:{
        #int dfd
        0: {},
        #const char *pathname
        1: {},
        #unsigned int at_flags
        2: {},
        #const char *name
        3: {},
        #struct xattr_args *uargs
        4: {},
        #size_t usize
        5: {},
    },
    #listxattrat
    465:{
        #int dfd
        0: {},
        #const char *pathname
        1: {},
        #unsigned int at_flags
        2: {},
        #char *list
        3: {},
        #size_t size
        4: {},
    },
    #removexattrat
    466:{
        #int dfd
        0: {},
        #const char *pathname
        1: {},
        #unsigned int at_flags
        2: {},
        #const char *name
        3: {},
    },
}
