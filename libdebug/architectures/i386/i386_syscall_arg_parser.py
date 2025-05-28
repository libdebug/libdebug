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
        #pid_t upid
        0: {},
        #int *stat_addr
        1: {},
        #int options
        2: {},
        #struct rusage *ru
        3: {},
    },
    #ipc
    117:{
        #unsigned int call
        0: {},
        #int first
        1: {},
        #unsigned long second
        2: {},
        #unsigned long third
        3: {},
        #void *ptr
        4: {},
        #long fifth
        5: {},
    },
    #fsync
    118:{
        #unsigned int fd
        0: {},
    },
    #sigreturn
    119:{
    },
    #clone
    120:{
        #unsigned long clone_flags
        0: {},
        #unsigned long newsp
        1: {},
        #int *parent_tidptr
        2: {},
        #unsigned long tls
        3: {},
        #int *child_tidptr
        4: {},
    },
    #setdomainname
    121:{
        #char *name
        0: {},
        #int len
        1: {},
    },
    #newuname
    122:{
        #struct new_utsname *name
        0: {},
    },
    #modify_ldt
    123:{
        #int func
        0: {},
        #void *ptr
        1: {},
        #unsigned long bytecount
        2: {},
    },
    #adjtimex
    124:{
        #struct old_timex32 *utp
        0: {},
    },
    #mprotect
    125:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
        #unsigned long prot
        2: {},
    },
    #sigprocmask
    126:{
        #int how
        0: {},
        #old_sigset_t *nset
        1: {},
        #old_sigset_t *oset
        2: {},
    },
    #init_module
    128:{
        #void *umod
        0: {},
        #unsigned long len
        1: {},
        #const char *uargs
        2: {},
    },
    #delete_module
    129:{
        #const char *name_user
        0: {},
        #unsigned int flags
        1: {},
    },
    #quotactl
    131:{
        #unsigned int cmd
        0: {},
        #const char *special
        1: {},
        #qid_t id
        2: {},
        #void *addr
        3: {},
    },
    #getpgid
    132:{
        #pid_t pid
        0: {},
    },
    #fchdir
    133:{
        #unsigned int fd
        0: {},
    },
    #sysfs
    135:{
        #int option
        0: {},
        #unsigned long arg1
        1: {},
        #unsigned long arg2
        2: {},
    },
    #personality
    136:{
        #unsigned int personality
        0: {},
    },
    #setfsuid16
    138:{
        #old_uid_t uid
        0: {},
    },
    #setfsgid16
    139:{
        #old_gid_t gid
        0: {},
    },
    #llseek
    140:{
        #unsigned int fd
        0: {},
        #unsigned long offset_high
        1: {},
        #unsigned long offset_low
        2: {},
        #loff_t *result
        3: {},
        #unsigned int whence
        4: {},
    },
    #getdents
    141:{
        #unsigned int fd
        0: {},
        #struct linux_dirent *dirent
        1: {},
        #unsigned int count
        2: {},
    },
    #select
    142:{
        #int n
        0: {},
        #fd_set *inp
        1: {},
        #fd_set *outp
        2: {},
        #fd_set *exp
        3: {},
        #struct __kernel_old_timeval *tvp
        4: {},
    },
    #flock
    143:{
        #unsigned int fd
        0: {},
        #unsigned int cmd
        1: {},
    },
    #msync
    144:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
        #int flags
        2: {},
    },
    #readv
    145:{
        #unsigned long fd
        0: {},
        #const struct iovec *vec
        1: {},
        #unsigned long vlen
        2: {},
    },
    #writev
    146:{
        #unsigned long fd
        0: {},
        #const struct iovec *vec
        1: {},
        #unsigned long vlen
        2: {},
    },
    #getsid
    147:{
        #pid_t pid
        0: {},
    },
    #fdatasync
    148:{
        #unsigned int fd
        0: {},
    },
    #mlock
    150:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
    },
    #munlock
    151:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
    },
    #mlockall
    152:{
        #int flags
        0: {},
    },
    #munlockall
    153:{
    },
    #sched_setparam
    154:{
        #pid_t pid
        0: {},
        #struct sched_param *param
        1: {},
    },
    #sched_getparam
    155:{
        #pid_t pid
        0: {},
        #struct sched_param *param
        1: {},
    },
    #sched_setscheduler
    156:{
        #pid_t pid
        0: {},
        #int policy
        1: {},
        #struct sched_param *param
        2: {},
    },
    #sched_getscheduler
    157:{
        #pid_t pid
        0: {},
    },
    #sched_yield
    158:{
    },
    #sched_get_priority_max
    159:{
        #int policy
        0: {},
    },
    #sched_get_priority_min
    160:{
        #int policy
        0: {},
    },
    #sched_rr_get_interval
    161:{
        #pid_t pid
        0: {},
        #struct old_timespec32 *interval
        1: {},
    },
    #nanosleep
    162:{
        #struct old_timespec32 *rqtp
        0: {},
        #struct old_timespec32 *rmtp
        1: {},
    },
    #mremap
    163:{
        #unsigned long addr
        0: {},
        #unsigned long old_len
        1: {},
        #unsigned long new_len
        2: {},
        #unsigned long flags
        3: {},
        #unsigned long new_addr
        4: {},
    },
    #setresuid16
    164:{
        #old_uid_t ruid
        0: {},
        #old_uid_t euid
        1: {},
        #old_uid_t suid
        2: {},
    },
    #getresuid16
    165:{
        #old_uid_t *ruidp
        0: {},
        #old_uid_t *euidp
        1: {},
        #old_uid_t *suidp
        2: {},
    },
    #vm86
    166:{
        #unsigned long cmd
        0: {},
        #unsigned long arg
        1: {},
    },
    #poll
    168:{
        #struct pollfd *ufds
        0: {},
        #unsigned int nfds
        1: {},
        #int timeout_msecs
        2: {},
    },
    #setresgid16
    170:{
        #old_gid_t rgid
        0: {},
        #old_gid_t egid
        1: {},
        #old_gid_t sgid
        2: {},
    },
    #getresgid16
    171:{
        #old_gid_t *rgidp
        0: {},
        #old_gid_t *egidp
        1: {},
        #old_gid_t *sgidp
        2: {},
    },
    #prctl
    172:{
        #int option
        0: {},
        #unsigned long arg2
        1: {},
        #unsigned long arg3
        2: {},
        #unsigned long arg4
        3: {},
        #unsigned long arg5
        4: {},
    },
    #rt_sigreturn
    173:{
    },
    #rt_sigaction
    174:{
        #int sig
        0: {},
        #const struct sigaction *act
        1: {},
        #struct sigaction *oact
        2: {},
        #size_t sigsetsize
        3: {},
    },
    #rt_sigprocmask
    175:{
        #int how
        0: {},
        #sigset_t *nset
        1: {},
        #sigset_t *oset
        2: {},
        #size_t sigsetsize
        3: {},
    },
    #rt_sigpending
    176:{
        #sigset_t *uset
        0: {},
        #size_t sigsetsize
        1: {},
    },
    #rt_sigtimedwait
    177:{
        #const sigset_t *uthese
        0: {},
        #siginfo_t *uinfo
        1: {},
        #const struct old_timespec32 *uts
        2: {},
        #size_t sigsetsize
        3: {},
    },
    #rt_sigqueueinfo
    178:{
        #pid_t pid
        0: {},
        #int sig
        1: {},
        #siginfo_t *uinfo
        2: {},
    },
    #rt_sigsuspend
    179:{
        #sigset_t *unewset
        0: {},
        #size_t sigsetsize
        1: {},
    },
    #pread64
    180:{
        #unsigned int fd
        0: {},
        #char *ubuf
        1: {},
        #u32 count
        2: {},
        #u32 poslo
        3: {},
        #u32 poshi
        4: {},
    },
    #pwrite64
    181:{
        #unsigned int fd
        0: {},
        #const char *ubuf
        1: {},
        #u32 count
        2: {},
        #u32 poslo
        3: {},
        #u32 poshi
        4: {},
    },
    #chown16
    182:{
        #const char *filename
        0: {},
        #old_uid_t user
        1: {},
        #old_gid_t group
        2: {},
    },
    #getcwd
    183:{
        #char *buf
        0: {},
        #unsigned long size
        1: {},
    },
    #capget
    184:{
        #cap_user_header_t header
        0: {},
        #cap_user_data_t dataptr
        1: {},
    },
    #capset
    185:{
        #cap_user_header_t header
        0: {},
        #const cap_user_data_t data
        1: {},
    },
    #sigaltstack
    186:{
        #const stack_t *uss
        0: {},
        #stack_t *uoss
        1: {},
    },
    #sendfile
    187:{
        #int out_fd
        0: {},
        #int in_fd
        1: {},
        #off_t *offset
        2: {},
        #size_t count
        3: {},
    },
    #vfork
    190:{
    },
    #getrlimit
    191:{
        #unsigned int resource
        0: {},
        #struct rlimit *rlim
        1: {},
    },
    #mmap_pgoff
    192:{
        #unsigned long addr
        0: {},
        #unsigned long len
        1: {},
        #unsigned long prot
        2: {},
        #unsigned long flags
        3: {},
        #unsigned long fd
        4: {},
        #unsigned long pgoff
        5: {},
    },
    #truncate64
    193:{
        #const char *filename
        0: {},
        #unsigned long offset_low
        1: {},
        #unsigned long offset_high
        2: {},
    },
    #ftruncate64
    194:{
        #unsigned int fd
        0: {},
        #unsigned long offset_low
        1: {},
        #unsigned long offset_high
        2: {},
    },
    #stat64
    195:{
        #const char *filename
        0: {},
        #struct stat64 *statbuf
        1: {},
    },
    #lstat64
    196:{
        #const char *filename
        0: {},
        #struct stat64 *statbuf
        1: {},
    },
    #fstat64
    197:{
        #unsigned long fd
        0: {},
        #struct stat64 *statbuf
        1: {},
    },
    #lchown
    198:{
        #const char *filename
        0: {},
        #uid_t user
        1: {},
        #gid_t group
        2: {},
    },
    #getuid
    199:{
    },
    #getgid
    200:{
    },
    #geteuid
    201:{
    },
    #getegid
    202:{
    },
    #setreuid
    203:{
        #uid_t ruid
        0: {},
        #uid_t euid
        1: {},
    },
    #setregid
    204:{
        #gid_t rgid
        0: {},
        #gid_t egid
        1: {},
    },
    #getgroups
    205:{
        #int gidsetsize
        0: {},
        #gid_t *grouplist
        1: {},
    },
    #setgroups
    206:{
        #int gidsetsize
        0: {},
        #gid_t *grouplist
        1: {},
    },
    #fchown
    207:{
        #unsigned int fd
        0: {},
        #uid_t user
        1: {},
        #gid_t group
        2: {},
    },
    #setresuid
    208:{
        #uid_t ruid
        0: {},
        #uid_t euid
        1: {},
        #uid_t suid
        2: {},
    },
    #getresuid
    209:{
        #uid_t *ruidp
        0: {},
        #uid_t *euidp
        1: {},
        #uid_t *suidp
        2: {},
    },
    #setresgid
    210:{
        #gid_t rgid
        0: {},
        #gid_t egid
        1: {},
        #gid_t sgid
        2: {},
    },
    #getresgid
    211:{
        #gid_t *rgidp
        0: {},
        #gid_t *egidp
        1: {},
        #gid_t *sgidp
        2: {},
    },
    #chown
    212:{
        #const char *filename
        0: {},
        #uid_t user
        1: {},
        #gid_t group
        2: {},
    },
    #setuid
    213:{
        #uid_t uid
        0: {},
    },
    #setgid
    214:{
        #gid_t gid
        0: {},
    },
    #setfsuid
    215:{
        #uid_t uid
        0: {},
    },
    #setfsgid
    216:{
        #gid_t gid
        0: {},
    },
    #pivot_root
    217:{
        #const char *new_root
        0: {},
        #const char *put_old
        1: {},
    },
    #mincore
    218:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
        #unsigned char *vec
        2: {},
    },
    #madvise
    219:{
        #unsigned long start
        0: {},
        #size_t len_in
        1: {},
        #int behavior
        2: {},
    },
    #getdents64
    220:{
        #unsigned int fd
        0: {},
        #struct linux_dirent64 *dirent
        1: {},
        #unsigned int count
        2: {},
    },
    #fcntl64
    221:{
        #unsigned int fd
        0: {},
        #unsigned int cmd
        1: {},
        #unsigned long arg
        2: {},
    },
    #gettid
    224:{
    },
    #readahead
    225:{
        #int fd
        0: {},
        #unsigned int off_lo
        1: {},
        #unsigned int off_hi
        2: {},
        #size_t count
        3: {},
    },
    #setxattr
    226:{
        #const char *pathname
        0: {},
        #const char *name
        1: {},
        #const void *value
        2: {},
        #size_t size
        3: {},
        #int flags
        4: {},
    },
    #lsetxattr
    227:{
        #const char *pathname
        0: {},
        #const char *name
        1: {},
        #const void *value
        2: {},
        #size_t size
        3: {},
        #int flags
        4: {},
    },
    #fsetxattr
    228:{
        #int fd
        0: {},
        #const char *name
        1: {},
        #const void *value
        2: {},
        #size_t size
        3: {},
        #int flags
        4: {},
    },
    #getxattr
    229:{
        #const char *pathname
        0: {},
        #const char *name
        1: {},
        #void *value
        2: {},
        #size_t size
        3: {},
    },
    #lgetxattr
    230:{
        #const char *pathname
        0: {},
        #const char *name
        1: {},
        #void *value
        2: {},
        #size_t size
        3: {},
    },
    #fgetxattr
    231:{
        #int fd
        0: {},
        #const char *name
        1: {},
        #void *value
        2: {},
        #size_t size
        3: {},
    },
    #listxattr
    232:{
        #const char *pathname
        0: {},
        #char *list
        1: {},
        #size_t size
        2: {},
    },
    #llistxattr
    233:{
        #const char *pathname
        0: {},
        #char *list
        1: {},
        #size_t size
        2: {},
    },
    #flistxattr
    234:{
        #int fd
        0: {},
        #char *list
        1: {},
        #size_t size
        2: {},
    },
    #removexattr
    235:{
        #const char *pathname
        0: {},
        #const char *name
        1: {},
    },
    #lremovexattr
    236:{
        #const char *pathname
        0: {},
        #const char *name
        1: {},
    },
    #fremovexattr
    237:{
        #int fd
        0: {},
        #const char *name
        1: {},
    },
    #tkill
    238:{
        #pid_t pid
        0: {},
        #int sig
        1: {},
    },
    #sendfile64
    239:{
        #int out_fd
        0: {},
        #int in_fd
        1: {},
        #loff_t *offset
        2: {},
        #size_t count
        3: {},
    },
    #futex
    240:{
        #u32 *uaddr
        0: {},
        #int op
        1: {},
        #u32 val
        2: {},
        #const struct old_timespec32 *utime
        3: {},
        #u32 *uaddr2
        4: {},
        #u32 val3
        5: {},
    },
    #sched_setaffinity
    241:{
        #pid_t pid
        0: {},
        #unsigned int len
        1: {},
        #unsigned long *user_mask_ptr
        2: {},
    },
    #sched_getaffinity
    242:{
        #pid_t pid
        0: {},
        #unsigned int len
        1: {},
        #unsigned long *user_mask_ptr
        2: {},
    },
    #set_thread_area
    243:{
        #struct user_desc *u_info
        0: {},
    },
    #get_thread_area
    244:{
        #struct user_desc *u_info
        0: {},
    },
    #io_setup
    245:{
        #unsigned nr_events
        0: {},
        #aio_context_t *ctxp
        1: {},
    },
    #io_destroy
    246:{
        #aio_context_t ctx
        0: {},
    },
    #io_getevents
    247:{
        #__u32 ctx_id
        0: {},
        #__s32 min_nr
        1: {},
        #__s32 nr
        2: {},
        #struct io_event *events
        3: {},
        #struct old_timespec32 *timeout
        4: {},
    },
    #io_submit
    248:{
        #aio_context_t ctx_id
        0: {},
        #long nr
        1: {},
        #struct iocb **iocbpp
        2: {},
    },
    #io_cancel
    249:{
        #aio_context_t ctx_id
        0: {},
        #struct iocb *iocb
        1: {},
        #struct io_event *result
        2: {},
    },
    #fadvise64
    250:{
        #int fd
        0: {},
        #unsigned int offset_lo
        1: {},
        #unsigned int offset_hi
        2: {},
        #size_t len
        3: {},
        #int advice
        4: {},
    },
    #exit_group
    252:{
        #int error_code
        0: {},
    },
    #epoll_create
    254:{
        #int size
        0: {},
    },
    #epoll_ctl
    255:{
        #int epfd
        0: {},
        #int op
        1: {},
        #int fd
        2: {},
        #struct epoll_event *event
        3: {},
    },
    #epoll_wait
    256:{
        #int epfd
        0: {},
        #struct epoll_event *events
        1: {},
        #int maxevents
        2: {},
        #int timeout
        3: {},
    },
    #remap_file_pages
    257:{
        #unsigned long start
        0: {},
        #unsigned long size
        1: {},
        #unsigned long prot
        2: {},
        #unsigned long pgoff
        3: {},
        #unsigned long flags
        4: {},
    },
    #set_tid_address
    258:{
        #int *tidptr
        0: {},
    },
    #timer_create
    259:{
        #const clockid_t which_clock
        0: {},
        #struct sigevent *timer_event_spec
        1: {},
        #timer_t *created_timer_id
        2: {},
    },
    #timer_settime
    260:{
        #timer_t timer_id
        0: {},
        #int flags
        1: {},
        #struct old_itimerspec32 *new
        2: {},
        #struct old_itimerspec32 *old
        3: {},
    },
    #timer_gettime
    261:{
        #timer_t timer_id
        0: {},
        #struct old_itimerspec32 *setting
        1: {},
    },
    #timer_getoverrun
    262:{
        #timer_t timer_id
        0: {},
    },
    #timer_delete
    263:{
        #timer_t timer_id
        0: {},
    },
    #clock_settime
    264:{
        #clockid_t which_clock
        0: {},
        #struct old_timespec32 *tp
        1: {},
    },
    #clock_gettime
    265:{
        #clockid_t which_clock
        0: {},
        #struct old_timespec32 *tp
        1: {},
    },
    #clock_getres
    266:{
        #clockid_t which_clock
        0: {},
        #struct old_timespec32 *tp
        1: {},
    },
    #clock_nanosleep
    267:{
        #clockid_t which_clock
        0: {},
        #int flags
        1: {},
        #struct old_timespec32 *rqtp
        2: {},
        #struct old_timespec32 *rmtp
        3: {},
    },
    #statfs64
    268:{
        #const char *pathname
        0: {},
        #size_t sz
        1: {},
        #struct statfs64 *buf
        2: {},
    },
    #fstatfs64
    269:{
        #unsigned int fd
        0: {},
        #size_t sz
        1: {},
        #struct statfs64 *buf
        2: {},
    },
    #tgkill
    270:{
        #pid_t tgid
        0: {},
        #pid_t pid
        1: {},
        #int sig
        2: {},
    },
    #utimes
    271:{
        #const char *filename
        0: {},
        #struct old_timeval32 *t
        1: {},
    },
    #fadvise64_64
    272:{
        #int fd
        0: {},
        #__u32 offset_low
        1: {},
        #__u32 offset_high
        2: {},
        #__u32 len_low
        3: {},
        #__u32 len_high
        4: {},
        #int advice
        5: {},
    },
    #mbind
    274:{
        #unsigned long start
        0: {},
        #unsigned long len
        1: {},
        #unsigned long mode
        2: {},
        #const unsigned long *nmask
        3: {},
        #unsigned long maxnode
        4: {},
        #unsigned int flags
        5: {},
    },
    #get_mempolicy
    275:{
        #int *policy
        0: {},
        #unsigned long *nmask
        1: {},
        #unsigned long maxnode
        2: {},
        #unsigned long addr
        3: {},
        #unsigned long flags
        4: {},
    },
    #set_mempolicy
    276:{
        #int mode
        0: {},
        #const unsigned long *nmask
        1: {},
        #unsigned long maxnode
        2: {},
    },
    #mq_open
    277:{
        #const char *u_name
        0: {},
        #int oflag
        1: {},
        #umode_t mode
        2: {},
        #struct mq_attr *u_attr
        3: {},
    },
    #mq_unlink
    278:{
        #const char *u_name
        0: {},
    },
    #mq_timedsend
    279:{
        #mqd_t mqdes
        0: {},
        #const char *u_msg_ptr
        1: {},
        #unsigned int msg_len
        2: {},
        #unsigned int msg_prio
        3: {},
        #const struct old_timespec32 *u_abs_timeout
        4: {},
    },
    #mq_timedreceive
    280:{
        #mqd_t mqdes
        0: {},
        #char *u_msg_ptr
        1: {},
        #unsigned int msg_len
        2: {},
        #unsigned int *u_msg_prio
        3: {},
        #const struct old_timespec32 *u_abs_timeout
        4: {},
    },
    #mq_notify
    281:{
        #mqd_t mqdes
        0: {},
        #const struct sigevent *u_notification
        1: {},
    },
    #mq_getsetattr
    282:{
        #mqd_t mqdes
        0: {},
        #const struct mq_attr *u_mqstat
        1: {},
        #struct mq_attr *u_omqstat
        2: {},
    },
    #kexec_load
    283:{
        #unsigned long entry
        0: {},
        #unsigned long nr_segments
        1: {},
        #struct kexec_segment *segments
        2: {},
        #unsigned long flags
        3: {},
    },
    #waitid
    284:{
        #int which
        0: {},
        #pid_t upid
        1: {},
        #struct siginfo *infop
        2: {},
        #int options
        3: {},
        #struct rusage *ru
        4: {},
    },
    #add_key
    286:{
        #const char *_type
        0: {},
        #const char *_description
        1: {},
        #const void *_payload
        2: {},
        #size_t plen
        3: {},
        #key_serial_t ringid
        4: {},
    },
    #request_key
    287:{
        #const char *_type
        0: {},
        #const char *_description
        1: {},
        #const char *_callout_info
        2: {},
        #key_serial_t destringid
        3: {},
    },
    #keyctl
    288:{
        #int option
        0: {},
        #unsigned long arg2
        1: {},
        #unsigned long arg3
        2: {},
        #unsigned long arg4
        3: {},
        #unsigned long arg5
        4: {},
    },
    #ioprio_set
    289:{
        #int which
        0: {},
        #int who
        1: {},
        #int ioprio
        2: {},
    },
    #ioprio_get
    290:{
        #int which
        0: {},
        #int who
        1: {},
    },
    #inotify_init
    291:{
    },
    #inotify_add_watch
    292:{
        #int fd
        0: {},
        #const char *pathname
        1: {},
        #u32 mask
        2: {},
    },
    #inotify_rm_watch
    293:{
        #int fd
        0: {},
        #__s32 wd
        1: {},
    },
    #migrate_pages
    294:{
        #pid_t pid
        0: {},
        #unsigned long maxnode
        1: {},
        #const unsigned long *old_nodes
        2: {},
        #const unsigned long *new_nodes
        3: {},
    },
    #openat
    295:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #int flags
        2: {},
        #umode_t mode
        3: {},
    },
    #mkdirat
    296:{
        #int dfd
        0: {},
        #const char *pathname
        1: {},
        #umode_t mode
        2: {},
    },
    #mknodat
    297:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #umode_t mode
        2: {},
        #unsigned int dev
        3: {},
    },
    #fchownat
    298:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #uid_t user
        2: {},
        #gid_t group
        3: {},
        #int flag
        4: {},
    },
    #futimesat
    299:{
        #unsigned int dfd
        0: {},
        #const char *filename
        1: {},
        #struct old_timeval32 *t
        2: {},
    },
    #fstatat64
    300:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #struct stat64 *statbuf
        2: {},
        #int flag
        3: {},
    },
    #unlinkat
    301:{
        #int dfd
        0: {},
        #const char *pathname
        1: {},
        #int flag
        2: {},
    },
    #renameat
    302:{
        #int olddfd
        0: {},
        #const char *oldname
        1: {},
        #int newdfd
        2: {},
        #const char *newname
        3: {},
    },
    #linkat
    303:{
        #int olddfd
        0: {},
        #const char *oldname
        1: {},
        #int newdfd
        2: {},
        #const char *newname
        3: {},
        #int flags
        4: {},
    },
    #symlinkat
    304:{
        #const char *oldname
        0: {},
        #int newdfd
        1: {},
        #const char *newname
        2: {},
    },
    #readlinkat
    305:{
        #int dfd
        0: {},
        #const char *pathname
        1: {},
        #char *buf
        2: {},
        #int bufsiz
        3: {},
    },
    #fchmodat
    306:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #umode_t mode
        2: {},
    },
    #faccessat
    307:{
        #int dfd
        0: {},
        #const char *filename
        1: {},
        #int mode
        2: {},
    },
    #pselect6
    308:{
        #int n
        0: {},
        #fd_set *inp
        1: {},
        #fd_set *outp
        2: {},
        #fd_set *exp
        3: {},
        #struct old_timespec32 *tsp
        4: {},
        #void *sig
        5: {},
    },
    #ppoll
    309:{
        #struct pollfd *ufds
        0: {},
        #unsigned int nfds
        1: {},
        #struct old_timespec32 *tsp
        2: {},
        #const sigset_t *sigmask
        3: {},
        #size_t sigsetsize
        4: {},
    },
    #unshare
    310:{
        #unsigned long unshare_flags
        0: {},
    },
    #set_robust_list
    311:{
        #struct robust_list_head *head
        0: {},
        #size_t len
        1: {},
    },
    #get_robust_list
    312:{
        #int pid
        0: {},
        #struct robust_list_head **head_ptr
        1: {},
        #size_t *len_ptr
        2: {},
    },
    #splice
    313:{
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
    #sync_file_range
    314:{
        #int fd
        0: {},
        #unsigned int off_low
        1: {},
        #unsigned int off_hi
        2: {},
        #unsigned int n_low
        3: {},
        #unsigned int n_hi
        4: {},
        #int flags
        5: {},
    },
    #tee
    315:{
        #int fdin
        0: {},
        #int fdout
        1: {},
        #size_t len
        2: {},
        #unsigned int flags
        3: {},
    },
    #vmsplice
    316:{
        #int fd
        0: {},
        #const struct iovec *uiov
        1: {},
        #unsigned long nr_segs
        2: {},
        #unsigned int flags
        3: {},
    },
    #move_pages
    317:{
        #pid_t pid
        0: {},
        #unsigned long nr_pages
        1: {},
        #const void **pages
        2: {},
        #const int *nodes
        3: {},
        #int *status
        4: {},
        #int flags
        5: {},
    },
    #getcpu
    318:{
        #unsigned *cpup
        0: {},
        #unsigned *nodep
        1: {},
        #struct getcpu_cache *unused
        2: {},
    },
    #epoll_pwait
    319:{
        #int epfd
        0: {},
        #struct epoll_event *events
        1: {},
        #int maxevents
        2: {},
        #int timeout
        3: {},
        #const sigset_t *sigmask
        4: {},
        #size_t sigsetsize
        5: {},
    },
    #utimensat
    320:{
        #unsigned int dfd
        0: {},
        #const char *filename
        1: {},
        #struct old_timespec32 *t
        2: {},
        #int flags
        3: {},
    },
    #signalfd
    321:{
        #int ufd
        0: {},
        #sigset_t *user_mask
        1: {},
        #size_t sizemask
        2: {},
    },
    #timerfd_create
    322:{
        #int clockid
        0: {},
        #int flags
        1: {},
    },
    #eventfd
    323:{
        #unsigned int count
        0: {},
    },
    #fallocate
    324:{
        #int fd
        0: {},
        #int mode
        1: {},
        #unsigned int offset_lo
        2: {},
        #unsigned int offset_hi
        3: {},
        #unsigned int len_lo
        4: {},
        #unsigned int len_hi
        5: {},
    },
    #timerfd_settime
    325:{
        #int ufd
        0: {},
        #int flags
        1: {},
        #const struct old_itimerspec32 *utmr
        2: {},
        #struct old_itimerspec32 *otmr
        3: {},
    },
    #timerfd_gettime
    326:{
        #int ufd
        0: {},
        #struct old_itimerspec32 *otmr
        1: {},
    },
    #signalfd4
    327:{
        #int ufd
        0: {},
        #sigset_t *user_mask
        1: {},
        #size_t sizemask
        2: {},
        #int flags
        3: {},
    },
    #eventfd2
    328:{
        #unsigned int count
        0: {},
        #int flags
        1: {},
    },
    #epoll_create1
    329:{
        #int flags
        0: {},
    },
    #dup3
    330:{
        #unsigned int oldfd
        0: {},
        #unsigned int newfd
        1: {},
        #int flags
        2: {},
    },
    #pipe2
    331:{
        #int *fildes
        0: {},
        #int flags
        1: {},
    },
    #inotify_init1
    332:{
        #int flags
        0: {},
    },
    #preadv
    333:{
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
    },
    #pwritev
    334:{
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
    },
    #rt_tgsigqueueinfo
    335:{
        #pid_t tgid
        0: {},
        #pid_t pid
        1: {},
        #int sig
        2: {},
        #siginfo_t *uinfo
        3: {},
    },
    #perf_event_open
    336:{
        #struct perf_event_attr *attr_uptr
        0: {},
        #pid_t pid
        1: {},
        #int cpu
        2: {},
        #int group_fd
        3: {},
        #unsigned long flags
        4: {},
    },
    #recvmmsg
    337:{
        #int fd
        0: {},
        #struct mmsghdr *mmsg
        1: {},
        #unsigned int vlen
        2: {},
        #unsigned int flags
        3: {},
        #struct old_timespec32 *timeout
        4: {},
    },
    #fanotify_init
    338:{
        #unsigned int flags
        0: {},
        #unsigned int event_f_flags
        1: {},
    },
    #fanotify_mark
    339:{
        #int fanotify_fd
        0: {},
        #unsigned int flags
        1: {},
        #u32 mask_lo
        2: {},
        #u32 mask_hi
        3: {},
        #int dfd
        4: {},
        #const char *pathname
        5: {},
    },
    #prlimit64
    340:{
        #pid_t pid
        0: {},
        #unsigned int resource
        1: {},
        #const struct rlimit64 *new_rlim
        2: {},
        #struct rlimit64 *old_rlim
        3: {},
    },
    #name_to_handle_at
    341:{
        #int dfd
        0: {},
        #const char *name
        1: {},
        #struct file_handle *handle
        2: {},
        #void *mnt_id
        3: {},
        #int flag
        4: {},
    },
    #open_by_handle_at
    342:{
        #int mountdirfd
        0: {},
        #struct file_handle *handle
        1: {},
        #int flags
        2: {},
    },
    #clock_adjtime
    343:{
        #clockid_t which_clock
        0: {},
        #struct old_timex32 *utp
        1: {},
    },
    #syncfs
    344:{
        #int fd
        0: {},
    },
    #sendmmsg
    345:{
        #int fd
        0: {},
        #struct mmsghdr *mmsg
        1: {},
        #unsigned int vlen
        2: {},
        #unsigned int flags
        3: {},
    },
    #setns
    346:{
        #int fd
        0: {},
        #int flags
        1: {},
    },
    #process_vm_readv
    347:{
        #pid_t pid
        0: {},
        #const struct iovec *lvec
        1: {},
        #unsigned long liovcnt
        2: {},
        #const struct iovec *rvec
        3: {},
        #unsigned long riovcnt
        4: {},
        #unsigned long flags
        5: {},
    },
    #process_vm_writev
    348:{
        #pid_t pid
        0: {},
        #const struct iovec *lvec
        1: {},
        #unsigned long liovcnt
        2: {},
        #const struct iovec *rvec
        3: {},
        #unsigned long riovcnt
        4: {},
        #unsigned long flags
        5: {},
    },
    #kcmp
    349:{
        #pid_t pid1
        0: {},
        #pid_t pid2
        1: {},
        #int type
        2: {},
        #unsigned long idx1
        3: {},
        #unsigned long idx2
        4: {},
    },
    #finit_module
    350:{
        #int fd
        0: {},
        #const char *uargs
        1: {},
        #int flags
        2: {},
    },
    #sched_setattr
    351:{
        #pid_t pid
        0: {},
        #struct sched_attr *uattr
        1: {},
        #unsigned int flags
        2: {},
    },
    #sched_getattr
    352:{
        #pid_t pid
        0: {},
        #struct sched_attr *uattr
        1: {},
        #unsigned int usize
        2: {},
        #unsigned int flags
        3: {},
    },
    #renameat2
    353:{
        #int olddfd
        0: {},
        #const char *oldname
        1: {},
        #int newdfd
        2: {},
        #const char *newname
        3: {},
        #unsigned int flags
        4: {},
    },
    #seccomp
    354:{
        #unsigned int op
        0: {},
        #unsigned int flags
        1: {},
        #void *uargs
        2: {},
    },
    #getrandom
    355:{
        #char *ubuf
        0: {},
        #size_t len
        1: {},
        #unsigned int flags
        2: {},
    },
    #memfd_create
    356:{
        #const char *uname
        0: {},
        #unsigned int flags
        1: {},
    },
    #bpf
    357:{
        #int cmd
        0: {},
        #union bpf_attr *uattr
        1: {},
        #unsigned int size
        2: {},
    },
    #execveat
    358:{
        #int fd
        0: {},
        #const char *filename
        1: {},
        #const char *const *argv
        2: {},
        #const char *const *envp
        3: {},
        #int flags
        4: {},
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
