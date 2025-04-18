#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

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

# Common flags flags across syscalls
OPEN_FLAGS = \
{
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

OPEN_MODES = \
{
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

SIGNALS = \
{
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

WHICH_CLOCK = \
{
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

OPENAT_DFD = \
{
    0xffffff9c: "AT_FDCWD",
}

SPLICE_FLAGS = \
{
    0x01: "SPLICE_F_MOVE",
    0x02: "SPLICE_F_NONBLOCK",
    0x04: "SPLICE_F_MORE",
    0x08: "SPLICE_F_GIFT",
}

AMD64_SYSCALL_PARSER_MAP = \
{
    #open
    2:{
        #int flags
        1: OPEN_FLAGS,
        #umode_t mode
        2: OPEN_MODES,
    },
    #lseek
    8:{
        #unsigned int whence
        2: {
            0: "SEEK_SET",
            1: "SEEK_CUR",
            2: "SEEK_END",
            3: "SEEK_DATA",
            4: "SEEK_HOLE",
        },
    },
    #mmap
    9:{
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
            0x00000040: "MAP_32BIT",
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
    #mprotect
    10:{
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
    #rt_sigaction
    13:{
        #int sig
        0: SIGNALS,
    },
    #rt_sigprocmask
    14:{
        #int how
        0: {
            0: "SIG_BLOCK",
            1: "SIG_UNBLOCK",
            2: "SIG_SETMASK",
            "parsing_mode": "sequential",
        },
    },
    #access
    21:{
        #int mode
        1: {
            0: "F_OK",
            1: "X_OK",
            2: "W_OK",
            4: "R_OK",
        },
    },
    #mremap
    25:{
        #unsigned long flags
        3: {
            1: "MREMAP_MAYMOVE",
            2: "MREMAP_FIXED",
            4: "MREMAP_DONTUNMAP",
        },
    },
    #msync
    26:{
        #int flags
        2: {
            1: "MS_ASYNC",
            2: "MS_INVALIDATE",
            4: "MS_SYNC",
        },
    },
    #madvise
    28:{
        #int behavior
        2: {
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
        },
    },
    #shmget
    29:{
        #int shmflg
        2: {
            0o00001000: "IPC_CREAT",
            0o00002000: "IPC_EXCL",
            0o00010000: "SHM_NORESERVE",
            0x54000000: "SHM_HUGE_2MB",
            0x78000000: "SHM_HUGE_1GB",
            0o0004000: "SHM_HUGETLB",
            0o0000032: "SHM_HUGE_SHIFT",
        },
    },
    #shmat
    30:{
        #int shmflg
        2: {
            0o010000: "SHM_RDONLY",
            0o020000: "SHM_RND",
            0o040000: "SHM_REMAP",
            0o0100000: "SHM_EXEC",
        },
    },
    #shmctl
    31:{
        #int cmd
        1: {
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
        },
    },
    #getitimer
    36:{
        #int which
        0: {
            0: "ITIMER_REAL",
            1: "ITIMER_VIRTUAL",
            2: "ITIMER_PROF",
            "parsing_mode": "sequential",
        },
    },
    #setitimer
    38:{
        #int which
        0: {
            0: "ITIMER_REAL",
            1: "ITIMER_VIRTUAL",
            2: "ITIMER_PROF",
            "parsing_mode": "sequential",
        },
    },
    #socket
    41:{
        #int family
        0: {
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
        },
        #int type
        1: {
            "sequential_flags": {
                0x000001: "SOCK_STREAM",
                0x000002: "SOCK_DGRAM",
                0x000003: "SOCK_RAW",
                0x000004: "SOCK_RDM",
                0x000005: "SOCK_SEQPACKET",
                0x00000a: "SOCK_PACKET",
            },
            "or_flags": {
                0x000800: "SOCK_NONBLOCK",
                0x080000: "SOCK_CLOEXEC",
            },
            "parsing_mode": "mixed",
        },
        #int protocol
        # 2: {},
    },
    #sendto
    44:{
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
    #recvfrom
    45:{
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
    #sendmsg
    46:{
        #unsigned int flags
        2: {
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
    #recvmsg
    47:{
        #unsigned int flags
        2: {
            0x40000000: "MSG_CMSG_CLOEXEC",
            0x00000040: "MSG_DONTWAIT",
            0x00002000: "MSG_ERRQUEUE",
            0x00000001: "MSG_OOB",
            0x00000002: "MSG_PEEK",
            0x00000020: "MSG_TRUNC",
            0x00000100: "MSG_WAITALL",
        },
    },
    #shutdown
    48:{
        #int how
        1: {
            0: "SHUT_RD",
            1: "SHUT_WR",
            2: "SHUT_RDWR",
            "parsing_mode": "sequential",
        },
    },
    #socketpair
    53:{
        #int family
        0: {
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
        },
        #int type
        1: {
            "sequential_flags": {
                0x000001: "SOCK_STREAM",
                0x000002: "SOCK_DGRAM",
                0x000003: "SOCK_RAW",
                0x000004: "SOCK_RDM",
                0x000005: "SOCK_SEQPACKET",
                0x00000a: "SOCK_PACKET",
            },
            "or_flags": {
                0x000800: "SOCK_NONBLOCK",
                0x080000: "SOCK_CLOEXEC",
            },
            "parsing_mode": "mixed",
        },
        #int protocol
        # 2: {},
    },
    #setsockopt
    54:{
        # TODO: Complex parsing, future work
        #int level
        1: {},
        # SO_ACCEPTCONN, SO_ATTACH_FILTER, SO_ATTACH_BPF, SO_ATTACH_REUSEPORT_CBPF, SO_ATTACH_REUSEPORT_EBPF, SO_BINDTODEVICE, SO_BROADCAST, SO_BSDCOMPAT, SO_DEBUG, SO_DETACH_FILTER, SO_DETACH_BPF, SO_DOMAIN, SO_ERROR, SO_DONTROUTE,
        # SO_INCOMING_CPU, SO_INCOMING_NAPI_ID, SO_KEEPALIVE, SO_LINGER, SO_LOCK_FILTER, SO_MARK, SO_OOBINLINE, SO_PASSCRED, SO_PASSSEC, SO_PEEK_OFF, SO_PEERCRED, SO_PEERSEC, SO_PRIORITY, SO_RCVBUF, SO_RCVBUFFORCE, SO_RCVLOWAT,
        # SO_SNDLOWAT, SO_RCVTIMEO, SO_SNDTIMEO, SO_REUSEADDR, SO_REUSEPORT, SO_RXQ_OVFL, SO_SELECT_ERR_QUEUE, SO_SNDBUF, SO_SNDBUFFORCE, SO_TIMESTAMP, SO_TIMESTAMPNS, SO_TYPE, SO_BUSY_POLL
        #int optname
        2: {},
    },
    #getsockopt
    55:{
        # TODO: Complex parsing, future work
        #int level
        1: {},
        #int optname
        2: {},
    },
    #clone
    56:{
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
    #wait4
    61:{
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
    #kill
    62:{
        #int sig
        1: SIGNALS,
    },
    #semget
    64:{
        #key_t key
        0: {
            0: "IPC_PRIVATE",
        },
        #int semflg
        2: {
            0o0001000: "IPC_CREAT",
            0o0002000: "IPC_EXCL",
            0o0004000: "IPC_NOWAIT",
        },
    },
    # semctl
    66:{
        #int cmd
        2: {
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
        },
    },
    # TODO: Crazy complex parsing, future work
    # # fcntl
    # 72:{
    #     #unsigned int fd
    #     0: {},
    #     #unsigned int cmd
    #     1: {},
    #     #unsigned long arg
    #     2: {},
    # },
    #flock
    73:{
        #unsigned int cmd
        1: {
            1: "LOCK_SH",
            2: "LOCK_EX",
            4: "LOCK_NB",
            8: "LOCK_UN",
        },
    },
    #mkdir
    83:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #creat
    85:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #chmod
    90:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #fchmod
    91:{
        #umode_t mode
        1: OPEN_MODES,
    },
    #umask
    95:{
        #int mask
        0: OPEN_MODES,
    },
    #getrlimit
    97:{
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
    #getrusage
    98:{
        #int who
        0: {
            0: "RUSAGE_SELF",
            0xffffffff: "RUSAGE_CHILDREN",
            0xfffffffe: "RUSAGE_BOTH",
            1: "RUSAGE_THREAD",
            "parsing_mode": "sequential",
        },
    },
    #ptrace
    101:{
        #long request
        0: {
            # Arch-specific
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
            30: "PTRACE_ARCH_PRCTL",
            31: "PTRACE_SYSEMU",
            32: "PTRACE_SYSEMU_SINGLESTEP",
            33: "PTRACE_SINGLEBLOCK",
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
            0x420a: "PTRACE_GETSIGMASK",
            0x420b: "PTRACE_SETSIGMASK",
            0x420c: "PTRACE_SECCOMP_GET_FILTER",
            0x420d: "PTRACE_SECCOMP_GET_METADATA",
            0x420e: "PTRACE_GET_SYSCALL_INFO",
            0x420f: "PTRACE_GET_RSEQ_CONFIGURATION",
            0x4210: "PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG",
            0x4211: "PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG",
            "parsing_mode": "sequential",
        },
        #unsigned long data
        3: {
            "parsing_mode": "custom",
            "parser": parse_ptrace_data,
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
    #rt_sigqueueinfo
    129:{
        #int sig
        1: SIGNALS,
    },
    #mknod
    133:{
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
    #personality
    135:{
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
            0x400000b: "PER_IRIX64",
            0x400000a: "PER_IRIXN32",
            0x4000005: "PER_ISCR4",
            0x0000000: "PER_LINUX",
            0x0000008: "PER_LINUX32",
            0x8000008: "PER_LINUX32_3GB",
            0x000f: "PER_OSF4",
            0x0000000c: "PER_RISCOS",
            0x07000003: "PER_SCOSVR3",
            0x0400000d: "PER_SOLARIS",
            0x04000006: "PER_SUNOS",
            0x05000002: "PER_SVR3",
            0x04100001: "PER_SVR4",
            0x0410000e: "PER_UW7",
            0x05000004: "PER_WYSEV386",
            0x05000007: "PER_XENIX",
        },
    },
    #getpriority
    140:{
        #int which
        0: {
            0: "PRIO_PROCESS",
            1: "PRIO_PGRP",
            2: "PRIO_USER",
            "parsing_mode": "sequential",
        },
    },
    #setpriority
    141:{
        #int which
        0: {
            0: "PRIO_PROCESS",
            1: "PRIO_PGRP",
            2: "PRIO_USER",
            "parsing_mode": "sequential",
        },
    },
    #sched_setscheduler
    144:{
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
    146:{
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
    147:{
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
    #mlockall
    151:{
        #int flags
        0: {
            0x00000001: "MCL_CURRENT",
            0x00000002: "MCL_FUTURE",
            0x00000004: "MCL_ONFAULT",
        },
    },
    #prctl
    157:{
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
    #arch_prctl
    158:{
        #int option
        0: {
            0x1001: "ARCH_SET_GS",
            0x1002: "ARCH_SET_FS",
            0x1003: "ARCH_GET_FS",
            0x1004: "ARCH_GET_GS",
            0x1011: "ARCH_GET_CPUID",
            0x1012: "ARCH_SET_CPUID",
            # From linux / arch / x86 / include / uapi / asm / prctl.h
            # Undocumented, unsure if they should be included
            #define ARCH_GET_XCOMP_SUPP		0x1021
            #define ARCH_GET_XCOMP_PERM		0x1022
            #define ARCH_REQ_XCOMP_PERM		0x1023
            #define ARCH_GET_XCOMP_GUEST_PERM	0x1024
            #define ARCH_REQ_XCOMP_GUEST_PERM	0x1025

            #define ARCH_XCOMP_TILECFG		17
            #define ARCH_XCOMP_TILEDATA		18

            #define ARCH_MAP_VDSO_X32		0x2001
            #define ARCH_MAP_VDSO_32		0x2002
            #define ARCH_MAP_VDSO_64		0x2003

            # /* Don't use 0x3001-0x3004 because of old glibcs */

            #define ARCH_GET_UNTAG_MASK		0x4001
            #define ARCH_ENABLE_TAGGED_ADDR		0x4002
            #define ARCH_GET_MAX_TAG_BITS		0x4003
            #define ARCH_FORCE_TAGGED_SVA		0x4004

            #define ARCH_SHSTK_ENABLE		0x5001
            #define ARCH_SHSTK_DISABLE		0x5002
            #define ARCH_SHSTK_LOCK			0x5003
            #define ARCH_SHSTK_UNLOCK		0x5004
            #define ARCH_SHSTK_STATUS		0x5005
        },
    },
    #setrlimit
    160:{
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
    #mount
    165:{
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
    #umount
    166:{
        #int flags
        1: {
            0x00000001: "MNT_FORCE",
            0x00000002: "MNT_DETACH",
            0x00000004: "MNT_EXPIRE",
            0x00000008: "UMOUNT_NOFOLLOW",
            0x80000000: "UMOUNT_UNUSED",
        },
    },
    #swapon
    167:{
        #int swap_flags
        1: {
            0x8000: "SWAP_FLAG_PREFER",
            0x10000: "SWAP_FLAG_DISCARD",
        },
    },
    #reboot
    169:{
        #int magic1
        0: {
            0xfee1dead: "LINUX_REBOOT_MAGIC1",
            "parsing_mode": "sequential",
        },
        #int magic2
        1: {
            672274793: "LINUX_REBOOT_MAGIC2",
            85072278: "LINUX_REBOOT_MAGIC2A",
            369367448: "LINUX_REBOOT_MAGIC2B",
            537993216: "LINUX_REBOOT_MAGIC2C",
            "parsing_mode": "sequential",
        },
        #unsigned int cmd
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
    #delete_module
    176:{
        #unsigned int flags
        1: {
            0o0004000: "O_NONBLOCK",
            0o0001000: "O_TRUNC",
        },
    },
    #quotactl
    179:{
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
        # Technically if cmd is Q_QUOTAON,
        # we could parse the ID with QFMT defines but
        # it's likely not worth it
    },
    #setxattr
    188:{
        #int flags
        4: {
            0x00000001: "XATTR_CREATE",
            0x00000002: "XATTR_REPLACE",
            "parsing_mode": "sequential",
        },
    },
    #lsetxattr
    189:{
        #int flags
        4: {
            0x00000001: "XATTR_CREATE",
            0x00000002: "XATTR_REPLACE",
            "parsing_mode": "sequential",
        },
    },
    #fsetxattr
    190:{
        #int flags
        4: {
            0x00000001: "XATTR_CREATE",
            0x00000002: "XATTR_REPLACE",
            "parsing_mode": "sequential",
        },
    },
    #tkill
    200:{
        #int sig
        1: SIGNALS,
    },
    #futex
    202:{
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
    #remap_file_pages
    216:{
        #unsigned long flags
        4: {
            # All flags other that MAP_NONBLOCK are ignored
            0x00010000: "MAP_NONBLOCK",
        },
    },
    #fadvise64
    221:{
        3: {
            0: "POSIX_FADV_NORMAL",
            1: "POSIX_FADV_RANDOM",
            2: "POSIX_FADV_SEQUENTIAL",
            3: "POSIX_FADV_WILLNEED",
            4: "POSIX_FADV_DONTNEED",
            5: "POSIX_FADV_NOREUSE",
        },
    },
    #timer_settime
    223:{
        #int flags
        1: {
            1: "TIMER_ABSTIME",
        },
    },
    #clock_settime
    227:{
        #const clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #clock_gettime
    228:{
        #const clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #clock_getres
    229:{
        #const clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #clock_nanosleep
    230:{
        #const clockid_t which_clock
        0: WHICH_CLOCK,
        #int flags
        1: {
            1: "TIMER_ABSTIME",
        },
    },
    #epoll_ctl
    233:{
        #int op
        1: {
            1: "EPOLL_CTL_ADD",
            2: "EPOLL_CTL_DEL",
            3: "EPOLL_CTL_MOD",
            "parsing_mode": "sequential",
        },
    },
    #tgkill
    234:{
        #int sig
        2: SIGNALS,
    },
    #mbind
    237:{
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
    #set_mempolicy
    238:{
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
    },
    #get_mempolicy
    239:{
        #unsigned long flags
        4: {
            0b0001: "MPOL_F_NODE",
            0b0010: "MPOL_F_ADDR",
            0b0100: "MPOL_F_MEMS_ALLOWED",
        },
    },
    #mq_open
    240:{
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
    246:{
        #unsigned long flags
        3: {
            "or_flags": {
                0x00000001: "KEXEC_ON_CRASH",
                0x00000002: "KEXEC_PRESERVE_CONTEXT",
                0x00000004: "KEXEC_UPDATE_ELFCOREHDR",
                0x00000008: "KEXEC_CRASH_HOTPLUG_SUPPORT",
                0xffff0000: "KEXEC_ARCH_MASK",
            },
            "sequential_flags": {
                0x0: "KEXEC_ARCH_DEFAULT",
                0x30000: "KEXEC_ARCH_386",
                0x40000: "KEXEC_ARCH_68K",
                0xf0000: "KEXEC_ARCH_PARISC",
                0x3e0000: "KEXEC_ARCH_X86_64",
                0x140000: "KEXEC_ARCH_PPC",
                0x150000: "KEXEC_ARCH_PPC64",
                0x320000: "KEXEC_ARCH_IA_64",
                0x280000: "KEXEC_ARCH_ARM",
                0x160000: "KEXEC_ARCH_S390",
                0x2a0000: "KEXEC_ARCH_SH",
                0xa0000: "KEXEC_ARCH_MIPS_LE",
                0x80000: "KEXEC_ARCH_MIPS",
                0xb70000: "KEXEC_ARCH_AARCH64",
                0xf30000: "KEXEC_ARCH_RISCV",
                0x1020000: "KEXEC_ARCH_LOONGARCH",
            },
            "parsing_mode": "mixed",
        },
    },
    #waitid
    247:{
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
    248:{
        #key_serial_t ringid
        4: {
            0xffffffffffffffff: "KEY_SPEC_THREAD_KEYRING",
            0xfffffffffffffffe: "KEY_SPEC_PROCESS_KEYRING",
            0xfffffffffffffffd: "KEY_SPEC_SESSION_KEYRING",
            0xfffffffffffffffc: "KEY_SPEC_USER_KEYRING",
            0xfffffffffffffffb: "KEY_SPEC_USER_SESSION_KEYRING",
            0xfffffffffffffffa: "KEY_SPEC_GROUP_KEYRING",
            0xffffffffffffff9f: "KEY_SPEC_REQKEY_AUTH_KEY",
            0xffffffffffffff9e: "KEY_SPEC_REQUESTOR_KEYRING",
            "parsing_mode": "sequential",
        },
    },
    #request_key
    249:{
        #key_serial_t destringid
        3: {
            0xffffffffffffffff: "KEY_SPEC_THREAD_KEYRING",
            0xfffffffffffffffe: "KEY_SPEC_PROCESS_KEYRING",
            0xfffffffffffffffd: "KEY_SPEC_SESSION_KEYRING",
            0xfffffffffffffffc: "KEY_SPEC_USER_KEYRING",
            0xfffffffffffffffb: "KEY_SPEC_USER_SESSION_KEYRING",
            0xfffffffffffffffa: "KEY_SPEC_GROUP_KEYRING",
            0xffffffffffffff9f: "KEY_SPEC_REQKEY_AUTH_KEY",
            0xffffffffffffff9e: "KEY_SPEC_REQUESTOR_KEYRING",
            "parsing_mode": "sequential",
        },
    },
    #keyctl
    250:{
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
    251:{
        #int which
        0: {
            1: "IOPRIO_WHO_PROCESS",
            2: "IOPRIO_WHO_PGRP",
            3: "IOPRIO_WHO_USER",
            "parsing_mode": "sequential",
        },
    },
    #ioprio_get
    252:{
        #int which
        0: {
            1: "IOPRIO_WHO_PROCESS",
            2: "IOPRIO_WHO_PGRP",
            3: "IOPRIO_WHO_USER",
            "parsing_mode": "sequential",
        },
    },
    #openat
    257:{
        #int dfd
        0: OPENAT_DFD,
        #int flags
        2: OPEN_FLAGS,
        #umode_t mode
        3: OPEN_MODES,
    },
    #mkdirat
    258:{
        #int dfd
        0: OPENAT_DFD,
        #umode_t mode
        2: OPEN_MODES,
    },
    #mknodat
    259:{
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
    260:{
        #int dfd
        0: OPENAT_DFD,
        #int flag
        4: {
            0x1000: "AT_EMPTY_PATH",
            0x100: "AT_SYMLINK_NOFOLLOW",
        },
    },
    #newfstatat
    262:{
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
    263:{
        #int dfd
        0: OPENAT_DFD,
        #int flag
        2: {
            0x200: "AT_REMOVEDIR",
        },
    },
    #renameat
    264:{
        #int olddfd
        0: OPENAT_DFD,
    },
    #linkat
    265:{
        #int olddfd
        0: OPENAT_DFD,
        #int flags
        4: {
            0x1000: "AT_EMPTY_PATH",
            0x400: "AT_SYMLINK_FOLLOW",
        },
    },
    #symlinkat
    266:{
        #int newdfd
        1: OPENAT_DFD,
    },
    #readlinkat
    267:{
        #int dfd
        0: OPENAT_DFD,
    },
    #fchmodat
    268:{
        #int dfd
        0: OPENAT_DFD,
        #umode_t mode
        2: OPEN_MODES,
    },
    #faccessat
    269:{
        #int dfd
        0: OPENAT_DFD,
        #int mode
        2: OPEN_MODES,
    },
    #unshare
    272:{
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
    275:{
        #unsigned int flags
        5: SPLICE_FLAGS,
    },
    #tee
    276:{
        #unsigned int flags
        3: SPLICE_FLAGS,
    },
    #sync_file_range
    277:{
        #unsigned int flags
        3: {
            1: "SYNC_FILE_RANGE_WAIT_BEFORE",
            2: "SYNC_FILE_RANGE_WRITE",
            4: "SYNC_FILE_RANGE_WAIT_AFTER",
        },
    },
    #vmsplice
    278:{
        #unsigned int flags
        3: SPLICE_FLAGS,
    },
    #move_pages
    279:{
        #int flags
        5: {
            0b10: "MPOL_MF_MOVE",
            0b100: "MPOL_MF_MOVE_ALL",
        },
    },
    #utimensat
    280:{
        #int flags
        3: {
            0x1000: "AT_EMPTY_PATH",
            0x100: "AT_SYMLINK_NOFOLLOW",
        },
    },
    #timerfd_create
    283:{
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
    285:{
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
    286:{
        #int flags
        1: {
            0x00000001: "TFD_TIMER_ABSTIME",
            0x00000002: "TFD_TIMER_CANCEL_ON_SET",
        },
    },
    #accept4
    288:{
        #int flags
        3: {
            0o02000000: "SOCK_CLOEXEC",
            0o00004000: "SOCK_NONBLOCK",
        },
    },
    #signalfd4
    289:{
        #int flags
        3: {
            0o02000000: "SFD_CLOEXEC",
            0o00004000: "SFD_NONBLOCK",
        },
    },
    #eventfd2
    290:{
        #int flags
        1: {
            0o00000001: "EFD_SEMAPHORE",
            0o02000000: "EFD_CLOEXEC",
            0o00004000: "EFD_NONBLOCK",
        },
    },
    #epoll_create1
    291:{
        #int flags
        0: {
            0o02000000: "EPOLL_CLOEXEC",
        },
    },
    #dup3
    292:{
        #int flags
        2: {
            0o02000000: "O_CLOEXEC",
        },
    },
    #pipe2
    293:{
        #int flags
        1: {
            0o02000000: "O_CLOEXEC",
            0o00004000: "O_NONBLOCK",
            0o00040000: "O_DIRECT",
            0o00000200: "O_EXCL",
        },
    },
    #inotify_init1
    294:{
        #int flags
        0: {
            0o02000000: "IN_CLOEXEC",
            0o00004000: "IN_NONBLOCK",
        },
    },
    #rt_tgsigqueueinfo
    297:{
        #int sig
        2: SIGNALS,
    },
    #perf_event_open
    298:{
        #unsigned long flags
        4: {
            0b0001: "PERF_FLAG_FD_NO_GROUP",
            0b0010: "PERF_FLAG_FD_OUTPUT",
            0b0100: "PERF_FLAG_PID_CGROUP",
            0b1000: "PERF_FLAG_FD_CLOEXEC",
        },
    },
    #recvmmsg
    299:{
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
    300:{
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
    301:{
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
        #__u64 mask
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
        3: OPENAT_DFD,
    },
    #prlimit64
    302:{
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
            0xffffffff: "RLIM_INFINITY",
            "parsing_mode": "sequential",
        },
    },
    #name_to_handle_at
    303:{
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
    304:{
        #int mountdirfd
        0: OPENAT_DFD,
        #int flags
        2: OPEN_FLAGS,
    },
    #clock_adjtime
    305:{
        #const clockid_t which_clock
        0: WHICH_CLOCK,
    },
    #sendmmsg
    307:{
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
    308:{
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
    312:{
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
    313:{
        #int flags
        2: {
            1: "MODULE_INIT_IGNORE_MODVERSIONS",
            2: "MODULE_INIT_IGNORE_VERMAGIC",
            4: "MODULE_INIT_COMPRESSED_FILE",
        },
    },
    #renameat2
    316:{
        #unsigned int flags
        4: {
            0b001: "RENAME_NOREPLACE",
            0b010: "RENAME_EXCHANGE",
            0b100: "RENAME_WHITEOUT",
        },
    },
    #seccomp
    317:{
        #unsigned int op
        0: {
            0: "SECCOMP_SET_MODE_STRICT",
            1: "SECCOMP_SET_MODE_FILTER",
            2: "SECCOMP_GET_ACTION_AVAIL",
            3: "SECCOMP_GET_NOTIF_SIZES",
        },
        #unsigned int flags
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
    318:{
        #char *ubuf
        0: {},
        #size_t len
        1: {},
        #unsigned int flags
        2: {},
    },
    #memfd_create
    319:{
        #const char *uname
        0: {},
        #unsigned int flags
        1: {},
    },
    #kexec_file_load
    320:{
        #int kernel_fd
        0: {},
        #int initrd_fd
        1: {},
        #unsigned long cmdline_len
        2: {},
        #const char *cmdline_ptr
        3: {},
        #unsigned long flags
        4: {
            # /*
            # * Kexec file load interface flags.
            # * KEXEC_FILE_UNLOAD : Unload already loaded kexec/kdump image.
            # * KEXEC_FILE_ON_CRASH : Load/unload operation belongs to kdump image.
            # * KEXEC_FILE_NO_INITRAMFS : No initramfs is being loaded. Ignore the initrd
            # *                           fd field.
            # */
            #define KEXEC_FILE_UNLOAD	0x00000001
            #define KEXEC_FILE_ON_CRASH	0x00000002
            #define KEXEC_FILE_NO_INITRAMFS	0x00000004
            #define KEXEC_FILE_DEBUG	0x00000008
        },
    },
    #bpf
    321:{
        #int cmd
        0: {},
        #union bpf_attr *uattr
        1: {},
        #unsigned int size
        2: {},
    },
    #execveat
    322:{
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
    #userfaultfd
    323:{
        #int flags
        0: {},
    },
    #membarrier
    324:{
        #int cmd
        0: {},
        #unsigned int flags
        1: {},
        #int cpu_id
        2: {},
    },
    #mlock2
    325:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
        #int flags
        2: {},
    },
    #copy_file_range
    326:{
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
    327:{
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
    328:{
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
    #pkey_mprotect
    329:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
        #unsigned long prot
        2: {},
        #int pkey
        3: {},
    },
    #pkey_alloc
    330:{
        #unsigned long flags
        0: {},
        #unsigned long init_val
        1: {},
    },
    #pkey_free
    331:{
        #int pkey
        0: {},
    },
    #statx
    332:{
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
    #io_pgetevents
    333:{
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
    #rseq
    334:{
        #struct rseq *rseq
        0: {},
        #u32 rseq_len
        1: {},
        #int flags
        2: {},
        #u32 sig
        3: {},
    },
    #uretprobe
    335:{
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
        0: OPENAT_DFD,
        #int mode
        2: OPEN_MODES,
        #int flags
        3: {
            0x200: "AT_EACCESS",
            0x1000: "AT_EMPTY_PATH",
            0x100: "AT_SYMLINK_NOFOLLOW",
        },
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
        0: OPENAT_DFD,
        #umode_t mode
        2: OPEN_MODES,
        #unsigned int flags
        3: {
            0x100: "AT_SYMLINK_NOFOLLOW",
        },
    },
    #map_shadow_stack
    453:{
        #unsigned long addr
        0: {},
        #unsigned long size
        1: {},
        #unsigned int flags
        2: {},
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
    #mseal
    462:{
        #unsigned long start
        0: {},
        #size_t len
        1: {},
        #unsigned long flags
        2: {},
    },
    # #setxattrat
    # 463:{
    #     #int dfd
    #     0: {},
    #     #const char *pathname
    #     1: {},
    #     #unsigned int at_flags
    #     2: {},
    #     #const char *name
    #     3: {},
    #     #const struct xattr_args *uargs
    #     4: {},
    #     #size_t usize
    #     5: {},
    # },
    # #getxattrat
    # 464:{
    #     #int dfd
    #     0: {},
    #     #const char *pathname
    #     1: {},
    #     #unsigned int at_flags
    #     2: {},
    #     #const char *name
    #     3: {},
    #     #struct xattr_args *uargs
    #     4: {},
    #     #size_t usize
    #     5: {},
    # },
    # #listxattrat
    # 465:{
    #     #int dfd
    #     0: {},
    #     #const char *pathname
    #     1: {},
    #     #unsigned int at_flags
    #     2: {},
    #     #char *list
    #     3: {},
    #     #size_t size
    #     4: {},
    # },
    # #removexattrat
    # 466:{
    #     #int dfd
    #     0: {},
    #     #const char *pathname
    #     1: {},
    #     #unsigned int at_flags
    #     2: {},
    #     #const char *name
    #     3: {},
    # },
}
