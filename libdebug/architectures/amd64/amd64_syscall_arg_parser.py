#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

AMD64_SYSCALL_PARSER_MAP = \
{
#open
2:{
    #int flags
    1: {
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
    },
    #umode_t mode
    2: {
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
    },
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
    0: {
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
    },
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
    # WNOHANG, WUNTRACED, WCONTINUED
    #int options
    2: {
        0x00000001: "WNOHANG",
        0x00000002: "WUNTRACED",
        0x00000004: "WCONTINUED",
    },
},
#kill
62:{
    #int sig
    1: {
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
    },
},
# #semget
# 64:{
#     #key_t key
#     0: {},
#     #int nsems
#     1: {},
#     #int semflg
#     2: {},
# },
#semop
# 65:{
#     #int semid
#     0: {},
#     #struct sembuf *tsops
#     1: {},
#     #unsigned nsops
#     2: {},
# },
#semctl
# 66:{
#     #int semid
#     0: {},
#     #int semnum
#     1: {},
#     #int cmd
#     2: {},
#     #unsigned long arg
#     3: {},
# },
#msgget
# 68:{
#     #key_t key
#     0: {},
#     #int msgflg
#     1: {},
# },
# #msgsnd
# 69:{
#     #int msqid
#     0: {},
#     #struct msgbuf *msgp
#     1: {},
#     #size_t msgsz
#     2: {},
#     #int msgflg
#     3: {},
# },
# #msgrcv
# 70:{
#     #int msqid
#     0: {},
#     #struct msgbuf *msgp
#     1: {},
#     #size_t msgsz
#     2: {},
#     #long msgtyp
#     3: {},
#     #int msgflg
#     4: {},
# },
# #msgctl
# 71:{
#     #int msqid
#     0: {},
#     #int cmd
#     1: {},
#     #struct msqid_ds *buf
#     2: {},
# },
#fcntl
72:{
    #unsigned int fd
    0: {},
    #unsigned int cmd
    1: {},
    #unsigned long arg
    2: {},
},
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
    1: {
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
    },
},
#creat
85:{
    #umode_t mode
    1: {
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
    },
},
#chmod
90:{
    #umode_t mode
    1: {
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
    },
},
#fchmod
91:{
    #umode_t mode
    1: {
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
    },
},
#umask
95:{
    #int mask
    0: {
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
    },
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
        -1: "RUSAGE_CHILDREN",
        -2: "RUSAGE_BOTH",
        1: "RUSAGE_THREAD",
        "parsing_mode": "sequential",
    },
},
#ptrace
101:{
    #long request
    0: {},
    #long pid
    1: {},
    #unsigned long addr
    2: {},
    #unsigned long data
    3: {},
},
#syslog
103:{
    #int type
    0: {},
    #char *buf
    1: {},
    #int len
    2: {},
},
#capget
125:{
    #cap_user_header_t header
    0: {},
    #cap_user_data_t dataptr
    1: {},
},
#capset
126:{
    #cap_user_header_t header
    0: {},
    #const cap_user_data_t data
    1: {},
},
#rt_sigpending
127:{
    #sigset_t *uset
    0: {},
    #size_t sigsetsize
    1: {},
},
#rt_sigtimedwait
128:{
    #const sigset_t *uthese
    0: {},
    #siginfo_t *uinfo
    1: {},
    #const struct __kernel_timespec *uts
    2: {},
    #size_t sigsetsize
    3: {},
},
#rt_sigqueueinfo
129:{
    #pid_t pid
    0: {},
    #int sig
    1: {},
    #siginfo_t *uinfo
    2: {},
},
#rt_sigsuspend
130:{
    #sigset_t *unewset
    0: {},
    #size_t sigsetsize
    1: {},
},
#sigaltstack
131:{
    #const stack_t *uss
    0: {},
    #stack_t *uoss
    1: {},
},
#mknod
133:{
    #const char *filename
    0: {},
    #umode_t mode
    1: {},
    #unsigned dev
    2: {},
},
#personality
135:{
    #unsigned int personality
    0: {},
},
#ustat
136:{
    #unsigned dev
    0: {},
    #struct ustat *ubuf
    1: {},
},
#sysfs
139:{
    #int option
    0: {},
    #unsigned long arg1
    1: {},
    #unsigned long arg2
    2: {},
},
#getpriority
140:{
    #int which
    0: {},
    #int who
    1: {},
},
#setpriority
141:{
    #int which
    0: {},
    #int who
    1: {},
    #int niceval
    2: {},
},
#sched_setparam
142:{
    #pid_t pid
    0: {},
    #struct sched_param *param
    1: {},
},
#sched_getparam
143:{
    #pid_t pid
    0: {},
    #struct sched_param *param
    1: {},
},
#sched_setscheduler
144:{
    #pid_t pid
    0: {},
    #int policy
    1: {},
    #struct sched_param *param
    2: {},
},
#sched_getscheduler
145:{
    #pid_t pid
    0: {},
},
#sched_get_priority_max
146:{
    #int policy
    0: {},
},
#sched_get_priority_min
147:{
    #int policy
    0: {},
},
#sched_rr_get_interval
148:{
    #pid_t pid
    0: {},
    #struct __kernel_timespec *interval
    1: {},
},
#mlockall
151:{
    #int flags
    0: {},
},
#modify_ldt
154:{
    #int func
    0: {},
    #void *ptr
    1: {},
    #unsigned long bytecount
    2: {},
},
#prctl
157:{
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
#arch_prctl
158:{
    #int option
    0: {},
    #unsigned long arg2
    1: {},
},
#setrlimit
160:{
    #unsigned int resource
    0: {},
    #struct rlimit *rlim
    1: {},
},
#mount
165:{
    #char *dev_name
    0: {},
    #char *dir_name
    1: {},
    #char *type
    2: {},
    #unsigned long flags
    3: {},
    #void *data
    4: {},
},
#umount
166:{
    #char *name
    0: {},
    #int flags
    1: {},
},
#swapon
167:{
    #const char *specialfile
    0: {},
    #int swap_flags
    1: {},
},
#swapoff
168:{
    #const char *specialfile
    0: {},
},
#reboot
169:{
    #int magic1
    0: {},
    #int magic2
    1: {},
    #unsigned int cmd
    2: {},
    #void *arg
    3: {},
},
#iopl
172:{
    #unsigned int level
    0: {},
},
#ioperm
173:{
    #unsigned long from
    0: {},
    #unsigned long num
    1: {},
    #int turn_on
    2: {},
},
#init_module
175:{
    #void *umod
    0: {},
    #unsigned long len
    1: {},
    #const char *uargs
    2: {},
},
#delete_module
176:{
    #const char *name_user
    0: {},
    #unsigned int flags
    1: {},
},
#quotactl
179:{
    #unsigned int cmd
    0: {},
    #const char *special
    1: {},
    #qid_t id
    2: {},
    #void *addr
    3: {},
},
#readahead
187:{
    #int fd
    0: {},
    #loff_t offset
    1: {},
    #size_t count
    2: {},
},
#setxattr
188:{
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
189:{
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
190:{
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
191:{
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
192:{
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
193:{
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
194:{
    #const char *pathname
    0: {},
    #char *list
    1: {},
    #size_t size
    2: {},
},
#llistxattr
195:{
    #const char *pathname
    0: {},
    #char *list
    1: {},
    #size_t size
    2: {},
},
#flistxattr
196:{
    #int fd
    0: {},
    #char *list
    1: {},
    #size_t size
    2: {},
},
#removexattr
197:{
    #const char *pathname
    0: {},
    #const char *name
    1: {},
},
#lremovexattr
198:{
    #const char *pathname
    0: {},
    #const char *name
    1: {},
},
#fremovexattr
199:{
    #int fd
    0: {},
    #const char *name
    1: {},
},
#tkill
200:{
    #pid_t pid
    0: {},
    #int sig
    1: {},
},
#time
201:{
    #__kernel_old_time_t *tloc
    0: {},
},
#futex
202:{
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
#sched_setaffinity
203:{
    #pid_t pid
    0: {},
    #unsigned int len
    1: {},
    #unsigned long *user_mask_ptr
    2: {},
},
#sched_getaffinity
204:{
    #pid_t pid
    0: {},
    #unsigned int len
    1: {},
    #unsigned long *user_mask_ptr
    2: {},
},
#io_setup
206:{
    #unsigned nr_events
    0: {},
    #aio_context_t *ctxp
    1: {},
},
#io_destroy
207:{
    #aio_context_t ctx
    0: {},
},
#io_getevents
208:{
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
},
#io_submit
209:{
    #aio_context_t ctx_id
    0: {},
    #long nr
    1: {},
    #struct iocb **iocbpp
    2: {},
},
#io_cancel
210:{
    #aio_context_t ctx_id
    0: {},
    #struct iocb *iocb
    1: {},
    #struct io_event *result
    2: {},
},
#epoll_create
213:{
    #int size
    0: {},
},
#remap_file_pages
216:{
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
#getdents64
217:{
    #unsigned int fd
    0: {},
    #struct linux_dirent64 *dirent
    1: {},
    #unsigned int count
    2: {},
},
#set_tid_address
218:{
    #int *tidptr
    0: {},
},
#restart_syscall
219:{
},
#semtimedop
220:{
    #int semid
    0: {},
    #struct sembuf *tsops
    1: {},
    #unsigned int nsops
    2: {},
    #const struct __kernel_timespec *timeout
    3: {},
},
#fadvise64
221:{
    #int fd
    0: {},
    #loff_t offset
    1: {},
    #size_t len
    2: {},
    #int advice
    3: {},
},
#timer_create
222:{
    #const clockid_t which_clock
    0: {},
    #struct sigevent *timer_event_spec
    1: {},
    #timer_t *created_timer_id
    2: {},
},
#timer_settime
223:{
    #timer_t timer_id
    0: {},
    #int flags
    1: {},
    #const struct __kernel_itimerspec *new_setting
    2: {},
    #struct __kernel_itimerspec *old_setting
    3: {},
},
#timer_gettime
224:{
    #timer_t timer_id
    0: {},
    #struct __kernel_itimerspec *setting
    1: {},
},
#timer_getoverrun
225:{
    #timer_t timer_id
    0: {},
},
#timer_delete
226:{
    #timer_t timer_id
    0: {},
},
#clock_settime
227:{
    #const clockid_t which_clock
    0: {},
    #const struct __kernel_timespec *tp
    1: {},
},
#clock_gettime
228:{
    #const clockid_t which_clock
    0: {},
    #struct __kernel_timespec *tp
    1: {},
},
#clock_getres
229:{
    #const clockid_t which_clock
    0: {},
    #struct __kernel_timespec *tp
    1: {},
},
#clock_nanosleep
230:{
    #const clockid_t which_clock
    0: {},
    #int flags
    1: {},
    #const struct __kernel_timespec *rqtp
    2: {},
    #struct __kernel_timespec *rmtp
    3: {},
},
#exit_group
231:{
    #int error_code
    0: {},
},
#epoll_wait
232:{
    #int epfd
    0: {},
    #struct epoll_event *events
    1: {},
    #int maxevents
    2: {},
    #int timeout
    3: {},
},
#epoll_ctl
233:{
    #int epfd
    0: {},
    #int op
    1: {},
    #int fd
    2: {},
    #struct epoll_event *event
    3: {},
},
#tgkill
234:{
    #pid_t tgid
    0: {},
    #pid_t pid
    1: {},
    #int sig
    2: {},
},
#mbind
237:{
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
#set_mempolicy
238:{
    #int mode
    0: {},
    #const unsigned long *nmask
    1: {},
    #unsigned long maxnode
    2: {},
},
#get_mempolicy
239:{
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
#mq_open
240:{
    #const char *u_name
    0: {},
    #int oflag
    1: {},
    #umode_t mode
    2: {},
    #struct mq_attr *u_attr
    3: {},
},
#mq_timedsend
242:{
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
243:{
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
#mq_notify
244:{
    #mqd_t mqdes
    0: {},
    #const struct sigevent *u_notification
    1: {},
},
#mq_getsetattr
245:{
    #mqd_t mqdes
    0: {},
    #const struct mq_attr *u_mqstat
    1: {},
    #struct mq_attr *u_omqstat
    2: {},
},
#kexec_load
246:{
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
247:{
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
248:{
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
249:{
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
250:{
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
251:{
    #int which
    0: {},
    #int who
    1: {},
    #int ioprio
    2: {},
},
#ioprio_get
252:{
    #int which
    0: {},
    #int who
    1: {},
},
#inotify_init
253:{
},
#inotify_add_watch
254:{
    #int fd
    0: {},
    #const char *pathname
    1: {},
    #u32 mask
    2: {},
},
#inotify_rm_watch
255:{
    #int fd
    0: {},
    #__s32 wd
    1: {},
},
#migrate_pages
256:{
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
257:{
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
258:{
    #int dfd
    0: {},
    #const char *pathname
    1: {},
    #umode_t mode
    2: {},
},
#mknodat
259:{
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
260:{
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
261:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #struct __kernel_old_timeval *utimes
    2: {},
},
#newfstatat
262:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #struct stat *statbuf
    2: {},
    #int flag
    3: {},
},
#unlinkat
263:{
    #int dfd
    0: {},
    #const char *pathname
    1: {},
    #int flag
    2: {},
},
#renameat
264:{
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
265:{
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
266:{
    #const char *oldname
    0: {},
    #int newdfd
    1: {},
    #const char *newname
    2: {},
},
#readlinkat
267:{
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
268:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #umode_t mode
    2: {},
},
#faccessat
269:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #int mode
    2: {},
},
#pselect6
270:{
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
271:{
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
#unshare
272:{
    #unsigned long unshare_flags
    0: {},
},
#set_robust_list
273:{
    #struct robust_list_head *head
    0: {},
    #size_t len
    1: {},
},
#get_robust_list
274:{
    #int pid
    0: {},
    #struct robust_list_head **head_ptr
    1: {},
    #size_t *len_ptr
    2: {},
},
#splice
275:{
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
#tee
276:{
    #int fdin
    0: {},
    #int fdout
    1: {},
    #size_t len
    2: {},
    #unsigned int flags
    3: {},
},
#sync_file_range
277:{
    #int fd
    0: {},
    #loff_t offset
    1: {},
    #loff_t nbytes
    2: {},
    #unsigned int flags
    3: {},
},
#vmsplice
278:{
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
279:{
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
#utimensat
280:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #struct __kernel_timespec *utimes
    2: {},
    #int flags
    3: {},
},
#epoll_pwait
281:{
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
#signalfd
282:{
    #int ufd
    0: {},
    #sigset_t *user_mask
    1: {},
    #size_t sizemask
    2: {},
},
#timerfd_create
283:{
    #int clockid
    0: {},
    #int flags
    1: {},
},
#eventfd
284:{
    #unsigned int count
    0: {},
},
#fallocate
285:{
    #int fd
    0: {},
    #int mode
    1: {},
    #loff_t offset
    2: {},
    #loff_t len
    3: {},
},
#timerfd_settime
286:{
    #int ufd
    0: {},
    #int flags
    1: {},
    #const struct __kernel_itimerspec *utmr
    2: {},
    #struct __kernel_itimerspec *otmr
    3: {},
},
#timerfd_gettime
287:{
    #int ufd
    0: {},
    #struct __kernel_itimerspec *otmr
    1: {},
},
#accept4
288:{
    #int fd
    0: {},
    #struct sockaddr *upeer_sockaddr
    1: {},
    #int *upeer_addrlen
    2: {},
    #int flags
    3: {},
},
#signalfd4
289:{
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
290:{
    #unsigned int count
    0: {},
    #int flags
    1: {},
},
#epoll_create1
291:{
    #int flags
    0: {},
},
#dup3
292:{
    #unsigned int oldfd
    0: {},
    #unsigned int newfd
    1: {},
    #int flags
    2: {},
},
#pipe2
293:{
    #int *fildes
    0: {},
    #int flags
    1: {},
},
#inotify_init1
294:{
    #int flags
    0: {},
},
#preadv
295:{
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
296:{
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
297:{
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
298:{
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
299:{
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
#fanotify_init
300:{
    #unsigned int flags
    0: {},
    #unsigned int event_f_flags
    1: {},
},
#fanotify_mark
301:{
    #int fanotify_fd
    0: {},
    #unsigned int flags
    1: {},
    #__u64 mask
    2: {},
    #int dfd
    3: {},
    #const char *pathname
    4: {},
},
#prlimit64
302:{
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
303:{
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
304:{
    #int mountdirfd
    0: {},
    #struct file_handle *handle
    1: {},
    #int flags
    2: {},
},
#clock_adjtime
305:{
    #const clockid_t which_clock
    0: {},
    #struct __kernel_timex *utx
    1: {},
},
#syncfs
306:{
    #int fd
    0: {},
},
#sendmmsg
307:{
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
308:{
    #int fd
    0: {},
    #int flags
    1: {},
},
#getcpu
309:{
    #unsigned *cpup
    0: {},
    #unsigned *nodep
    1: {},
    #struct getcpu_cache *unused
    2: {},
},
#process_vm_readv
310:{
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
311:{
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
312:{
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
313:{
    #int fd
    0: {},
    #const char *uargs
    1: {},
    #int flags
    2: {},
},
#sched_setattr
314:{
    #pid_t pid
    0: {},
    #struct sched_attr *uattr
    1: {},
    #unsigned int flags
    2: {},
},
#sched_getattr
315:{
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
316:{
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
317:{
    #unsigned int op
    0: {},
    #unsigned int flags
    1: {},
    #void *uargs
    2: {},
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
    4: {},
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
