#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from libdebug.architectures.syscall_arg_parser import or_parse, sequential_parse
from libdebug.utils.gnu_constants import GnuConstants

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


def parse_fcntl_arg(cmd: int, arg: int) -> str:
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


AMD64_SYSCALL_PARSER_MAP = {
    # open
    2: {
        # int flags
        1: GnuConstants.OPEN_FLAGS,
        # umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    # lseek
    8: {
        # unsigned int whence
        2: GnuConstants.LSEEK_WHENCE,
    },
    # mmap
    9: {
        # unsigned long prot
        2: GnuConstants.MMAP_PROT,
        # unsigned long flags
        3: {
            GnuConstants.MMAP_FLAGS_COMMON + {0x00000040: "MAP_32BIT"},
        },
    },
    # mprotect
    10: {
        # unsigned long prot
        2: GnuConstants.MPROTECT_PROT,
    },
    # rt_sigaction
    13: {
        # int sig
        0: GnuConstants.SIGNALS,
    },
    # rt_sigprocmask
    14: {
        # int how
        0: GnuConstants.RT_SIGPROCMASK_HOW,
    },
    # access
    21: {
        # int mode
        1: GnuConstants.ACCESS_MODES,
    },
    # mremap
    25: {
        # unsigned long flags
        3: GnuConstants.MREMAP_FLAGS,
    },
    # msync
    26: {
        # int flags
        2: GnuConstants.MSYNC_FLAGS,
    },
    # madvise
    28: {
        # int behavior
        2: GnuConstants.ADVISE_BEHAVIORS,
    },
    # shmget
    29: {
        # int shmflg
        2: GnuConstants.SHMGET_FLAGS,
    },
    # shmat
    30: {
        # int shmflg
        2: GnuConstants.SHMAT_FLAGS,
    },
    # shmctl
    31: {
        # int cmd
        1: GnuConstants.SHMCTL_CMDS,
    },
    # getitimer
    36: {
        # int which
        0: GnuConstants.ITIMER_WHICH,
    },
    # setitimer
    38: {
        # int which
        0: GnuConstants.ITIMER_WHICH,
    },
    # socket
    41: {
        # int family
        0: GnuConstants.SOCKET_FAMILIES,
        # int type
        1: GnuConstants.SOCKET_TYPES,
        # int protocol
        # Note: Protocol is not parsed here, as it is often 0
    },
    # sendto
    44: {
        # unsigned int flags
        3: GnuConstants.SENDTO_FLAGS,
    },
    # recvfrom
    45: {
        # unsigned int flags
        3: GnuConstants.RECV_FLAGS,
    },
    # sendmsg
    46: {
        # unsigned int flags
        2: GnuConstants.SENDMSG_FLAGS,
    },
    # recvmsg
    47: {
        # unsigned int flags
        2: GnuConstants.RECVMMSG_FLAGS,
    },
    # shutdown
    48: {
        # int how
        1: GnuConstants.SHUTDOWN_HOW,
    },
    # socketpair
    53: {
        # int family
        0: GnuConstants.SOCKET_FAMILIES,
        # int type
        1: GnuConstants.SOCKET_TYPES,
        # int protocol
        # Note: Protocol is not parsed here, as it is often 0
    },
    # setsockopt
    54: {
        # TODO: Complex parsing, future work
        # int level
        1: {},
        # SO_ACCEPTCONN, SO_ATTACH_FILTER, SO_ATTACH_BPF, SO_ATTACH_REUSEPORT_CBPF, SO_ATTACH_REUSEPORT_EBPF, SO_BINDTODEVICE, SO_BROADCAST, SO_BSDCOMPAT, SO_DEBUG, SO_DETACH_FILTER, SO_DETACH_BPF, SO_DOMAIN, SO_ERROR, SO_DONTROUTE,
        # SO_INCOMING_CPU, SO_INCOMING_NAPI_ID, SO_KEEPALIVE, SO_LINGER, SO_LOCK_FILTER, SO_MARK, SO_OOBINLINE, SO_PASSCRED, SO_PASSSEC, SO_PEEK_OFF, SO_PEERCRED, SO_PEERSEC, SO_PRIORITY, SO_RCVBUF, SO_RCVBUFFORCE, SO_RCVLOWAT,
        # SO_SNDLOWAT, SO_RCVTIMEO, SO_SNDTIMEO, SO_REUSEADDR, SO_REUSEPORT, SO_RXQ_OVFL, SO_SELECT_ERR_QUEUE, SO_SNDBUF, SO_SNDBUFFORCE, SO_TIMESTAMP, SO_TIMESTAMPNS, SO_TYPE, SO_BUSY_POLL
        # int optname
        2: {},
    },
    # getsockopt
    55: {
        # TODO: Complex parsing, future work
        # int level
        1: {},
        # int optname
        2: {},
    },
    # clone
    56: {
        # unsigned long clone_flags
        0: GnuConstants.CLONE_FLAGS_COMMON,
    },
    # wait4
    61: {
        # int options
        2: GnuConstants.WAIT4_OPTIONS,
    },
    # kill
    62: {
        # int sig
        1: GnuConstants.SIGNALS,
    },
    # semget
    64: {
        # key_t key
        0: GnuConstants.SEMGET_KEYS,
        # int semflg
        2: GnuConstants.SEMGET_FLAGS,
    },
    # semctl
    66: {
        # int cmd
        2: GnuConstants.SEMCTL_CMDS,
    },
    # msgget
    68: {
        # key_t key
        0: GnuConstants.MSGGET_KEYS,
        # int msgflg
        2: GnuConstants.MSGGET_FLAGS,
    },
    # msgsnd
    69: {
        # int msgflg
        3: GnuConstants.MSGSND_FLAGS,
    },
    # msgrcv
    70: {
        # int msgflg
        4: GnuConstants.MSGRCV_FLAGS,
    },
    # msgctl
    71: {
        # int cmd
        1: GnuConstants.MSGCTL_CMDS,
    },
    # fcntl
    72: {
        # unsigned int cmd
        1: GnuConstants.FCNTL_CMDS,
        # unsigned long arg
        2: {
            "parsing_mode": "custom",
            "parser": parse_fcntl_arg,
        },
    },
    # flock
    73: {
        # unsigned int cmd
        1: GnuConstants.FLOCK_CMDS,
    },
    # mkdir
    83: {
        # umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    # creat
    85: {
        # umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    # chmod
    90: {
        # umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    # fchmod
    91: {
        # umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    # umask
    95: {
        # int mask
        0: GnuConstants.OPEN_MODES,
    },
    # getrlimit
    97: {
        # unsigned int resource
        0: GnuConstants.RLIMIT_RESOURCES,
    },
    # getrusage
    98: {
        # int who
        0: GnuConstants.RUSAGE_WHO,
    },
    # ptrace
    101: {
        # long request
        0: GnuConstants.PTRACE_COMMON_REQUESTS
        + {
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
        },
        # unsigned long data
        3: {
            "parsing_mode": "custom",
            "parser": parse_ptrace_data,
        },
    },
    # syslog
    103: {
        # int type
        0: GnuConstants.SYSLOG_TYPES,
    },
    # rt_sigqueueinfo
    129: {
        # int sig
        1: GnuConstants.SIGNALS,
    },
    # mknod
    133: {
        # umode_t mode
        1: GnuConstants.MKNOD_MODES,
    },
    # personality
    135: {
        # unsigned int personality
        0: GnuConstants.PROCESS_PERSONALITIES,
    },
    # getpriority
    140: {
        # int which
        0: GnuConstants.PRIORITY_WHICH,
    },
    # setpriority
    141: {
        # int which
        0: GnuConstants.PRIORITY_WHICH,
    },
    # sched_setscheduler
    144: {
        # int policy
        1: GnuConstants.SCHEDULER_POLICIES,
    },
    # sched_get_priority_max
    146: {
        # int policy
        0: GnuConstants.SCHEDULER_POLICIES,
    },
    # sched_get_priority_min
    147: {
        # int policy
        0: GnuConstants.SCHEDULER_POLICIES,
    },
    # mlockall
    151: {
        # int flags
        0: GnuConstants.MLOCKALL_FLAGS,
    },
    # prctl
    157: {
        # int option
        0: GnuConstants.PRCTL_OPTIONS,
    },
    # arch_prctl
    158: {
        # int option
        0: {
            0x1001: "ARCH_SET_GS",
            0x1002: "ARCH_SET_FS",
            0x1003: "ARCH_GET_FS",
            0x1004: "ARCH_GET_GS",
            0x1011: "ARCH_GET_CPUID",
            0x1012: "ARCH_SET_CPUID",
            # From linux / arch / x86 / include / uapi / asm / prctl.h
            # Undocumented, unsure if they should be included
            # define ARCH_GET_XCOMP_SUPP		0x1021
            # define ARCH_GET_XCOMP_PERM		0x1022
            # define ARCH_REQ_XCOMP_PERM		0x1023
            # define ARCH_GET_XCOMP_GUEST_PERM	0x1024
            # define ARCH_REQ_XCOMP_GUEST_PERM	0x1025
            # define ARCH_XCOMP_TILECFG		17
            # define ARCH_XCOMP_TILEDATA		18
            # define ARCH_MAP_VDSO_X32		0x2001
            # define ARCH_MAP_VDSO_32		0x2002
            # define ARCH_MAP_VDSO_64		0x2003
            # /* Don't use 0x3001-0x3004 because of old glibcs */
            # define ARCH_GET_UNTAG_MASK		0x4001
            # define ARCH_ENABLE_TAGGED_ADDR		0x4002
            # define ARCH_GET_MAX_TAG_BITS		0x4003
            # define ARCH_FORCE_TAGGED_SVA		0x4004
            # define ARCH_SHSTK_ENABLE		0x5001
            # define ARCH_SHSTK_DISABLE		0x5002
            # define ARCH_SHSTK_LOCK			0x5003
            # define ARCH_SHSTK_UNLOCK		0x5004
            # define ARCH_SHSTK_STATUS		0x5005
        },
    },
    # setrlimit
    160: {
        # unsigned int resource
        0: GnuConstants.RLIMIT_RESOURCES,
    },
    # mount
    165: {
        # unsigned long flags
        3: GnuConstants.MOUNT_FLAGS,
    },
    # umount
    166: {
        # int flags
        1: GnuConstants.UMOUNT_FLAGS,
    },
    # swapon
    167: {
        # int swap_flags
        1: GnuConstants.SWAPON_FLAGS,
    },
    # reboot
    169: {
        # int magic1
        0: GnuConstants.REBOOT_MAGIC1,
        # int magic2
        1: GnuConstants.REBOOT_MAGIC2,
        # unsigned int cmd
        2: GnuConstants.REBOOT_CMDS,
    },
    # delete_module
    176: {
        # unsigned int flags
        1: GnuConstants.DELETE_MODULE_FLAGS,
    },
    # quotactl
    179: {
        # unsigned int cmd
        0: GnuConstants.QUOTACTL_CMDS,
        # Technically if cmd is Q_QUOTAON,
        # we could parse the ID with QFMT defines but
        # it's likely not worth it
    },
    # setxattr
    188: {
        # int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    # lsetxattr
    189: {
        # int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    # fsetxattr
    190: {
        # int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    # tkill
    200: {
        # int sig
        1: GnuConstants.SIGNALS,
    },
    # futex
    202: {
        # int op
        1: GnuConstants.FUTEX_OPS,
    },
    # remap_file_pages
    216: {
        # unsigned long flags
        4: GnuConstants.REMAP_FILE_PAGES_FLAGS,
    },
    # fadvise64
    221: {
        # int advice
        3: GnuConstants.FADVISE_ADVICE,
    },
    # timer_settime
    223: {
        # int flags
        1: GnuConstants.TIMER_SETTIME_FLAGS,
    },
    # clock_settime
    227: {
        # const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    # clock_gettime
    228: {
        # const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    # clock_getres
    229: {
        # const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    # clock_nanosleep
    230: {
        # const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
        # int flags
        1: GnuConstants.CLOCK_NANOSLEEP_FLAGS,
    },
    # epoll_ctl
    233: {
        # int op
        1: GnuConstants.EPOLL_CTL_OPS,
    },
    # tgkill
    234: {
        # int sig
        2: GnuConstants.SIGNALS,
    },
    # mbind
    237: {
        # unsigned long mode
        2: GnuConstants.MBIND_MODES,
        # unsigned int flags
        5: GnuConstants.MBIND_FLAGS,
    },
    # set_mempolicy
    238: {
        # int mode
        0: GnuConstants.SETMEMPOLICY_MODES,
    },
    # get_mempolicy
    239: {
        # unsigned long flags
        4: GnuConstants.GETMEMPOLICY_FLAGS,
    },
    # mq_open
    240: {
        # int oflag
        1: GnuConstants.MQ_OPEN_FLAGS,
        # umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    # kexec_load
    246: {
        # unsigned long flags
        3: GnuConstants.KEXEC_LOAD_FLAGS,
    },
    # waitid
    247: {
        # int which
        0: GnuConstants.WAITID_WHICH,
        # int options
        3: GnuConstants.WAITID_OPTIONS,
    },
    # add_key
    248: {
        # key_serial_t ringid
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
    # request_key
    249: {
        # key_serial_t destringid
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
    # keyctl
    250: {
        # int option
        0: GnuConstants.KEYCTL_OPTIONS,
    },
    # ioprio_set
    251: {
        # int which
        0: GnuConstants.IOPRIO_WHICH,
    },
    # ioprio_get
    252: {
        # int which
        0: GnuConstants.IOPRIO_WHICH,
    },
    # openat
    257: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # int flags
        2: GnuConstants.OPEN_FLAGS,
        # umode_t mode
        3: GnuConstants.OPEN_MODES,
    },
    # mkdirat
    258: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    # mknodat
    259: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # umode_t mode
        2: GnuConstants.MKNOD_MODES,
    },
    # fchownat
    260: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # int flag
        4: GnuConstants.FCHOWNAT_FLAGS,
    },
    # newfstatat
    262: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # int flag
        3: GnuConstants.NEWSTATFS_FLAGS,
    },
    # unlinkat
    263: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # int flag
        2: GnuConstants.UNLINKAT_FLAGS,
    },
    # renameat
    264: {
        # int olddfd
        0: GnuConstants.OPENAT_DFD,
    },
    # linkat
    265: {
        # int olddfd
        0: GnuConstants.OPENAT_DFD,
        # int newdfd
        2: GnuConstants.OPENAT_DFD,
        # int flags
        4: GnuConstants.LINKAT_FLAGS,
    },
    # symlinkat
    266: {
        # int newdfd
        1: GnuConstants.OPENAT_DFD,
    },
    # readlinkat
    267: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
    },
    # fchmodat
    268: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    # faccessat
    269: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # int mode
        2: GnuConstants.OPEN_MODES,
    },
    # unshare
    272: {
        # unsigned long unshare_flags
        0: GnuConstants.UNSHARE_FLAGS,
    },
    # splice
    275: {
        # unsigned int flags
        5: GnuConstants.SPLICE_FLAGS,
    },
    # tee
    276: {
        # unsigned int flags
        3: GnuConstants.SPLICE_FLAGS,
    },
    # sync_file_range
    277: {
        # unsigned int flags
        3: GnuConstants.SYNC_FILE_RANGE_FLAGS,
    },
    # vmsplice
    278: {
        # unsigned int flags
        3: GnuConstants.SPLICE_FLAGS,
    },
    # move_pages
    279: {
        # int flags
        5: GnuConstants.MOVEPAGES_FLAGS,
    },
    # utimensat
    280: {
        # int flags
        3: GnuConstants.UTIMENSAT_FLAGS,
    },
    # timerfd_create
    283: {
        # int clockid
        0: GnuConstants.TIMERFD_CREATE_CLOCKS,
        # int flags
        1: GnuConstants.TIMERFD_CREATE_FLAGS,
    },
    # fallocate
    285: {
        # int mode
        1: GnuConstants.FALLOCATE_MODES,
    },
    # timerfd_settime
    286: {
        # int flags
        1: GnuConstants.TIMERFD_SETTIME_FLAGS,
    },
    # accept4
    288: {
        # int flags
        3: GnuConstants.ACCEPT_FLAGS,
    },
    # signalfd4
    289: {
        # int flags
        3: GnuConstants.SIGNALFD_FLAGS,
    },
    # eventfd2
    290: {
        # int flags
        1: GnuConstants.EVENTFD_FLAGS,
    },
    # epoll_create1
    291: {
        # int flags
        0: GnuConstants.EPOLL_CREATE_FLAGS,
    },
    # dup3
    292: {
        # int flags
        2: GnuConstants.DUP3_FLAGS,
    },
    # pipe2
    293: {
        # int flags
        1: GnuConstants.PIPE2_FLAGS,
    },
    # inotify_init1
    294: {
        # int flags
        0: GnuConstants.INOTIFY_INIT_FLAGS,
    },
    # rt_tgsigqueueinfo
    297: {
        # int sig
        2: GnuConstants.SIGNALS,
    },
    # perf_event_open
    298: {
        # unsigned long flags
        4: GnuConstants.PERF_EVENT_OPEN_FLAGS,
    },
    # recvmmsg
    299: {
        # unsigned int flags
        3: GnuConstants.RECVMMSG_FLAGS,
    },
    # fanotify_init
    300: {
        # unsigned int flags
        0: GnuConstants.FANOTIFY_INIT_FLAGS,
        # unsigned int event_f_flags
        1: GnuConstants.OPEN_FLAGS,
    },
    # fanotify_mark
    301: {
        # unsigned int flags
        1: GnuConstants.FANOTIFY_MARK_FLAGS,
        # __u64 mask
        2: GnuConstants.FANOTIFY_MARK_MASK,
        # int dfd
        3: GnuConstants.OPENAT_DFD,
    },
    # prlimit64
    302: {
        # unsigned int resource
        1: GnuConstants.PRLIMIT_RESOURCES,
    },
    # name_to_handle_at
    303: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # int flag
        4: GnuConstants.NAME_TO_HANDLE_FLAGS,
    },
    # open_by_handle_at
    304: {
        # int mountdirfd
        0: GnuConstants.OPENAT_DFD,
        # int flags
        2: GnuConstants.OPEN_FLAGS,
    },
    # clock_adjtime
    305: {
        # const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    # sendmmsg
    307: {
        # unsigned int flags
        3: GnuConstants.SENDTO_FLAGS,
    },
    # setns
    308: {
        # int flags
        1: GnuConstants.SETNS_FLAGS,
    },
    # kcmp
    312: {
        # int type
        2: GnuConstants.KCMP_TYPES,
    },
    # finit_module
    313: {
        # int flags
        2: GnuConstants.FINIT_MODULE_FLAGS,
    },
    # renameat2
    316: {
        # int olddfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned int flags
        4: GnuConstants.RENAMEAT_FLAGS,
    },
    # seccomp
    317: {
        # unsigned int op
        0: GnuConstants.SECCOMP_OPS,
        # unsigned int flags
        1: GnuConstants.SECCOMP_FLAGS,
    },
    # getrandom
    318: {
        # unsigned int flags
        2: GnuConstants.GETRANDOM_FLAGS,
    },
    # memfd_create
    319: {
        # unsigned int flags
        1: GnuConstants.MEMFD_CREATE_FLAGS,
    },
    # kexec_file_load
    320: {
        # unsigned long flags
        4: GnuConstants.KEXEC_FILE_LOAD_FLAGS,
    },
    # bpf
    321: {
        # int cmd
        0: GnuConstants.BPF_CMDS,
    },
    # execveat
    322: {
        # int fd
        0: GnuConstants.OPENAT_DFD,
        # int flags
        4: GnuConstants.EXECVEAT_FLAGS,
    },
    # userfaultfd
    323: {
        # int flags
        0: GnuConstants.USERFAULTFD_FLAGS,
    },
    # membarrier
    324: {
        # int cmd
        0: GnuConstants.MEMBARRIER_CMDS,
        # unsigned int flags
        1: GnuConstants.MEMBARRIER_FLAGS,
    },
    # mlock2
    325: {
        # int flags
        2: GnuConstants.MLOCK_FLAGS,
    },
    # preadv2
    327: {
        # rwf_t flags
        5: GnuConstants.PREADV_FLAGS,
    },
    # pwritev2
    328: {
        # rwf_t flags
        5: GnuConstants.PREADV_FLAGS,
    },
    # pkey_mprotect
    329: {
        # unsigned long prot
        2: GnuConstants.PKEY_MPROTECT_PROTS,
    },
    # pkey_alloc
    330: {
        # unsigned long init_val
        1: GnuConstants.PKEY_ALLOC_INIT_VALS,
    },
    # statx
    332: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned flags
        2: GnuConstants.STATX_FLAGS,
        #unsigned int mask
        3: GnuConstants.STATX_MASKS,
    },
    # rseq
    334: {
        # int flags
        2: GnuConstants.RSEQ_FLAGS,
    },
    # pidfd_send_signal
    424: {
        # int sig
        1: GnuConstants.SIGNALS,
        # unsigned int flags
        3: GnuConstants.PIDFD_SEND_SIGNAL_FLAGS,
    },
    # io_uring_enter
    426: {
        #u32 flags
        2: GnuConstants.IO_URING_ENTER_FLAGS,
    },
    # io_uring_register
    427: {
        # unsigned int opcode
        1: GnuConstants.IO_URING_REGISTER_OPCODES,
    },
    # open_tree
    428: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned flags
        2: GnuConstants.OPENTREE_FLAGS,
    },
    # move_mount
    429: {
        # int from_dfd
        0: GnuConstants.OPENAT_DFD,
        # int to_dfd
        2: GnuConstants.OPENAT_DFD,
        # unsigned int flags
        4: GnuConstants.MOVE_MOUNT_FLAGS,
    },
    # fsopen
    430: {
        # unsigned int flags
        1: GnuConstants.FSOPEN_FLAGS,
    },
    # fsconfig
    431: {
        # unsigned int cmd
        1: GnuConstants.FSCONFIG_CMDS,
    },
    # fsmount
    432: {
        # unsigned int flags
        1: GnuConstants.FSMOUNT_FLAGS,
        # unsigned int attr_flags
        2: GnuConstants.FSMOUNT_ATTR_FLAGS,
    },
    # fspick
    433: {
        # int dfd
        0: {
            GnuConstants.OPENAT_DFD,
        },
        # unsigned int flags
        2: GnuConstants.FSPICK_FLAGS,
    },
    # pidfd_open
    434: {
        # unsigned int flags
        1: GnuConstants.PIDFD_OPEN_FLAGS,
    },
    # close_range
    436: {
        # unsigned int flags
        2: GnuConstants.CLOSE_RANGE_FLAGS,
    },
    # openat2
    437: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
    },
    # faccessat2
    439: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # int mode
        2: GnuConstants.OPEN_MODES,
        # int flags
        3: GnuConstants.FACCESSAT_FLAGS,
    },
    # process_madvise
    440: {
        # int behavior
        3: GnuConstants.ADVISE_BEHAVIORS,
    },
    # mount_setattr
    442: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned int flags
        2: GnuConstants.MOUNT_SETATTR_FLAGS,
    },
    # landlock_create_ruleset
    444: {
        # const __u32 flags
        2: GnuConstants.LANDLOCK_CREATE_RULESET_FLAGS,
    },
    # landlock_add_rule
    445: {
        # const enum landlock_rule_type rule_type
        1: GnuConstants.LANDLOCK_ADD_RULE_TYPES,
    },
    # memfd_secret
    447: {
        # unsigned int flags
        0: GnuConstants.MEMFD_SECRET_FLAGS,
    },
    # futex_waitv
    449: {
        # clockid_t clockid
        4: GnuConstants.WHICH_CLOCK,
    },
    # cachestat
    451: {
        # unsigned int fd
        0: GnuConstants.OPENAT_DFD,
    },
    # fchmodat2
    452: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # umode_t mode
        2: GnuConstants.OPEN_MODES,
        # unsigned int flags
        3: GnuConstants.FCHMODAT_FLAGS,
    },
    # map_shadow_stack
    453: {
        # unsigned int flags
        2: GnuConstants.MAP_SHADOW_STACK_FLAGS,
    },
    # futex_wait
    455: {
        # clockid_t clockid
        5: GnuConstants.WHICH_CLOCK,
    },
    # listmount
    458: {
        # unsigned int flags
        3: GnuConstants.LISTMOUNT_FLAGS,
    },
    # lsm_get_self_attr
    459: {
        # u32 flags
        3: GnuConstants.LSM_GET_SELF_ATTR_FLAGS,
    },
    # setxattrat
    463: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
    # getxattrat
    464: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
    },
    # listxattrat
    465: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
    # removexattrat
    466: {
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
}
