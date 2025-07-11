#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.utils.gnu_constants import GnuConstants

# !!! Parsing Values are up to date with Linux Kernel 6.15 !!!

#TODO: Check if we can use the same parser for x86_64
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

AARCH64_SYSCALL_PARSER_MAP = \
{
    #setxattr
    5:{
        #int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    #lsetxattr
    6:{
        #int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    #fsetxattr
    7:{
        #int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    #eventfd2
    19:{
        #int flags
        1: GnuConstants.EVENTFD_FLAGS,
    },
    #epoll_create1
    20:{
        #int flags
        0: GnuConstants.EPOLL_CREATE_FLAGS,
    },
    #epoll_ctl
    21:{
        #int op
        1: GnuConstants.EPOLL_CTL_OPS,
    },
    #dup3
    24:{
        #int flags
        2: GnuConstants.DUP3_FLAGS,
    },
    #fcntl
    25:{
        #unsigned int cmd
        1: GnuConstants.FCNTL_CMDS,
        #unsigned long arg
        2: {
            "parsing_mode": "custom",
            "parser": GnuConstants.parse_fcntl_arg,
        },
    },
    #inotify_init1
    26:{
        #int flags
        0: GnuConstants.INOTIFY_INIT_FLAGS,
    },
    #ioprio_set
    30:{
        #int which
        0: GnuConstants.IOPRIO_WHICH,
    },
    #ioprio_get
    31:{
        #int which
        0: GnuConstants.IOPRIO_WHICH,
    },
    #flock
    32:{
        #unsigned int cmd
        1: GnuConstants.FLOCK_CMDS,
    },
    #mknodat
    33:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #umode_t mode
        2: GnuConstants.MKNOD_MODES,
    },
    #mkdirat
    34:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    #unlinkat
    35:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        2: GnuConstants.UNLINKAT_FLAGS,
    },
    #symlinkat
    36:{
        #int newdfd
        1: GnuConstants.OPENAT_DFD,
    },
    #linkat
    37:{
        #int olddfd
        0: GnuConstants.OPENAT_DFD,
        #int newdfd
        2: GnuConstants.OPENAT_DFD,
        #int flags
        4: GnuConstants.LINKAT_FLAGS,
    },
    #renameat
    38:{
        #int olddfd
        0: GnuConstants.OPENAT_DFD,
    },
    #umount
    39:{
        #int flags
        1: GnuConstants.UMOUNT_FLAGS,
    },
    #mount
    40:{
        #unsigned long flags
        3: GnuConstants.MOUNT_FLAGS,
    },
    #fallocate
    47:{
        #int mode
        1: GnuConstants.FALLOCATE_MODES,
    },
    #faccessat
    48:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int mode
        2: GnuConstants.OPEN_MODES,
    },
    #fchmod
    52:{
        #umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    #fchmodat
    53:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    #fchownat
    54:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        4: GnuConstants.FCHOWNAT_FLAGS,
    },
    #openat
    56:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flags
        2: GnuConstants.OPEN_FLAGS,
        #umode_t mode
        3: GnuConstants.OPEN_MODES,
    },
    #pipe2
    59:{
        #int flags
        1: GnuConstants.PIPE2_FLAGS,
    },
    #quotactl
    60:{
        #unsigned int cmd
        0: GnuConstants.QUOTACTL_CMDS,
        # Technically if cmd is Q_QUOTAON,
        # we could parse the ID with QFMT defines but
        # it's likely not worth it
    },
    #lseek
    62:{
        #unsigned int whence
        2: GnuConstants.LSEEK_WHENCE,
    },
    #signalfd4
    74:{
        #int flags
        3: GnuConstants.SIGNALFD_FLAGS,
    },
    #vmsplice
    75:{
        #unsigned int flags
        3: GnuConstants.VMSPLICE_FLAGS,
    },
    #splice
    76:{
        #unsigned int flags
        5: GnuConstants.SPLICE_FLAGS,
    },
    #tee
    77:{
        #unsigned int flags
        3: GnuConstants.SPLICE_FLAGS,
    },
    #readlinkat
    78:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
    },
    #newfstatat
    79:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        3: GnuConstants.NEWSTATFS_FLAGS,
    },
    #sync_file_range
    84:{
        #unsigned int flags
        3: GnuConstants.SYNC_FILE_RANGE_FLAGS,
    },
    #timerfd_create
    85:{
        #int clockid
        0: GnuConstants.TIMERFD_CREATE_CLOCKS,
        #int flags
        1: GnuConstants.TIMERFD_CREATE_FLAGS,
    },
    #timerfd_settime
    86:{
        #int flags
        1: GnuConstants.TIMERFD_SETTIME_FLAGS,
    },
    #utimensat
    88:{
        #int flags
        3: GnuConstants.UTIMENSAT_FLAGS,
    },
    #personality
    92:{
        #unsigned int personality
        0: GnuConstants.PROCESS_PERSONALITIES | {
            0x0080000: "PER_LINUX_FDPIC | FDPIC_FUNCPTRS", # Applies only to ARM and SuperH
        },
    },
    #waitid
    95:{
        #int which
        0: GnuConstants.WAITID_WHICH,
        #int options
        3: GnuConstants.WAITID_OPTIONS,
    },
    #unshare
    97:{
        #unsigned long unshare_flags
        0: GnuConstants.UNSHARE_FLAGS,
    },
    #futex
    98:{
        #int op
        1: GnuConstants.FUTEX_OPS,
    },
    #getitimer
    102:{
        #int which
        0: GnuConstants.ITIMER_WHICH,
    },
    #setitimer
    103:{
        #int which
        0: GnuConstants.ITIMER_WHICH,
    },
    #kexec_load
    104:{
        #unsigned long flags
        3: GnuConstants.KEXEC_LOAD_FLAGS,
    },
    #delete_module
    106:{
        #unsigned int flags
        1: GnuConstants.DELETE_MODULE_FLAGS,
    },
    #timer_create
    107:{
        #const clockid_t which_clock
        0: GnuConstants.TIMER_CREATE_WHICH_CLOCK,
    },
    #timer_settime
    110:{
        #int flags
        1: GnuConstants.TIMER_SETTIME_FLAGS,
    },
    #clock_settime
    112:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_gettime
    113:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_getres
    114:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_nanosleep
    115:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
        #int flags
        1: GnuConstants.CLOCK_NANOSLEEP_FLAGS,
    },
    #syslog
    116:{
        #int type
        0: GnuConstants.SYSLOG_TYPES,
    },
    #ptrace
    117:{
        #long request
        0: GnuConstants.PTRACE_COMMON_REQUESTS | {
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
            12: "PTRACE_GETREGS",
            13: "PTRACE_SETREGS",
            14: "PTRACE_GETFPREGS",
            15: "PTRACE_SETFPREGS",
            16: "PTRACE_ATTACH",
            17: "PTRACE_DETACH",
            18: "PTRACE_GETWMMXREGS",
            19: "PTRACE_SETWMMXREGS",
            21: "PTRACE_OLDSETOPTIONS",
            22: "PTRACE_GET_THREAD_AREA",
            23: "PTRACE_SET_SYSCALL",
            24: "PTRACE_SYSCALL",
            25: "PTRACE_GETCRUNCHREGS", # Should be obsolete
            26: "PTRACE_SETCRUNCHREGS", # Should be obsolete
            27: "PTRACE_GETVFPREGS",
            28: "PTRACE_SETVFPREGS",
            29: "PTRACE_GETHBPREGS",
            30: "PTRACE_SETHBPREGS",
            31: "PTRACE_GETFDPIC",
            "PTRACE_GETFDPIC_EXEC": 0,
            "PTRACE_GETFDPIC_INTERP": 1,
        },
        #unsigned long data
        3: {
            "parsing_mode": "custom",
            "parser": parse_ptrace_data,
        },
    },
    #sched_setscheduler
    119:{
        #int policy
        1: GnuConstants.SCHEDULER_POLICIES,
    },
    #sched_get_priority_max
    125:{
        #int policy
        0: GnuConstants.SCHEDULER_POLICIES,
    },
    #sched_get_priority_min
    126:{
        #int policy
        0: GnuConstants.SCHEDULER_POLICIES,
    },
    #kill
    129:{
        #int sig
        1: GnuConstants.SIGNALS,
    },
    #tkill
    130:{
        #int sig
        1: GnuConstants.SIGNALS,
    },
    #tgkill
    131:{
        #int sig
        2: GnuConstants.SIGNALS,
    },
    #rt_sigaction
    134:{
        #int sig
        0: GnuConstants.SIGNALS,
    },
    #rt_sigprocmask
    135:{
        #int how
        0: GnuConstants.RT_SIGPROCMASK_HOW,
    },
    #rt_sigqueueinfo
    138:{
        #int sig
        1: GnuConstants.SIGNALS,
    },
    #setpriority
    140:{
        #int which
        0: GnuConstants.PRIORITY_WHICH,
    },
    #getpriority
    141:{
        #int which
        0: GnuConstants.PRIORITY_WHICH,
    },
    #reboot
    142:{
        #int magic1
        0: GnuConstants.REBOOT_MAGIC1,
        #int magic2
        1: GnuConstants.REBOOT_MAGIC2,
        #unsigned int cmd
        2: GnuConstants.REBOOT_CMDS,
    },
    #getrlimit
    163:{
        #unsigned int resource
        0: GnuConstants.RLIMIT_RESOURCES,
    },
    #setrlimit
    164:{
        #unsigned int resource
        0: GnuConstants.RLIMIT_RESOURCES,
        #struct rlimit *rlim
        1: {},
    },
    #getrusage
    165:{
        #int who
        0: GnuConstants.RUSAGE_WHO,
    },
    #umask
    166:{
        #int mask
        0: GnuConstants.OPEN_MODES,
    },
    #prctl
    167:{
        #int option
        0: GnuConstants.PRCTL_OPTIONS,
    },
    #mq_open
    180:{
        #int oflag
        1: GnuConstants.MQ_OPEN_FLAGS,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    #msgget
    186:{
        #key_t key
        0: GnuConstants.MSGGET_KEYS,
        #int msgflg
        1: GnuConstants.MSGGET_FLAGS,
    },
    #msgctl
    187:{
        #int cmd
        1: GnuConstants.MSGCTL_CMDS,
    },
    #msgrcv
    188:{
        #int msgflg
        4: GnuConstants.MSGRCV_FLAGS,
    },
    #msgsnd
    189:{
        #int msgflg
        3: GnuConstants.MSGSND_FLAGS,
    },
    #semget
    190:{
        #key_t key
        0: GnuConstants.SEMGET_KEYS,
        #int semflg
        2: GnuConstants.SEMGET_FLAGS,
    },
    #semctl
    191:{
        #int cmd
        2: GnuConstants.SEMCTL_CMDS,
    },
    #shmget
    194:{
        #int shmflg
        2: GnuConstants.SHMGET_FLAGS,
    },
    #shmctl
    195:{
        #int cmd
        1: GnuConstants.SHMCTL_CMDS,
    },
    #shmat
    196:{
        #int shmflg
        2: GnuConstants.SHMAT_FLAGS,
    },
    #socket
    198:{
        # int family
        0: GnuConstants.SOCKET_FAMILIES,
        # int type
        1: GnuConstants.SOCKET_TYPES,
        # int protocol
        # Note: Protocol is not parsed here, as it is often 0
    },
    #socketpair
    199:{
        # int family
        0: GnuConstants.SOCKET_FAMILIES,
        # int type
        1: GnuConstants.SOCKET_TYPES,
        # int protocol
        # Note: Protocol is not parsed here, as it is often 0
    },
    #sendto
    206:{
        #unsigned int flags
        3: GnuConstants.SENDTO_FLAGS,
    },
    #recvfrom
    207:{
        #unsigned int flags
        3: GnuConstants.RECV_FLAGS,
    },
    #setsockopt
    # TODO: Complex parsing, future work
    # 208:{
    #     #int fd
    #     0: {},
    #     #int level
    #     1: {},
    #     #int optname
    #     2: {},
    #     #char *optval
    #     3: {},
    #     #int optlen
    #     4: {},
    # },
    #getsockopt
    # TODO: Complex parsing, future work
    # 209:{
    #     #int fd
    #     0: {},
    #     #int level
    #     1: {},
    #     #int optname
    #     2: {},
    #     #char *optval
    #     3: {},
    #     #int *optlen
    #     4: {},
    # },
    #shutdown
    210:{
        #int how
        1: GnuConstants.SHUTDOWN_HOW,
    },
    #sendmsg
    211:{
        #unsigned int flags
        2: GnuConstants.SENDMSG_FLAGS,
    },
    #recvmsg
    212:{
        #unsigned int flags
        2: GnuConstants.RECVMMSG_FLAGS,
    },
    #mremap
    216:{
        #unsigned long flags
        3: GnuConstants.MREMAP_FLAGS,
    },
    #add_key
    217:{
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
    218:{
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
    219:{
        #int option
        0: GnuConstants.KEYCTL_OPTIONS,
    },
    #clone
    220:{
        #unsigned long clone_flags
        0: GnuConstants.CLONE_FLAGS_COMMON,
    },
    #mmap
    222:{
        #unsigned long prot
        2: GnuConstants.MMAP_PROT,
        #unsigned long flags
        3: GnuConstants.MMAP_FLAGS_COMMON,
    },
    #fadvise64_64
    223:{
        #int advice
        3: GnuConstants.FADVISE_ADVICE,
    },
    #swapon
    224:{
        #int swap_flags
        1: GnuConstants.SWAPON_FLAGS,
    },
    #mprotect
    226:{
        #unsigned long prot
        2: GnuConstants.MPROTECT_PROT,
    },
    #msync
    227:{
        #int flags
        2: GnuConstants.MSYNC_FLAGS,
    },
    #mlockall
    230:{
        #int flags
        0: GnuConstants.MLOCKALL_FLAGS,
    },
    #madvise
    233:{
        #int behavior
        2: GnuConstants.ADVISE_BEHAVIORS,
    },
    #remap_file_pages
    234:{
        #unsigned long flags
        4: GnuConstants.REMAP_FILE_PAGES_FLAGS,
    },
    #mbind
    235:{
        #unsigned long mode
        2: GnuConstants.MBIND_MODES,
        #unsigned int flags
        5: GnuConstants.MBIND_FLAGS,
    },
    #get_mempolicy
    236:{
        #unsigned long flags
        4: GnuConstants.GETMEMPOLICY_FLAGS,
    },
    #set_mempolicy
    237:{
        #int mode
        0: GnuConstants.SETMEMPOLICY_MODES,
    },
    #move_pages
    239:{
        #int flags
        5: GnuConstants.MOVEPAGES_FLAGS,
    },
    #rt_tgsigqueueinfo
    240:{
        #int sig
        2: GnuConstants.SIGNALS,
    },
    #perf_event_open
    241:{
        #unsigned long flags
        4: GnuConstants.PERF_EVENT_OPEN_FLAGS,
    },
    #accept4
    242:{
        #int flags
        3: GnuConstants.ACCEPT_FLAGS,
    },
    #recvmmsg
    243:{
        #unsigned int flags
        3: GnuConstants.RECVMMSG_FLAGS,
    },
    #wait4
    260:{
        #int options
        2: GnuConstants.WAIT4_OPTIONS,
    },
    #prlimit64
    261:{
        #unsigned int resource
        1: GnuConstants.PRLIMIT_RESOURCES,
    },
    #fanotify_init
    262:{
        #unsigned int flags
        0: GnuConstants.FANOTIFY_INIT_FLAGS,
        #unsigned int event_f_flags
        1: GnuConstants.FANOTIFY_EVENT_F_FLAGS,
    },
    #fanotify_mark
    263:{
        #unsigned int flags
        1: GnuConstants.FANOTIFY_MARK_FLAGS,
        #__u64 mask
        2: GnuConstants.FANOTIFY_MARK_MASK,
        #int dfd
        3: GnuConstants.OPENAT_DFD,
    },
    #name_to_handle_at
    264:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        4: GnuConstants.NAME_TO_HANDLE_FLAGS,
    },
    #open_by_handle_at
    265:{
        #int mountdirfd
        0: GnuConstants.OPENAT_DFD,
        #int flags
        2: GnuConstants.OPEN_FLAGS,
    },
    #clock_adjtime
    266:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #setns
    268:{
        #int flags
        1: GnuConstants.SETNS_FLAGS,
    },
    #sendmmsg
    269:{
        #unsigned int flags
        3: GnuConstants.SENDTO_FLAGS,
    },
    #kcmp
    272:{
        #int type
        2: GnuConstants.KCMP_TYPES,
    },
    #finit_module
    273:{
        #int flags
        2: GnuConstants.FINIT_MODULE_FLAGS,
    },
    #renameat2
    276:{
        #int olddfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int flags
        4: GnuConstants.RENAMEAT_FLAGS,
    },
    #seccomp
    277:{
        #unsigned int op
        0: GnuConstants.SECCOMP_OPS,
        #unsigned int flags
        1: GnuConstants.SECCOMP_FLAGS,
    },
    #getrandom
    278:{
        #unsigned int flags
        2: GnuConstants.GETRANDOM_FLAGS,
    },
    #memfd_create
    279:{
        #unsigned int flags
        1: GnuConstants.MEMFD_CREATE_FLAGS,
    },
    #bpf
    280:{
        #int cmd
        0: GnuConstants.BPF_CMDS,
    },
    #execveat
    281:{
        #int fd
        0: GnuConstants.OPENAT_DFD,
        #int flags
        4: GnuConstants.EXECVEAT_FLAGS,
    },
    #userfaultfd
    282:{
        #int flags
        0: GnuConstants.USERFAULTFD_FLAGS,
    },
    #membarrier
    283:{
        #int cmd
        0: GnuConstants.MEMBARRIER_CMDS,
        #unsigned int flags
        1: GnuConstants.MEMBARRIER_FLAGS,
    },
    #mlock2
    284:{
        #int flags
        2: GnuConstants.MLOCK_FLAGS,
    },
    #preadv2
    286:{
        #rwf_t flags
        5: GnuConstants.PREADV_FLAGS,
    },
    #pwritev2
    287:{
        #rwf_t flags
        5: GnuConstants.PREADV_FLAGS,
    },
    #pkey_mprotect
    288:{
        #unsigned long prot
        2: GnuConstants.PKEY_MPROTECT_PROTS,
    },
    #pkey_alloc
    289:{
        #unsigned long init_val
        1: GnuConstants.PKEY_ALLOC_INIT_VALS,
    },
    #statx
    291:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned flags
        2: GnuConstants.STATX_FLAGS,
        #unsigned int mask
        3: GnuConstants.STATX_MASKS,
    },
    #rseq
    293:{
        #int flags
        2: GnuConstants.RSEQ_FLAGS,
    },
    #kexec_file_load
    294:{
        #unsigned long flags
        4: GnuConstants.KEXEC_FILE_LOAD_FLAGS,
    },
    #pidfd_send_signal
    424:{
        #int sig
        1: GnuConstants.SIGNALS,
        #unsigned int flags
        3: GnuConstants.PIDFD_SEND_SIGNAL_FLAGS,
    },
    #io_uring_enter
    426:{
        #u32 flags
        3: GnuConstants.IO_URING_ENTER_FLAGS,
    },
    #io_uring_register
    427:{
        #unsigned int opcode
        1: GnuConstants.IO_URING_REGISTER_OPCODES,
    },
    #open_tree
    428:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned flags
        2: GnuConstants.OPENTREE_FLAGS,
    },
    #move_mount
    429:{
        #int from_dfd
        0: GnuConstants.OPENAT_DFD,
        #int to_dfd
        2: GnuConstants.OPENAT_DFD,
        #unsigned int flags
        4: GnuConstants.MOVE_MOUNT_FLAGS,
    },
    #fsopen
    430:{
        #unsigned int flags
        1: GnuConstants.FSOPEN_FLAGS,
    },
    #fsconfig
    431:{
        #unsigned int cmd
        1: GnuConstants.FSCONFIG_CMDS,
    },
    #fsmount
    432:{
        #unsigned int flags
        1: GnuConstants.FSMOUNT_FLAGS,
        #unsigned int attr_flags
        2: GnuConstants.FSMOUNT_ATTR_FLAGS,
    },
    #fspick
    433:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int flags
        2: GnuConstants.FSPICK_FLAGS,
    },
    #pidfd_open
    434:{
        #unsigned int flags
        1: GnuConstants.PIDFD_OPEN_FLAGS,
    },
    #close_range
    436:{
        #unsigned int flags
        2: GnuConstants.CLOSE_RANGE_FLAGS,
    },
    #openat2
    437:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
    },
    #faccessat2
    439:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int mode
        2: GnuConstants.OPEN_MODES,
        #int flags
        3: GnuConstants.FACCESSAT_FLAGS,
    },
    #process_madvise
    440:{
        #int behavior
        3: GnuConstants.ADVISE_BEHAVIORS,
    },
    #mount_setattr
    442:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int flags
        2: GnuConstants.MOUNT_SETATTR_FLAGS,
    },
    #quotactl_fd
    443:{
        #unsigned int cmd
        1: GnuConstants.QUOTACTL_CMDS,
    },
    #landlock_create_ruleset
    444:{
        #const __u32 flags
        2: GnuConstants.LANDLOCK_CREATE_RULESET_FLAGS,
    },
    #landlock_add_rule
    445:{
        #const enum landlock_rule_type rule_type
        1: GnuConstants.LANDLOCK_ADD_RULE_TYPES,
    },
    #memfd_secret
    447:{
        #unsigned int flags
        0: GnuConstants.MEMFD_SECRET_FLAGS,
    },
    #futex_waitv
    449:{
        #clockid_t clockid
        4: GnuConstants.WHICH_CLOCK,
    },
    #fchmodat2
    452:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
        #unsigned int flags
        3: GnuConstants.FCHMODAT_FLAGS,
    },
    #map_shadow_stack
    453:{
        #unsigned int flags
        2: GnuConstants.MAP_SHADOW_STACK_FLAGS,
    },
    #futex_wake
    454:{
        #unsigned int flags
        3: GnuConstants.FUTEX2_FLAGS,
    },
    #futex_wait
    455:{
        #clockid_t clockid
        5: GnuConstants.WHICH_CLOCK,
    },
    #listmount
    458:{
        #unsigned int flags
        3: GnuConstants.LISTMOUNT_FLAGS,
    },
    #lsm_get_self_attr
    459:{
        #u32 flags
        3: GnuConstants.LSM_GET_SELF_ATTR_FLAGS,
    },
    #setxattrat
    463:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
    #getxattrat
    464:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
    #listxattrat
    465:{
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
    #removexattrat
    466:{
        # int dfd
        0: GnuConstants.OPENAT_DFD,
        # unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
}
