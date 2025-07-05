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

I386_SYSCALL_PARSER_MAP = {
    #open
    5:{
        #int flags
        1: GnuConstants.OPEN_FLAGS,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    #waitpid
    7:{
        #int options
        2: GnuConstants.WAITID_OPTIONS,
    },
    #creat
    8:{
        #umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    #mknod
    14:{
        #umode_t mode
        1: GnuConstants.MKNOD_MODES,
    },
    #chmod
    15:{
        #umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    #lseek
    19:{
        #unsigned int whence
        2: GnuConstants.LSEEK_WHENCE,
    },
    #mount
    21:{
        #unsigned long flags
        3: GnuConstants.MOUNT_FLAGS,
    },
    #ptrace
    26:{
        #long request
        0: GnuConstants.PTRACE_COMMON_REQUESTS + {
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
        1: GnuConstants.ACCESS_MODES,
    },
    #kill
    37:{
        #int sig
        1: GnuConstants.SIGNALS,
    },
    #mkdir
    39:{
        #umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    #signal
    48:{
        #int sig
        0: GnuConstants.SIGNALS,
    },
    #umount
    52:{
        #int flags
        1: GnuConstants.UMOUNT_FLAGS,
    },
    #fcntl
    55:{
        #unsigned int cmd
        1: GnuConstants.FCNTL_CMDS,
        #unsigned long arg
        2: {
            "parsing_mode": "custom",
            "parser": GnuConstants.parse_fcntl_arg,
        },
    },
    #umask
    60:{
        #int mask
        0: GnuConstants.OPEN_MODES,
    },
    #sigaction
    67:{
        #int sig
        0: GnuConstants.SIGNALS,
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
        0: GnuConstants.RLIMIT_RESOURCES
    },
    #getrusage
    77:{
        #int who
        0: GnuConstants.RUSAGE_WHO,
    },
    #swapon
    87:{
        #int swap_flags
        1: GnuConstants.SWAPON_FLAGS,
    },
    #reboot
    88: {
        # int magic1
        0: GnuConstants.REBOOT_MAGIC1,
        # int magic2
        1: GnuConstants.REBOOT_MAGIC2,
        # unsigned int cmd
        2: GnuConstants.REBOOT_CMDS,
    },
    # TODO: Implement struct parsing just for this
    # #mmap
    # 90:{
    #     #struct mmap_arg_struct *arg
    #     0: {},
    # },
    #fchmod
    94:{
        #umode_t mode
        1: GnuConstants.OPEN_MODES,
    },
    #getpriority
    96:{
        #int which
        0: GnuConstants.PRIORITY_WHICH,
    },
    #setpriority
    97:{
        #int which
        0: GnuConstants.PRIORITY_WHICH,
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
        0: GnuConstants.SYSLOG_TYPES,
    },
    #setitimer
    104:{
        #int which
        0: GnuConstants.ITIMER_WHICH,
    },
    #getitimer
    105:{
        #int which
        0: GnuConstants.ITIMER_WHICH,
    },
    #wait4
    114:{
        #int options
        2: GnuConstants.WAIT4_OPTIONS,
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
        0: GnuConstants.CLONE_FLAGS,
    },
    #mprotect
    125:{
        #unsigned long prot
        2: GnuConstants.MPROTECT_PROT,
    },
    #sigprocmask
    126:{
        #int how
        0: GnuConstants.RT_SIGPROCMASK_HOW,
    },
    #delete_module
    129:{
        #unsigned int flags
        1: GnuConstants.DELETE_MODULE_FLAGS,
    },
    #quotactl
    131:{
        #unsigned int cmd
        0: GnuConstants.QUOTACTL_CMDS,
    },
    #fchdir
    133:{
        #unsigned int fd
        0: GnuConstants.OPENAT_DFD,
    },
    #personality
    136:{
        #unsigned int personality
        0: GnuConstants.PROCESS_PERSONALITIES,
    },
    #llseek
    140:{
        #unsigned int whence
        4: GnuConstants.LSEEK_WHENCE,
    },
    #flock
    143:{
        #unsigned int cmd
        1: GnuConstants.FLOCK_CMDS,
    },
    #msync
    144:{
        #int flags
        2: GnuConstants.MSYNC_FLAGS,
    },
    #mlockall
    152:{
        #int flags
        0: GnuConstants.MLOCKALL_FLAGS,
    },
    #sched_setscheduler
    156:{
        #int policy
        1: GnuConstants.SCHEDULER_POLICIES,
    },
    #sched_get_priority_max
    159:{
        #int policy
        0: GnuConstants.SCHEDULER_POLICIES,
    },
    #sched_get_priority_min
    160:{
        #int policy
        0: GnuConstants.SCHEDULER_POLICIES,
    },
    #mremap
    163:{
        #unsigned long flags
        3: GnuConstants.MREMAP_FLAGS,
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
        0: GnuConstants.SIGNALS,
    },
    #rt_sigprocmask
    175:{
        #int how
        0: GnuConstants.RT_SIGPROCMASK_HOW,
    },
    #getrlimit
    191:{
        #unsigned int resource
        0: GnuConstants.RLIMIT_RESOURCES,
    },
    #mmap_pgoff
    192:{
        #unsigned long prot
        2: GnuConstants.MMAP_PROT,
        #unsigned long flags
        3: GnuConstants.MMAP_FLAGS_COMMON,
    },
    #madvise
    219:{
        #int behavior
        2: GnuConstants.ADVISE_BEHAVIORS,
    },
    #fcntl64
    221:{
        #unsigned int cmd
        1: GnuConstants.FCNTL64_CMDS,
        #unsigned long arg
        2: {
            "parsing_mode": "custom",
            "parser": GnuConstants.parse_fcntl_arg,
        },
    },
    #setxattr
    226:{
        #int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    #lsetxattr
    227:{
        #int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    #fsetxattr
    228:{
        #int flags
        4: GnuConstants.XATTR_FLAGS,
    },
    #tkill
    238:{
        #int sig
        1: GnuConstants.SIGNALS,
    },
    #futex
    240:{
        #int op
        1: GnuConstants.FUTEX_OPS,
    },
    #fadvise64
    250:{
        #int advice
        4: GnuConstants.FADVISE_ADVICE,
    },
    #epoll_ctl
    255:{
        #int op
        1: GnuConstants.EPOLL_CTL_OPS,
    },
    #remap_file_pages
    257:{
        #unsigned long flags
        4: GnuConstants.REMAP_FILE_PAGES_FLAGS,
    },
    #timer_create
    259:{
        #const clockid_t which_clock
        0: GnuConstants.TIMER_CREATE_WHICH_CLOCK,
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
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_gettime
    265:{
        #clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_getres
    266:{
        #clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_nanosleep
    267:{
        #clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
        #int flags
        1: GnuConstants.CLOCK_NANOSLEEP_FLAGS,
    },
    #tgkill
    270:{
        #int sig
        2: GnuConstants.SIGNALS,
    },
    #fadvise64_64
    272:{
        #int advice
        5: GnuConstants.FADVISE_ADVICE,
    },
    #mbind
    274:{
        #unsigned long mode
        2: GnuConstants.MBIND_MODES,
        #unsigned int flags
        5: GnuConstants.MBIND_FLAGS,
    },
    #get_mempolicy
    275:{
        #unsigned long flags
        4: GnuConstants.GETMEMPOLICY_FLAGS,
    },
    #set_mempolicy
    276:{
        #int mode
        0: GnuConstants.SETMEMPOLICY_MODES,
    },
    #mq_open
    277:{
        #int oflag
        1: GnuConstants.MQ_OPEN_FLAGS,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    #kexec_load
    283:{
        #unsigned long flags
        3: GnuConstants.KEXEC_LOAD_FLAGS,
    },
    #waitid
    284:{
        #int which
        0: GnuConstants.WAITID_WHICH,
        #int options
        3: GnuConstants.WAITID_OPTIONS,
    },
    #add_key
    286:{
        #key_serial_t ringid
        4: {
            0xFFFFFFFF: "KEY_SPEC_THREAD_KEYRING",
            0xFFFFFFFD: "KEY_SPEC_SESSION_KEYRING",
            0xFFFFFFFE: "KEY_SPEC_PROCESS_KEYRING",
            0xFFFFFFFC: "KEY_SPEC_USER_KEYRING",
            0xFFFFFFFB: "KEY_SPEC_USER_SESSION_KEYRING",
            0xFFFFFFFA: "KEY_SPEC_GROUP_KEYRING",
            0xFFFFFF9F: "KEY_SPEC_REQKEY_AUTH_KEY",
            0xFFFFFF9E: "KEY_SPEC_REQUESTOR_KEYRING",
            "parsing_mode": "sequential",
        },
    },
    #request_key
    287:{
        #key_serial_t destringid
        3: {
            0xFFFFFFFF: "KEY_SPEC_THREAD_KEYRING",
            0xFFFFFFFE: "KEY_SPEC_PROCESS_KEYRING",
            0xFFFFFFFD: "KEY_SPEC_SESSION_KEYRING",
            0xFFFFFFFC: "KEY_SPEC_USER_KEYRING",
            0xFFFFFFFB: "KEY_SPEC_USER_SESSION_KEYRING",
            0xFFFFFFFA: "KEY_SPEC_GROUP_KEYRING",
            0xFFFFFF9F: "KEY_SPEC_REQKEY_AUTH_KEY",
            0xFFFFFF9E: "KEY_SPEC_REQUESTOR_KEYRING",
            "parsing_mode": "sequential",
        },
    },
    #keyctl
    288:{
        #int option
        0: GnuConstants.KEYCTL_OPTIONS,
    },
    #ioprio_set
    289:{
        #int which
        0: GnuConstants.IOPRIO_WHICH,
    },
    #ioprio_get
    290:{
        #int which
        0: GnuConstants.IOPRIO_WHICH,
    },
    #openat
    295:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flags
        2: GnuConstants.OPEN_FLAGS,
        #umode_t mode
        3: GnuConstants.OPEN_MODES,
    },
    #mkdirat
    296:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    #mknodat
    297:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #umode_t mode
        2: GnuConstants.MKNOD_MODES,
    },
    #fchownat
    298:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        4: GnuConstants.FCHOWNAT_FLAGS,
    },
    #futimesat
    299:{
        #unsigned int dfd
        0: GnuConstants.OPENAT_DFD,
    },
    #fstatat64
    300:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        3: GnuConstants.NEWSTATFS_FLAGS,
    },
    #unlinkat
    301:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        2: GnuConstants.UNLINKAT_FLAGS,
    },
    #renameat
    302:{
        #int olddfd
        0: GnuConstants.OPENAT_DFD,
    },
    #linkat
    303:{
        #int olddfd
        0: GnuConstants.OPENAT_DFD,
        #int newdfd
        2: GnuConstants.OPENAT_DFD,
        #int flags
        4: GnuConstants.LINKAT_FLAGS,
    },
    #symlinkat
    304:{
        #int newdfd
        1: GnuConstants.OPENAT_DFD,
    },
    #readlinkat
    305:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
    },
    #fchmodat
    306:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #umode_t mode
        2: GnuConstants.OPEN_MODES,
    },
    #faccessat
    307:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int mode
        2: GnuConstants.OPEN_MODES,
    },
    #unshare
    310:{
        #unsigned long unshare_flags
        0: GnuConstants.UNSHARE_FLAGS,
    },
    #splice
    313:{
        #unsigned int flags
        5: GnuConstants.SPLICE_FLAGS,
    },
    #sync_file_range
    314:{
        #int flags
        5: GnuConstants.SYNC_FILE_RANGE_FLAGS,
    },
    #tee
    315:{
        #unsigned int flags
        3: GnuConstants.SPLICE_FLAGS,
    },
    #vmsplice
    316:{
        #unsigned int flags
        3: GnuConstants.VMSPLICE_FLAGS,
    },
    #move_pages
    317:{
        #int flags
        5: GnuConstants.MOVEPAGES_FLAGS,
    },
    #utimensat
    320:{
        #int flags
        3: GnuConstants.UTIMENSAT_FLAGS,
    },
    #timerfd_create
    322:{
        #int clockid
        0: GnuConstants.TIMERFD_CREATE_CLOCKS,
        #int flags
        1: GnuConstants.TIMERFD_CREATE_FLAGS,
    },
    #fallocate
    324:{
        #int mode
        1: GnuConstants.FALLOCATE_MODES,
    },
    #timerfd_settime
    325:{
        #int flags
        1: GnuConstants.TIMERFD_SETTIME_FLAGS,
    },
    #signalfd4
    327:{
        #int flags
        3: GnuConstants.SIGNALFD_FLAGS,
    },
    #eventfd2
    328:{
        #int flags
        1: GnuConstants.EVENTFD_FLAGS,
    },
    #epoll_create1
    329:{
        #int flags
        0: GnuConstants.EPOLL_CREATE_FLAGS,
    },
    #dup3
    330:{
        #int flags
        2: GnuConstants.DUP3_FLAGS,
    },
    #pipe2
    331:{
        #int flags
        1: GnuConstants.PIPE2_FLAGS,
    },
    #inotify_init1
    332:{
        #int flags
        0: GnuConstants.INOTIFY_INIT_FLAGS,
    },
    #rt_tgsigqueueinfo
    335:{
        #int sig
        2: GnuConstants.SIGNALS,
    },
    #perf_event_open
    336:{
        #unsigned long flags
        4: GnuConstants.PERF_EVENT_OPEN_FLAGS,
    },
    #recvmmsg
    337:{
        #unsigned int flags
        3: GnuConstants.RECVMMSG_FLAGS,
    },
    #fanotify_init
    338:{
        #unsigned int flags
        0: GnuConstants.FANOTIFY_INIT_FLAGS,
        #unsigned int event_f_flags
        1: GnuConstants.FANOTIFY_EVENT_F_FLAGS,
    },
    #fanotify_mark
    339:{
        #unsigned int flags
        1: GnuConstants.FANOTIFY_MARK_FLAGS,
        #u32 mask_lo
        2: GnuConstants.FANOTIFY_MARK_MASK,
        #int dfd
        4: GnuConstants.OPENAT_DFD,
    },
    #prlimit64
    340:{
        #unsigned int resource
        1: GnuConstants.PRLIMIT_RESOURCES,
    },
    #name_to_handle_at
    341:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flag
        4: GnuConstants.NAME_TO_HANDLE_FLAGS,
    },
    #open_by_handle_at
    342:{
        #int mountdirfd
        0: GnuConstants.OPENAT_DFD,
        #int flags
        2: GnuConstants.OPEN_FLAGS,
    },
    #clock_adjtime
    343:{
        #clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #sendmmsg
    345:{
        #unsigned int flags
        3: GnuConstants.SENDTO_FLAGS,
    },
    #setns
    346:{
        #int flags
        1: GnuConstants.SETNS_FLAGS,
    },
    #kcmp
    349:{
        #int type
        2: GnuConstants.KCMP_TYPES,
    },
    #finit_module
    350:{
        #int flags
        2: GnuConstants.FINIT_MODULE_FLAGS,
    },
    #renameat2
    353:{
        # int olddfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int flags
        4: GnuConstants.RENAMEAT_FLAGS,
    },
    #seccomp
    354:{
        # unsigned int op
        0: GnuConstants.SECCOMP_OPS,
        # unsigned int flags
        1: GnuConstants.SECCOMP_FLAGS,
    },
    #getrandom
    355:{
        #unsigned int flags
        2: GnuConstants.GETRANDOM_FLAGS,
    },
    #memfd_create
    356:{
        #unsigned int flags
        1: GnuConstants.MEMFD_CREATE_FLAGS,
    },
    #bpf
    357:{
        #int cmd
        0: GnuConstants.BPF_CMDS,
    },
    #execveat
    358:{
        #int fd
        0: GnuConstants.OPENAT_DFD,
        #int flags
        4: GnuConstants.EXECVEAT_FLAGS,
    },
    #socket
    359:{
        #int family
        0: GnuConstants.SOCKET_FAMILIES,
        #int type
        1: GnuConstants.SOCKET_TYPES,
        #int protocol
        # Note: Socket protocol is not parsed here as it is often 0
    },
    #socketpair
    360:{
        #int family
        0: GnuConstants.SOCKET_FAMILIES,
        #int type
        1: GnuConstants.SOCKET_TYPES,
        #int protocol
        # Note: Socket protocol is not parsed here as it is often 0
    },
    #accept4
    364:{
        #int flags
        3: GnuConstants.ACCEPT_FLAGS,
    },
    # TODO: Complex parsing, future work
    # #getsockopt
    # 365:{
    #     #int level
    #     1: {},
    #     #int optname
    #     2: {},
    # },
    #setsockopt
    # 366:{
    #     #int level
    #     1: {},
    #     #int optname
    #     2: {},
    # },
    #sendto
    369:{
        #unsigned int flags
        3: GnuConstants.SENDTO_FLAGS,
    },
    #sendmsg
    370:{
        #unsigned int flags
        2: GnuConstants.SENDMSG_FLAGS,
    },
    #recvfrom
    371:{
        #unsigned int flags
        3: GnuConstants.RECV_FLAGS,
    },
    #recvmsg
    372:{
        #unsigned int flags
        2: GnuConstants.RECVMMSG_FLAGS,
    },
    #shutdown
    373:{
        #int how
        1: GnuConstants.SHUTDOWN_HOW,
    },
    #userfaultfd
    374:{
        #int flags
        0: GnuConstants.USERFAULTFD_FLAGS,
    },
    #membarrier
    375:{
        #int cmd
        0: GnuConstants.MEMBARRIER_CMDS,
        #unsigned int flags
        1: GnuConstants.MEMBARRIER_FLAGS,
    },
    #mlock2
    376:{
        #int flags
        2: GnuConstants.MLOCK_FLAGS,
    },
    #preadv2
    378:{
        #rwf_t flags
        5: GnuConstants.PREADV_FLAGS,
    },
    #pwritev2
    379:{
        #rwf_t flags
        5: GnuConstants.PREADV_FLAGS,
    },
    #statx
    383:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned flags
        2: GnuConstants.STATX_FLAGS,
        #unsigned int mask
        3: GnuConstants.STATX_MASKS,
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
    #rseq
    386:{
        #int flags
        2: GnuConstants.RSEQ_FLAGS,
    },
    #semget
    393:{
        #key_t key
        0: GnuConstants.SEMGET_KEYS,
        #int semflg
        2: GnuConstants.SEMGET_FLAGS,
    },
    #semctl
    394:{
        #int cmd
        2: GnuConstants.SEMCTL_CMDS,
    },
    #shmget
    395:{
        #int shmflg
        2: GnuConstants.SHMGET_FLAGS,
    },
    #shmctl
    396:{
        #int cmd
        1: GnuConstants.SHMCTL_CMDS,
    },
    #shmat
    397:{
        #int shmflg
        2: GnuConstants.SHMAT_FLAGS,
    },
    #msgget
    399:{
        #key_t key
        0: GnuConstants.MSGGET_KEYS,
        #int msgflg
        1: GnuConstants.MSGGET_FLAGS,
    },
    #msgsnd
    400:{
        #int msgflg
        3: GnuConstants.MSGSND_FLAGS,
    },
    #msgrcv
    401:{
        #int msgflg
        4: GnuConstants.MSGRCV_FLAGS,
    },
    #msgctl
    402:{
        #int cmd
        1: GnuConstants.MSGCTL_CMDS,
    },
    #clock_gettime
    403:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_settime
    404:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_adjtime
    405:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_getres
    406:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
    },
    #clock_nanosleep
    407:{
        #const clockid_t which_clock
        0: GnuConstants.WHICH_CLOCK,
        #int flags
        1: GnuConstants.CLOCK_NANOSLEEP_FLAGS,
    },
    #timer_settime
    409:{
        #int flags
        1: GnuConstants.TIMER_SETTIME_FLAGS,
    },
    #timerfd_settime
    411:{
        #int flags
        1: GnuConstants.TIMERFD_SETTIME_FLAGS,
    },
    #utimensat
    412:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #int flags
        3: GnuConstants.UTIMENSAT_FLAGS,
    },
    #recvmmsg
    417:{
        #unsigned int flags
        3: GnuConstants.RECVMMSG_FLAGS,
    },
    #futex
    422:{
        #int op
        1: GnuConstants.FUTEX_OPS,
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
        #const __u32 flags
        3: GnuConstants.LANDLOCK_ADD_RULE_FLAGS,
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
    #cachestat
    451:{
        #unsigned int fd
        0: GnuConstants.OPENAT_DFD,
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
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
    #removexattrat
    466:{
        #int dfd
        0: GnuConstants.OPENAT_DFD,
        #unsigned int at_flags
        2: GnuConstants.XATTRAT_FLAGS,
    },
}