#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

AARCH64_SYSCALL_PARSER_MAP = \
{
#io_setup
0:{
    #unsigned nr_events
    0: {},
    #aio_context_t *ctxp
    1: {},
},
#io_destroy
1:{
    #aio_context_t ctx
    0: {},
},
#io_submit
2:{
    #aio_context_t ctx_id
    0: {},
    #long nr
    1: {},
    #struct iocb **iocbpp
    2: {},
},
#io_cancel
3:{
    #aio_context_t ctx_id
    0: {},
    #struct iocb *iocb
    1: {},
    #struct io_event *result
    2: {},
},
#io_getevents
4:{
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
#setxattr
5:{
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
6:{
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
7:{
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
8:{
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
9:{
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
10:{
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
11:{
    #const char *pathname
    0: {},
    #char *list
    1: {},
    #size_t size
    2: {},
},
#llistxattr
12:{
    #const char *pathname
    0: {},
    #char *list
    1: {},
    #size_t size
    2: {},
},
#flistxattr
13:{
    #int fd
    0: {},
    #char *list
    1: {},
    #size_t size
    2: {},
},
#removexattr
14:{
    #const char *pathname
    0: {},
    #const char *name
    1: {},
},
#lremovexattr
15:{
    #const char *pathname
    0: {},
    #const char *name
    1: {},
},
#fremovexattr
16:{
    #int fd
    0: {},
    #const char *name
    1: {},
},
#getcwd
17:{
    #char *buf
    0: {},
    #unsigned long size
    1: {},
},
#eventfd2
19:{
    #unsigned int count
    0: {},
    #int flags
    1: {},
},
#epoll_create1
20:{
    #int flags
    0: {},
},
#epoll_ctl
21:{
    #int epfd
    0: {},
    #int op
    1: {},
    #int fd
    2: {},
    #struct epoll_event *event
    3: {},
},
#epoll_pwait
22:{
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
#dup
23:{
    #unsigned int fildes
    0: {},
},
#dup3
24:{
    #unsigned int oldfd
    0: {},
    #unsigned int newfd
    1: {},
    #int flags
    2: {},
},
#fcntl
25:{
    #unsigned int fd
    0: {},
    #unsigned int cmd
    1: {},
    #unsigned long arg
    2: {},
},
#inotify_init1
26:{
    #int flags
    0: {},
},
#inotify_add_watch
27:{
    #int fd
    0: {},
    #const char *pathname
    1: {},
    #u32 mask
    2: {},
},
#inotify_rm_watch
28:{
    #int fd
    0: {},
    #__s32 wd
    1: {},
},
#ioctl
29:{
    #unsigned int fd
    0: {},
    #unsigned int cmd
    1: {},
    #unsigned long arg
    2: {},
},
#ioprio_set
30:{
    #int which
    0: {},
    #int who
    1: {},
    #int ioprio
    2: {},
},
#ioprio_get
31:{
    #int which
    0: {},
    #int who
    1: {},
},
#flock
32:{
    #unsigned int fd
    0: {},
    #unsigned int cmd
    1: {},
},
#mknodat
33:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #umode_t mode
    2: {},
    #unsigned int dev
    3: {},
},
#mkdirat
34:{
    #int dfd
    0: {},
    #const char *pathname
    1: {},
    #umode_t mode
    2: {},
},
#unlinkat
35:{
    #int dfd
    0: {},
    #const char *pathname
    1: {},
    #int flag
    2: {},
},
#symlinkat
36:{
    #const char *oldname
    0: {},
    #int newdfd
    1: {},
    #const char *newname
    2: {},
},
#linkat
37:{
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
#renameat
38:{
    #int olddfd
    0: {},
    #const char *oldname
    1: {},
    #int newdfd
    2: {},
    #const char *newname
    3: {},
},
#umount
39:{
    #char *name
    0: {},
    #int flags
    1: {},
},
#mount
40:{
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
#pivot_root
41:{
    #const char *new_root
    0: {},
    #const char *put_old
    1: {},
},
#statfs
43:{
    #const char *pathname
    0: {},
    #struct statfs *buf
    1: {},
},
#fstatfs
44:{
    #unsigned int fd
    0: {},
    #struct statfs *buf
    1: {},
},
#truncate
45:{
    #const char *path
    0: {},
    #long length
    1: {},
},
#ftruncate
46:{
    #unsigned int fd
    0: {},
    #off_t length
    1: {},
},
#fallocate
47:{
    #int fd
    0: {},
    #int mode
    1: {},
    #loff_t offset
    2: {},
    #loff_t len
    3: {},
},
#faccessat
48:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #int mode
    2: {},
},
#chdir
49:{
    #const char *filename
    0: {},
},
#fchdir
50:{
    #unsigned int fd
    0: {},
},
#chroot
51:{
    #const char *filename
    0: {},
},
#fchmod
52:{
    #unsigned int fd
    0: {},
    #umode_t mode
    1: {},
},
#fchmodat
53:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #umode_t mode
    2: {},
},
#fchownat
54:{
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
#fchown
55:{
    #unsigned int fd
    0: {},
    #uid_t user
    1: {},
    #gid_t group
    2: {},
},
#openat
56:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #int flags
    2: {},
    #umode_t mode
    3: {},
},
#close
57:{
    #unsigned int fd
    0: {},
},
#vhangup
58:{
},
#pipe2
59:{
    #int *fildes
    0: {},
    #int flags
    1: {},
},
#quotactl
60:{
    #unsigned int cmd
    0: {},
    #const char *special
    1: {},
    #qid_t id
    2: {},
    #void *addr
    3: {},
},
#getdents64
61:{
    #unsigned int fd
    0: {},
    #struct linux_dirent64 *dirent
    1: {},
    #unsigned int count
    2: {},
},
#lseek
62:{
    #unsigned int fd
    0: {},
    #off_t offset
    1: {},
    #unsigned int whence
    2: {},
},
#read
63:{
    #unsigned int fd
    0: {},
    #char *buf
    1: {},
    #size_t count
    2: {},
},
#write
64:{
    #unsigned int fd
    0: {},
    #const char *buf
    1: {},
    #size_t count
    2: {},
},
#readv
65:{
    #unsigned long fd
    0: {},
    #const struct iovec *vec
    1: {},
    #unsigned long vlen
    2: {},
},
#writev
66:{
    #unsigned long fd
    0: {},
    #const struct iovec *vec
    1: {},
    #unsigned long vlen
    2: {},
},
#pread64
67:{
    #unsigned int fd
    0: {},
    #char *buf
    1: {},
    #size_t count
    2: {},
    #loff_t pos
    3: {},
},
#pwrite64
68:{
    #unsigned int fd
    0: {},
    #const char *buf
    1: {},
    #size_t count
    2: {},
    #loff_t pos
    3: {},
},
#preadv
69:{
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
70:{
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
#sendfile64
71:{
    #int out_fd
    0: {},
    #int in_fd
    1: {},
    #loff_t *offset
    2: {},
    #size_t count
    3: {},
},
#pselect6
72:{
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
73:{
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
#signalfd4
74:{
    #int ufd
    0: {},
    #sigset_t *user_mask
    1: {},
    #size_t sizemask
    2: {},
    #int flags
    3: {},
},
#vmsplice
75:{
    #int fd
    0: {},
    #const struct iovec *uiov
    1: {},
    #unsigned long nr_segs
    2: {},
    #unsigned int flags
    3: {},
},
#splice
76:{
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
77:{
    #int fdin
    0: {},
    #int fdout
    1: {},
    #size_t len
    2: {},
    #unsigned int flags
    3: {},
},
#readlinkat
78:{
    #int dfd
    0: {},
    #const char *pathname
    1: {},
    #char *buf
    2: {},
    #int bufsiz
    3: {},
},
#newfstatat
79:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #struct stat *statbuf
    2: {},
    #int flag
    3: {},
},
#newfstat
80:{
    #unsigned int fd
    0: {},
    #struct stat *statbuf
    1: {},
},
#sync
81:{
},
#fsync
82:{
    #unsigned int fd
    0: {},
},
#fdatasync
83:{
    #unsigned int fd
    0: {},
},
#sync_file_range
84:{
    #int fd
    0: {},
    #loff_t offset
    1: {},
    #loff_t nbytes
    2: {},
    #unsigned int flags
    3: {},
},
#timerfd_create
85:{
    #int clockid
    0: {},
    #int flags
    1: {},
},
#timerfd_settime
86:{
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
87:{
    #int ufd
    0: {},
    #struct __kernel_itimerspec *otmr
    1: {},
},
#utimensat
88:{
    #int dfd
    0: {},
    #const char *filename
    1: {},
    #struct __kernel_timespec *utimes
    2: {},
    #int flags
    3: {},
},
#acct
89:{
    #const char *name
    0: {},
},
#capget
90:{
    #cap_user_header_t header
    0: {},
    #cap_user_data_t dataptr
    1: {},
},
#capset
91:{
    #cap_user_header_t header
    0: {},
    #const cap_user_data_t data
    1: {},
},
#personality
92:{
    #unsigned int personality
    0: {},
},
#exit
93:{
    #int error_code
    0: {},
},
#exit_group
94:{
    #int error_code
    0: {},
},
#waitid
95:{
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
#set_tid_address
96:{
    #int *tidptr
    0: {},
},
#unshare
97:{
    #unsigned long unshare_flags
    0: {},
},
#futex
98:{
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
#set_robust_list
99:{
    #struct robust_list_head *head
    0: {},
    #size_t len
    1: {},
},
#get_robust_list
100:{
    #int pid
    0: {},
    #struct robust_list_head **head_ptr
    1: {},
    #size_t *len_ptr
    2: {},
},
#nanosleep
101:{
    #struct __kernel_timespec *rqtp
    0: {},
    #struct __kernel_timespec *rmtp
    1: {},
},
#getitimer
102:{
    #int which
    0: {},
    #struct __kernel_old_itimerval *value
    1: {},
},
#setitimer
103:{
    #int which
    0: {},
    #struct __kernel_old_itimerval *value
    1: {},
    #struct __kernel_old_itimerval *ovalue
    2: {},
},
#kexec_load
104:{
    #unsigned long entry
    0: {},
    #unsigned long nr_segments
    1: {},
    #struct kexec_segment *segments
    2: {},
    #unsigned long flags
    3: {},
},
#init_module
105:{
    #void *umod
    0: {},
    #unsigned long len
    1: {},
    #const char *uargs
    2: {},
},
#delete_module
106:{
    #const char *name_user
    0: {},
    #unsigned int flags
    1: {},
},
#timer_create
107:{
    #const clockid_t which_clock
    0: {},
    #struct sigevent *timer_event_spec
    1: {},
    #timer_t *created_timer_id
    2: {},
},
#timer_gettime
108:{
    #timer_t timer_id
    0: {},
    #struct __kernel_itimerspec *setting
    1: {},
},
#timer_getoverrun
109:{
    #timer_t timer_id
    0: {},
},
#timer_settime
110:{
    #timer_t timer_id
    0: {},
    #int flags
    1: {},
    #const struct __kernel_itimerspec *new_setting
    2: {},
    #struct __kernel_itimerspec *old_setting
    3: {},
},
#timer_delete
111:{
    #timer_t timer_id
    0: {},
},
#clock_settime
112:{
    #const clockid_t which_clock
    0: {},
    #const struct __kernel_timespec *tp
    1: {},
},
#clock_gettime
113:{
    #const clockid_t which_clock
    0: {},
    #struct __kernel_timespec *tp
    1: {},
},
#clock_getres
114:{
    #const clockid_t which_clock
    0: {},
    #struct __kernel_timespec *tp
    1: {},
},
#clock_nanosleep
115:{
    #const clockid_t which_clock
    0: {},
    #int flags
    1: {},
    #const struct __kernel_timespec *rqtp
    2: {},
    #struct __kernel_timespec *rmtp
    3: {},
},
#syslog
116:{
    #int type
    0: {},
    #char *buf
    1: {},
    #int len
    2: {},
},
#ptrace
117:{
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
    #long pid
    1: {},
    #unsigned long addr
    2: {},
    #unsigned long data
    3: {},
},
#sched_setparam
118:{
    #pid_t pid
    0: {},
    #struct sched_param *param
    1: {},
},
#sched_setscheduler
119:{
    #pid_t pid
    0: {},
    #int policy
    1: {},
    #struct sched_param *param
    2: {},
},
#sched_getscheduler
120:{
    #pid_t pid
    0: {},
},
#sched_getparam
121:{
    #pid_t pid
    0: {},
    #struct sched_param *param
    1: {},
},
#sched_setaffinity
122:{
    #pid_t pid
    0: {},
    #unsigned int len
    1: {},
    #unsigned long *user_mask_ptr
    2: {},
},
#sched_getaffinity
123:{
    #pid_t pid
    0: {},
    #unsigned int len
    1: {},
    #unsigned long *user_mask_ptr
    2: {},
},
#sched_yield
124:{
},
#sched_get_priority_max
125:{
    #int policy
    0: {},
},
#sched_get_priority_min
126:{
    #int policy
    0: {},
},
#sched_rr_get_interval
127:{
    #pid_t pid
    0: {},
    #struct __kernel_timespec *interval
    1: {},
},
#restart_syscall
128:{
},
#kill
129:{
    #pid_t pid
    0: {},
    #int sig
    1: {},
},
#tkill
130:{
    #pid_t pid
    0: {},
    #int sig
    1: {},
},
#tgkill
131:{
    #pid_t tgid
    0: {},
    #pid_t pid
    1: {},
    #int sig
    2: {},
},
#sigaltstack
132:{
    #const stack_t *uss
    0: {},
    #stack_t *uoss
    1: {},
},
#rt_sigsuspend
133:{
    #sigset_t *unewset
    0: {},
    #size_t sigsetsize
    1: {},
},
#rt_sigaction
134:{
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
135:{
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
136:{
    #sigset_t *uset
    0: {},
    #size_t sigsetsize
    1: {},
},
#rt_sigtimedwait
137:{
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
138:{
    #pid_t pid
    0: {},
    #int sig
    1: {},
    #siginfo_t *uinfo
    2: {},
},
#rt_sigreturn
139:{
},
#setpriority
140:{
    #int which
    0: {},
    #int who
    1: {},
    #int niceval
    2: {},
},
#getpriority
141:{
    #int which
    0: {},
    #int who
    1: {},
},
#reboot
142:{
    #int magic1
    0: {},
    #int magic2
    1: {},
    #unsigned int cmd
    2: {},
    #void *arg
    3: {},
},
#setregid
143:{
    #gid_t rgid
    0: {},
    #gid_t egid
    1: {},
},
#setgid
144:{
    #gid_t gid
    0: {},
},
#setreuid
145:{
    #uid_t ruid
    0: {},
    #uid_t euid
    1: {},
},
#setuid
146:{
    #uid_t uid
    0: {},
},
#setresuid
147:{
    #uid_t ruid
    0: {},
    #uid_t euid
    1: {},
    #uid_t suid
    2: {},
},
#getresuid
148:{
    #uid_t *ruidp
    0: {},
    #uid_t *euidp
    1: {},
    #uid_t *suidp
    2: {},
},
#setresgid
149:{
    #gid_t rgid
    0: {},
    #gid_t egid
    1: {},
    #gid_t sgid
    2: {},
},
#getresgid
150:{
    #gid_t *rgidp
    0: {},
    #gid_t *egidp
    1: {},
    #gid_t *sgidp
    2: {},
},
#setfsuid
151:{
    #uid_t uid
    0: {},
},
#setfsgid
152:{
    #gid_t gid
    0: {},
},
#times
153:{
    #struct tms *tbuf
    0: {},
},
#setpgid
154:{
    #pid_t pid
    0: {},
    #pid_t pgid
    1: {},
},
#getpgid
155:{
    #pid_t pid
    0: {},
},
#getsid
156:{
    #pid_t pid
    0: {},
},
#setsid
157:{
},
#getgroups
158:{
    #int gidsetsize
    0: {},
    #gid_t *grouplist
    1: {},
},
#setgroups
159:{
    #int gidsetsize
    0: {},
    #gid_t *grouplist
    1: {},
},
#newuname
160:{
    #struct new_utsname *name
    0: {},
},
#sethostname
161:{
    #char *name
    0: {},
    #int len
    1: {},
},
#setdomainname
162:{
    #char *name
    0: {},
    #int len
    1: {},
},
#getrlimit
163:{
    #unsigned int resource
    0: {},
    #struct rlimit *rlim
    1: {},
},
#setrlimit
164:{
    #unsigned int resource
    0: {},
    #struct rlimit *rlim
    1: {},
},
#getrusage
165:{
    #int who
    0: {},
    #struct rusage *ru
    1: {},
},
#umask
166:{
    #int mask
    0: {},
},
#prctl
167:{
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
#getcpu
168:{
    #unsigned *cpup
    0: {},
    #unsigned *nodep
    1: {},
    #struct getcpu_cache *unused
    2: {},
},
#gettimeofday
169:{
    #struct __kernel_old_timeval *tv
    0: {},
    #struct timezone *tz
    1: {},
},
#settimeofday
170:{
    #struct __kernel_old_timeval *tv
    0: {},
    #struct timezone *tz
    1: {},
},
#adjtimex
171:{
    #struct __kernel_timex *txc_p
    0: {},
},
#getpid
172:{
},
#getppid
173:{
},
#getuid
174:{
},
#geteuid
175:{
},
#getgid
176:{
},
#getegid
177:{
},
#gettid
178:{
},
#sysinfo
179:{
    #struct sysinfo *info
    0: {},
},
#mq_open
180:{
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
181:{
    #const char *u_name
    0: {},
},
#mq_timedsend
182:{
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
183:{
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
184:{
    #mqd_t mqdes
    0: {},
    #const struct sigevent *u_notification
    1: {},
},
#mq_getsetattr
185:{
    #mqd_t mqdes
    0: {},
    #const struct mq_attr *u_mqstat
    1: {},
    #struct mq_attr *u_omqstat
    2: {},
},
#msgget
186:{
    #key_t key
    0: {},
    #int msgflg
    1: {},
},
#msgctl
187:{
    #int msqid
    0: {},
    #int cmd
    1: {},
    #struct msqid_ds *buf
    2: {},
},
#msgrcv
188:{
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
#msgsnd
189:{
    #int msqid
    0: {},
    #struct msgbuf *msgp
    1: {},
    #size_t msgsz
    2: {},
    #int msgflg
    3: {},
},
#semget
190:{
    #key_t key
    0: {},
    #int nsems
    1: {},
    #int semflg
    2: {},
},
#semctl
191:{
    #int semid
    0: {},
    #int semnum
    1: {},
    #int cmd
    2: {},
    #unsigned long arg
    3: {},
},
#semtimedop
192:{
    #int semid
    0: {},
    #struct sembuf *tsops
    1: {},
    #unsigned int nsops
    2: {},
    #const struct __kernel_timespec *timeout
    3: {},
},
#semop
193:{
    #int semid
    0: {},
    #struct sembuf *tsops
    1: {},
    #unsigned nsops
    2: {},
},
#shmget
194:{
    #key_t key
    0: {},
    #size_t size
    1: {},
    #int shmflg
    2: {},
},
#shmctl
195:{
    #int shmid
    0: {},
    #int cmd
    1: {},
    #struct shmid_ds *buf
    2: {},
},
#shmat
196:{
    #int shmid
    0: {},
    #char *shmaddr
    1: {},
    #int shmflg
    2: {},
},
#shmdt
197:{
    #char *shmaddr
    0: {},
},
#socket
198:{
    #int family
    0: {},
    #int type
    1: {},
    #int protocol
    2: {},
},
#socketpair
199:{
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
200:{
    #int fd
    0: {},
    #struct sockaddr *umyaddr
    1: {},
    #int addrlen
    2: {},
},
#listen
201:{
    #int fd
    0: {},
    #int backlog
    1: {},
},
#accept
202:{
    #int fd
    0: {},
    #struct sockaddr *upeer_sockaddr
    1: {},
    #int *upeer_addrlen
    2: {},
},
#connect
203:{
    #int fd
    0: {},
    #struct sockaddr *uservaddr
    1: {},
    #int addrlen
    2: {},
},
#getsockname
204:{
    #int fd
    0: {},
    #struct sockaddr *usockaddr
    1: {},
    #int *usockaddr_len
    2: {},
},
#getpeername
205:{
    #int fd
    0: {},
    #struct sockaddr *usockaddr
    1: {},
    #int *usockaddr_len
    2: {},
},
#sendto
206:{
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
#recvfrom
207:{
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
#setsockopt
208:{
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
#getsockopt
209:{
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
#shutdown
210:{
    #int fd
    0: {},
    #int how
    1: {},
},
#sendmsg
211:{
    #int fd
    0: {},
    #struct user_msghdr *msg
    1: {},
    #unsigned int flags
    2: {},
},
#recvmsg
212:{
    #int fd
    0: {},
    #struct user_msghdr *msg
    1: {},
    #unsigned int flags
    2: {},
},
#readahead
213:{
    #int fd
    0: {},
    #loff_t offset
    1: {},
    #size_t count
    2: {},
},
#brk
214:{
    #unsigned long brk
    0: {},
},
#munmap
215:{
    #unsigned long addr
    0: {},
    #size_t len
    1: {},
},
#mremap
216:{
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
#add_key
217:{
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
218:{
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
219:{
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
#clone
220:{
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
#execve
221:{
    #const char *filename
    0: {},
    #const char *const *argv
    1: {},
    #const char *const *envp
    2: {},
},
#mmap
222:{
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
    #unsigned long off
    5: {},
},
#fadvise64_64
223:{
    #int fd
    0: {},
    #loff_t offset
    1: {},
    #loff_t len
    2: {},
    #int advice
    3: {},
},
#swapon
224:{
    #const char *specialfile
    0: {},
    #int swap_flags
    1: {},
},
#swapoff
225:{
    #const char *specialfile
    0: {},
},
#mprotect
226:{
    #unsigned long start
    0: {},
    #size_t len
    1: {},
    #unsigned long prot
    2: {},
},
#msync
227:{
    #unsigned long start
    0: {},
    #size_t len
    1: {},
    #int flags
    2: {},
},
#mlock
228:{
    #unsigned long start
    0: {},
    #size_t len
    1: {},
},
#munlock
229:{
    #unsigned long start
    0: {},
    #size_t len
    1: {},
},
#mlockall
230:{
    #int flags
    0: {},
},
#munlockall
231:{
},
#mincore
232:{
    #unsigned long start
    0: {},
    #size_t len
    1: {},
    #unsigned char *vec
    2: {},
},
#madvise
233:{
    #unsigned long start
    0: {},
    #size_t len_in
    1: {},
    #int behavior
    2: {},
},
#remap_file_pages
234:{
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
#mbind
235:{
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
236:{
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
237:{
    #int mode
    0: {},
    #const unsigned long *nmask
    1: {},
    #unsigned long maxnode
    2: {},
},
#migrate_pages
238:{
    #pid_t pid
    0: {},
    #unsigned long maxnode
    1: {},
    #const unsigned long *old_nodes
    2: {},
    #const unsigned long *new_nodes
    3: {},
},
#move_pages
239:{
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
#rt_tgsigqueueinfo
240:{
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
241:{
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
#accept4
242:{
    #int fd
    0: {},
    #struct sockaddr *upeer_sockaddr
    1: {},
    #int *upeer_addrlen
    2: {},
    #int flags
    3: {},
},
#recvmmsg
243:{
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
#wait4
260:{
    #pid_t upid
    0: {},
    #int *stat_addr
    1: {},
    #int options
    2: {},
    #struct rusage *ru
    3: {},
},
#prlimit64
261:{
    #pid_t pid
    0: {},
    #unsigned int resource
    1: {},
    #const struct rlimit64 *new_rlim
    2: {},
    #struct rlimit64 *old_rlim
    3: {},
},
#fanotify_init
262:{
    #unsigned int flags
    0: {},
    #unsigned int event_f_flags
    1: {},
},
#fanotify_mark
263:{
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
#name_to_handle_at
264:{
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
265:{
    #int mountdirfd
    0: {},
    #struct file_handle *handle
    1: {},
    #int flags
    2: {},
},
#clock_adjtime
266:{
    #const clockid_t which_clock
    0: {},
    #struct __kernel_timex *utx
    1: {},
},
#syncfs
267:{
    #int fd
    0: {},
},
#setns
268:{
    #int fd
    0: {},
    #int flags
    1: {},
},
#sendmmsg
269:{
    #int fd
    0: {},
    #struct mmsghdr *mmsg
    1: {},
    #unsigned int vlen
    2: {},
    #unsigned int flags
    3: {},
},
#process_vm_readv
270:{
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
271:{
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
272:{
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
273:{
    #int fd
    0: {},
    #const char *uargs
    1: {},
    #int flags
    2: {},
},
#sched_setattr
274:{
    #pid_t pid
    0: {},
    #struct sched_attr *uattr
    1: {},
    #unsigned int flags
    2: {},
},
#sched_getattr
275:{
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
276:{
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
277:{
    #unsigned int op
    0: {},
    #unsigned int flags
    1: {},
    #void *uargs
    2: {},
},
#getrandom
278:{
    #char *ubuf
    0: {},
    #size_t len
    1: {},
    #unsigned int flags
    2: {},
},
#memfd_create
279:{
    #const char *uname
    0: {},
    #unsigned int flags
    1: {},
},
#bpf
280:{
    #int cmd
    0: {},
    #union bpf_attr *uattr
    1: {},
    #unsigned int size
    2: {},
},
#execveat
281:{
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
282:{
    #int flags
    0: {},
},
#membarrier
283:{
    #int cmd
    0: {},
    #unsigned int flags
    1: {},
    #int cpu_id
    2: {},
},
#mlock2
284:{
    #unsigned long start
    0: {},
    #size_t len
    1: {},
    #int flags
    2: {},
},
#copy_file_range
285:{
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
286:{
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
287:{
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
288:{
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
289:{
    #unsigned long flags
    0: {},
    #unsigned long init_val
    1: {},
},
#pkey_free
290:{
    #int pkey
    0: {},
},
#statx
291:{
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
292:{
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
293:{
    #struct rseq *rseq
    0: {},
    #u32 rseq_len
    1: {},
    #int flags
    2: {},
    #u32 sig
    3: {},
},
#kexec_file_load
294:{
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
