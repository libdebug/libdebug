#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

I386_SYSCALL_PARSER_MAP = \
{
#restart_syscall
0:{
},
#exit
1:{
    #int error_code
    0: {},
},
#fork
2:{
},
#read
3:{
    #unsigned int fd
    0: {},
    #char *buf
    1: {},
    #size_t count
    2: {},
},
#write
4:{
    #unsigned int fd
    0: {},
    #const char *buf
    1: {},
    #size_t count
    2: {},
},
#open
5:{
    #const char *filename
    0: {},
    #int flags
    1: {},
    #umode_t mode
    2: {},
},
#close
6:{
    #unsigned int fd
    0: {},
},
#waitpid
7:{
    #pid_t pid
    0: {},
    #int *stat_addr
    1: {},
    #int options
    2: {},
},
#creat
8:{
    #const char *pathname
    0: {},
    #umode_t mode
    1: {},
},
#link
9:{
    #const char *oldname
    0: {},
    #const char *newname
    1: {},
},
#unlink
10:{
    #const char *pathname
    0: {},
},
#execve
11:{
    #const char *filename
    0: {},
    #const char *const *argv
    1: {},
    #const char *const *envp
    2: {},
},
#chdir
12:{
    #const char *filename
    0: {},
},
#time
13:{
    #old_time32_t *tloc
    0: {},
},
#mknod
14:{
    #const char *filename
    0: {},
    #umode_t mode
    1: {},
    #unsigned dev
    2: {},
},
#chmod
15:{
    #const char *filename
    0: {},
    #umode_t mode
    1: {},
},
#lchown16
16:{
    #const char *filename
    0: {},
    #old_uid_t user
    1: {},
    #old_gid_t group
    2: {},
},
#stat
18:{
    #const char *filename
    0: {},
    #struct __old_kernel_stat *statbuf
    1: {},
},
#lseek
19:{
    #unsigned int fd
    0: {},
    #off_t offset
    1: {},
    #unsigned int whence
    2: {},
},
#getpid
20:{
},
#mount
21:{
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
#oldumount
22:{
    #char *name
    0: {},
},
#setuid16
23:{
    #old_uid_t uid
    0: {},
},
#getuid16
24:{
},
#stime
25:{
    #old_time32_t *tptr
    0: {},
},
#ptrace
26:{
    #long request
    0: {},
    #long pid
    1: {},
    #unsigned long addr
    2: {},
    #unsigned long data
    3: {},
},
#alarm
27:{
    #unsigned int seconds
    0: {},
},
#fstat
28:{
    #unsigned int fd
    0: {},
    #struct __old_kernel_stat *statbuf
    1: {},
},
#pause
29:{
},
#utime
30:{
    #const char *filename
    0: {},
    #struct old_utimbuf32 *t
    1: {},
},
#access
33:{
    #const char *filename
    0: {},
    #int mode
    1: {},
},
#nice
34:{
    #int increment
    0: {},
},
#sync
36:{
},
#kill
37:{
    #pid_t pid
    0: {},
    #int sig
    1: {},
},
#rename
38:{
    #const char *oldname
    0: {},
    #const char *newname
    1: {},
},
#mkdir
39:{
    #const char *pathname
    0: {},
    #umode_t mode
    1: {},
},
#rmdir
40:{
    #const char *pathname
    0: {},
},
#dup
41:{
    #unsigned int fildes
    0: {},
},
#pipe
42:{
    #int *fildes
    0: {},
},
#times
43:{
    #struct tms *tbuf
    0: {},
},
#brk
45:{
    #unsigned long brk
    0: {},
},
#setgid16
46:{
    #old_gid_t gid
    0: {},
},
#getgid16
47:{
},
#signal
48:{
    #int sig
    0: {},
    #__sighandler_t handler
    1: {},
},
#geteuid16
49:{
},
#getegid16
50:{
},
#acct
51:{
    #const char *name
    0: {},
},
#umount
52:{
    #char *name
    0: {},
    #int flags
    1: {},
},
#ioctl
54:{
    #unsigned int fd
    0: {},
    #unsigned int cmd
    1: {},
    #unsigned long arg
    2: {},
},
#fcntl
55:{
    #unsigned int fd
    0: {},
    #unsigned int cmd
    1: {},
    #unsigned long arg
    2: {},
},
#setpgid
57:{
    #pid_t pid
    0: {},
    #pid_t pgid
    1: {},
},
#olduname
59:{
    #struct oldold_utsname *name
    0: {},
},
#umask
60:{
    #int mask
    0: {},
},
#chroot
61:{
    #const char *filename
    0: {},
},
#ustat
62:{
    #unsigned dev
    0: {},
    #struct ustat *ubuf
    1: {},
},
#dup2
63:{
    #unsigned int oldfd
    0: {},
    #unsigned int newfd
    1: {},
},
#getppid
64:{
},
#getpgrp
65:{
},
#setsid
66:{
},
#sigaction
67:{
    #int sig
    0: {},
    #const struct old_sigaction *act
    1: {},
    #struct old_sigaction *oact
    2: {},
},
#sgetmask
68:{
},
#ssetmask
69:{
    #int newmask
    0: {},
},
#setreuid16
70:{
    #old_uid_t ruid
    0: {},
    #old_uid_t euid
    1: {},
},
#setregid16
71:{
    #old_gid_t rgid
    0: {},
    #old_gid_t egid
    1: {},
},
#sigsuspend
72:{
    #int unused1
    0: {},
    #int unused2
    1: {},
    #old_sigset_t mask
    2: {},
},
#sigpending
73:{
    #old_sigset_t *uset
    0: {},
},
#sethostname
74:{
    #char *name
    0: {},
    #int len
    1: {},
},
#setrlimit
75:{
    #unsigned int resource
    0: {},
    #struct rlimit *rlim
    1: {},
},
#getrlimit
76:{
    #unsigned int resource
    0: {},
    #struct rlimit *rlim
    1: {},
},
#getrusage
77:{
    #int who
    0: {},
    #struct rusage *ru
    1: {},
},
#gettimeofday
78:{
    #struct __kernel_old_timeval *tv
    0: {},
    #struct timezone *tz
    1: {},
},
#settimeofday
79:{
    #struct __kernel_old_timeval *tv
    0: {},
    #struct timezone *tz
    1: {},
},
#getgroups16
80:{
    #int gidsetsize
    0: {},
    #old_gid_t *grouplist
    1: {},
},
#setgroups16
81:{
    #int gidsetsize
    0: {},
    #old_gid_t *grouplist
    1: {},
},
#select
82:{
    #struct sel_arg_struct *arg
    0: {},
},
#symlink
83:{
    #const char *oldname
    0: {},
    #const char *newname
    1: {},
},
#lstat
84:{
    #const char *filename
    0: {},
    #struct __old_kernel_stat *statbuf
    1: {},
},
#readlink
85:{
    #const char *path
    0: {},
    #char *buf
    1: {},
    #int bufsiz
    2: {},
},
#uselib
86:{
    #const char *library
    0: {},
},
#swapon
87:{
    #const char *specialfile
    0: {},
    #int swap_flags
    1: {},
},
#reboot
88:{
    #int magic1
    0: {},
    #int magic2
    1: {},
    #unsigned int cmd
    2: {},
    #void *arg
    3: {},
},
#readdir
89:{
    #unsigned int fd
    0: {},
    #struct old_linux_dirent *dirent
    1: {},
    #unsigned int count
    2: {},
},
#mmap
90:{
    #struct mmap_arg_struct *arg
    0: {},
},
#munmap
91:{
    #unsigned long addr
    0: {},
    #size_t len
    1: {},
},
#truncate
92:{
    #const char *path
    0: {},
    #long length
    1: {},
},
#ftruncate
93:{
    #unsigned int fd
    0: {},
    #off_t length
    1: {},
},
#fchmod
94:{
    #unsigned int fd
    0: {},
    #umode_t mode
    1: {},
},
#fchown16
95:{
    #unsigned int fd
    0: {},
    #old_uid_t user
    1: {},
    #old_gid_t group
    2: {},
},
#getpriority
96:{
    #int which
    0: {},
    #int who
    1: {},
},
#setpriority
97:{
    #int which
    0: {},
    #int who
    1: {},
    #int niceval
    2: {},
},
#statfs
99:{
    #const char *pathname
    0: {},
    #struct statfs *buf
    1: {},
},
#fstatfs
100:{
    #unsigned int fd
    0: {},
    #struct statfs *buf
    1: {},
},
#ioperm
101:{
    #unsigned long from
    0: {},
    #unsigned long num
    1: {},
    #int turn_on
    2: {},
},
#socketcall
102:{
    #int call
    0: {},
    #unsigned long *args
    1: {},
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
#setitimer
104:{
    #int which
    0: {},
    #struct __kernel_old_itimerval *value
    1: {},
    #struct __kernel_old_itimerval *ovalue
    2: {},
},
#getitimer
105:{
    #int which
    0: {},
    #struct __kernel_old_itimerval *value
    1: {},
},
#newstat
106:{
    #const char *filename
    0: {},
    #struct stat *statbuf
    1: {},
},
#newlstat
107:{
    #const char *filename
    0: {},
    #struct stat *statbuf
    1: {},
},
#newfstat
108:{
    #unsigned int fd
    0: {},
    #struct stat *statbuf
    1: {},
},
#uname
109:{
    #struct old_utsname *name
    0: {},
},
#iopl
110:{
    #unsigned int level
    0: {},
},
#vhangup
111:{
},
#vm86old
113:{
    #struct vm86_struct *user_vm86
    0: {},
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
#swapoff
115:{
    #const char *specialfile
    0: {},
},
#sysinfo
116:{
    #struct sysinfo *info
    0: {},
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
