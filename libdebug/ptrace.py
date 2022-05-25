from ctypes import CDLL, create_string_buffer, POINTER, c_void_p, c_int, c_long, c_char_p, get_errno, set_errno
import struct
import logging
import errno

NULL = 0
PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24
PTRACE_GET_THREAD_AREA = 25
PTRACE_SET_THREAD_AREA = 26
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_INTERRUPT =  0x4207
PTRACE_O_TRACESYSGOOD        = 0x00000001
PTRACE_O_TRACEFORK        = 0x00000002
PTRACE_O_TRACEVFORK   = 0x00000004
PTRACE_O_TRACECLONE        = 0x00000008
PTRACE_O_TRACEEXEC        = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT        = 0x00000040
PTRACE_O_MASK                = 0x0000007f
PTRACE_EVENT_FORK        = 1
PTRACE_EVENT_VFORK        = 2
PTRACE_EVENT_CLONE        = 3
PTRACE_EVENT_EXEC        = 4
PTRACE_EVENT_VFORK_DONE = 5,
PTRACE_EVENT_EXIT        = 6

WNOHANG = 1

class PtraceFail(Exception):
    pass


class Ptrace():
    def __init__(self):
        self.libc = CDLL("libc.so.6", use_errno=True)
        self.args_ptr = [c_int, c_long, c_long, c_char_p]
        self.args_int = [c_int, c_long, c_long, c_long]
        self.libc.ptrace.argtypes = self.args_ptr
        self.libc.ptrace.restype = c_long
        self.buf = create_string_buffer(1000)


    def waitpid(self, tid, buf, options):
        return self.libc.waitpid(tid, buf, options)

    def setregs(self, tid, data):
        bdata = create_string_buffer(data)
        self.libc.ptrace.argtypes = self.args_ptr
        if (self.libc.ptrace(PTRACE_SETREGS, tid, NULL, bdata) == -1):
            raise PtraceFail("SetRegs Failed. Do you have permisio? Running as sudo?")


    def getregs(self, tid):
        buf = create_string_buffer(1000)
        self.libc.ptrace.argtypes = self.args_ptr
        set_errno(0)
        if (self.libc.ptrace(PTRACE_GETREGS, tid, NULL, buf) == -1):
            return None

        return buf


    def setfpregs(self, tid, data):
        bdata = create_string_buffer(data)
        self.libc.ptrace.argtypes = self.args_ptr
        if (self.libc.ptrace(PTRACE_SETFPREGS, tid, NULL, bdata) == -1):
            raise PtraceFail("SetRegs Failed. Do you have permisio? Running as sudo?")


    def getfpregs(self, tid):
        buf = create_string_buffer(1000)
        self.libc.ptrace.argtypes = self.args_ptr
        set_errno(0)
        if (self.libc.ptrace(PTRACE_GETFPREGS, tid, NULL, self.buf) == -1):
            return None
        return buf


    def singlestep(self, tid):
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL) == -1):
            raise PtraceFail("Step Failed. Do you have permisions? Running as sudo?")


    def cont(self, tid):
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_CONT, tid, NULL, NULL) == -1):
            raise PtraceFail("[%d] Continue Failed. Do you have permisions? Running as sudo?" % tid)


    def poke(self, tid, addr, value):
        set_errno(0)
        self.libc.ptrace.argtypes = self.args_int
        data = self.libc.ptrace(PTRACE_POKEDATA, tid, addr, value)

        # This errno is a libc artifact. The syscall return errno as return value and the value in the data parameter
        # We may considere to do direct syscall to avoid errno of libc
        err = get_errno()
        if err == errno.EIO:
            raise PtraceFail("Poke Failed. Are you accessing a valid address?")


    def peek(self, tid, addr):
        set_errno(0)
        self.libc.ptrace.argtypes = self.args_int
        data = self.libc.ptrace(PTRACE_PEEKDATA, tid, addr, NULL)

        # This errno is a libc artifact. The syscall return errno as return value and the value in the data parameter
        # We may considere to do direct syscall to avoid errno of libc
        err = get_errno()
        if err == errno.EIO:
            raise PtraceFail("Peek Failed. Are you accessing a valid address?")
        return data


    def setoptions(self, tid, options):
        self.libc.ptrace.argtypes = self.args_int
        r = self.libc.ptrace(PTRACE_SETOPTIONS, tid, NULL, options)
        if (r == -1):
            raise PtraceFail("Option Setup Failed. Do you have permisions? Running as sudo?")


    def attach(self, tid):
        self.libc.ptrace.argtypes = self.args_int
        set_errno(0)
        r = self.libc.ptrace(PTRACE_ATTACH, tid, NULL, NULL)
        logging.debug("attached %d", r)
        if (r == -1):
            err = get_errno()
            raise PtraceFail("Attach Failed. Err:%d Do you have permisions? Running as sudo?" % err)


    def detach(self, tid):
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_DETACH, tid, NULL, NULL) == -1):
            raise PtraceFail("Detach Failed. Do you have permisio? Running as sudo?")


    def traceme(self):
        self.libc.ptrace.argtypes = self.args_int
        r = self.libc.ptrace(PTRACE_TRACEME, NULL, NULL, NULL)


AMD64_REGS = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]
FPREGS_SHORT = ["cwd", "swd", "ftw", "fop"]
FPREGS_LONG  = ["rip", "rdp"]
FPREGS_INT   = ["mxcsr", "mxcr_mask"]
FPREGS_80    = ["st%d" %i for i in range(8)]
FPREGS_128   = ["xmm%d" %i for i in range(16)]
