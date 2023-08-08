from ctypes import CDLL, create_string_buffer, POINTER, c_void_p, c_int, c_long, c_char_p, get_errno, set_errno
import struct
import logging
import errno
import os
from queue import Queue
from threading import Lock
from .utils import inverse_mapping

logging = logging.getLogger("libdebug-ptrace")

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
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT =  0x4207
PTRACE_LISTEN = 0x4208
PTRACE_PEEKSIGINFO = 0x4209
PTRACE_GETSIGMASK = 0x420a
PTRACE_SETSIGMASK = 0x420b
PTRACE_SECCOMP_GET_FILTER = 0x420c
PTRACE_SECCOMP_GET_METADATA = 0x420d
PTRACE_GET_SYSCALL_INFO = 0x420e
PTRACE_GET_RSEQ_CONFIGURATION = 0x420f
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT = 0x00000040
PTRACE_O_TRACESECCOMP = 0x00000080
PTRACE_O_EXITKILL = 0x00100000
PTRACE_O_SUSPEND_SECCOMP = 0x00200000
PTRACE_O_MASK = 0x003000ff
PTRACE_EVENT_FORK        = 1
PTRACE_EVENT_VFORK        = 2
PTRACE_EVENT_CLONE        = 3
PTRACE_EVENT_EXEC        = 4
PTRACE_EVENT_VFORK_DONE = 5,
PTRACE_EVENT_EXIT        = 6
PTRACE_EVENT_SECCOMP =  7

WNOHANG = 1


TRACE_EVENT = {
    "PTRACE_EVENT_FORK":         1,
    "PTRACE_EVENT_VFORK":        2,
    "PTRACE_EVENT_CLONE":        3,
    "PTRACE_EVENT_EXEC":         4,
    "PTRACE_EVENT_VFORK_DONE":   5,
    "PTRACE_EVENT_EXIT":         6,
    "PTRACE_EVENT_SECCOMP":      7,
}

TRACE_EVENT_NUM = inverse_mapping(TRACE_EVENT)

def ptrace_event_from_num(num):
    if num in TRACE_EVENT_NUM:
        return TRACE_EVENT_NUM[num]
    return "%d" % num


# /* If WIFEXITED(STATUS), the low-order 8 bits of the status.  */
def WEXITSTATUS(status):
    return (((status) & 0xff00) >> 8)

# /* If WIFSIGNALED(STATUS), the terminating signal.  */
def WTERMSIG(status):
    return ((status) & 0x7f)

# /* If WIFSTOPPED(STATUS), the signal that stopped the child.  */
def WSTOPSIG(status):
    return WEXITSTATUS(status)

# /* Nonzero if STATUS indicates normal termination.  */
def WIFEXITED(status):
    return (WTERMSIG(status) == 0)

# /* Nonzero if STATUS indicates termination by a signal.  */
def WIFSIGNALED(status):
    val = ((((status) & 0x7f) + 1) >> 1)
    return (val < 128)

# /* Nonzero if STATUS indicates the child is stopped.  */
def WIFSTOPPED(status):
    return (((status) & 0xff) == 0x7f)
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


    def singlestep(self, tid, signal=0x0):
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_SINGLESTEP, tid, NULL, signal) == -1):
            raise PtraceFail("Step Failed. Do you have permisions? Running as sudo?")


    def cont(self, tid, signal):
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_CONT, tid, NULL, signal) == -1):
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
        logging.debug("attached %d", tid)
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

    #USER struct
    def poke_user(self, tid, addr, value):
        set_errno(0)
        self.libc.ptrace.argtypes = self.args_int
        data = self.libc.ptrace(PTRACE_POKEUSER, tid, addr, value)

        # This errno is a libc artifact. The syscall return errno as return value and the value in the data parameter
        # We may considere to do direct syscall to avoid errno of libc
        err = get_errno()
        if err == errno.EIO:
            raise PtraceFail("Poke User Failed. Are you accessing a valid address?")


    def peek_user(self, tid, addr):
        set_errno(0)
        self.libc.ptrace.argtypes = self.args_int
        data = self.libc.ptrace(PTRACE_PEEKUSER, tid, addr, NULL)

        # This errno is a libc artifact. The syscall return errno as return value and the value in the data parameter
        # We may considere to do direct syscall to avoid errno of libc
        err = get_errno()
        if err == errno.EIO:
            raise PtraceFail("Peek User Failed. Are you accessing a valid address?")
        return data

def debug_decorator(func):
    def parse(self, *args, **kwargs):
        logging.debug(f"calling {func.__name__}")
        result = func(self, *args, **kwargs)
        logging.debug(f"{func.__name__} returned {result}")
        return result
    return parse

def lock_decorator(func):
    def parse(self, *args, **kwargs):
        with self.lock:
            result = func(self, *args, **kwargs)
            if type(result) is PtraceFail:
                raise result
        return result
    return parse

class Ptracer:
        def __init__(self):
            self.ptrace = Ptrace()
            self.queries = Queue()
            self.retval = Queue()
            self.lock = Lock()

        def start(self):
            logging.debug("ptracer is running")
            while True:
                ptrace_request, tid, arg1, arg2 = self.queries.get()

                try:
                    # Brutto, ma dovrebbe funzionare
                    if type(ptrace_request) is str:
                        # È una run
                        path, args = ptrace_request, tid
                        pid = self._run(path, args)
                        self.retval.put(pid)

                    if ptrace_request == PTRACE_SETREGS:
                        self.retval.put(self.ptrace.setregs(tid, arg2))
                    
                    if ptrace_request == PTRACE_GETREGS:
                        self.retval.put(self.ptrace.getregs(tid))   

                    if ptrace_request == PTRACE_SETFPREGS:
                        self.retval.put(self.ptrace.setfpregs(tid, arg2))

                    if ptrace_request == PTRACE_GETFPREGS:
                        self.retval.put(self.ptrace.getfpregs(tid))

                    if ptrace_request == PTRACE_SINGLESTEP:
                        self.retval.put(self.ptrace.singlestep(tid, arg2))

                    if ptrace_request == PTRACE_CONT:
                        self.retval.put(self.ptrace.cont(tid, arg2))

                    if ptrace_request == PTRACE_POKEDATA:
                        self.retval.put(self.ptrace.poke(tid, arg1, arg2))

                    if ptrace_request == PTRACE_PEEKDATA:
                        self.retval.put(self.ptrace.peek(tid, arg1))

                    if ptrace_request == PTRACE_SETOPTIONS:
                        self.retval.put(self.ptrace.setoptions(tid, arg2))

                    if ptrace_request == PTRACE_ATTACH:
                        self.retval.put(self.ptrace.attach(tid))

                    if ptrace_request == PTRACE_SEIZE:
                        self.retval.put(self.ptrace.seize(tid, arg2))

                    if ptrace_request == PTRACE_DETACH:
                        self.retval.put(self.ptrace.detach(tid))

                    if ptrace_request == PTRACE_INTERRUPT:
                        self.retval.put(self.ptrace.interrupt(tid))

                    if ptrace_request == PTRACE_POKEUSER:
                        self.retval.put(self.ptrace.poke_user(tid, arg1, arg2))

                    if ptrace_request == PTRACE_PEEKUSER:
                        self.retval.put(self.ptrace.peek_user(tid, arg1))
                
                except Exception as e:
                    self.retval.put(e)

        @lock_decorator
        @debug_decorator
        def run(self, path, args):
            self.queries.put((path, args, NULL, NULL))
            return self.retval.get()

        @lock_decorator
        def setregs(self, tid, data):
           self.queries.put((PTRACE_SETREGS, tid, NULL, data))
           return self.retval.get()

        @lock_decorator
        def getregs(self, tid):
            self.queries.put((PTRACE_GETREGS, tid, NULL, NULL))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def setfpregs(self, tid, data):
            self.queries.put((PTRACE_SETFPREGS, tid, NULL, data))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def getfpregs(self, tid):
            self.queries.put((PTRACE_GETFPREGS, tid, NULL, NULL))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def singlestep(self, tid, signal=0x0):
            self.queries.put((PTRACE_SINGLESTEP, tid, NULL, signal))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def cont(self, tid, signal=0x0):
            self.queries.put((PTRACE_CONT, tid, NULL, signal))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def poke(self, tid, addr, value):
            self.queries.put((PTRACE_POKEDATA, tid, addr, value))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def peek(self, tid, addr):
            self.queries.put((PTRACE_PEEKDATA, tid, addr, NULL))
            return self.retval.get()
                
        @lock_decorator
        @debug_decorator
        def setoptions(self, tid, options):
            self.queries.put((PTRACE_SETOPTIONS, tid, NULL, options))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def attach(self, tid):
            self.queries.put((PTRACE_ATTACH, tid, NULL, NULL))
            return self.retval.get()
            
        @lock_decorator
        @debug_decorator
        def seize(self, tid, options=NULL):
            self.queries.put((PTRACE_SEIZE, tid, NULL, options))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def detach(self, tid):
            self.queries.put((PTRACE_DETACH, tid, NULL, NULL))
            return self.retval.get()


        @lock_decorator
        @debug_decorator
        def interrupt(self, tid):
            self.queries.put((PTRACE_INTERRUPT, tid, NULL, NULL))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def poke_user(self, tid, addr, value):
            self.queries.put((PTRACE_POKEUSER, tid, addr, value))
            return self.retval.get()

        @lock_decorator
        @debug_decorator
        def peek_user(self, tid, addr):
            self.queries.put((PTRACE_PEEKUSER, tid, addr, NULL))
            return self.retval.get()
        

        # A parte perchè non hanno devono essere eseguiti dentro al thread
        
        def traceme(self):
            self.ptrace.traceme()

        def waitpid(self, tid, buf, options):
            return self.ptrace.waitpid(tid, buf, options)

        def _run(self, path, args):
            pid = os.fork()
            if pid == 0:
                #child process
                # PTRACE ME
                # Ho provato a fare stop e seize che permetterebbe di non avere una funzione run qui e di usare ptrace_interrupt, ma ho avuto un comportamento diverso da quello che si aspettavano i test quindi ho lasciato perdere, ma potrebbe essere interessante
                #pid = os.getpid()
                #self._sig_stop(pid)
                self.ptrace.traceme()
                # logging.debug("attached %d", r)
                args = [path,] + args
                try:
                    os.execv(path, args)
                except Exception as e:
                    raise PtraceFail("Exec of new process failed: %r" % e)
            return pid

AMD64_REGS = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]
FPREGS_SHORT = ["cwd", "swd", "ftw", "fop"]
FPREGS_LONG  = ["rip", "rdp"]
FPREGS_INT   = ["mxcsr", "mxcr_mask"]
FPREGS_80    = ["st%d" %i for i in range(8)]
FPREGS_128   = ["xmm%d" %i for i in range(16)]
AMD64_DBGREGS_OFF = {'DR0': 0x350, 'DR1': 0x358, 'DR2': 0x360, 'DR3': 0x368, 'DR4': 0x370, 'DR5': 0x378, 'DR6': 0x380, 'DR7': 0x388}
AMD64_DBGREGS_CTRL_LOCAL = {'DR0': 1<<0, 'DR1': 1<<2, 'DR2': 1<<4, 'DR3': 1<<6}
AMD64_DBGREGS_CTRL_COND  = {'DR0': 16, 'DR1': 20, 'DR2': 24, 'DR3': 28}
AMD64_DBGREGS_CTRL_COND_VAL  = {'X': 0, 'W': 1, 'IO': 2, 'RW': 3}
AMD64_DBGREGS_CTRL_LEN   = {'DR0': 18, 'DR1': 22, 'DR2': 26, 'DR3': 30}
AMD64_DBGREGS_CTRL_LEN_VAL  = {1: 0, 2: 1, 8: 2, 4: 3}
