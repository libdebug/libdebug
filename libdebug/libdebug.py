from ctypes import CDLL, create_string_buffer, POINTER, c_void_p, c_int, c_long, c_char_p, get_errno, set_errno
from .ptrace import *
import struct
import subprocess
import errno
import collections
import os
import signal 

class DebugFail(Exception):
    pass

class Memory(collections.abc.MutableSequence):

    def __init__(self, getter, setter):
        self.getword = getter
        self.setword = setter
        self.word_size = 8

    def _retrive_data(self, start, stop):
        data = b""
        for i in range(start, stop, self.word_size):
            n = self.getword(i)
            data += struct.pack("<q", n)
        return data

    def __getitem__(self, index):
        if isinstance(index, slice):
            start = index.start // self.word_size * self.word_size
            stop = (index.stop + self.word_size) // self.word_size * self.word_size
            return self._retrive_data(start, stop)[index.start-start: index.stop-start]
        else:
            return (self.getword(index) & 0xff).to_bytes(1, 'little')

    def _set_data(self, start, value):
        for i in range(start, (start + len(value)), self.word_size):
            chunk = value[(i-start) : (i+self.word_size-start)]
            data = struct.unpack("<Q", chunk)[0]
            self.setword(i, data)

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            start = index.start // self.word_size * self.word_size
            #TODO if is a slice ensure that value is not going after the end
            stop = (index.start + len(value) + self.word_size) // self.word_size * self.word_size
            index = index.start
        else:
            start = index
            stop = (index + len(value) + self.word_size) // self.word_size * self.word_size

        #Maybe all this alligment stuff is useless if I can do writes allinge per byte.
        orig_data = self._retrive_data(start, stop)
        new_data = orig_data[0:index-start] + value + orig_data[index-start+len(value):]
        self._set_data(index, new_data)


    def __len__(self):
        return 0

    def __delitem__(self, index):
        self.__setitem__(self, index, b'\x00')

    def insert(self, index, value):
        self.__setitem__(self, index, value)

class Debugger:

    def __init__(self, pid=None):
        self.pid = None
        self.old_pid = None
        self.process = None
        self.libc = CDLL("libc.so.6", use_errno=True)
        self.args_ptr = [c_int, c_long, c_long, c_char_p]
        self.args_int = [c_int, c_long, c_long, c_long]
        self.libc.ptrace.argtypes = self.args_ptr
        self.libc.ptrace.restype = c_long
        self.buf = create_string_buffer(1000)
        self.regs_names = AMD64_REGS
        self.reg_size = 8
        self.regs = {}
        self.mem = Memory(self.peek, self.poke)
        self.breakpoints = {}

        #create property for registers
        for r in self.regs_names:
            setattr(Debugger, r, self.get_reg(r))
        
        if pid is not None:
            self.attach(pid)


    ### Attach/Detach
    def run(self, path):
        #TODO implement as a execve that start with a stopped program
        self.process = subprocess.Popen([path,])
        self.attach(self.process.pid)

    def attach(self, pid):
        self.pid = pid
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_ATTACH, self.pid, NULL, NULL) == -1):
            raise DebugFail("Attach Failed. Do you have permisions? Running as sudo?")
        self.libc.waitpid(pid, NULL, 0)
    
    def reattach(self):
        if self.old_pid is None:
            raise DebugFail("ReAttach Failed. You never attached before! Use attach or run first. and detach")
        self.attach(self.old_pid)

    def detach(self):
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_DETACH, self.pid, NULL, NULL) == -1):
            raise DebugFail("Detach Failed. Do you have permisio? Running as sudo?")
        self.old_pid = self.pid
        self.pid = None

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            self.process.kill()

    def gdb(self):

        #Stop the process so you can continue exactly form where you let in the script
        os.kill(self.pid, signal.SIGSTOP)
        #detach
        pid = self.pid
        self.detach()
        #correctly identify the binary
        #if i have the bianry file set it to gdb as well
        # set up a startup script to continue?
        # powndbg example startup
        # gdb -q /home/jinblack/guesser/guesser 2312 -x "/tmp/tmp.Zo2Rv6ane"
        os.execv('/bin/gdb', ['-q', "--pid", "%d" % pid])



    ## Registers

    def get_reg(self, name):
        def getter(self):
            #reload registers
            self.get_regs()
            return self.regs[name]
        def setter(self, value):
            self.regs[name] = value
            self.set_regs()
        return property(getter, setter, None, name)

    def set_regs(self):
        regs_values = []
        for name in self.regs_names:
            regs_values.append(self.regs[name])
 
        data = struct.pack("<" + "Q"*len(self.regs_names), *regs_values)
        bdata = create_string_buffer(data)

        self.libc.ptrace.argtypes = self.args_ptr
        if (self.libc.ptrace(PTRACE_SETREGS, self.pid, NULL, bdata) == -1):
            raise DebugFail("SetRegs Failed. Do you have permisio? Running as sudo?")

    def get_regs(self):
        self.libc.ptrace.argtypes = self.args_ptr
        if (self.libc.ptrace(PTRACE_GETREGS, self.pid, NULL, self.buf) == -1):
            raise DebugFail("GetRegs Failed. Do you have permisio? Running as sudo?")
        buf_size = len(self.regs_names) * self.reg_size 
        regs = struct.unpack("<" + "Q"*len(self.regs_names), self.buf[:buf_size])
 
        for name, value in zip(self.regs_names, regs):
            self.regs[name] = value
 
        return self.regs
    

    ## Memory

    def peek(self, addr):
        # according to man ptrace no difference for PTRACE_PEEKTEXT and PTRACE_PEEKDATA on linux
        set_errno(0)

        self.libc.ptrace.argtypes = self.args_int
        data = self.libc.ptrace(PTRACE_PEEKDATA, self.pid, addr, NULL)

        # This errno is a libc artifact. The syscall return errno as return value and the value in the data parameter
        # We may considere to do direct syscall to avoid errno of libc
        err = get_errno()
        if err == errno.EIO:
            raise DebugFail("Peek Failed. Are you accessing a valid address?")

        return data
    
    def poke(self, addr, value):
        # according to man ptrace no difference for PTRACE_POKETEXT and PTRACE_POKEDATA on linux
        set_errno(0)

        self.libc.ptrace.argtypes = self.args_int
        data = self.libc.ptrace(PTRACE_POKEDATA, self.pid, addr, value)

        # This errno is a libc artifact. The syscall return errno as return value and the value in the data parameter
        # We may considere to do direct syscall to avoid errno of libc
        err = get_errno()
        if err == errno.EIO:
            raise DebugFail("Poke Failed. Are you accessing a valid address?")

    ## Control Flow
    def _set_breakpoints(self):
        for b in self.breakpoints:
            self.breakpoints[b] = self.mem[b]
            self.mem[b] = b"\xcc"

    def _retore_breakpoints(self):
        # Some time this stop exactly before the execution of the bp some time after.
        if self.rip not in self.breakpoints and self.rip-1 in self.breakpoints:
            self.rip -= 1
        for b in self.breakpoints:
            self.mem[b] = self.breakpoints[b]
            self.breakpoints[b] = None

    def step(self):
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_SINGLESTEP, self.pid, NULL, NULL) == -1):
            raise DebugFail("Step Failed. Do you have permisions? Running as sudo?")
        self.libc.waitpid(self.pid, self.buf, 0)


    def step_until(self, rip):
        #Maybe punt a max stept or a timeout
        while True:
            self.step()
            if self.rip == rip:
                break

    def cont(self):
        #I need to execute at least another instruction otherwise I get always in the same bp
        self.step()
        self._set_breakpoints()
        self.libc.ptrace.argtypes = self.args_int
        # Probably should implement a timeout
        if (self.libc.ptrace(PTRACE_CONT, self.pid, NULL, NULL) == -1):
            raise DebugFail("Continue Failed. Do you have permisions? Running as sudo?")
        self.libc.waitpid(self.pid, self.buf, 0)
        self._retore_breakpoints()

    def bp(self, addr):
        self.breakpoints[addr] = None

    def del_bp(self, addr):
        if addr in self.breakpoints:
            del self.breakpoints[addr]