from ctypes import CDLL, create_string_buffer, POINTER, c_void_p, c_int, c_long, c_char_p, get_errno, set_errno
from .ptrace import *
import struct
import subprocess
import errno
import collections
import os
import signal 
import time
import logging
import re

logging = logging.getLogger("libdebug")

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
        logging.debug("writing @%#x <- %s", start, value)
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
            start = index // self.word_size * self.word_size
            stop = (index + len(value) + self.word_size) // self.word_size * self.word_size
        #Maybe all this alligment stuff is useless if I can do writes allinge per byte.
        logging.debug("mem index:%#x, value: %s, start:%#x, stop:%x", index, value, start, stop)
        orig_data = self._retrive_data(start, stop)
        new_data = orig_data[0:index-start] + value + orig_data[index-start+len(value):]
        self._set_data(start, new_data)


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
        #According to ptrace manual we need to keep track od the running state to discern if ESRCH is becouse the process is running or dead
        self.running = True
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
        self.map = {}
        self.bases = {}

        #create property for registers
        for r in self.regs_names:
            setattr(Debugger, r, self._get_reg(r))
        
        if pid is not None:
            self.attach(pid)

    ## Utils
    @staticmethod
    def _u64(value):
        return struct.unpack("<Q", value)[0]

    @staticmethod
    def _u32(value):
        return struct.unpack("<I", value)[0]

    def _sig_stop(self):
        os.kill(self.pid, signal.SIGSTOP)

    def _wait_process(self):
        options = 0
        for i in range(8):
            self.buf[i] = b"\x00"
        r = self.libc.waitpid(self.pid, self.buf, options)
        status = self._u32(self.buf[:4])
        logging.debug("waitpid status: %#x, ret: %d", status, r)
        self._retrieve_maps()
        self.running = False

    def _stop_process(self):
        logging.debug("Stopping the process")
        self._sig_stop()
        self._wait_process()
        self.running = False

    def _enforce_stop(self):
        # Can we trust self.running without any check?
        if self.running and self._test_execution() == False:
            self._stop_process()


    ### Attach/Detach
    def run(self, path, sleep=None):
        """
        Run a program from the start using th epat as input
        """
        #TODO implement as a execve that start with a stopped program
        args = [path,]
        self.process = subprocess.Popen(args)
        logging.info("new process <%d> %r", self.process.pid, args)
        if sleep is not None:
            time.sleep(sleep)
        self.attach(self.process.pid)


    def attach(self, pid):
        """
        Attach to a process using the pid
        """
        logging.info("attaching to pid %d", pid)      
        self.pid = pid
        self.libc.ptrace.argtypes = self.args_int
        r = self.libc.ptrace(PTRACE_ATTACH, self.pid, NULL, NULL)
        logging.debug("attached %d", r)
        if (r == -1):
            raise DebugFail("Attach Failed. Do you have permisions? Running as sudo?")
        self._wait_process()

    def reattach(self):
        """
        Reattach to the last process. This works only after detach.
        """

        logging.debug("RE-attaching to pid %d", self.old_pid)             
        if self.old_pid is None:
            raise DebugFail("ReAttach Failed. You never attached before! Use attach or run first. and detach")
        self.attach(self.old_pid)


    def detach(self):
        """
        Detach the current process
        """

        logging.info("Detach pid %d", self.pid)      
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_DETACH, self.pid, NULL, NULL) == -1):
            raise DebugFail("Detach Failed. Do you have permisio? Running as sudo?")
        self.old_pid = self.pid
        self.pid = None


    def shutdown(self):
        """
        This sto the execution of the process executed with `run`
        """

        if self.process is not None:
            self.detach()
            self.process.terminate()
            self.process.kill()
            os.kill(self.old_pid, signal.SIGKILL)


    def gdb(self):
        """
        Migrate the dubugging to gdb
        """

        #Stop the process so you can continue exactly form where you let in the script
        self._sig_stop()
        #detach
        pid = self.pid
        self.detach()
        #correctly identify the binary
        # pwndbg example startup
        # gdb -q /home/jinblack/guesser/guesser 2312 -x "/tmp/tmp.Zo2Rv6ane"
        
        # Signal is already stopped but gdb send another SIGSTOP `-ex continue` 
        # will get read of on STOP with a continue
        os.execv('/bin/gdb', ['-q', "--pid", "%d" % pid, "-ex", "continue"])



    ## Registers

    def _get_reg(self, name):
        #This is an helping function to generate properties to access registers        
        def getter(self):
            #reload registers
            self.get_regs()
            return self.regs[name]
        def setter(self, value):
            self.get_regs()
            self.regs[name] = value
            self.set_regs()
        return property(getter, setter, None, name)

    def set_regs(self):
        self._enforce_stop()

        regs_values = []
        for name in self.regs_names:
            regs_values.append(self.regs[name])
 
        data = struct.pack("<" + "Q"*len(self.regs_names), *regs_values)
        bdata = create_string_buffer(data)

        self.libc.ptrace.argtypes = self.args_ptr
        if (self.libc.ptrace(PTRACE_SETREGS, self.pid, NULL, bdata) == -1):
            raise DebugFail("SetRegs Failed. Do you have permisio? Running as sudo?")


    def _test_execution(self):

        self.libc.ptrace.argtypes = self.args_ptr
        set_errno(0)
        if (self.libc.ptrace(PTRACE_GETREGS, self.pid, NULL, self.buf) == -1):
            err = get_errno()
            #We use geT_regs as test for the process if it is running we may stoppit before executing something
            # ether the process is dead or is running
            if err == errno.ESRCH and self.running:
                #we should stop the process.
                return False
            elif err == errno.ESRCH and not self.running:
                logging.critical("The proccess is dead!")
            else:
                logging.debug("getregs error: %d", err)
                raise DebugFail("GetRegs Failed. Do you have permisio? Running as sudo?")

        return True

    def get_regs(self):
        self._enforce_stop()

        self.libc.ptrace.argtypes = self.args_ptr
        set_errno(0)
        if (self.libc.ptrace(PTRACE_GETREGS, self.pid, NULL, self.buf) == -1):
            err = get_errno()
            #We use geT_regs as test for the process if it is running we may stoppit before executing something
            # ether the process is dead or is running
            if err == errno.ESRCH and self.running:
                #we should stop the process.
                return None
            elif err == errno.ESRCH and not self.running:
                logging.critical("The proccess is dead!")
            else:
                logging.debug("getregs error: %d", err)
                raise DebugFail("GetRegs Failed. Do you have permisio? Running as sudo?")

        buf_size = len(self.regs_names) * self.reg_size 
        regs = struct.unpack("<" + "Q"*len(self.regs_names), self.buf[:buf_size])
 
        for name, value in zip(self.regs_names, regs):
            self.regs[name] = value
 
        return self.regs
    

    ## Memory

    def peek(self, addr):
        self._check_mem_address(addr)
        self._enforce_stop()
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
        self._check_mem_address(addr)
        self._enforce_stop()

        # according to man ptrace no difference for PTRACE_POKETEXT and PTRACE_POKEDATA on linux
        set_errno(0)

        self.libc.ptrace.argtypes = self.args_int
        data = self.libc.ptrace(PTRACE_POKEDATA, self.pid, addr, value)

        # This errno is a libc artifact. The syscall return errno as return value and the value in the data parameter
        # We may considere to do direct syscall to avoid errno of libc
        err = get_errno()
        if err == errno.EIO:
            raise DebugFail("Poke Failed. Are you accessing a valid address?")

    def _base_guess(self):
        self.bases["main"] = min([m for m in self.map if self.map[m]['file'] is not None])
        logging.debug("new base main guessed at %#x", self.bases["main"])

        for m in self.map:
            if self.map[m]['offset'] == 0 and self.map[m]['file'] is not None:
                name = self.map[m]['file']
                self.bases[name] = m
                logging.debug("new base %s guessed at %#x", name, m)

    def _retrieve_maps(self):
        # map file example
        # 55c1b7eaf000-55c1b7eb0000 r--p 00000000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb0000-55c1b7eb1000 r-xp 00001000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb1000-55c1b7eb2000 r--p 00002000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb2000-55c1b7eb3000 r--p 00002000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb3000-55c1b7eb4000 rw-p 00003000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 7f7fd6b48000-7f7fd6b4a000 rw-p 00000000 00:00 0 
        # 7f7fd6b4a000-7f7fd6b76000 r--p 00000000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6b76000-7f7fd6cec000 r-xp 0002c000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6cec000-7f7fd6d40000 r--p 001a2000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d40000-7f7fd6d41000 ---p 001f6000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d41000-7f7fd6d44000 r--p 001f6000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d44000-7f7fd6d47000 rw-p 001f9000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d47000-7f7fd6d56000 rw-p 00000000 00:00 0 
        # 7f7fd6d96000-7f7fd6d98000 r--p 00000000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6d98000-7f7fd6dbf000 r-xp 00002000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6dbf000-7f7fd6dca000 r--p 00029000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6dcb000-7f7fd6dcd000 r--p 00034000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6dcd000-7f7fd6dcf000 rw-p 00036000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7ffcc2eef000-7ffcc2f10000 rw-p 00000000 00:00 0                          [stack]
        # 7ffcc2fab000-7ffcc2faf000 r--p 00000000 00:00 0                          [vvar]
        # 7ffcc2faf000-7ffcc2fb1000 r-xp 00000000 00:00 0                          [vdso]
        # ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
        l_regx = "(?P<start>[0-9a-f]+)-(?P<stop>[0-9a-f]+)\s+(?P<read>[r-])(?P<write>[w-])(?P<exec>[x-])([p-])\s+(?P<offset>[0-9a-f]+)\s+\d\d:\d\d\s+(?P<inode>[0-9]+)\s+(?P<pathname>\/.*[\w:]+|\[\w+\])?"
        pid = self.pid
        logging.debug("Retrieving mem maps")
        with open(f"/proc/{pid}/maps", 'r') as f:
            self.map = {}
            for l in f.readlines():
                m = re.match(l_regx, l)
                md = m.groupdict()
                perm = 4 if md['read']  == 'r' else 0 \
                     + 2 if md['write'] == 'w' else 0 \
                     + 1 if md['exec']  == 'x' else 0
                start = int(md['start'], 16)
                stop = int(md['stop'], 16)
                offset = int(md['offset'], 16)

                segment = {"start": start, 
                           "stop": stop,
                           "perms": perm,
                           "offset": offset, 
                           "pathname": md['pathname'],
                           "file": os.path.basename(md['pathname'])  if md['pathname'] is not None else None}
                self.map[start] = segment
        self._base_guess()

    def _check_mem_address(self, addr, warn=True):
        for m in self.map:
            if self.map[m]['start'] <= addr < self.map[m]['stop']:
                return True
        if warn:
            logging.warning("The address %#x is outside any memory reagion", addr)
        return False

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
        """
        Execute the next instruction (Step Into)
        """
        self._enforce_stop()
        #Step can stuck running into syscalls
        self.running = True
        self.libc.ptrace.argtypes = self.args_int
        if (self.libc.ptrace(PTRACE_SINGLESTEP, self.pid, NULL, NULL) == -1):
            raise DebugFail("Step Failed. Do you have permisions? Running as sudo?")
        self._wait_process()


    def step_until(self, rip):
        """
        Execute using single step until the value of rip is equal to the argument
        """

        #Maybe punt a max stept or a timeout
        while True:
            self.step()
            if self.rip == rip:
                break

    def cont(self, blocking=True):
        """
        Continue the execution until the next breakpoint is hitted or the program is stopped
        """

        #I need to execute at least another instruction otherwise I get always in the same bp
        self.step()
        self._set_breakpoints()
        self.libc.ptrace.argtypes = self.args_int
        self.running = True
        # Probably should implement a timeout
        if (self.libc.ptrace(PTRACE_CONT, self.pid, NULL, NULL) == -1):
            raise DebugFail("Continue Failed. Do you have permisions? Running as sudo?")
        if blocking:
            self._wait_process()
            self._retore_breakpoints()
            logging.debug("Continue Stopped")

    def finish(self, blocking=True):
        """
        Execute until the end of the current function.
        This works only if the program use the rbp register as base address.
        """
        # This works only if the binary use the baseptr for the frames
        if not self._check_mem_address(self.rbp):
            logging.error("rbp %#x is not a valid frame. Impossible to execute finish", self.rbp)
            raise DebugFail("Finish Failed. Frame not found")
        ret_addr = Debugger._u64(self.mem[self.rbp+0x8: self.rbp+0x10])
        logging.info("finish executing until Return Address found at %#x", ret_addr)
        self.bp(ret_addr)
        self.cont(blocking)
        self.del_bp(ret_addr)

    def bp(self, addr):
        """
        Set a breakpoint to specific address
        """
        if addr not in self.breakpoints:
            self._check_mem_address(addr)
            logging.info("new BreakPoint at %#x", addr)
            self.breakpoints[addr] = None
        return addr

    def breakpoint(self, addr, name=None):
        if name is None and self._check_mem_address(addr, warn=False):
            return self.bp(addr)
        # BP not found as valid address.
        if name is None:
            name = "main"
        #Look for the lib that start with that name
        if name not in self.bases:
            for x in self.bases:
                if x.startwith(name):
                    name = x
                    break
        # did not find any valid region. Try standard bp
        if name not in self.bases:
            return self.bp(addr)
        # compute and set the bp
        logging.info("relative BreakPoint, region: %s, start:%#x", name, self.bases[name])
        real_address = self.bases[name] + addr
        return self.bp(real_address)

    def del_bp(self, addr):
        """
        Remove the breakpoint
        """
        if addr in self.breakpoints:
            logging.info("delete BreakPoint at %#x", addr)
            del self.breakpoints[addr]
