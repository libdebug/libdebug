#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
from lxml import etree
import socket
import subprocess
import time

from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.state.thread_context import ThreadContext
from libdebug.state.debugging_context import (
    provide_context,
    context_extend_from,
    link_context,
)
from libdebug.data.memory_map import MemoryMap
from libdebug.data.register_holder import RegisterHolder
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.syscall_hook import SyscallHook
from libdebug.liblog import liblog
from libdebug.utils.pipe_manager import PipeManager
from libdebug.qemu_stub.qemu_register_file import QemuRegisterFile
from libdebug.qemu_stub.qemu_generic_register_holder import QemuGenericRegisterHolder
from libdebug.qemu_stub.qemu_status_handler import QemuStatusHandler
from libdebug.qemu_stub.qemu_target_xml_parser import parse_qemu_target_xml


LIBDEBUG_SUPPORTED_FEATURES = "qSupported:vContSupported+"

LIBDEBUG_QEMU_PORT = 37669

COUNT = 2


# https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html
class QemuStubInterface(DebuggingInterface):
    """The interface used by `_InternalDebugger` to communicate with the QEMU GDBstub."""

    _step_until_supported = False
    """Whether the remote GDBstub supports the `step_until` feature."""

    _thread_registers: dict[int, QemuRegisterFile] = {}
    """A dictionary that holds the register files of the threads."""

    _current_thread: int
    """The active thread ID for communication with the stub."""

    _status_handler: QemuStatusHandler
    """The status handler for the QEMU stub."""

    def __init__(self):
        super().__init__()

        self.registers_xml_definition_file = None
        self.registers_definition = None
        self.xml_parser = etree.XMLParser(recover=True)

        self.context = provide_context(self)

        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._killed = True

    def _start_qemu(self, port: int):
        # TODO handle other architectures
        binary = "qemu-x86_64-static"

        argv = [
            binary,
            "-g",
            str(port),
        ] + self.context.argv

        self._qemu_process = subprocess.Popen(
            argv,
            env=self.context.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )

    def _format_msg(self, msg: str) -> bytes:
        checksum = sum(msg.encode()) % 256
        return f"${msg}#{checksum:02x}".encode()

    def _send_message(self, msg: str):
        self.connection.send(self._format_msg(msg))

    def _recv_response(self):
        ack = self.connection.recv(1)

        if ack != b"+":
            raise RuntimeError("Failed to receive ack")

        response = self.connection.recv(4096)

        # Acknowledge the response
        self.connection.send(b"+")

        return response[1:-3]

    def _open_connection(self, port: int):
        time.sleep(0.01)
        if self._qemu_process.poll() is not None:
            return False

        while True:
            try:
                self.connection.connect(("localhost", port))
                break
            except ConnectionRefusedError:
                time.sleep(0.001)

                if self._qemu_process.poll() is not None:
                    # We must try starting QEMU again, but with a different port
                    return False

        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        liblog.debugger("Connected to QEMU GDBstub")

        return True

    def _send_supported_features(self):
        self._send_message(LIBDEBUG_SUPPORTED_FEATURES)
        response = self._recv_response()

        liblog.debugger("Received supported features")

        if not all(x in response for x in [b"vContSupported"]):
            raise RuntimeError("Remote does not support all the required features")

    def _ask_vcont_support(self):
        self._send_message("vCont?")
        response = self._recv_response()

        liblog.debugger("Received vCont response")

        if not all(x in response for x in [b"c", b"C", b"s", b"S"]):
            raise RuntimeError("vCont is not supported by the remote")

        if b"r" in response:
            # https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html#vCont-packet
            self._step_until_supported = True

    def _read_target_xml(self):
        self._send_message("qXfer:features:read:target.xml:0,fff")
        response = self._recv_response()

        # We don't have the xi: namespace in the XML, so we just remove it LoL
        response = response.replace(b"xi:", b"")

        liblog.debugger("Received target XML")

        root = etree.fromstring(response[1:].decode(), self.xml_parser)

        architecture = root.find("architecture").text
        target_xml = root.find("include").attrib["href"]

        liblog.debugger(
            f"Architecture: {architecture}, register definitions: {target_xml}"
        )

        if self.registers_xml_definition_file != target_xml:
            # We need to read the new register definitions
            self.registers_definition = None

        self.registers_xml_definition_file = target_xml

        if ":" in architecture:
            architecture = architecture.split(":")[1]

    def _read_register_defs_xml(self):
        target_xml = self.registers_xml_definition_file

        offset = 0
        # Any size bigger than 0x7FE will make QEMU just ignore it, so we use 0x7FE
        size = 0x7FE
        response = b""

        while True:
            self._send_message(f"qXfer:features:read:{target_xml}:{offset:x},{size:x}")
            part = self._recv_response()

            # We skip the first byte, which is the packet type
            response += part[1:]
            offset += size - 1

            if len(part) < size:
                break

        liblog.debugger("Received register definitions XML")

        self.registers_definition = parse_qemu_target_xml(response.decode())

    def _read_current_thread_id(self):
        self._send_message("qC")
        response = self._recv_response()

        return int(response.decode()[2:], 16)

    def _read_thread_registers(self, thread_id: int):
        if thread_id != self._current_thread:
            # TODO: Implement thread switching
            raise NotImplementedError("Thread switching is not supported")

        self._send_message("g")
        response = self._recv_response()

        return bytes.fromhex(response.decode())

    def _write_thread_registers(self, thread_id: int, data: bytes):
        if thread_id != self._current_thread:
            # TODO: Implement thread switching
            raise NotImplementedError("Thread switching is not supported")

        self._send_message(f"G{data.hex()}")
        if self._recv_response() != b"OK":
            raise RuntimeError("Failed to write registers")

    def _ask_initial_stop_reason(self):
        self._send_message("?")
        response = self._recv_response()

        # The expected response is something like "S05;thread:1a;"
        # Which implies that the thread ID is 0x1a and it stopped because of a signal 5
        thread_id = int(
            response[response.find(b"thread:") + 7 : response.find(b";")], 16
        )

        return thread_id

    def _flush_register_changes(self):
        """Flushes any register that changed to the remote."""
        for thread_id, register_file in self._thread_registers.items():
            if register_file.changed:
                self._write_thread_registers(
                    thread_id, register_file.internal_representation
                )

    def _is_process_dead(self, response: bytes) -> bool:
        return response == b"W00"

    def reset(self):
        self.connection.close()
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.registers_definition = None

        self._killed = False
        self._thread_registers = {}
        self._current_thread = 0

    def run(self):
        liblog.debugger("Running a new QEMU session.")

        # Instantiate the status handler
        with context_extend_from(self):
            self._status_handler = QemuStatusHandler()

        connection_port = LIBDEBUG_QEMU_PORT

        if not self._killed:
            # Let's hope that this is enough for QEMU to free up the port
            self._qemu_process.kill()
            self._qemu_process.wait()

        self.reset()

        while True:
            self._start_qemu(connection_port)

            if self._open_connection(connection_port):
                # We have successfully connected to the GDBstub
                break

            # TODO maybe randomize the port in a different way?
            # Multiple threads would still be trying to connect to the same port
            # And in some cases they might connect to the wrong QEMU instance
            connection_port += 1

        self._send_supported_features()
        self._ask_vcont_support()
        self._read_target_xml()

        if self.registers_definition is None:
            self._read_register_defs_xml()

        if self.registers_definition is None:
            raise RuntimeError("Failed to read register definitions")

        stdin, stdout, stderr = (
            self._qemu_process.stdin,
            self._qemu_process.stdout,
            self._qemu_process.stderr,
        )

        self.context.pipe_manager = PipeManager(
            stdin.fileno(), stdout.fileno(), stderr.fileno()
        )

        thread_id = self._ask_initial_stop_reason()

        self.context.process_id = thread_id
        self._current_thread = thread_id

        register_file = QemuRegisterFile(self._read_thread_registers(thread_id))
        register_holder = QemuGenericRegisterHolder(
            register_file, "little", self.registers_definition
        )

        self._thread_registers[thread_id] = register_file

        with context_extend_from(self):
            thread = ThreadContext.new(thread_id, register_holder)

        link_context(thread, self)

        liblog.debugger("Registered new thread")
        self.context.insert_new_thread(thread)

        liblog.debugger("QEMU session started")

    def attach(self, pid: int):
        """Attaches to the specified process.

        Args:
            pid (int): the pid of the process to attach to.
        """
        pass

    def kill(self):
        """Instantly terminates the process."""
        self._send_message("k")
        self._killed = True

    def cont(self):
        """Continues the execution of the process."""
        self._flush_register_changes()

        # We must check if any breakpoint has been enabled or disabled
        # If so, we must notify the remote
        for bp in self.context.breakpoints.values():
            if bp._changed:
                if bp.enabled:
                    self._send_message(f"Z0,{bp.address:x},1")
                else:
                    self._send_message(f"z0,{bp.address:x},1")

                self._recv_response()

        # If we have hit a breakpoint, we need to step over it before continuing
        # Thus, we use vCont to step and then continue
        self._send_message("vCont;s:-1")
        self._recv_response()
        self._send_message("vCont;c:-1")

    def wait(self):
        """Waits for the process to stop."""
        if not self._killed:
            try:
                response = self._recv_response()

                if self._is_process_dead(response):
                    raise RuntimeError("The process has died")
            except RuntimeError:
                # Unexpected state, which probably means that the process died
                self._killed = True
                self._qemu_process.wait()
            else:
                # We must update the register files
                for thread_id in self._thread_registers.keys():
                    self._thread_registers[
                        thread_id
                    ].internal_representation = self._read_thread_registers(thread_id)

                # Parse the stop reason
                stop_reason = response.decode()
                self._status_handler.handle_response(stop_reason)
        else:
            # The process was killed, we need to wait for the subprocess to terminate
            self._qemu_process.wait()

        return False

    def migrate_to_gdb(self):
        """Migrates the current process to GDB."""
        pass

    def migrate_from_gdb(self):
        """Migrates the current process from GDB."""
        pass

    def step(self, thread: ThreadContext):
        """Executes a single instruction of the specified thread.

        Args:
            thread (ThreadContext): The thread to step.
        """
        self._flush_register_changes()
        self._send_message("vCont;s:-1")

    def step_until(self, thread: ThreadContext, address: int, max_steps: int):
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """
        pass

    @functools.cache
    def maps(self) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        # QEMU does not support memory maps
        # self._send_message("qXfer:memory-map:read::0,fff")

        # We have to craft a fictional memory map
        self._send_message("qOffsets")
        response = self._recv_response()
        text = int(response.decode().split(";")[0].split("=")[1], 16)

        # Is there anything before the base address? Idk
        # How big is the memory map? Idk
        # What are the permissions? Idk
        # Will this break? Yes
        return [
            MemoryMap(text, 2**64 - 1, "rwx", -1, 0, self.context.argv[0]),
        ]

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers for the specified thread.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        pass

    def set_breakpoint(self, breakpoint: Breakpoint):
        """Sets a breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        self._send_message(f"Z0,{breakpoint.address:x},1")

        if self._recv_response() != b"OK":
            raise RuntimeError("Failed to set breakpoint")

        self.context.insert_new_breakpoint(breakpoint)

    def unset_breakpoint(self, breakpoint: Breakpoint):
        """Restores the original instruction flow at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to restore.
        """
        self._send_message(f"z0,{breakpoint.address:x},1")
        self.context.remove_breakpoint(breakpoint)

    def set_syscall_hook(self, hook: SyscallHook):
        """Sets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to set.
        """
        pass

    def unset_syscall_hook(self, hook: SyscallHook):
        """Unsets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to unset.
        """
        pass

    def peek_memory(self, address: int) -> int:
        """Reads the memory at the specified address.

        Args:
            address (int): The address to read.

        Returns:
            int: The read memory value.
        """
        self._send_message(f"m{address:x},8")
        response = self._recv_response()
        # GDB returns the memory in hex format, in inverted endianness from what we expect
        return int.from_bytes(bytes.fromhex(response.decode()), "little")

    def poke_memory(self, address: int, data: int):
        """Writes the memory at the specified address.

        Args:
            address (int): The address to write.
            data (int): The value to write.
        """
        data = data.to_bytes(8, "little").hex()
        self._send_message(f"M{address:x},8:{data}")
        if self._recv_response() != b"OK":
            raise RuntimeError("Failed to write memory")
