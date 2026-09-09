"""Architecture-changing exec on an amd64 host with i386 compatibility."""

from unittest import TestCase, skipUnless

from libdebug import debugger
from libdebug.data.event_type import EventType
from libdebug.utils.libcontext import libcontext


class ExecArchTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires an amd64 host with i386 compatibility")
    def test_architecture_exec(self):
        for bits in ((64, 32), (32, 64), (64, 32, 64)):
            with self.subTest(bits=bits):
                images = tuple((f"binaries/{'amd64' if bit == 64 else 'i386'}/exec_abi{bit}" for bit in bits))
                d = debugger(list(images), stop_on_exec=True)
                try:
                    pipe = d.run()
                    survivor = d.threads[0]
                    for index, image in enumerate(images):
                        arch = "amd64" if image.endswith("64") else "i386"
                        self.assertEqual(d.arch, arch, "exec must refresh the target ABI")
                        self.assertIs(d.threads[0], survivor)
                        ip = "rip" if arch == "amd64" else "eip"
                        self.assertEqual(getattr(survivor.regs, ip), survivor.instruction_pointer)
                        register = "rdi" if arch == "amd64" else "ebx"
                        saved = getattr(survivor.regs, register)
                        setattr(survivor.regs, register, 0x12345678)
                        self.assertEqual(survivor.syscall_arg0, 0x12345678)
                        survivor.syscall_arg0 = 0x23456789
                        self.assertEqual(getattr(survivor.regs, register), 0x23456789)
                        setattr(survivor.regs, register, saved)
                        entered, returned = [], []

                        def on_enter(t, h):
                            self.assertEqual(t.syscall_arg0, 1)
                            self.assertEqual(t.syscall_arg2, 4)
                            self.assertEqual(t.memory[t.syscall_arg1, 4, "absolute"], b"ABI\n")
                            entered.append(t.syscall_number)

                        def on_exit(t, h):
                            returned.append(t.syscall_return)

                        d.handle_syscall("write", on_enter=on_enter, on_exit=on_exit)
                        bp = d.breakpoint("checkpoint", hardware=True, file=image)
                        d.cont()
                        d.wait()
                        self.assertEqual(bp.hit_count, 1)
                        bp.disable()
                        d.cont()
                        d.wait()
                        self.assertEqual(entered, [1 if arch == "amd64" else 4])
                        self.assertEqual(returned, [4])
                        self.assertEqual(pipe.recvline(), b"ABI")
                        if index + 1 < len(images):
                            self.assertEqual(d.resume_context.event_type[d.pid], EventType.EXEC)
                    self.assertEqual(d.exit_code, 0)
                finally:
                    d.kill()
                    d.terminate()
