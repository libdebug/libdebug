"""Exec replaces image-specific state before the new image can run."""

from unittest import TestCase, skipUnless

from elftools.elf.elffile import ELFFile
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.data.event_type import EventType
from libdebug.utils.libcontext import libcontext


class ExecTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires an amd64 host with i386 compatibility")
    def test_image_breakpoints(self):
        for suffix in ("", "-cet"):
            for fast in (True, False):
                with self.subTest(control_flow_protection=bool(suffix), fast_memory=fast):
                    old = RESOLVE_EXE("exec_old" + suffix)
                    new = RESOLVE_EXE("exec_new" + suffix)
                    with open(new, "rb") as stream:
                        section = ELFFile(stream).get_section_by_name(".probe")
                        address, expected = section["sh_addr"], section.data()
                    d = debugger([old, new], stop_on_exec=True, fast_memory=fast)
                    try:
                        pipe = d.run()
                        before = d.memory[address, len(expected), "absolute"]
                        self.assertNotEqual(before, expected)
                        d.breakpoint(address, file="absolute")
                        for offset in (1, 2, 3, 4):
                            d.breakpoint(address + offset, hardware=True, file="absolute")
                        d.cont()
                        d.wait()
                        self.assertEqual(d.resume_context.event_type[d.pid], EventType.EXEC)
                        self.assertEqual(
                            d.memory[address, len(expected), "absolute"],
                            expected,
                            "old instruction bytes must never be restored into the new image",
                        )
                        self.assertEqual(d.breakpoints, {})
                        sw = d.breakpoint(address, file="absolute")
                        hardware = [d.breakpoint(f"probe_return+{offset}", hardware=True) for offset in range(4)]
                        d.cont()
                        d.wait()
                        self.assertEqual(sw.hit_count, 1)
                        sw.disable()
                        d.cont()
                        d.wait()
                        self.assertEqual(hardware[0].hit_count, 1)
                        for bp in hardware:
                            bp.disable()
                        d.cont()
                        d.wait()
                        self.assertEqual(pipe.recvline(), b"IMAGE 42")
                        self.assertEqual(d.exit_code, 0)
                    finally:
                        d.kill()
                        d.terminate()
