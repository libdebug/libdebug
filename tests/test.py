import unittest
from libdebug import Debugger
from pwn import process
from tqdm import tqdm


class Debugger_read(unittest.TestCase):
    def setUp(self):
        self.d = Debugger()
        self.d.run("./read_test", sleep=0.1)
        self.mem_addr = 0x1AABBCC1000

    def tearDown(self):
        self.d.shutdown()

    def test_read_register(self):
        self.assertEqual(self.d.rax, 0x0011223344556677)
        self.assertEqual(self.d.rbx, 0x1122334455667788)
        self.assertEqual(self.d.rcx, 0x2233445566778899)
        self.assertEqual(self.d.rdx, 0x33445566778899AA)
        self.assertEqual(self.d.rdi, 0x445566778899AABB)
        self.assertEqual(self.d.rsi, 0x5566778899AABBCC)
        self.assertEqual(self.d.rsp, 0x66778899AABBCCDD)
        self.assertEqual(self.d.rbp, 0x778899AABBCCDDEE)
        self.assertEqual(self.d.r8, 0x8899AABBCCDDEEFF)
        self.assertEqual(self.d.r9, 0xFFEEDDCCBBAA9988)
        self.assertEqual(self.d.r10, 0xEEDDCCBBAA998877)
        self.assertEqual(self.d.r11, 0xDDCCBBAA99887766)
        self.assertEqual(self.d.r12, 0xCCBBAA9988776655)
        self.assertEqual(self.d.r13, 0xBBAA998877665544)
        self.assertEqual(self.d.r14, 0xAA99887766554433)
        self.assertEqual(self.d.r15, 0x9988776655443322)

    def test_read_memory(self):
        self.assertEqual(
            self.d.mem[self.mem_addr : self.mem_addr + 10],
            b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6",
        )

    def test_brekpoint_relative(self):
        b = self.d.breakpoint(0x10E2)
        self.d.cont()
        rip = self.d.rip
        value = self.d.bases["main"] + 0x10E2
        self.assertEqual(rip, value)

    def test_brekpoint_relative_hw(self):
        # Probably we should test the bp delete and so on
        b = self.d.breakpoint(0x10E2, hw=True)
        self.d.cont()
        rip = self.d.rip
        value = self.d.bases["main"] + 0x10E2
        self.assertEqual(rip, value)

    def test_step(self):
        b = self.d.breakpoint(0x10E2)
        self.d.cont()
        rip = self.d.rip
        value = self.d.bases["main"] + 0x10EC
        self.d.step()
        rip = self.d.rip
        self.assertEqual(rip, value)


class Debugger_read_mem(unittest.TestCase):
    def setUp(self):
        self.d = Debugger()
        self.d.run("./read_test_mem")
        self.mem_addr = 0x1AABBCC1000

    def tearDown(self):
        self.d.shutdown()

    def test_watchpoint_hw(self):
        # Probably we should test the bp delete and so on
        for x in self.d.map:
            print("%#lx" % x, self.d.map[x]["file"])

        bp = self.d.breakpoint(0x1088)  # aftermmap
        self.d.cont()
        self.d.del_bp(bp)

        # Probably we should test the bp delete and so on
        for x in self.d.map:
            print("%#lx" % x, self.d.map[x]["file"])
        self.d.mem[self.mem_addr : self.mem_addr + 8] = b"\x00" * 8
        b = self.d.watch(self.mem_addr)
        self.d.cont()

        print("rip: %#lx" % self.d.rip)
        print("rdi %#lx" % self.d.rdi)

        # self.d.step()
        value = self.d.mem[self.mem_addr : self.mem_addr + 8]
        self.assertNotEqual(b"\x00" * 8, value)


# This is bugged I do not understand yet.
class Debugger_write(unittest.TestCase):
    def setUp(self):
        self.d = Debugger()
        self.p = process("./write_test")
        self.d.attach(self.p.pid)

    def tearDown(self):
        self.d.shutdown()
        self.p.close()

    def test_write_register(self):
        self.d.rax = 0x1234567890ABCDEF
        self.d.rbx = 0x1234567890ABCDEF
        self.d.rcx = 0x1234567890ABCDEF
        self.d.rdx = 0x1234567890ABCDEF
        self.d.rdi = 0x1234567890ABCDEF
        self.d.rsi = 0x1234567890ABCDEF
        self.d.rsp = 0x1234567890ABCDEF
        self.d.rbp = 0x1234567890ABCDEF
        self.d.r8 = 0x1234567890ABCDEF
        self.d.r9 = 0x1234567890ABCDEF
        self.d.r10 = 0x1234567890ABCDEF
        self.d.r11 = 0x1234567890ABCDEF
        self.d.r12 = 0x1234567890ABCDEF
        self.d.r13 = 0x1234567890ABCDEF
        self.d.r14 = 0x1234567890ABCDEF
        self.d.r15 = 0x1234567890ABCDEF

        self.assertEqual(self.d.rax, 0x1234567890ABCDEF)
        self.assertEqual(self.d.rbx, 0x1234567890ABCDEF)
        self.assertEqual(self.d.rcx, 0x1234567890ABCDEF)
        self.assertEqual(self.d.rdx, 0x1234567890ABCDEF)
        self.assertEqual(self.d.rdi, 0x1234567890ABCDEF)
        self.assertEqual(self.d.rsi, 0x1234567890ABCDEF)
        self.assertEqual(self.d.rsp, 0x1234567890ABCDEF)
        self.assertEqual(self.d.rbp, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r8, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r9, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r10, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r11, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r12, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r13, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r14, 0x1234567890ABCDEF)
        self.assertEqual(self.d.r15, 0x1234567890ABCDEF)

    def test_write_memory(self):
        b = self.d.breakpoint(0x1073)

        strings_addr = self.d.bases["main"] + 0x2004
        test_string = b"AAAABBBB"
        self.d.mem[strings_addr : strings_addr + len(test_string)] = test_string

        # print 8 strings
        for i in range(8):
            self.d.cont()

        data = self.p.recv(3000)
        self.assertTrue(test_string in data)


class Debugger_cf(unittest.TestCase):
    def setUp(self):
        self.d = Debugger()
        self.binary = "./read_test"

    def tearDown(self):
        self.d.shutdown()

    def test_start_in_ld(self):
        self.d.run(self.binary)
        ip = self.d.rip
        for m in self.d.map:
            if "ld-linux-x86-64.so" in self.d.map[m]["file"]:
                if self.d.map[m]["start"] <= ip <= self.d.map[m]["stop"]:
                    self.assertTrue(True)
                    return
        # rip was not in ld.so
        self.assertTrue(False)


class Debugger_toomanyfiles(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_toomanyfiles(self):
        try:
            for _ in tqdm(range(32768)):
                d = Debugger()
                d.run("./read_test")
                d.shutdown()
            self.assertTrue(True)
        except Exception:
            self.assertTrue(False)
            return


if __name__ == "__main__":
    unittest.main()
