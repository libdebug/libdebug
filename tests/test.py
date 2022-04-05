import unittest
from libdebug import Debugger

class Debugger_read(unittest.TestCase):
    def setUp(self):
        self.d = Debugger()
        self.d.run("./read_test", sleep=0.1)
        self.mem_addr = 0x1aabbcc1000

    def tearDown(self):
        self.d.stop()

    def test_read_register(self):
        self.assertEqual(self.d.rax, 0x0011223344556677)
        self.assertEqual(self.d.rbx, 0x1122334455667788)
        self.assertEqual(self.d.rcx, 0x2233445566778899)
        self.assertEqual(self.d.rdx, 0x33445566778899aa)
        self.assertEqual(self.d.rdi, 0x445566778899aabb)
        self.assertEqual(self.d.rsi, 0x5566778899aabbcc)
        self.assertEqual(self.d.rsp, 0x66778899aabbccdd)
        self.assertEqual(self.d.rbp, 0x778899aabbccddee)
        self.assertEqual(self.d.r8 , 0x8899aabbccddeeff)
        self.assertEqual(self.d.r9 , 0xffeeddccbbaa9988)
        self.assertEqual(self.d.r10, 0xeeddccbbaa998877)
        self.assertEqual(self.d.r11, 0xddccbbaa99887766)
        self.assertEqual(self.d.r12, 0xccbbaa9988776655)
        self.assertEqual(self.d.r13, 0xbbaa998877665544)
        self.assertEqual(self.d.r14, 0xaa99887766554433)
        self.assertEqual(self.d.r15, 0x9988776655443322)

    def test_read_memory(self):
        self.assertEqual(self.d.mem[self.mem_addr: self.mem_addr+10], b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6")

    def test_brekpoint_relative(self):
        b = self.d.breakpoint(0x10e2)
        self.d.cont()
        rip = self.d.rip
        value = self.d.bases['main'] + 0x10e2
        self.assertEqual (rip, value)

    def test_step(self):
        b = self.d.breakpoint(0x10e2)
        self.d.cont()
        rip = self.d.rip
        value = self.d.bases['main'] + 0x10ec
        self.d.step()
        rip = self.d.rip
        self.assertEqual (rip, value)


# This is bugged I do not understand yet.
# class Debugger_write(unittest.TestCase):
#     def setUp(self):
#         self.d = Debugger()
#         self.d.run("./write_test", sleep=0.1, pipeout=True)

#     def tearDown(self):
#         self.d.stop()

#     def test_write_memory(self):
#         b = self.d.breakpoint(0x1056)
#         print("%#x" % self.d.rip)
#         for i in range(100):
#             print(i)
#             self.d.step()

#         strings_addr = self.d.bases['main']  + 0x2ff8 + 0x1041
#         test_string = b"AAAABBBBCCCCDDDD"
#         self.d.mem[strings_addr:strings_addr+len(test_string)] = test_string
#         # self.d.cont(blocking=False)
#         for i in range(100):
#             self.d.step()
#         data = self.d.process.stdout.read()
#         print("data", data)
#         self.assertTrue(test_string in data) 

if __name__ == '__main__':
    unittest.main()