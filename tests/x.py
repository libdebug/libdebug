from libdebug import Debugger
import time

d = Debugger()
d.run("./read_test_thread")

print("rax: %#x" % d.rax)
d.rax = 0
# d.rip = 0x17
print("rax: %#x" % d.rax)
print("rsp: %#x" % d.rsp)
# data = d.peek(d.rsp)
# print("[rsp]: %#x" % data)
# d.poke(d.rsp, 0x17ff18ff19)
# print("[rsp]: %#x" % d.peek(d.rsp))
# print("[rsp]: ", d.mem[d.rsp:d.rsp+0x10])
# print("[rsp]: ", d.mem[d.rsp])

# print("[rsp]: ", d.mem[d.rsp:d.rsp+0x10])
# d.mem[d.rsp:d.rsp+0x10] = b"AAAAAAABC"
# print("[rsp]: ", d.mem[d.rsp:d.rsp+0x10])

# d.poke(d.rsp, data)
# print("[rsp]: %#x" % d.peek(d.rsp))
r = d.rip
print("rip: %#x" % d.rip)
# d.bp(r)
# d.cont()
# print("rip: %#x" % d.rip)
# if (r != d.rip):
#     d.gdb()
# d.del_bp(r)

# d.step()
# print("rip: %#x" % d.rip)
# d.step()
# print("rip: %#x" % d.rip)

# for i in range(10):
#     d.cont(blocking=False)
#     time.sleep(0.1)
#     print("rip: %#x" % d.rip)
# fpregs = d.get_fpregs()
# for r in fpregs:
#     print("%s: %#x" % (r,fpregs[r]))

# bp = d.breakpoint(0x1074)
# d.cont()
# for i in range(10):
#     d.next()
#     print("next rip: %#x" % d.rip)


# d.finish()
# d.gdb()

# input("reattach?")
# d.reattach()

# r = d.rip
# print("rip: %#x" % d.rip)
# d.step()
# print("rip: %#x" % d.rip)
# d.step()
# print("rip: %#x" % d.rip)

# d.gdb(spawn=True)
# input("finish_with_gdb?")
# d.reattach()
# print("rip: %#x" % d.rip)
print(d.map)
b = d.breakpoint(0x12a6)

import IPython
IPython.embed()


d.detach()
d.shutdown()
