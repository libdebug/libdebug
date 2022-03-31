from libdebug import Debugger

d = Debugger()
d.run("./test")

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

d.step()
print("rip: %#x" % d.rip)
d.step()
print("rip: %#x" % d.rip)

# d.gdb()

# input("reattach?")
# d.reattach()

# r = d.rip
# print("rip: %#x" % d.rip)
# d.step()
# print("rip: %#x" % d.rip)
# d.step()
# print("rip: %#x" % d.rip)

# d.gdb()
import IPython
IPython.embed()

d.detach()
d.stop()
