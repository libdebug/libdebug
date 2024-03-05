from libdebug import debugger

d = debugger("/home/mrindeciso/Documents/test/test")

d.run()


def u64(b):
    return hex(int.from_bytes(b, "little")).ljust(18)


bp1 = d.breakpoint("function_1+16")
bp2 = d.breakpoint("function_2+16")

for _ in range(4):
    d.cont()
    d.wait()
    for j, (tid, t) in enumerate(d.threads.items()):
        print(f"[{tid}] 0x{t.registers.register_file.fs_base:x}")
        tls = t.registers.register_file.fs_base
        try:
            tcache_ptr = int.from_bytes(t.memory[tls - 0x30, 8], "little")
        except BaseException:
            tcache_ptr = None

        if tcache_ptr:
            for i in range(32):
                print(f"  [{i}] {u64(t.memory[tcache_ptr + i * 8, 8])}")

    print()

d.kill()
