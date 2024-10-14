---
icon: material/skull-crossbones-outline
search:
    boost: 0.8
---
# :material-skull-crossbones-outline: DEF CON Quals 2023 - nlinks
This is a script that solves the challenge [nlinks](https://github.com/Nautilus-Institute/quals-2023/tree/main/nlinks) from DEF CON Quals 2023. Please find the binary executables [here](https://github.com/libdebug/libdebug/tree/main/test/amd64).
```python
def get_passsphrase_from_class_1_binaries(previous_flag):
    flag = b""

    d = debugger("CTF/1")
    r = d.run()

    bp = d.breakpoint(0x7EF1, hardware=True, file="binary")

    d.cont()

    r.recvuntil(b"Passphrase:\n")

    # We send a fake flag after the valid password
    r.send(previous_flag + b"a" * 8)

    for _ in range(8):
        # Here we reached the breakpoint
        if not bp.hit_on(d):
            print("Here we should have hit the breakpoint")

        offset = ord("a") ^ d.regs.rbp
        d.regs.rbp = d.regs.r13

        # We calculate the correct character value and append it to the flag
        flag += (offset ^ d.regs.r13).to_bytes(1, "little")

        d.cont()

    r.recvline()

    d.kill()

    # Here the value of flag is b"\x00\x006\x00\x00\x00(\x00"
    return flag

def get_passsphrase_from_class_2_binaries(previous_flag):
    bitmap = {}
    lastpos = 0
    flag = b""

    d = debugger("CTF/2")
    r = d.run()

    bp1 = d.breakpoint(0xD8C1, hardware=True, file="binary")
    bp2 = d.breakpoint(0x1858, hardware=True, file="binary")
    bp3 = d.breakpoint(0xDBA1, hardware=True, file="binary")

    d.cont()

    r.recvuntil(b"Passphrase:\n")
    r.send(previous_flag + b"a" * 8)

    while True:
        if d.regs.rip == bp1.address:
            # Prepare for the next element in the bitmap
            lastpos = d.regs.rbp
            d.regs.rbp = d.regs.r13 + 1
        elif d.regs.rip == bp2.address:
            # Update the bitmap
            bitmap[d.regs.r12 & 0xFF] = lastpos & 0xFF
        elif d.regs.rip == bp3.address:
            # Use the bitmap to calculate the expected character
            d.regs.rbp = d.regs.r13
            wanted = d.regs.rbp
            needed = 0
            for i in range(8):
                if wanted & (2**i):
                    needed |= bitmap[2**i]
            flag += chr(needed).encode()

            if bp3.hit_count == 8:
                # We have found all the characters
                d.cont()
                break

        d.cont()

    d.kill()

    # Here the value of flag is b"\x00\x00\x00\x01\x00\x00a\x00"
    return flag

def get_passsphrase_from_class_3_binaries():
    flag = b""

    d = debugger("CTF/0")
    r = d.run()

    bp = d.breakpoint(0x91A1, hardware=True, file="binary")

    d.cont()

    r.send(b"a" * 8)

    for _ in range(8):

        # Here we reached the breakpoint
        if not bp.hit_on(d):
            print("Here we should have hit the breakpoint")

        offset = ord("a") - d.regs.rbp
        d.regs.rbp = d.regs.r13

        # We calculate the correct character value and append it to the flag
        flag += chr((d.regs.r13 + offset) % 256).encode("latin-1")

        d.cont()

    r.recvline()

    d.kill()

    # Here the value of flag is b"BM8\xd3\x02\x00\x00\x00"
    return flag

def run_nlinks():
    flag0 = get_passsphrase_from_class_3_binaries()
    flag1 = get_passsphrase_from_class_1_binaries(flag0)
    flag2 = get_passsphrase_from_class_2_binaries(flag1)

    print(flag0, flag1, flag2)

```