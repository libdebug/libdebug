Code Examples
=============

This section contains some examples of how to use the libdebug. They are either snippets taken from our write-ups of CTF challenges or ad-hoc examples. Please find the binary executables in the test/binaries folder.

Example Script for the presentation at CyberChallenge.it Finals 2024
-------------------------------------------------------------------

This is a script that was used during the workshop presentation at the CyberChallenge.it Finals 2024. 

.. code-block:: python

    from libdebug import debugger
    from string import ascii_letters, digits

    d = debugger("cc_workshop", escape_antidebug=True)

    alphabet = ascii_letters + digits + "_{}"

    for c in alphabet:
        r = d.run()
        bp = d.breakpoint(0x13e1, hardware=True, file="binary")
        d.cont()

        r.sendline(c.encode())

        d.wait()
        
        d.kill()

        print(c, bp.hit_count)

        if bp.hit_count > 0:
            print('Found:', c)
            break

DEFCON Quals 2022 - nCuts
--------------------------

This is a script that solves the challenge `nCuts <https://github.com/Nautilus-Institute/quals-2022/tree/main/ncuts>`_ from DEFCON Quals 2022. Please find the binary executables in the test/CTF folder.

.. code-block:: python

    def get_passsphrase_from_class_1_binaries(self, previous_flag):
        flag = b""

        d = debugger("CTF/1")
        r = d.run()

        bp = d.breakpoint(0x7EF1, hardware=True, file="binary")

        d.cont()

        r.recvuntil(b"Passphrase:\n")
        r.send(previous_flag + b"a" * 8)

        for _ in range(8):
            # Here we reached the breakpoint
            if not bp.hit_on(d):
                print("Here we should have hit the breakpoint")

            offset = ord("a") ^ d.regs.rbp
            d.regs.rbp = d.regs.r13
            flag += (offset ^ d.regs.r13).to_bytes(1, "little")

            d.cont()

        r.recvline()

        d.kill()

        # Here the value of flag is b"\x00\x006\x00\x00\x00(\x00"
        return flag

    def get_passsphrase_from_class_2_binaries(self, previous_flag):
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
                lastpos = d.regs.rbp
                d.regs.rbp = d.regs.r13 + 1
            elif d.regs.rip == bp2.address:
                bitmap[d.regs.r12 & 0xFF] = lastpos & 0xFF
            elif d.regs.rip == bp3.address:
                d.regs.rbp = d.regs.r13
                wanted = d.regs.rbp
                needed = 0
                for i in range(8):
                    if wanted & (2**i):
                        needed |= bitmap[2**i]
                flag += chr(needed).encode()

                if bp3.hit_count == 8:
                    d.cont()
                    break

            d.cont()

        d.kill()

        # Here the value of flag is b"\x00\x00\x00\x01\x00\x00a\x00"

    def get_passsphrase_from_class_3_binaries(self):
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

            flag += chr((d.regs.r13 + offset) % 256).encode("latin-1")

            d.cont()

        r.recvline()

        d.kill()

        # Here the value of flag is b"BM8\xd3\x02\x00\x00\x00"
        return flag

    def run_ncuts(self):
        flag = self.get_passsphrase_from_class_3_binaries()
        flag = self.get_passsphrase_from_class_1_binaries(flag)
        self.get_passsphrase_from_class_2_binaries(flag)