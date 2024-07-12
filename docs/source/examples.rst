Code Examples
=============

This section contains some examples of how to use libdebug. They are either snippets taken from our write-ups of CTF challenges, or ad-hoc examples. Please find the binary executables in the test/binaries folder.

CyberChallenge.IT 2024 - Workshop
-------------------------------------------------------------------

.. This is a script that was used during the workshop presentation at the CyberChallenge.it Finals 2024.
This script was used to show the various features of libdebug during the Workshop at the CyberChallenge.IT 2024 Finals.
An explanation of the script, along with a brief introduction to libdebug, is available in the `official stream of the event <https://www.youtube.com/live/Ten8S50Fy7s?si=w8usHtnN5v6FWipQ&t=8253>`_, starting from 2:17:00.


.. code-block:: python

    from libdebug import debugger
    from string import ascii_letters, digits


    # Enable the escape_antidebug option to bypass the ptrace call
    d = debugger("main", escape_antidebug=True)

    def callback(_, __):
        # This will automatically issue a continue when the breakpoint is hit
        pass

    def on_enter_nanosleep(t, _):
        # This sets every argument to NULL to make the syscall fail
        t.syscall_arg0 = 0
        t.syscall_arg1 = 0
        t.syscall_arg2 = 0
        t.syscall_arg3 = 0

    alphabet = ascii_letters + digits + "_{}"

    flag = b""
    best_hit_count = 0

    while True:
        for c in alphabet:
            r = d.run()

            # Any time we call run() we have to reset the breakpoint and syscall handler
            bp = d.breakpoint(0x13e1, hardware=True, callback=callback, file="binary")
            d.handle_syscall("clock_nanosleep", on_enter=on_enter_nanosleep)

            d.cont()

            r.sendline(flag + c.encode())

            # This makes the debugger wait for the process to terminate
            d.wait()

            response = r.recvline()

            # `run()` will automatically kill any still-running process, but it's good practice to do it manually
            d.kill()

            if b"Yeah" in response:
                # The flag is correct
                flag += c.encode()
                print(flag)
                break

            if bp.hit_count > best_hit_count:
                # We have found a new flag character
                best_hit_count = bp.hit_count
                flag += c.encode()
                print(flag)
                break

        if c == "}":
            break

    print(flag)

DEFCON Quals 2023 - nlinks
--------------------------

This is a script that solves the challenge `nlinks <https://github.com/Nautilus-Institute/quals-2023/tree/main/nlinks>`_ from DEFCON Quals 2023. Please find the binary executables in the test/CTF folder.

.. code-block:: python

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
