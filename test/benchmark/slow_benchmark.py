#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

# This is a slow benchmark to test the performance of the library.

import string
import time

from libdebug import debugger
from tqdm import tqdm


#
# vmwhere1 - challenge from UIUCTF 2023
#
def test_vmwhere1():
    flag = b""
    counter = 3
    stop = False

    d = debugger(["../CTF/vmwhere1", "../CTF/vmwhere1_program"])

    while not stop:
        for el in string.printable:
            r = d.run()
            bp = d.breakpoint(0x1587, hardware=True)
            d.cont()

            r.recvline()
            r.recvuntil(b"the password:\n")

            r.sendline(flag + el.encode())

            while d.regs.rip == bp.address:
                d.cont()

            message = r.recvline()

            if b"Incorrect" not in message:
                flag += el.encode()
                stop = True
                d.kill()
                break
            else:
                if bp.hit_count > counter:
                    counter = bp.hit_count
                    flag += el.encode()
                    d.kill()
                    break

            d.kill()


def test_vmwhere1_callback():
    flag = b""
    counter = 3
    stop = False

    d = debugger(["../CTF/vmwhere1", "../CTF/vmwhere1_program"])

    def callback(d, bp):
        pass

    while not stop:
        for el in string.printable:
            r = d.run()
            bp = d.breakpoint(0x1587, hardware=True, callback=callback)
            d.cont()

            r.recvline()
            r.recvuntil(b"the password:\n")

            r.sendline(flag + el.encode())

            message = r.recvline()

            if b"Incorrect" not in message:
                flag += el.encode()
                stop = True
                d.kill()
                break
            else:
                if bp.hit_count > counter:
                    counter = bp.hit_count
                    flag += el.encode()
                    d.kill()
                    break

            d.kill()


#
# deep-dive-division - challenge from KalmarCTF 2024
#
def test_deep_dive_division():
    def brutone(flag, current):
        def checkino(d, b):
            nonlocal counter
            if int.from_bytes(d.memory[d.regs.rax + d.regs.r9, 1], "little") == 0:
                counter += 1

        candidate = []
        for c in string.printable:
            counter = 0
            r = d.run()
            d.breakpoint(0x4012F2, hardware=True, callback=checkino)
            d.cont()
            r.sendlineafter(b"flag?", flag + c.encode())
            r.recvline(2)

            d.kill()
            if counter > current:
                candidate.append(c)
        return candidate

    d = debugger("../CTF/deep-dive-division")
    candidate = {}

    flag = b""
    current = 6

    candidate = brutone(flag, current)
    while True:
        if len(candidate) == 0:
            break
        elif len(candidate) == 1:
            current += 1
            flag += candidate[0].encode()
            candidate = brutone(flag, current)
        else:
            current += 1

            for c in candidate:
                flag_ = flag + c.encode()
                candidate = brutone(flag_, current)
                if candidate != []:
                    flag = flag_
                    break


n_executions = 500

print("Starting benchmark...")

print("Starting vmwhere1...")
time_sum = 0
rangen_executions = range(n_executions)
for i in tqdm(rangen_executions):
    start = time.perf_counter()
    test_vmwhere1()
    end = time.perf_counter()
    time_sum += end - start
print("Result:", time_sum / n_executions)

print("Starting vmwhere1_callback...")
time_sum = 0
range_n_executions = range(n_executions)
for i in tqdm(range_n_executions):
    start = time.perf_counter()
    test_vmwhere1_callback()
    end = time.perf_counter()
    time_sum += end - start
print("Result:", time_sum / n_executions)

print("Starting deep_dive_division...")
time_sum = 0
range_n_executions = range(n_executions)
for i in tqdm(range_n_executions):
    start = time.perf_counter()
    test_deep_dive_division()
    end = time.perf_counter()
    time_sum += end - start
print("Result:", time_sum / n_executions)
