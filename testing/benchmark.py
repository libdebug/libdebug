#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from libdebug import debugger
from libdebug.oldlibdebug import Debugger as OldDebugger
from pwn import ELF
from time import perf_counter

elf = ELF("./binaries/benchmark", checksec=False)


def benchmark_software():
    d = debugger("binaries/benchmark")
    d.start()

    def counter(d, b):
        if b.hit_count % 1e5 == 0:
            print(f"Hit count: {b.hit_count}")

    d.b("f", counter)
    d.cont()
    d.kill()


def benchmark_hardware():
    d = debugger("binaries/benchmark")
    d.start()

    def counter(d, b):
        if b.hit_count % 1e5 == 0:
            print(f"Hit count: {b.hit_count}")

    d.b("f", counter, hardware_assisted=True)
    d.cont()
    d.kill()


def benchmark_old_software():
    d = OldDebugger()
    d.run("./binaries/benchmark")
    addr = d.bp(elf.symbols["f"])
    d.cont()

    count = 0

    while True:
        if d.rip == addr:
            count += 1
            if count % 1e5 == 0:
                print(f"Hit count: {count}")
                break

        d.cont()

    d.shutdown()


def benchmark_old_hardware():
    d = OldDebugger()
    d.run("./binaries/benchmark")
    addr = d.breakpoint(elf.symbols["f"], hw=True)
    d.cont()

    count = 0

    while True:
        if d.rip == addr:
            count += 1
            if count % 1e5 == 0:
                print(f"Hit count: {count}")
                break

        d.cont()

    d.shutdown()


start = perf_counter()
benchmark_old_software()
end = perf_counter()

print(f"Old libdebug benchmark sw breakpoints: {end - start} seconds")

start = perf_counter()
benchmark_software()
end = perf_counter()

print(f"New libdebug benchmark sw breakpoints: {end - start} seconds")

start = perf_counter()
benchmark_old_hardware()
end = perf_counter()

print(f"Old libdebug benchmark hw breakpoints: {end - start} seconds")

start = perf_counter()
benchmark_hardware()
end = perf_counter()

print(f"New libdebug benchmark hw breakpoints: {end - start} seconds")
