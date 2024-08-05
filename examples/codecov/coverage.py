#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

# The following example demonstrates how libdebug can be used, in conjunction with
# other libraries, to efficiently perform unit testing and code coverage analysis on
# a compiled executable.

import base64
import capstone
import libdebug
import pwn


# We use pwntools to load the binary and extract the function we want to test
# This can be performed manually using pyelftools or similar libraries
main = pwn.ELF("./main", checksec=False)
function_name = "long_from_base64_decimal_str"
function = main.functions[function_name]
function_asm = main.read(function.address, function.size)


# This function uses the Capstone disassembler to find all branches in a specific function
# It does so by looking for all conditional jumps (jcc) and computing the target address
# It is not perfect, as some binaries may use register-based jumps, or other more complex
# control flow structures, but it works well for most cases
def detect_function_branches(function_asm: str) -> list:
    """Find all branches in a function."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    branches = set()
    for i in md.disasm(function_asm, function.address):
        if i.mnemonic.startswith("j") and i.mnemonic != "jmp":
            try:
                branches.add((i.address, i.operands[0].imm, i.address + i.size))
            except:
                print(f"Failed to parse branch at {hex(i.address)}")

    return branches


branches = detect_function_branches(function_asm)


# This function sets up a debugger instance, as provided by libdebug, and sets up
# breakpoints on all branches detected in the function. It returns the debugger,
# along with the pipe to the target process and a list of breakpoints set.
def setup_debugger():
    """Setup the debugger."""
    def empty_callback(_, __): pass

    debugger = libdebug.debugger("main")
    pipe = debugger.run()
    breakpoints = []
    for b in branches:
        bp_conditional = debugger.breakpoint(b[0], callback=empty_callback)
        bp_target = debugger.breakpoint(b[1], callback=empty_callback)
        bp_non_hit = debugger.breakpoint(b[2], callback=empty_callback)
        breakpoints.append((bp_conditional, bp_target, bp_non_hit))

    return (debugger, pipe, breakpoints)


# We use a global variable to store the coverage information
# This is a dictionary where the key is the branch address and the value is a set
# containing two elements: whether the conditional branch was hit and whether the
# target branch was not hit. This allows us to calculate the coverage of the function
# by counting the number of branches that were hit.
coverage = {branch[1]: set() for branch in branches}


# This function is used to register the coverage information for a specific set of breakpoints
# It iterates over all breakpoints and checks whether the conditional branch was hit and whether
# the target branch was not hit. It then updates the coverage dictionary accordingly.
def register_coverage(bps):
    for bp in bps:
        # Check that we hit a conditional jump instruction
        if bp[0].hit_count > 0:
            # Check that the took the jump
            coverage[bp[1].address].add(bp[1].hit_count > 0)
            # Check that we did not take the jump
            coverage[bp[1].address].add(bp[2].hit_count == 0)

# This function calculates the coverage of the function by counting the number of branches
# that were hit. It does so by summing the number of branches that were hit and dividing
# by the total number of branches.
def calculate_coverage():
    covered = sum(len(coverage[branch]) for branch in coverage)
    total = len(coverage) * 2
    return covered / total


def test_correct_input():
    number = base64.b64encode(b"1234567890")
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"1234567890"
    debugger.terminate()

def test_empty_string():
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(b"")
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

def test_invalid_length_base64():
    number = base64.b64encode(b"1234567890")[:-1]
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

def test_invalid_base64_characters():
    number = base64.b64encode(b"1234567890")[:-1] + b"\xf0"
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

def test_out_of_range_base64_characters_1():
    number = b"::::"
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

def test_out_of_range_base64_characters_2():
    number = b"!!!!"
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

def test_out_of_range_base64_characters_3():
    number = b"//++"
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"0"
    debugger.terminate()

def test_out_of_range_base64_characters_4():
    number = b"{{}}"
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

def test_out_of_range_base64_characters_5():
    number = b"\x1f\x1f\x1f\x1f"
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

# This test validates that the function correctly handles null input
# This is a tricky condition to hit, as the compiled binary will not
# pass a null pointer to the function, but we can manually set the
# rdi register to 0 to simulate this condition and check that the
# function correctly handles it.
def test_null_input():
    number = base64.b64encode(b"1234567890")
    debugger, pipe, breakpoints = setup_debugger()

    # Set an additional breakpoint at the beginning of the function to test
    debugger.breakpoint("long_from_base64_decimal_str")

    debugger.cont()
    pipe.sendline(number)

    # We are in the prologue of the function, set the first argument to 0
    # to simulate a null pointer being passed
    debugger.regs.rdi = 0

    debugger.cont()
    pipe.recvline()
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

# This test validates that the function correctly handles a malloc failure
# We can simulate this condition by setting the size of the allocation to
# the maximum value of a 64-bit integer, which will cause the malloc function
# to fail and return NULL. We can then check that the function correctly handles
# this condition and returns an error message.
def test_malloc_failure():
    number = base64.b64encode(b"1234567890")
    debugger, pipe, breakpoints = setup_debugger()

    # Set a breakpoint on malloc and simulate a failure
    def bad_malloc(t, _):
        # Make the malloc call fail if we are trying to allocate the input string
        if t.regs.rdi == len(number):
            t.regs.rdi = 2**64 - 1

    # Set a breakpoint on malloc, located in libc
    debugger.breakpoint("malloc", callback=bad_malloc, file="libc")

    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

def test_integer_overflow():
    number = base64.b64encode(b"123456789012345678901234567890")
    debugger, pipe, breakpoints = setup_debugger()
    debugger.cont()
    pipe.recvline()
    pipe.sendline(number)
    debugger.wait()
    register_coverage(breakpoints)
    assert pipe.recvline().strip() == b"Invalid input string"
    debugger.terminate()

if __name__ == "__main__":
    print("Testing correct input")
    test_correct_input()
    print(f"Coverage: {calculate_coverage()}")
    print("Testing invalid input: empty string")
    test_empty_string()
    print(f"Coverage: {calculate_coverage()}")
    print("Testing invalid input: bad base64 length")
    test_invalid_length_base64()
    print(f"Coverage: {calculate_coverage()}")
    print("Testing invalid input: bad base64 characters")
    test_invalid_base64_characters()
    print(f"Coverage: {calculate_coverage()}")
    print("Testing all valid base64 characters")
    test_out_of_range_base64_characters_1()
    test_out_of_range_base64_characters_2()
    test_out_of_range_base64_characters_3()
    test_out_of_range_base64_characters_4()
    test_out_of_range_base64_characters_5()
    print(f"Coverage: {calculate_coverage()}")
    print("Testing invalid input: null input")
    test_null_input()
    print(f"Coverage: {calculate_coverage()}")
    print("Testing malloc failure")
    test_malloc_failure()
    print(f"Coverage: {calculate_coverage()}")
    print("Testing integer overflow")
    test_integer_overflow()
    print(f"Coverage: {calculate_coverage()}")
