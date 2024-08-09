#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger, libcontext
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile


##############################################################
######    Automatically find the offsets of interest    ######
##############################################################

def find_patterns_in_section(section, md):
    """Find patterns in the given section. We want to find every DISPATCHER inlined in the libpython shared library."""
    jmp_rax_offsets = []
    prev_instructions = []

    for i in md.disasm(section.data(), section['sh_addr']):
        prev_instructions.append((i.mnemonic, i.op_str))
        if len(prev_instructions) > 3:
            prev_instructions.pop(0)

        if len(prev_instructions) == 3:
            if (prev_instructions[0] == ('movzx', 'eax, r15b') and
                (prev_instructions[1] == ('mov', 'rax, qword ptr [rdi + rax*8]') 
                or
                prev_instructions[1] == ('mov', 'rax, qword ptr [rbx + rax*8]')
                or
                prev_instructions[1] == ('mov', 'rax, qword ptr [rdx + rax*8]')
                or 
                prev_instructions[1] == ('mov', 'rax, qword ptr [rcx + rax*8]')
                or 
                prev_instructions[1] == ('mov', 'rax, qword ptr [r8 + rax*8]')
                or 
                prev_instructions[1] == ('mov', 'rax, qword ptr [r9 + rax*8]')
                or
                prev_instructions[1] == ('mov', 'rax, qword ptr [rsi + rax*8]')
                )
                and
                prev_instructions[2] == ('jmp', 'rax')):
                jmp_rax_offsets.append(i.address)
            elif (prev_instructions[0] == ('mov', 'r15, rax') and
                (prev_instructions[1] == ('mov', 'rax, qword ptr [rdi + rax*8]') 
                or
                prev_instructions[1] == ('mov', 'rax, qword ptr [rbx + rax*8]')
                or
                prev_instructions[1] == ('mov', 'rax, qword ptr [rdx + rax*8]')
                or 
                prev_instructions[1] == ('mov', 'rax, qword ptr [rcx + rax*8]')
                or 
                prev_instructions[1] == ('mov', 'rax, qword ptr [r8 + rax*8]')
                or 
                prev_instructions[1] == ('mov', 'rax, qword ptr [r9 + rax*8]')
                or
                prev_instructions[1] == ('mov', 'rax, qword ptr [rsi + rax*8]')
                )
                and
                prev_instructions[2] == ('jmp', 'rax')):
                jmp_rax_offsets.append(i.address)

    return jmp_rax_offsets

with open('./libpython3.12.so.1.0', 'rb') as f:
    elf = ELFFile(f)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Collect all offsets from executable sections
    all_offsets = []
    for section in elf.iter_sections():
        if section['sh_flags'] & 0x4:  # SHF_EXECINSTR
            offsets = find_patterns_in_section(section, md)
            all_offsets.extend(offsets)


##############################################################
######  Dump the executed python opcodes with libdebug  ######
##############################################################

# Create a dictionary with python opcodes as keys and mnemonics as values.
# The dict is hardcoded to avoid differences in the opcode values between
# the python versions used to dump the opcodes and the python version of 
# the python interpreter used to execute the python script under analysis.
opcode_to_mnemonic = {
    0x97: "RESUME",
    0x64: "LOAD_CONST",
    0x5a: "STORE_NAME",
    0x65: "LOAD_NAME",
    0x7a: "BINARY_OP",
    0x2: "PUSH_NULL",
    0xab: "CALL",
    0x1: "POP_TOP",
    0x79: "RETURN_CONST",
    0x3: "INTERPRETER_EXIT"
}

def dumper(t,_):
    """Callback function to dump the executed python opcode."""
    print(f"Executed opcode: {t.regs.r15:#x} - {opcode_to_mnemonic.get(t.regs.r15, 'UNKNOWN')}")

d = debugger(["./python3.12", "python_script.py"], env={"LD_LIBRARY_PATH": "."})

# Set the symbol level to 5, this will enable the debugger to resolve symbols using debuinfod files
libcontext.sym_lvl = 5 

r = d.run()

# This function is executed before each chunk of python bytecode is interpreted
bp_run_mod = d.breakpoint("run_mod", file = "libpython3", hardware=True)

# Start the execution
d.cont()

# Wait for the breakpoint to be hit
d.wait()

while bp_run_mod.hit_on(d):
        if bp_run_mod.hit_count == 2:
            # At this point of the execution, the python bytecode releted to the python script
            # is executed. We can now set breakpoints on the offsets we found in the shared library
            for addr in all_offsets:
                d.breakpoint(addr, callback=dumper, file = "libpython3")
            # Set a breakpoint on the _PyArena_Free function, executed when the python script ends 
            bp_py_arena_free = d.breakpoint("_PyArena_Free", file = "libpython3")
            # Set a breakpoint on the binary operation function
            bp_binary_op = d.breakpoint(0x189f93, file = "libpython3")
        d.cont()
        d.wait()

while bp_binary_op.hit_on(d):
    # Transform the binary operation into a subtraction
    d.regs.rdx = 0xa # 0xa is the subtraction
    d.cont()
    d.wait()

if bp_py_arena_free.hit_on(d):
    # The python script has ended, we can now disable the breakpoints
    bp_py_arena_free.disable()
    for bp in d.breakpoints.values():
        bp.disable()

print("The result printed by the python script is:", r.recvline().decode())

d.kill()