#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from libdebug import debugger, libcontext
from libdebug.utils.debugging_utils import resolve_address_in_maps
import iced_x86 as iced
import argparse
import os
import magic

libcontext.sym_lvl = 5

###########################################
# -------- Linux Terminal Colors -------- #
###########################################
LT_COLOR_RED = "31"
LT_COLOR_GREEN = "32"
LT_COLOR_YELLOW = "33"
LT_COLOR_BLUE = "34"
LT_COLOR_MAGENTA = "35"
LT_COLOR_CYAN = "36"
LT_COLOR_WHITE = "37"
LT_COLOR_DEFAULT = "39"


#######################################
# -------- Utility Functions -------- #
#######################################

def p64(in_bytes):
    return in_bytes.to_bytes(8, byteorder='little')

def p32(in_bytes):
    return in_bytes.to_bytes(4, byteorder='little')

def p16(in_bytes):
    return in_bytes.to_bytes(2, byteorder='little')

def p8(in_bytes):
    return in_bytes.to_bytes(1, byteorder='little')

def u64(in_bytes):
    return int.from_bytes(in_bytes, byteorder='little')

def u32(in_bytes):
    return int.from_bytes(in_bytes, byteorder='little')

def u16(in_bytes):
    return int.from_bytes(in_bytes, byteorder='little')

def u8(in_bytes):
    return int.from_bytes(in_bytes, byteorder='little')

def print_color(message, color, end='\n'):
    print(f"\033[{color}m{message}\033[0m", end=end)

has_crashed = False
rip_overwritten = False
rbp_overwritten = False
canary_overwritten = False
fortify_failed = False

# Constants
MAX_AMD64_INSTRUCTION_LENGTH = 15
MAX_TEST_LEN = 128

##########################################
# ----------- Initialization ----------- #
##########################################

# Initialize a formatter
formatter = iced.Formatter(iced.FormatterSyntax.INTEL)

# Assumption: Input is given from stdin instead of a file or a command line argument
# Different scenarios can easily be handled by changing the input source

# Create the parser
parser = argparse.ArgumentParser(description='Find vulnerabilities in an AMD64 Linux ELF')

# Add the --maxlen argument
parser.add_argument('--maxlen', type=int, help='maximum length of the input to test')

# Add the positional argument for the file name
parser.add_argument('filename', type=str, help='the path to the file to process')

# Parse the arguments
args = parser.parse_args()

# Print the arguments
print(f'File name: {args.filename}')
if args.maxlen is not None:
    print(f'Max length: {args.maxlen}')

# Get the ELF file
ELF_PATH = args.filename
MAX_TEST_LEN = args.maxlen if args.maxlen is not None else MAX_TEST_LEN

# Check if the ELF file exists and is valid
if not os.path.exists(ELF_PATH):
    print(f"File {ELF_PATH} does not exist.")
    exit(1)
elif not os.access(ELF_PATH, os.R_OK):
    print(f"File {ELF_PATH} is not readable.")
    exit(1)
elif 'ELF 64-bit LSB pie executable, x86-64' not in magic.from_file(ELF_PATH):
    print(f"File {ELF_PATH} is not a 64-bit ELF file.")
    exit(1)

#########################################
# ------ Step 1 - "Fuzz" the ELF ------ #
#########################################

for test_padding_len in range(0, MAX_TEST_LEN, 4):
    print(f"[+] Testing payload length {test_padding_len}...")

    d = debugger(ELF_PATH)

    test_payload = b'A' * test_padding_len

    pipe = d.run()

    # Break on check stack canary and fortify fail
    check_stack_fail_br = d.breakpoint('__stack_chk_fail', file='libc.so.6')
    check_fortify_fail_br = d.breakpoint('__fortify_fail', file='libc.so.6')

    # Catch SIGSEGV and SIGABRT
    sig1_hdlr = d.catch_signal(signal='SIGSEGV')
    sig2_hdlr = d.catch_signal(signal='SIGABRT')

    d.cont()

    pipe.sendline(test_payload)

    d.wait()

    if sig1_hdlr.hit_on(d):
        print(">> Crashed with payload: ", test_payload)
        print_color(f">> Received signal: SIGSEGV", color=LT_COLOR_RED)
        has_crashed = True
    elif sig2_hdlr.hit_on(d):
        print(">> Crashed with payload: ", test_payload)
        print_color(f">> Received signal: SIGABRT", color=LT_COLOR_RED)
        has_crashed = True
    elif check_stack_fail_br.hit_on(d):
        print(">> Crashed with payload: ", test_payload)
        print_color(f">> Stack Canary check failed", color=LT_COLOR_RED)
        has_crashed = True
        canary_overwritten = True
    elif check_fortify_fail_br.hit_on(d):
        print(">> Crashed with payload: ", test_payload)
        print_color(f">> Fortify check failed", color=LT_COLOR_RED)
        has_crashed = True
        fortify_failed = True

    if has_crashed:
        print_color(f"[+] Crash detected with payload length {test_padding_len}", color=LT_COLOR_YELLOW)
        print_color('[+] Post-mortem analysis initiated', color=LT_COLOR_YELLOW)

        curr_rip = d.regs.rip

        # Check for RIP overwrite
        if '4141' in hex(d.regs.rip):
            print_color("--> RIP is overwritten with AAAA <--", color=LT_COLOR_RED)
            rip_overwritten = True
        else:
            print(f"RIP is at {hex(curr_rip)}")
            print("Disassembling the instruction at RIP...")

            # Dump instruction at rip
            window_from_rip = d.memory[curr_rip, MAX_AMD64_INSTRUCTION_LENGTH, 'absolute']

            # Disassemble the instruction (ignoring bytes that are not part of the instruction)
            decoder = iced.Decoder(64, window_from_rip)
            decoder.ip = curr_rip

            instruction = decoder.decode()

            # Get the instruction bytes and convert to hex bytes separated by spaces
            instruction_bytes = window_from_rip[:instruction.len]
            instruction_bytes_str = " ".join(f"{b:02X}" for b in instruction_bytes)

            # If the current rip corresponds to a known symbol, print the symbol
            try:
                symbol = resolve_address_in_maps(curr_rip, d.maps())

                if not symbol.startswith("0x"):
                    print_color(f"<{symbol}> ", color=LT_COLOR_CYAN, end="")
            except ValueError:
                pass

            # Decode and print each instruction
            asm = formatter.format(instruction)
            print_color(f"{hex(instruction.ip)}: {instruction_bytes_str.ljust(2*4, ' ')} | {asm}", color=LT_COLOR_CYAN)
        
        # Check for RBP overwrite
        if not rip_overwritten and '4141' in hex(d.regs.rbp):
            print_color("--> RBP is overwritten with AAAA <--", color=LT_COLOR_RED)
            print_color("Stack pivot detected", color=LT_COLOR_RED)
            rbp_overwritten = True
        else:
            print(f"RBP is at {hex(d.regs.rbp)}")

        # Shut up the warnings
        libcontext.general_logger = 'SILENT'
        
        # Stack trace
        print_color('\nStack trace:', color=LT_COLOR_RED)
        d.print_backtrace()

    d.kill()
    d.terminate()
    print()

    # We found the input to inspect, but let's see if we find also a way to control RIP
    if has_crashed and rip_overwritten:
        break

if not has_crashed:
    print_color("[+] No crash detected. Exiting", color=LT_COLOR_GREEN)
    exit(0)

if canary_overwritten:
    print_color("[+] Stack canary overwritten", color=LT_COLOR_YELLOW)
    print_color("[+] It is possible that an exploit is feasible given a leak of the canary", color=LT_COLOR_YELLOW)
    exit(0)

if fortify_failed:
    print_color("[+] Fortify check failed", color=LT_COLOR_YELLOW)
    print_color("[+] This mitigation can prevent a lot of exploits, but some workarounds are possible", color=LT_COLOR_YELLOW)
    exit(0)

if not rip_overwritten:
    print_color("[+] RIP is not overwritten", color=LT_COLOR_YELLOW)

    if rbp_overwritten:
        print_color("[+] However, the analyzer was able to detect a stack pivot", color=LT_COLOR_YELLOW)
        print_color("[+] Given a leak, we could use the stack pivot take control of the execution", color=LT_COLOR_YELLOW)

    exit(0)

# If we reach this point, we have a crash and RIP is overwritten
# We can now proceed to the part where we check which part of the input is used to overwrite RIP

print('\n-----------------------------------\n\n')

print("[+] A payload length that overwrites RIP has been found.")
print("[+] Starting taint analysis to find the setup.")

#########################################
# ------ Step 2 - Taint Analysis ------ #
#########################################

has_found_setup = False
taint_offset = -1

for taint_start_index in range(0, test_padding_len + 8, 8):
    taint_end_index = taint_start_index + 8

    TAINT = p64(0xdeadc0de)

    print(f"[+] Analyzing taint from {taint_start_index} to {taint_end_index}...")

    test_payload = b'A' * taint_start_index + TAINT + b'A' * (test_padding_len - taint_end_index) 

    print(f">> Testing payload: {test_payload}")

    d = debugger('bof')

    pipe = d.run()

    sigsegv_checker = d.catch_signal(signal='SIGSEGV')

    d.cont()

    pipe.sendline(test_payload)
    
    d.wait()

    if sigsegv_checker.hit_on(d):
        # Search registers for traces of the taint
        print_color("Received SIGSEGV", color=LT_COLOR_RED)

        # Dump registers
        print_color("Registers:", color=LT_COLOR_RED)
        print_color(f"RAX: {hex(d.regs.rax)}", color=LT_COLOR_RED)
        print_color(f"RBX: {hex(d.regs.rbx)}", color=LT_COLOR_RED)
        print_color(f"RCX: {hex(d.regs.rcx)}", color=LT_COLOR_RED)
        print_color(f"RDX: {hex(d.regs.rdx)}", color=LT_COLOR_RED)
        print_color(f"RDI: {hex(d.regs.rdi)}", color=LT_COLOR_RED)
        print_color(f"RSI: {hex(d.regs.rsi)}", color=LT_COLOR_RED)
        print_color(f"RBP: {hex(d.regs.rbp)}", color=LT_COLOR_RED)
        print_color(f"RSP: {hex(d.regs.rsp)}", color=LT_COLOR_RED)
        print_color(f"RIP: {hex(d.regs.rip)}", color=LT_COLOR_RED)

        # Say if any of the registers contain the taint
        if d.regs.rax == u64(TAINT):
            print("RAX contains the taint.")
        if d.regs.rbx == u64(TAINT):
            print("RBX contains the taint.")
        if d.regs.rcx == u64(TAINT):
            print("RCX contains the taint.")
        if d.regs.rdx == u64(TAINT):
            print("RDX contains the taint.")
        if d.regs.rdi == u64(TAINT):
            print("RDI contains the taint.")
        if d.regs.rsi == u64(TAINT):
            print("RSI contains the taint.")
        if d.regs.rbp == u64(TAINT):
            print("RBP contains the taint.")
        if d.regs.rsp == u64(TAINT):
            print("RSP contains the taint.")
        if d.regs.rip == u64(TAINT):
            print("RIP contains the taint.")
            has_found_setup = True
            taint_offset = taint_start_index
            break

        # Searching memory for the taint
        print("Searching memory for the taint...")

        for map in d.maps():
            # Skip non-writable maps (e.g., vsyscall)
            if 'w' not in map.permissions:
                continue
            
            pid = d.threads[0].process_id
            
            with open(f'/proc/{pid}/mem', 'rb', 0) as mem:
                mem.seek(map.start)
                memory_content = mem.read(map.end - map.start)

                if TAINT in memory_content:
                    print_color(f">> Taint found in {map.backing_file} at address {hex(map.start + memory_content.index(TAINT))}", color=LT_COLOR_RED)
    elif d.dead:
        print(f">>  Program exited with code {d.exit_code} and signal {d.exit_signal}")
                
    d.kill()
    d.terminate()

if not has_found_setup:
    print_color("[+] No setup found. Exiting...", color=LT_COLOR_GREEN)
    exit(0)

print_color(f"[+] Found setup at offset {taint_offset}", color=LT_COLOR_CYAN)
print_color("[+] This vulnerability can be exploited on systems with Intel CET disabled", color=LT_COLOR_CYAN)

# Future expansion: proxy the output to check for useful leaks (e.g, libc addresses, stack addresses, etc.)