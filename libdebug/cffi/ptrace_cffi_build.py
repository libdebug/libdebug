#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import platform
from pathlib import Path

from cffi import FFI


architecture = platform.machine()

if architecture == "x86_64":
    # We need to determine if we have AVX, AVX2, AVX512, etc.
    path = Path("/proc/cpuinfo")

    try:
        with path.open() as f:
            cpuinfo = f.read()
    except OSError as e:
        raise RuntimeError("Cannot read /proc/cpuinfo. Are you running on Linux?") from e

    if "avx512" in cpuinfo:
        fp_regs_struct = """
        struct reg_128
        {
            unsigned char data[16];
        };

        struct reg_256
        {
            unsigned char data[32];
        };

        struct reg_512
        {
            unsigned char data[64];
        };

        // For details about the layout of the xsave structure, see Intel's Architecture Instruction Set Extensions Programming Reference
        // Chapter 3.2.4 "The Layout of XSAVE Save Area"
        // https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf
        #pragma pack(push, 1)
        struct fp_regs_struct
        {
            unsigned long type;
            _Bool dirty; // true if the debugging script has modified the state of the registers
            _Bool fresh; // true if the registers have already been fetched for this state
            unsigned char bool_padding[6];
            unsigned char padding0[32];
            struct reg_128 st[8];
            struct reg_128 xmm0[16];
            unsigned char padding1[96];
            // end of the 512 byte legacy region
            unsigned char padding2[64];
            // ymm0 starts at offset 576
            struct reg_128 ymm0[16];
            unsigned char padding3[320];
            // zmm0 starts at offset 1152
            struct reg_256 zmm0[16];
            // zmm1 starts at offset 1664
            struct reg_512 zmm1[16];
            unsigned char padding4[8];
        };
        #pragma pack(pop)
        """

        fpregs_define = """
        #define FPREGS_AVX 2
        """
    elif "avx" in cpuinfo:
        fp_regs_struct = """
        struct reg_128
        {
            unsigned char data[16];
        };

        // For details about the layout of the xsave structure, see Intel's Architecture Instruction Set Extensions Programming Reference
        // Chapter 3.2.4 "The Layout of XSAVE Save Area"
        // https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf
        #pragma pack(push, 1)
        struct fp_regs_struct
        {
            unsigned long type;
            _Bool dirty; // true if the debugging script has modified the state of the registers
            _Bool fresh; // true if the registers have already been fetched for this state
            unsigned char bool_padding[6];
            unsigned char padding0[32];
            struct reg_128 st[8];
            struct reg_128 xmm0[16];
            unsigned char padding1[96];
            // end of the 512 byte legacy region
            unsigned char padding2[64];
            // ymm0 starts at offset 576
            struct reg_128 ymm0[16];
            unsigned char padding3[64];
        };
        #pragma pack(pop)
        """

        fpregs_define = """
        #define FPREGS_AVX 1
        """
    else:
        fp_regs_struct = """
        struct reg_128
        {
            unsigned char data[16];
        };

        // For details about the layout of the xsave structure, see Intel's Architecture Instruction Set Extensions Programming Reference
        // Chapter 3.2.4 "The Layout of XSAVE Save Area"
        // https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf
        #pragma pack(push, 1)
        struct fp_regs_struct
        {
            unsigned long type;
            _Bool dirty; // true if the debugging script has modified the state of the registers
            _Bool fresh; // true if the registers have already been fetched for this state
            unsigned char bool_padding[6];
            unsigned char padding0[32];
            struct reg_128 st[8];
            struct reg_128 xmm0[16];
            unsigned char padding1[96];
        };
        #pragma pack(pop)
        """

        fpregs_define = """
        #define FPREGS_AVX 0
        """

    if "xsave" not in cpuinfo:
        fpregs_define += """
        #define XSAVE 0
        """

        # We don't support non-XSAVE architectures
        raise NotImplementedError("XSAVE not supported. Please open an issue on GitHub and include your hardware details.")
    else:
        fpregs_define += """
        #define XSAVE 1
        """

    ptrace_regs_struct = """
    struct ptrace_regs_struct
    {
        unsigned long r15;
        unsigned long r14;
        unsigned long r13;
        unsigned long r12;
        unsigned long rbp;
        unsigned long rbx;
        unsigned long r11;
        unsigned long r10;
        unsigned long r9;
        unsigned long r8;
        unsigned long rax;
        unsigned long rcx;
        unsigned long rdx;
        unsigned long rsi;
        unsigned long rdi;
        unsigned long orig_rax;
        unsigned long rip;
        unsigned long cs;
        unsigned long eflags;
        unsigned long rsp;
        unsigned long ss;
        unsigned long fs_base;
        unsigned long gs_base;
        unsigned long ds;
        unsigned long es;
        unsigned long fs;
        unsigned long gs;
    };
    """

    arch_define = """
    #define ARCH_AMD64
    """

    breakpoint_define = """
    #define INSTRUCTION_POINTER(regs) (regs.rip)
    #define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFFFFFFFF00) | 0xCC)
    #define BREAKPOINT_SIZE 1
    #define IS_SW_BREAKPOINT(instruction) (instruction == 0xCC)
    """

    control_flow_define = """
    // X86_64 Architecture specific
    #define IS_RET_INSTRUCTION(instruction) (instruction == 0xC3 || instruction == 0xCB || instruction == 0xC2 || instruction == 0xCA)
    
    int IS_CALL_INSTRUCTION(uint8_t* instr)
    {
        // Check for direct CALL (E8 xx xx xx xx)
        if (instr[0] == (uint8_t)0xE8) {
            return 1; // It's a CALL
        }
        
        // Check for indirect CALL using ModR/M (FF /2)
        if (instr[0] == (uint8_t)0xFF) {
            // Extract ModR/M byte
            uint8_t modRM = (uint8_t)instr[1];
            uint8_t reg = (modRM >> 3) & 7; // Middle three bits

            if (reg == 2) {
                return 1; // It's a CALL
            }
        }

        return 0; // Not a CALL
    }
    """
elif architecture == "aarch64":
    fp_regs_struct = """
    struct reg_128
    {
        unsigned char data[16];
    };

    // /usr/include/aarch64-linux-gnu/asm/ptrace.h
    #pragma pack(push, 1)
    struct fp_regs_struct
    {
        _Bool dirty; // true if the debugging script has modified the state of the registers
        _Bool fresh; // true if the registers have already been fetched for this state
        unsigned char bool_padding[2];
        struct reg_128 vregs[32];
        unsigned int fpsr;
        unsigned int fpcr;
        unsigned long padding;
    };
    #pragma pack(pop)
    """

    fpregs_define = ""

    ptrace_regs_struct = """
    struct ptrace_regs_struct
    {
        unsigned long x0;
        unsigned long x1;
        unsigned long x2;
        unsigned long x3;
        unsigned long x4;
        unsigned long x5;
        unsigned long x6;
        unsigned long x7;
        unsigned long x8;
        unsigned long x9;
        unsigned long x10;
        unsigned long x11;
        unsigned long x12;
        unsigned long x13;
        unsigned long x14;
        unsigned long x15;
        unsigned long x16;
        unsigned long x17;
        unsigned long x18;
        unsigned long x19;
        unsigned long x20;
        unsigned long x21;
        unsigned long x22;
        unsigned long x23;
        unsigned long x24;
        unsigned long x25;
        unsigned long x26;
        unsigned long x27;
        unsigned long x28;
        unsigned long x29;
        unsigned long x30;
        unsigned long sp;
        unsigned long pc;
        unsigned long pstate;
        _Bool override_syscall_number;
    };
    """

    arch_define = """
    #define ARCH_AARCH64
    """

    breakpoint_define = """
    #define INSTRUCTION_POINTER(regs) (regs.pc)
    #define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFF00000000) | 0xD4200000)
    #define BREAKPOINT_SIZE 4
    #define IS_SW_BREAKPOINT(instruction) (instruction == 0xD4200000)
    """

    control_flow_define = """
    #define IS_RET_INSTRUCTION(instruction) (instruction == 0xD65F03C0)

    // AARCH64 Architecture specific
    int IS_CALL_INSTRUCTION(uint8_t* instr)
    {
        // Check for direct CALL (BL)
        if ((instr[3] & 0xFC) == 0x94) {
            return 1; // It's a CALL
        }

        // Check for indirect CALL (BLR)
        if ((instr[3] == 0xD6 && (instr[2] & 0x3F) == 0x3F)) {
            return 1; // It's a CALL
        }

        return 0; // Not a CALL
    }
    """
elif architecture == "i686":
    fp_regs_struct = """
    struct reg_80
    {
        unsigned char data[10];
    };

    struct fp_regs_struct
    {
        _Bool dirty; // true if the debugging script has modified the state of the registers
        _Bool fresh; // true if the registers have already been fetched for this state
        unsigned char bool_padding[2];
        unsigned short cwd;
        unsigned short swd;
        unsigned short twd;
        unsigned short fop;
        unsigned long ip;
        unsigned long cs;
        unsigned long dp;
        unsigned long ds;
        struct reg_80 st[8];
    };
    """

    fpregs_define = """
    #define FPREGS_AVX 0
    """

    ptrace_regs_struct = """
    struct ptrace_regs_struct
    {
        unsigned long ebx;
        unsigned long ecx;
        unsigned long edx;
        unsigned long esi;
        unsigned long edi;
        unsigned long ebp;
        unsigned long eax;
        unsigned long xds;
        unsigned long xes;
        unsigned long xfs;
        unsigned long xgs;
        unsigned long orig_eax;
        unsigned long eip;
        unsigned long xcs;
        unsigned long eflags;
        unsigned long esp;
        unsigned long xss;
    };
    """

    arch_define = """
    #define ARCH_I386
    """

    breakpoint_define = """
    #define INSTRUCTION_POINTER(regs) (regs.eip)
    #define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFF00) | 0xCC)
    #define BREAKPOINT_SIZE 1
    #define IS_SW_BREAKPOINT(instruction) (instruction == 0xCC)
    """

    control_flow_define = """
    // i686 Architecture specific
    #define IS_RET_INSTRUCTION(instruction) (instruction == 0xC3 || instruction == 0xCB || instruction == 0xC2 || instruction == 0xCA)

    int IS_CALL_INSTRUCTION(uint8_t* instr)
    {
        // Check for direct CALL (E8 xx xx xx xx)
        if (instr[0] == (uint8_t)0xE8) {
            return 1; // It's a CALL
        }

        // Check for indirect CALL using ModR/M (FF /2)
        if (instr[0] == (uint8_t)0xFF) {
            // Extract ModR/M byte
            uint8_t modRM = (uint8_t)instr[1];
            uint8_t reg = (modRM >> 3) & 7; // Middle three bits

            if (reg == 2) {
                return 1; // It's a CALL
            }
        }

        return 0; // Not a CALL
    }
    """
else:
    raise NotImplementedError(f"Architecture {platform.machine()} not available.")


ffibuilder = FFI()
ffibuilder.cdef(ptrace_regs_struct)
ffibuilder.cdef(fp_regs_struct, packed=True)
ffibuilder.cdef("""
    struct ptrace_hit_bp {
        int pid;
        uint64_t addr;
        uint64_t bp_instruction;
        uint64_t prev_instruction;
    };

    struct software_breakpoint {
        uint64_t addr;
        uint64_t instruction;
        uint64_t patched_instruction;
        char enabled;
        struct software_breakpoint *next;
    };

    struct hardware_breakpoint {
        uint64_t addr;
        int tid;
        char enabled;
        char type[2];
        char len;
        struct hardware_breakpoint *next;
    };

    struct thread {
        int tid;
        struct ptrace_regs_struct regs;
        struct fp_regs_struct fpregs;
        int signal_to_forward;
        struct thread *next;
    };

    struct thread_status {
        int tid;
        int status;
        struct thread_status *next;
    };

    struct global_state {
        struct thread *t_HEAD;
        struct thread *dead_t_HEAD;
        struct software_breakpoint *sw_b_HEAD;
        struct hardware_breakpoint *hw_b_HEAD;
        _Bool handle_syscall_enabled;
    };


    int ptrace_trace_me(void);
    int ptrace_attach(int pid);
    void ptrace_detach_and_cont(struct global_state *state, int pid);
    void ptrace_detach_for_kill(struct global_state *state, int pid);
    void ptrace_detach_for_migration(struct global_state *state, int pid);
    void ptrace_reattach_from_gdb(struct global_state *state, int pid);
    void ptrace_set_options(int pid);

    uint64_t ptrace_peekdata(int pid, uint64_t addr);
    uint64_t ptrace_pokedata(int pid, uint64_t addr, uint64_t data);

    struct fp_regs_struct *get_thread_fp_regs(struct global_state *state, int tid);
    void get_fp_regs(int tid, struct fp_regs_struct *fpregs);
    void set_fp_regs(int tid, struct fp_regs_struct *fpregs);

    uint64_t ptrace_geteventmsg(int pid);

    long singlestep(struct global_state *state, int tid);
    int step_until(struct global_state *state, int tid, uint64_t addr, int max_steps);

    int cont_all_and_set_bps(struct global_state *state, int pid);

    int stepping_finish(struct global_state *state, int tid);

    struct thread_status *wait_all_and_update_regs(struct global_state *state, int pid);
    void free_thread_status_list(struct thread_status *head);

    struct ptrace_regs_struct* register_thread(struct global_state *state, int tid);
    void unregister_thread(struct global_state *state, int tid);
    void free_thread_list(struct global_state *state);

    void register_breakpoint(struct global_state *state, int pid, uint64_t address);
    void unregister_breakpoint(struct global_state *state, uint64_t address);
    void enable_breakpoint(struct global_state *state, uint64_t address);
    void disable_breakpoint(struct global_state *state, uint64_t address);

    void register_hw_breakpoint(struct global_state *state, int tid, uint64_t address, char type[2], char len);
    void unregister_hw_breakpoint(struct global_state *state, int tid, uint64_t address);
    void enable_hw_breakpoint(struct global_state *state, int tid, uint64_t address);
    void disable_hw_breakpoint(struct global_state *state, int tid, uint64_t address);
    unsigned long get_hit_hw_breakpoint(struct global_state *state, int tid);
    int get_remaining_hw_breakpoint_count(struct global_state *state, int tid);
    int get_remaining_hw_watchpoint_count(struct global_state *state, int tid);

    void free_breakpoints(struct global_state *state);
"""
)

with open("libdebug/cffi/ptrace_cffi_source.c") as f:
    ffibuilder.set_source(
        "libdebug.cffi._ptrace_cffi",
        ptrace_regs_struct 
        + arch_define
        + fp_regs_struct
        + fpregs_define
        + breakpoint_define
        + control_flow_define
        + f.read(),
        libraries=[],
    )

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
