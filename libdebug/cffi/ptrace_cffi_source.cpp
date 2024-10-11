//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <nanobind/nanobind.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/list.h>
#include <nanobind/stl/map.h>
#include <nanobind/stl/pair.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/shared_ptr.h>


#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>


#define DR_BASE offsetof(struct user, u_debugreg[0])
#define DR_SIZE sizeof(unsigned long)
#define CTRL_LOCAL(x) (1 << (2 * x))
#define CTRL_COND(x) (16 + (4 * x))
#define CTRL_COND_VAL(x) (x == 'x' ? 0 : (x == 'w' ? 1 : 3))
#define CTRL_LEN(x) (18 + (4 * x))
#define CTRL_LEN_VAL(x) (x == 1 ? 0 : (x == 2 ? 1 : (x == 8 ? 2 : 3)))

#define INSTRUCTION_POINTER(regs) (regs->rip)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFFFFFFFF00) | 0xCC)
#define BREAKPOINT_SIZE 1
#define IS_SW_BREAKPOINT(instruction) (instruction == 0xCC)

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

namespace nb = nanobind;

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

struct reg_128
{
    std::array<unsigned char, 16> bytes;
};

#pragma pack(push, 1)
struct ptrace_fp_regs_struct
{
    unsigned long type;
    bool dirty; // true if the debugging script has modified the state of the registers
    bool fresh; // true if the registers have already been fetched for this state
    unsigned char bool_padding[6];
    unsigned char padding0[32];
    std::array<reg_128, 8> mmx;
    std::array<reg_128, 16> xmm0;
    unsigned char padding1[96];
    // end of the 512 byte legacy region
    unsigned char padding2[64];
    // ymm0 starts at offset 576
    std::array<reg_128, 16> ymm0;
    unsigned char padding3[64];
    unsigned char padding4[192]; // mpx save area
};
#pragma pack(pop)

struct software_breakpoint
{
    unsigned long addr;
    unsigned long instruction;
    unsigned long patched_instruction;
    bool enabled;
};

struct hardware_breakpoint
{
    unsigned long addr;
    int tid;
    bool enabled;
    int type;
    int len;
};

#pragma pack(push, 1)
struct thread
{
    pid_t tid;
    std::shared_ptr<ptrace_regs_struct> regs;
    std::shared_ptr<ptrace_fp_regs_struct> fpregs;
    int signal_to_forward;
};
#pragma pack(pop)

struct thread_status
{
    pid_t tid;
    int status;
};

class libdebug_ptrace_interface
{

private:
    pid_t process_id, group_id;
    bool handle_syscall;
    std::map<pid_t, thread> threads, dead_threads;
    std::map<unsigned long, software_breakpoint> software_breakpoints;
    std::vector<hardware_breakpoint> hardware_breakpoints;


    int getregs(thread &t)
    {
        return ptrace(PTRACE_GETREGS, t.tid, NULL, t.regs.get());
    }

    int setregs(thread &t)
    {
        return ptrace(PTRACE_SETREGS, t.tid, NULL, t.regs.get());
    }

    void getfpregs(thread &t)
    {
        iovec iov;
        ptrace_fp_regs_struct *fpregs = t.fpregs.get();

        iov.iov_base = (unsigned char *)(fpregs) + offsetof(ptrace_fp_regs_struct, padding0);
        iov.iov_len = sizeof(ptrace_fp_regs_struct) - offsetof(ptrace_fp_regs_struct, padding0);

        if (ptrace(PTRACE_GETREGSET, t.tid, NT_X86_XSTATE, &iov) == -1) {
            throw std::runtime_error("ptrace getregset xstate failed");
        }

        fpregs->fresh = 1;
    }

    void setfpregs(thread &t)
    {
        iovec iov;
        ptrace_fp_regs_struct *fpregs = t.fpregs.get();

        iov.iov_base = (unsigned char *)(fpregs) + offsetof(ptrace_fp_regs_struct, padding0);
        iov.iov_len = sizeof(ptrace_fp_regs_struct) - offsetof(ptrace_fp_regs_struct, padding0);

        if (ptrace(PTRACE_SETREGSET, t.tid, NT_X86_XSTATE, &iov) == -1) {
            throw std::runtime_error("ptrace setregset xstate failed");
        }

        fpregs->dirty = 0;
        fpregs->fresh = 0;
    }

    void check_and_set_fpregs(thread &t)
    {
        if (t.fpregs->dirty) {
            setfpregs(t);
        }

        t.fpregs->fresh = 0;
    }

    void step_thread(thread &t, bool forward_signal = true)
    {
        if (forward_signal) {
            if (ptrace(PTRACE_SINGLESTEP, t.tid, NULL, t.signal_to_forward) == -1) {
                throw std::runtime_error("ptrace singlestep failed");
            }

            t.signal_to_forward = 0;
        } else {
            if (ptrace(PTRACE_SINGLESTEP, t.tid, NULL, 0) == -1) {
                throw std::runtime_error("ptrace singlestep failed");
            }
        }
    }

    void cont_thread(thread &t)
    {
        if (ptrace(handle_syscall ? PTRACE_SYSCALL : PTRACE_CONT, t.tid, NULL, t.signal_to_forward) == -1) {
            throw std::runtime_error("ptrace cont failed");
        }

        t.signal_to_forward = 0;
    }

    void set_handle_syscall(bool should_handle_syscalls)
    {
        handle_syscall = should_handle_syscalls;
    }

    void install_hardware_breakpoint(hardware_breakpoint &bp)
    {
        // find a free debug register
        int i;
        for (i = 0; i < 4; i++) {
            unsigned long address = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + i * DR_SIZE);

            if (!address)
                break;
        }

        if (i == 4) {
            throw std::runtime_error("No free hardware breakpoint register");
        }

        unsigned long ctrl = CTRL_LOCAL(i) | CTRL_COND_VAL(bp.type) << CTRL_COND(i) | CTRL_LEN_VAL(bp.len) << CTRL_LEN(i);

        // read the state from DR7
        unsigned long state = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + 7 * DR_SIZE);

        // reset the state, for good measure
        state &= ~(3 << CTRL_COND(i));
        state &= ~(3 << CTRL_LEN(i));

        // register the breakpoint
        state |= ctrl;

        // write the address and the state
        ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + i * DR_SIZE, bp.addr);
        ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + 7 * DR_SIZE, state);
    }

    void remove_hardware_breakpoint(hardware_breakpoint &bp)
    {
        // find the register
        int i;
        for (i = 0; i < 4; i++) {
            unsigned long address = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + i * DR_SIZE);

            if (address == bp.addr)
                break;
        }

        if (i == 4) {
            throw std::runtime_error("Breakpoint not found");
        }

        // read the state from DR7
        unsigned long state = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + 7 * DR_SIZE);

        // reset the state
        state &= ~(3 << CTRL_COND(i));
        state &= ~(3 << CTRL_LEN(i));

        // write the state
        ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + 7 * DR_SIZE, state);

        // reset the address
        ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + i * DR_SIZE, 0);
    }

    unsigned long hit_breakpoint_address(pid_t tid)
    {
        unsigned long dr6 = ptrace(PTRACE_PEEKUSER, tid, DR_BASE + 6 * DR_SIZE);

        int index;
        for (index = 0; index < 4; index++) {
            if (dr6 & (1 << index))
                break;
        }

        if (index == 4) {
            return 0;
        }

        unsigned long address = ptrace(PTRACE_PEEKUSER, tid, DR_BASE + index * DR_SIZE);

        return address;
    }

    int prepare_for_run()
    {
        // Flush any register changes
        for (auto &t : threads) {
            if (setregs(t.second))
                throw std::runtime_error("setregs failed");

            check_and_set_fpregs(t.second);
        }

        // Iterate over all the threads and check if any of them has hit a software
        // breakpoint
        for (auto &t : threads) {
            bool t_hit = false;
            unsigned long ip = INSTRUCTION_POINTER(t.second.regs);

            for (auto &b : software_breakpoints) {
                if (b.first == ip) {
                    // We hit a software breakpoint on this thread
                    t_hit = true;
                    break;
                }
            }

            if (t_hit) {
                // Step over the breakpoint
                step_thread(t.second, false);

                // Wait for the child
                int status;
                waitpid(t.first, &status, 0);

                // status == 4991 ==> (WIFSTOPPED(status) && WSTOPSIG(status) ==
                // SIGSTOP) this should happen only if threads are involved
                if (status == 4991) {
                    step_thread(t.second, false);
                    waitpid(t.first, &status, 0);
                }
            }
        }

        // Restore any software breakpoints
        for (auto &bp : software_breakpoints) {
            if (bp.second.enabled) {
                ptrace(PTRACE_POKETEXT, process_id, (void *) bp.first, (void *) bp.second.patched_instruction);
            }
        }

        return 0;
    }

    bool check_if_dl_trampoline(unsigned long instruction_pointer)
    {
        // https://codebrowser.dev/glibc/glibc/sysdeps/i386/dl-trampoline.S.html
        //      0xf7fdaf80 <_dl_runtime_resolve+16>: pop    edx
        //      0xf7fdaf81 <_dl_runtime_resolve+17>: mov    ecx,DWORD PTR [esp]
        //      0xf7fdaf84 <_dl_runtime_resolve+20>: mov    DWORD PTR [esp],eax
        //      0xf7fdaf87 <_dl_runtime_resolve+23>: mov    eax,DWORD PTR [esp+0x4]
        // =>   0xf7fdaf8b <_dl_runtime_resolve+27>: ret    0xc
        //      0xf7fdaf8e:  xchg   ax,ax
        //      0xf7fdaf90 <_dl_runtime_profile>:    push   esp
        //      0xf7fdaf91 <_dl_runtime_profile+1>:  add    DWORD PTR [esp],0x8
        //      0xf7fdaf95 <_dl_runtime_profile+5>:  push   ebp
        //      0xf7fdaf96 <_dl_runtime_profile+6>:  push   eax
        //      0xf7fdaf97 <_dl_runtime_profile+7>:  push   ecx
        //      0xf7fdaf98 <_dl_runtime_profile+8>:  push   edx

        // https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/i386/dl-trampoline.S
        //      0xf7fd9004 <_dl_runtime_resolve+20>:	pop    edx
        //      0xf7fd9005 <_dl_runtime_resolve+21>:	mov    ecx,DWORD PTR [esp]
        //      0xf7fd9008 <_dl_runtime_resolve+24>:	mov    DWORD PTR [esp],eax
        //      0xf7fd900b <_dl_runtime_resolve+27>:	mov    eax,DWORD PTR [esp+0x4]
        // =>   0xf7fd900f <_dl_runtime_resolve+31>:	ret    0xc
        //      0xf7fd9012:	lea    esi,[esi+eiz*1+0x0]
        //      0xf7fd9019:	lea    esi,[esi+eiz*1+0x0]
        //      0xf7fd9020 <_dl_runtime_resolve_shstk>:	endbr32
        //      0xf7fd9024 <_dl_runtime_resolve_shstk+4>:	push   eax
        //      0xf7fd9025 <_dl_runtime_resolve_shstk+5>:	push   edx

        unsigned long data;

        // if ((instruction_pointer & 0xf) != 0xb) {
        //     return 0;
        // }
        // breaks if libc is compiled with CET

        instruction_pointer -= 0xb;

        data = peek_data(instruction_pointer);
        data = data & 0xFFFFFFFF; // on i386 we get 4 bytes from the ptrace call, while on amd64 we get 8 bytes

        if (data != 0x240c8b5a) {
            return false;
        }

        instruction_pointer += 0x4;

        data = peek_data(instruction_pointer);
        data = data & 0xFFFFFFFF;

        if (data != 0x8b240489) {
            return false;
        }

        instruction_pointer += 0x4;

        data = peek_data(instruction_pointer);
        data = data & 0xFFFFFFFF;

        if (data != 0xc2042444) {
            return false;
        }

        instruction_pointer += 0x4;

        data = peek_data(instruction_pointer);
        data = data & 0xFFFF;

        if (data != 0x000c) {
            return false;
        }

        return true;
    }

public:
    libdebug_ptrace_interface()
    {
        process_id = -1;
        group_id = -1;
        handle_syscall = false;
    }

    void cleanup()
    {
        threads.clear();
        dead_threads.clear();
        software_breakpoints.clear();
        hardware_breakpoints.clear();

        process_id = -1;
        group_id = -1;
        handle_syscall = false;
    }

    std::pair<std::shared_ptr<ptrace_regs_struct>, std::shared_ptr<ptrace_fp_regs_struct>> register_thread(const pid_t tid)
    {
        // Verify if the thread is already registered
        if (threads.find(tid) != threads.end()) {
            std::shared_ptr<ptrace_regs_struct> regs = threads[tid].regs;
            std::shared_ptr<ptrace_fp_regs_struct> fpregs = threads[tid].fpregs;

            return std::make_pair(regs, fpregs);
        }

        if (process_id == -1) {
            process_id = tid;
            group_id = getpgid(tid);
        }

        thread t;
        t.tid = tid;
        t.signal_to_forward = 0;
        t.regs = std::make_shared<ptrace_regs_struct>();
        t.fpregs = std::make_shared<ptrace_fp_regs_struct>();
        t.fpregs->type = 1;
        t.fpregs->dirty = 0;
        t.fpregs->fresh = 0;

        threads[tid] = t;

        getregs(threads[tid]);

        std::shared_ptr<ptrace_regs_struct> regs = threads[tid].regs;
        std::shared_ptr<ptrace_fp_regs_struct> fpregs = threads[tid].fpregs;

        return std::make_pair(regs, fpregs);
    }

    void unregister_thread(const pid_t tid)
    {
        // move the dead thread to the dead list
        dead_threads[tid] = threads[tid];
        threads.erase(tid);

        // remove any hardware breakpoints
        for (auto it = hardware_breakpoints.begin(); it != hardware_breakpoints.end();) {
            if (it->tid == tid) {
                hardware_breakpoints.erase(it);
            } else {
                ++it;
            }
        }
    }

    int attach(pid_t pid)
    {
        errno = 0;

        ptrace(PTRACE_ATTACH, pid, NULL, NULL);

        return errno;
    }

    void detach_for_migration()
    {
        // note that the order is important here: the main thread must be detached last
        for (auto it = threads.rbegin(); it != threads.rend(); ++it) {
            // let's attempt to set the registers of the thread
            if (setregs(it->second) == -1) {
                // if we can't read the registers, the thread is probably still running
                // ensure that the thread is stopped
                tgkill(process_id, it->first, SIGSTOP);

                // wait for it to stop
                waitpid(it->first, NULL, 0);

                // set the registers again, as the first time it failed
                setregs(it->second);
            }

            check_and_set_fpregs(it->second);

            // remove any installed hardware breakpoints
            for (auto &b : hardware_breakpoints) {
                if (b.tid == it->first) {
                    remove_hardware_breakpoint(b);
                }
            }

            // be sure that the thread will not run during gdb reattachment
            tgkill(process_id, it->first, SIGSTOP);

            // detach from it
            if (ptrace(PTRACE_DETACH, it->first, NULL, NULL) == -1) {
                throw std::runtime_error("ptrace detach failed");
            }
        }
    }

    void detach_and_cont()
    {
        detach_for_migration();

        // continue the execution of the process
        kill(process_id, SIGCONT);
    }

    void set_ptrace_options()
    {
        int options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD |
            PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

        for (auto &t : threads) {
            ptrace(PTRACE_SETOPTIONS, t.first, NULL, options);
        }
    }

    unsigned long get_event_msg(pid_t tid)
    {
        unsigned long data = 0;

        ptrace(PTRACE_GETEVENTMSG, tid, NULL, &data);

        return data;
    }

    std::vector<std::pair<pid_t, int>> wait_all_and_update_regs()
    {
        std::vector<std::pair<pid_t, int>> thread_statuses;

        int tid, status;

        tid = waitpid(-group_id, &status, 0);

        if (tid == -1) {
            throw std::runtime_error("waitpid failed");
        }

        thread_statuses.push_back({tid, status});

        // We must interrupt all the other threads with a SIGSTOP
        int temp_tid, temp_status;
        for (auto &t : threads) {
            if (t.first != tid) {
                // If GETREGS succeeds, the thread is already stopped, so we must
                // not "stop" it again
                if (getregs(t.second) == -1) {
                    // Stop the thread with a SIGSTOP
                    tgkill(process_id, t.first, SIGSTOP);
                    // Wait for the thread to stop
                    temp_tid = waitpid(t.first, &temp_status, 0);

                    // Register the status of the thread, as it might contain useful
                    // information
                    thread_statuses.push_back({temp_tid, temp_status});
                }
            }
        }

        // We keep polling but don't block, we want to get all the statuses we can
        while ((temp_tid = waitpid(-group_id, &temp_status, WNOHANG)) > 0) {
            thread_statuses.push_back({temp_tid, temp_status});
        }

        // Update the registers of all the threads
        for (auto &t : threads) {
            getregs(t.second);
        }

        // Restore any software breakpoints
        for (auto &bp : software_breakpoints) {
            if (bp.second.enabled) {
                ptrace(PTRACE_POKETEXT, process_id, (void *) bp.first, (void *) bp.second.instruction);
            }
        }

        return thread_statuses;
    }

    void cont_all_and_set_bps(bool handle_syscalls)
    {
        // Set the handle_syscall flag
        set_handle_syscall(handle_syscalls);

        prepare_for_run();

        // Continue all the threads
        for (auto &t : threads) {
            cont_thread(t.second);
        }
    }

    void step(pid_t tid)
    {
        // Flush any register changes
        if (setregs(threads[tid])) {
            throw std::runtime_error("setregs failed");
        }

        check_and_set_fpregs(threads[tid]);

        // Step the thread
        step_thread(threads[tid]);
    }

    void step_until(pid_t tid, unsigned long addr, int max_steps)
    {
        thread &t = threads[tid];

        // Flush any register changes
        if (setregs(t)) {
            throw std::runtime_error("setregs failed");
        }
        check_and_set_fpregs(t);

        unsigned long previous_ip;
        int count = 0, status = 0;

        // Remove any hardware breakpoints
        for (auto &bp : hardware_breakpoints) {
            if (bp.tid == tid) {
                remove_hardware_breakpoint(bp);
            }
        }

        while (max_steps == -1 || count < max_steps) {
            step_thread(t);

            // Wait for the child
            waitpid(tid, &status, 0);

            previous_ip = INSTRUCTION_POINTER(t.regs);

            // Update the registers
            getregs(t);

            if (INSTRUCTION_POINTER(t.regs) == addr) {
                break;
            }

            // If the instruction pointer didn't change, we have to step again
            // because we hit a hardware breakpoint
            if (INSTRUCTION_POINTER(t.regs) == previous_ip) {
                continue;
            }

            count++;
        }

        // Re-add the hardware breakpoints
        for (auto &bp : hardware_breakpoints) {
            if (bp.tid == tid && bp.enabled) {
                install_hardware_breakpoint(bp);
            }
        }
    }

    void stepping_finish(pid_t tid, bool use_trampoline_heuristic)
    {
        thread &stepping_thread = threads[tid];

        prepare_for_run();

        unsigned long previous_ip, current_ip;
        unsigned long opcode_window, opcode;

        // We need to keep track of the nested calls
        int nested_call_counter = 1;

        do {
            step_thread(stepping_thread);

            // Wait for the child
            int status;
            waitpid(tid, &status, 0);

            previous_ip = INSTRUCTION_POINTER(stepping_thread.regs);

            // Update the registers
            getregs(stepping_thread);

            current_ip = INSTRUCTION_POINTER(stepping_thread.regs);

            // Get value at current instruction pointer
            opcode_window = peek_data(current_ip);

            // On amd64 we care only about the first byte
            opcode = opcode_window & 0xFF;

            // If the instruction pointer didn't change, we return
            // because we hit a hardware breakpoint
            // we do the same if we hit a software breakpoint
            if (current_ip == previous_ip || IS_SW_BREAKPOINT(opcode))
                goto cleanup;

            if (IS_CALL_INSTRUCTION((uint8_t *) &opcode_window)) {
                nested_call_counter++;
            } else if (IS_RET_INSTRUCTION(opcode)) {
                nested_call_counter--;
            }

            if (use_trampoline_heuristic && check_if_dl_trampoline(current_ip)) {
                nested_call_counter++;
            }
        } while (nested_call_counter > 0);

        // We are in a return instruction, do the last step
        step_thread(stepping_thread);

        // Wait for the child
        int status;
        waitpid(tid, &status, 0);

        // Update the registers
        getregs(stepping_thread);

    cleanup:
        // Remove any installed breakpoint
        for (auto &b : software_breakpoints) {
            if (b.second.enabled) {
                poke_data(b.first, b.second.instruction);
            }
        }
    }

    void forward_signals(std::vector<std::pair<pid_t, int>> signals)
    {
        for (auto &s : signals) {
            threads[s.first].signal_to_forward = s.second;
        }
    }

    int get_remaining_hw_breakpoint_count(const pid_t tid)
    {
        int i;
        for (i = 0; i < 4; i++) {
            if (ptrace(PTRACE_PEEKUSER, tid, DR_BASE + (i * DR_SIZE), NULL) == 0) {
                break;
            }
        }

        return 4 - i;
    }

    void register_hw_breakpoint(const pid_t tid, unsigned long address, const int type, const int len)
    {
        hardware_breakpoint bp;

        for (auto &b : hardware_breakpoints) {
            if (b.addr == address && b.tid == tid) {
                throw std::runtime_error("Breakpoint already registered");
            }
        }

        bp.addr = address;
        bp.tid = tid;
        bp.enabled = true;
        bp.type = type;
        bp.len = len;

        hardware_breakpoints.push_back(bp);

        // Install the hardware breakpoint
        install_hardware_breakpoint(bp);
    }

    void unregister_hw_breakpoint(const pid_t tid, const unsigned long address)
    {
        for (auto it = hardware_breakpoints.begin(); it != hardware_breakpoints.end(); ++it) {
            if (it->addr == address && it->tid == tid) {
                if (it->enabled) {
                    // Remove the hardware breakpoint
                    remove_hardware_breakpoint(*it);
                }

                hardware_breakpoints.erase(it);
                break;
            }
        }
    }

    unsigned long get_hit_hw_breakpoint(const pid_t tid)
    {
        unsigned long address = hit_breakpoint_address(tid);

        if (address == 0) {
            return 0;
        }

        for (auto &bp : hardware_breakpoints) {
            if (bp.addr == address && bp.tid == tid) {
                return address;
            }
        }

        return 0;
    }

    void register_breakpoint(const unsigned long address)
    {
        unsigned long instruction = ptrace(PTRACE_PEEKTEXT, process_id, (void *) address, NULL);

        unsigned long patched_instruction = INSTALL_BREAKPOINT(instruction);

        if (software_breakpoints.find(address) != software_breakpoints.end()) {
            // The breakpoint is already registered
            // We just need to enable it
            software_breakpoints[address].enabled = true;
            return;
        }

        software_breakpoint bp;
        bp.addr = address;
        bp.instruction = instruction;
        bp.patched_instruction = patched_instruction;
        bp.enabled = true;

        software_breakpoints[address] = bp;
    }

    void unregister_breakpoint(const unsigned long address)
    {
        if (software_breakpoints.find(address) == software_breakpoints.end()) {
            throw std::runtime_error("Breakpoint not found");
        }

        software_breakpoints.erase(address);
    }

    void enable_breakpoint(const unsigned long address)
    {
        if (software_breakpoints.find(address) == software_breakpoints.end()) {
            throw std::runtime_error("Breakpoint not found");
        }

        software_breakpoints[address].enabled = true;

        ptrace(PTRACE_POKETEXT, process_id, (void *) address, (void *) software_breakpoints[address].patched_instruction);
    }

    void disable_breakpoint(const unsigned long address)
    {
        if (software_breakpoints.find(address) == software_breakpoints.end()) {
            throw std::runtime_error("Breakpoint not found");
        }

        software_breakpoints[address].enabled = false;

        ptrace(PTRACE_POKETEXT, process_id, (void *) address, (void *) software_breakpoints[address].instruction);
    }

    void detach_for_kill()
    {
        // note that the order is important here: the main thread must be detached last
        for (auto it = threads.rbegin(); it != threads.rend(); ++it) {
            // let's attempt to read the registers of the thread
            if (getregs(it->second)) {
                // the thread is probably still running
                // ensure that the thread is stopped
                tgkill(process_id, it->first, SIGSTOP);

                // wait for it to stop
                waitpid(it->first, NULL, 0);
            }

            // detach from it
            if (ptrace(PTRACE_DETACH, it->first, NULL, NULL)) {
                throw std::runtime_error("ptrace detach failed");
            }

            // kill it
            tgkill(process_id, it->first, SIGKILL);
        }

        // final waitpid for the zombie process
        waitpid(process_id, NULL, 0);
    }

    void get_fp_regs(pid_t tid)
    {
        thread &t = threads[tid];

        getfpregs(t);
    }

    unsigned long peek_data(unsigned long addr)
    {
        errno = 0;

        unsigned long value = ptrace(PTRACE_PEEKDATA, process_id, (void *) addr, NULL);

        if (errno) {
            throw std::runtime_error("ptrace peekdata failed");
        }

        return value;
    }

    void poke_data(unsigned long addr, unsigned long data)
    {
        if (ptrace(PTRACE_POKEDATA, process_id, (void *) addr, (void *) data) == -1) {
            throw std::runtime_error("ptrace pokedata failed");
        }
    }

};

NB_MODULE(_ptrace_cffi, m) {
    nb::class_<ptrace_regs_struct>(m, "ptrace_regs_struct")
        .def_rw("r15", &ptrace_regs_struct::r15)
        .def_rw("r14", &ptrace_regs_struct::r14)
        .def_rw("r13", &ptrace_regs_struct::r13)
        .def_rw("r12", &ptrace_regs_struct::r12)
        .def_rw("rbp", &ptrace_regs_struct::rbp)
        .def_rw("rbx", &ptrace_regs_struct::rbx)
        .def_rw("r11", &ptrace_regs_struct::r11)
        .def_rw("r10", &ptrace_regs_struct::r10)
        .def_rw("r9", &ptrace_regs_struct::r9)
        .def_rw("r8", &ptrace_regs_struct::r8)
        .def_rw("rax", &ptrace_regs_struct::rax)
        .def_rw("rcx", &ptrace_regs_struct::rcx)
        .def_rw("rdx", &ptrace_regs_struct::rdx)
        .def_rw("rsi", &ptrace_regs_struct::rsi)
        .def_rw("rdi", &ptrace_regs_struct::rdi)
        .def_rw("orig_rax", &ptrace_regs_struct::orig_rax)
        .def_rw("rip", &ptrace_regs_struct::rip)
        .def_rw("cs", &ptrace_regs_struct::cs)
        .def_rw("eflags", &ptrace_regs_struct::eflags)
        .def_rw("rsp", &ptrace_regs_struct::rsp)
        .def_rw("ss", &ptrace_regs_struct::ss)
        .def_rw("fs_base", &ptrace_regs_struct::fs_base)
        .def_rw("gs_base", &ptrace_regs_struct::gs_base)
        .def_rw("ds", &ptrace_regs_struct::ds)
        .def_rw("es", &ptrace_regs_struct::es)
        .def_rw("fs", &ptrace_regs_struct::fs)
        .def_rw("gs", &ptrace_regs_struct::gs);

    nb::class_<reg_128>(m, "reg_128")
        .def_rw("data", &reg_128::bytes);

    nb::class_<ptrace_fp_regs_struct>(m, "ptrace_fp_regs_struct")
        .def_ro("type", &ptrace_fp_regs_struct::type)
        .def_rw("dirty", &ptrace_fp_regs_struct::dirty)
        .def_rw("fresh", &ptrace_fp_regs_struct::fresh)
        .def_ro("mmx", &ptrace_fp_regs_struct::mmx)
        .def_ro("xmm0", &ptrace_fp_regs_struct::xmm0)
        .def_ro("ymm0", &ptrace_fp_regs_struct::ymm0);

    nb::class_<thread_status>(m, "thread_status")
        .def_rw("tid", &thread_status::tid)
        .def_rw("status", &thread_status::status);

    nb::class_<libdebug_ptrace_interface>(m, "libdebug_ptrace_interface")
        .def(nb::init<>())
        .def("cleanup", &libdebug_ptrace_interface::cleanup)
        .def("register_thread", &libdebug_ptrace_interface::register_thread)
        .def("unregister_thread", &libdebug_ptrace_interface::unregister_thread)
        .def("attach", &libdebug_ptrace_interface::attach)
        .def("detach_for_migration", &libdebug_ptrace_interface::detach_for_migration)
        .def("detach_and_cont", &libdebug_ptrace_interface::detach_and_cont)
        .def("set_ptrace_options", &libdebug_ptrace_interface::set_ptrace_options)
        .def("get_event_msg", &libdebug_ptrace_interface::get_event_msg)
        .def("wait_all_and_update_regs", &libdebug_ptrace_interface::wait_all_and_update_regs, nb::call_guard<nb::gil_scoped_release>())
        .def("cont_all_and_set_bps", &libdebug_ptrace_interface::cont_all_and_set_bps)
        .def("step", &libdebug_ptrace_interface::step)
        .def("step_until", &libdebug_ptrace_interface::step_until)
        .def("stepping_finish", &libdebug_ptrace_interface::stepping_finish)
        .def("forward_signals", &libdebug_ptrace_interface::forward_signals)
        .def("get_remaining_hw_breakpoint_count", &libdebug_ptrace_interface::get_remaining_hw_breakpoint_count)
        .def("get_remaining_hw_watchpoint_count", &libdebug_ptrace_interface::get_remaining_hw_breakpoint_count)
        .def("register_hw_breakpoint", &libdebug_ptrace_interface::register_hw_breakpoint)
        .def("unregister_hw_breakpoint", &libdebug_ptrace_interface::unregister_hw_breakpoint)
        .def("get_hit_hw_breakpoint", &libdebug_ptrace_interface::get_hit_hw_breakpoint)
        .def("register_breakpoint", &libdebug_ptrace_interface::register_breakpoint)
        .def("unregister_breakpoint", &libdebug_ptrace_interface::unregister_breakpoint)
        .def("enable_breakpoint", &libdebug_ptrace_interface::enable_breakpoint)
        .def("disable_breakpoint", &libdebug_ptrace_interface::disable_breakpoint)
        .def("detach_for_kill", &libdebug_ptrace_interface::detach_for_kill)
        .def("get_fp_regs", &libdebug_ptrace_interface::get_fp_regs)
        .def("peek_data", &libdebug_ptrace_interface::peek_data)
        .def("poke_data", &libdebug_ptrace_interface::poke_data);

    nb::set_leak_warnings(true);
}
