//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <nanobind/nanobind.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <algorithm>


#include "libdebug_ptrace_base.h"
#include "libdebug_ptrace_interface.h"

#ifdef ARCH_X86_64
#include "shared/x86_ptrace.h"
#include "amd64/amd64_ptrace.h"
#include "x86_fpregs_xsave_layout.h"
#endif

#ifdef ARCH_X86
#include "shared/x86_ptrace.h"
#include "i386/i386_ptrace.h"
#include "x86_fpregs_xsave_layout.h"
#endif

#ifdef ARCH_AARCH64
#include "aarch64/aarch64_ptrace.h"
#endif

namespace nb = nanobind;

void LibdebugPtraceInterface::getfpregs(Thread &t)
{
    arch_getfpregs(t);
    t.fpregs->fresh = 1;
}

void LibdebugPtraceInterface::setfpregs(Thread &t)
{
    arch_setfpregs(t);
    t.fpregs->dirty = 0;
    t.fpregs->fresh = 0;
}

void LibdebugPtraceInterface::check_and_set_fpregs(Thread &t)
{
    if (t.fpregs->dirty) {
        setfpregs(t);
    }

    t.fpregs->fresh = 0;
}

void LibdebugPtraceInterface::cont_thread(Thread &t)
{
    if (ptrace(handle_syscall ? PTRACE_SYSCALL : PTRACE_CONT, t.tid, NULL, t.signal_to_forward) == -1) {
        throw std::runtime_error("ptrace cont failed");
    }

    t.signal_to_forward = 0;
}

int LibdebugPtraceInterface::prepare_for_run()
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

    arch_check_if_hit_and_step_over();

    // Restore any software breakpoints
    for (auto &bp : software_breakpoints) {
        if (bp.second.enabled) {
            ptrace(PTRACE_POKETEXT, process_id, (void *) bp.first, (void *) bp.second.patched_instruction);
        }
    }

    return 0;
}

Thread& LibdebugPtraceInterface::try_get_thread(const pid_t tid)
{
    auto it = threads.find(tid);

    if (it == threads.end()) {
        throw std::runtime_error("Thread not found");
    }

    return it->second;
}

LibdebugPtraceInterface::LibdebugPtraceInterface()
{
    process_id = -1;
    handle_syscall = false;
}

void LibdebugPtraceInterface::cleanup()
{
    threads.clear();
    dead_threads.clear();
    software_breakpoints.clear();

    process_id = -1;
    handle_syscall = false;
}

std::pair<std::shared_ptr<PtraceRegsStruct>, std::shared_ptr<PtraceFPRegsStruct>> LibdebugPtraceInterface::register_thread(const pid_t tid)
{
    // Verify if the thread is already registered
    if (threads.find(tid) != threads.end()) {
        std::shared_ptr<PtraceRegsStruct> regs = threads[tid].regs;
        std::shared_ptr<PtraceFPRegsStruct> fpregs = threads[tid].fpregs;

        return std::make_pair(regs, fpregs);
    }

    if (process_id == -1) {
        process_id = tid;
    }

    Thread t;
    t.tid = tid;
    t.signal_to_forward = 0;
    t.regs = std::make_shared<PtraceRegsStruct>();
    t.fpregs = std::make_shared<PtraceFPRegsStruct>();
#if defined ARCH_X86_64 || defined ARCH_X86
    t.fpregs->type = FPREGS_TYPE;
#endif
    t.fpregs->dirty = 0;
    t.fpregs->fresh = 0;

    threads[tid] = t;

    getregs(threads[tid]);

    std::shared_ptr<PtraceRegsStruct> regs = threads[tid].regs;
    std::shared_ptr<PtraceFPRegsStruct> fpregs = threads[tid].fpregs;

    return std::make_pair(regs, fpregs);
}

void LibdebugPtraceInterface::unregister_thread(const pid_t tid)
{
    // move the dead thread to the dead list
    dead_threads[tid] = threads[tid];
    threads.erase(tid);
}

int LibdebugPtraceInterface::attach(pid_t tid)
{   
    if(ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
        return errno;
    }
    return 0;
}

void LibdebugPtraceInterface::detach_for_migration()
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
        for (auto &b : it->second.hardware_breakpoints) {
            remove_hardware_breakpoint(b.second);
        }

        // be sure that the thread will not run during gdb reattachment
        tgkill(process_id, it->first, SIGSTOP);

        // detach from it
        if (ptrace(PTRACE_DETACH, it->first, NULL, NULL) == -1) {
            throw std::runtime_error("ptrace detach failed");
        }
    }
}

void LibdebugPtraceInterface::reattach_from_migration(){
    for (auto it = threads.begin(); it != threads.end(); ++it) {
        // reattach to the process
        if (ptrace(PTRACE_ATTACH, it->first, NULL, NULL)) {
            throw std::runtime_error("ptrace attach failed");
        }

        if (getregs(it->second)) {
            // if we can't read the registers, the attach failed
            throw std::runtime_error("ptrace attach failed");
        }
    }

}

void LibdebugPtraceInterface::detach_and_cont()
{
    detach_for_migration();

    // continue the execution of the process
    kill(process_id, SIGCONT);
}

void LibdebugPtraceInterface::detach_from_child(pid_t pid, bool follow_child)
{  
    // the child will be in trace stop, we need to sync with it
    int status;
    waitpid(pid, &status, 0);

    if (follow_child){
        // send a SIGSTOP to the process to avoid the process to run after the detach
        kill(pid, SIGSTOP);
    }

    // we need to repair the memory of the software breakpoints
    for (auto &bp : software_breakpoints) {
        if (bp.second.enabled) {
            ptrace(PTRACE_POKETEXT, pid, (void *) bp.first, (void *) bp.second.instruction);
        }
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, 0) == -1) {
        printf("ptrace detach failed\n");
        throw std::runtime_error("ptrace detach failed");
    }
}

void LibdebugPtraceInterface::detach_for_kill()
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
        if (ptrace(PTRACE_DETACH, it->first, NULL, NULL) && errno != ESRCH) {
            throw std::runtime_error("ptrace detach failed");
        }

        // kill it
        tgkill(process_id, it->first, SIGKILL);
    }

    // final waitpid for the zombie process
    waitpid(process_id, NULL, 0);
}

void LibdebugPtraceInterface::set_tracing_options()
{
    int options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD |
        PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

    for (auto &t : threads) {
        ptrace(PTRACE_SETOPTIONS, t.first, NULL, options);
    }
}

void LibdebugPtraceInterface::cont_all_and_set_bps(bool handle_syscalls)
{
    // Set the handle_syscall flag
    handle_syscall = handle_syscalls;

    prepare_for_run();

    // Continue all the threads
    for (auto &t : threads) {
        cont_thread(t.second);
    }
}

void LibdebugPtraceInterface::step(const pid_t tid)
{
    Thread &t = try_get_thread(tid);

    // Flush any register changes
    if (setregs(t)) {
        throw std::runtime_error("setregs failed");
    }

    check_and_set_fpregs(t);

    // Step the thread
    // The third parameter indicates that we must step over hardware breakpoints
    step_thread(t, true, true);
}

void LibdebugPtraceInterface::step_until(const pid_t tid, const unsigned long addr, const int max_steps)
{
    Thread &t = try_get_thread(tid);

    // Flush any register changes
    if (setregs(t)) {
        throw std::runtime_error("setregs failed");
    }
    check_and_set_fpregs(t);

    unsigned long previous_ip;
    int count = 0, status = 0;

    // Remove any hardware breakpoints
    for (auto &bp : t.hardware_breakpoints) {
        remove_hardware_breakpoint(bp.second);
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
    for (auto &bp : t.hardware_breakpoints) {
        if (bp.second.enabled) {
            install_hardware_breakpoint(bp.second);
        }
    }
}

void LibdebugPtraceInterface::stepping_finish(const pid_t tid, const bool use_trampoline_heuristic)
{
    Thread &stepping_thread = try_get_thread(tid);

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

        // On amd64 and i386 we care only about the first byte
        // On aarch64 we care about the first 4 bytes
        opcode = opcode_window & 0xFFFFFFFF;

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

        if (IS_RET_INSTRUCTION(opcode) && use_trampoline_heuristic && check_if_dl_trampoline(current_ip)) {
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

unsigned long LibdebugPtraceInterface::get_thread_event_msg(const pid_t tid)
{
    unsigned long data = 0;

    ptrace(PTRACE_GETEVENTMSG, tid, NULL, &data);

    return data;
}

std::vector<std::pair<pid_t, int>> LibdebugPtraceInterface::wait_all_and_update_regs()
{
    std::vector<std::pair<pid_t, int>> thread_statuses;

    int tid, status;

    while (true) {
        // Check if any thread has finished
        bool anyFinished = std::any_of(threads.begin(), threads.end(), [&](auto &t) {
            tid = waitpid(t.first, &status, WNOHANG);
            return (tid != 0);
        });

        if (anyFinished) {
            break;
        }
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
    while (true) {
        bool eventRetrieved = false;

        for (auto &t : threads) {
            tid = waitpid(t.first, &status, WNOHANG);
            if (tid > 0) {
                // Record the PID and its status
                thread_statuses.push_back({tid, status});
                eventRetrieved = true;
            }
        }

        // If we didn't retrieve any new events, we're done
        if (!eventRetrieved) {
            break;
        }
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

void LibdebugPtraceInterface::forward_signals(const std::vector<std::pair<pid_t, int>> signals)
{
    for (auto &s : signals) {
        threads[s.first].signal_to_forward = s.second;
    }
}

void LibdebugPtraceInterface::register_breakpoint(const unsigned long address)
{
    unsigned long instruction = ptrace(PTRACE_PEEKTEXT, process_id, (void *) address, NULL);

    unsigned long patched_instruction = INSTALL_BREAKPOINT(instruction);

    if (software_breakpoints.find(address) != software_breakpoints.end()) {
        // The breakpoint is already registered
        // We just need to enable it
        software_breakpoints[address].enabled = true;
        return;
    }

    SoftwareBreakpoint bp;
    bp.addr = address;
    bp.instruction = instruction;
    bp.patched_instruction = patched_instruction;
    bp.enabled = true;

    software_breakpoints[address] = bp;
}

void LibdebugPtraceInterface::unregister_breakpoint(const unsigned long address)
{
    if (software_breakpoints.find(address) == software_breakpoints.end()) {
        throw std::runtime_error("Breakpoint not found");
    }

    software_breakpoints.erase(address);
}

void LibdebugPtraceInterface::enable_breakpoint(const unsigned long address)
{
    if (software_breakpoints.find(address) == software_breakpoints.end()) {
        throw std::runtime_error("Breakpoint not found");
    }

    software_breakpoints[address].enabled = true;

    ptrace(PTRACE_POKETEXT, process_id, (void *) address, (void *) software_breakpoints[address].patched_instruction);
}

void LibdebugPtraceInterface::disable_breakpoint(const unsigned long address)
{
    if (software_breakpoints.find(address) == software_breakpoints.end()) {
        throw std::runtime_error("Breakpoint not found");
    }

    software_breakpoints[address].enabled = false;

    ptrace(PTRACE_POKETEXT, process_id, (void *) address, (void *) software_breakpoints[address].instruction);
}

void LibdebugPtraceInterface::register_hw_breakpoint(const pid_t tid, unsigned long address, const int type, const int len)
{
    Thread &t = try_get_thread(tid);

    if (t.hardware_breakpoints.find(address) != t.hardware_breakpoints.end()) {
        throw std::runtime_error("Breakpoint already registered");
    }

    HardwareBreakpoint bp;
    bp.addr = address;
    bp.tid = tid;
    bp.enabled = true;
    bp.type = type;
    bp.len = len;

    // Insert the hardware breakpoint
    t.hardware_breakpoints[address] = bp;

    // Install the hardware breakpoint
    install_hardware_breakpoint(bp);
}

void LibdebugPtraceInterface::unregister_hw_breakpoint(const pid_t tid, const unsigned long address)
{
    Thread &t = try_get_thread(tid);

    if (t.hardware_breakpoints.find(address) == t.hardware_breakpoints.end()) {
        throw std::runtime_error("Breakpoint not found");
    }

    if (t.hardware_breakpoints[address].enabled) {
        // Remove the hardware breakpoint
        remove_hardware_breakpoint(t.hardware_breakpoints[address]);
    }

    t.hardware_breakpoints.erase(address);
}

unsigned long LibdebugPtraceInterface::get_hit_hw_breakpoint(const pid_t tid)
{
    Thread &t = try_get_thread(tid);

    unsigned long address = hit_hardware_breakpoint_address(tid);

    if (address == 0) {
        return 0;
    }

    if (t.hardware_breakpoints.find(address) != t.hardware_breakpoints.end()) {
        return address;
    }

    return 0;
}

void LibdebugPtraceInterface::get_fp_regs(pid_t tid)
{
    Thread &t = try_get_thread(tid);

    getfpregs(t);
}

unsigned long LibdebugPtraceInterface::peek_data(unsigned long addr)
{
    errno = 0;

    unsigned long value = ptrace(PTRACE_PEEKDATA, process_id, (void *) addr, NULL);

    if (errno) {
        throw std::runtime_error("ptrace peekdata failed");
    }

    return value;
}

void LibdebugPtraceInterface::poke_data(unsigned long addr, unsigned long data)
{
    if (ptrace(PTRACE_POKEDATA, process_id, (void *) addr, (void *) data) == -1) {
        throw std::runtime_error("ptrace pokedata failed");
    }
}

NB_MODULE(libdebug_ptrace_binding, m)
{
    init_libdebug_ptrace_registers(m);

    nb::class_<Reg128>(m, "Reg128", "A 128-bit register.")
        .def_rw(
            "data",
            &Reg128::bytes,
            "The data of the register, as a byte array."
        );

    nb::class_<Reg256>(m, "Reg256", "A 256-bit register.")
        .def_rw(
            "data",
            &Reg256::bytes,
            "The data of the register, as a byte array."
        );

    nb::class_<Reg512>(m, "Reg512", "A 512-bit register.")
        .def_rw(
            "data",
            &Reg512::bytes,
            "The data of the register, as a byte array."
        );

    nb::class_<ThreadStatus>(m, "ThreadStatus", "The waitpid result of a specific thread.")
        .def_ro(
            "tid",
            &ThreadStatus::tid,
            "The thread id."
        )
        .def_ro(
            "status",
            &ThreadStatus::status,
            "The waitpid result."
        );

    nb::class_<LibdebugPtraceInterface>(m, "LibdebugPtraceInterface", "The native binding for ptrace on Linux.")
        .def(
            nb::init<>(),
            "Initializes a new ptrace interface for debugging."
        )
        .def(
            "cleanup",
            &LibdebugPtraceInterface::cleanup,
            "Cleans up the instance from any previous state."
        )
        .def(
            "register_thread",
            &LibdebugPtraceInterface::register_thread,
            nb::arg("tid"),
            "Registers a new thread that must be debugged.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to be registered.\n"
            "\n"
            "Returns:\n"
            "    tuple: A tuple containing a reference to the registers, integer and floating point."
        )
        .def(
            "unregister_thread",
            &LibdebugPtraceInterface::unregister_thread,
            nb::arg("tid"),
            "Unregisters a thread that was previously registered.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to be unregistered."
        )
        .def(
            "attach",
            &LibdebugPtraceInterface::attach,
            nb::arg("tid"),
            "Attaches to a process for debugging.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to be attached to.\n"
            "\n"
            "Returns:\n"
            "    int: The error code of the operation, if any."
        )
        .def(
            "detach_for_migration",
            &LibdebugPtraceInterface::detach_for_migration,
            "Detaches from the process for migration to another debugger."
        )
        .def(
            "reattach_from_migration",
            &LibdebugPtraceInterface::reattach_from_migration,
            "Reattaches to the process after migration from another debugger."
        )
        .def(
            "detach_and_cont",
            &LibdebugPtraceInterface::detach_and_cont,
            "Detaches from the process and continues its execution."
        )
        .def(
            "detach_from_child",
            &LibdebugPtraceInterface::detach_from_child,
            nb::arg("pid"),
            nb::arg("follow_child"),
            "Detaches from a specific child process.\n"
            "\n"
            "Args:\n"
            "    pid (int): The process id to detach from."
            "    follow_child (bool): A flag to indicate if the child should be followed."
        )
        .def(
            "set_ptrace_options",
            &LibdebugPtraceInterface::set_tracing_options,
            "Sets the ptrace options for the process."
        )
        .def(
            "get_event_msg",
            &LibdebugPtraceInterface::get_thread_event_msg,
            nb::arg("tid"),
            "Gets an event message for a thread.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to get the event message for.\n"
            "\n"
            "Returns:\n"
            "    int: The event message."
        )
        .def(
            "wait_all_and_update_regs",
            &LibdebugPtraceInterface::wait_all_and_update_regs,
            nb::call_guard<nb::gil_scoped_release>(),
            "Waits for any thread to stop, interrupts all the others and updates the registers.\n"
            "\n"
            "Returns:\n"
            "    list: A list of tuples containing the thread id and the corresponding waitpid result."
        )
        .def(
            "cont_all_and_set_bps",
            &LibdebugPtraceInterface::cont_all_and_set_bps,
            nb::arg("handle_syscalls"),
            "Sets the breakpoints and continues all the threads.\n"
            "\n"
            "Args:\n"
            "    handle_syscalls (bool): A flag to indicate if the debuggee should stop on syscalls."
        )
        .def(
            "step",
            &LibdebugPtraceInterface::step,
            nb::arg("tid"),
            "Steps a thread by one instruction.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to step."
        )
        .def(
            "step_until",
            &LibdebugPtraceInterface::step_until,
            nb::arg("tid"),
            nb::arg("addr"),
            nb::arg("max_steps"),
            "Steps a thread until a specific address is reached, or for a maximum amount of steps.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to step.\n"
            "    addr (int): The address to step until.\n"
            "    max_steps (int): The maximum amount of steps to take, or -1 if unlimited."
        )
        .def(
            "stepping_finish",
            &LibdebugPtraceInterface::stepping_finish,
            nb::arg("tid"),
            nb::arg("use_trampoline_heuristic"),
            "Runs a thread until the end of the current function call, by single-stepping it.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to step.\n"
            "    use_trampoline_heuristic (bool): A flag to indicate if the trampoline heuristic for i386 should be used."
        ) 
        .def(
            "forward_signals",
            &LibdebugPtraceInterface::forward_signals,
            nb::arg("signals"),
            "Forwards signals to the threads.\n"
            "\n"
            "Args:\n"
            "    signals (list): A list of tuples containing the thread id and the signal to forward."
        )
        .def(
            "get_remaining_hw_breakpoint_count",
            &LibdebugPtraceInterface::get_remaining_hw_breakpoint_count,
            nb::arg("tid"),
            "Gets the remaining hardware breakpoint count for a thread.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to get the remaining hardware breakpoint count for.\n"
        )
        .def(
            "get_remaining_hw_watchpoint_count",
            &LibdebugPtraceInterface::get_remaining_hw_watchpoint_count,
            nb::arg("tid"),
            "Gets the remaining hardware watchpoint count for a thread.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to get the remaining hardware watchpoint count for.\n"
        )
        .def(
            "register_hw_breakpoint",
            &LibdebugPtraceInterface::register_hw_breakpoint,
            nb::arg("tid"),
            nb::arg("address"),
            nb::arg("type"),
            nb::arg("len"),
            "Registers a hardware breakpoint for a thread.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to register the hardware breakpoint for.\n"
            "    address (int): The address to set the hardware breakpoint at.\n"
            "    type (int): The type of the hardware breakpoint.\n"
            "    len (int): The length of the hardware breakpoint."
        )
        .def(
            "unregister_hw_breakpoint",
            &LibdebugPtraceInterface::unregister_hw_breakpoint,
            nb::arg("tid"),
            nb::arg("address"),
            "Unregisters a hardware breakpoint for a thread.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to unregister the hardware breakpoint for.\n"
            "    address (int): The address to remove the hardware breakpoint from."
        )
        .def(
            "get_hit_hw_breakpoint",
            &LibdebugPtraceInterface::get_hit_hw_breakpoint,
            nb::arg("tid"),
            "Gets the address of the hardware breakpoint hit by a specific thread, if any.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to get the hit hardware breakpoint for.\n"
            "\n"
            "Returns:\n"
            "    int: The address of the hit hardware breakpoint."
        )
        .def(
            "register_breakpoint",
            &LibdebugPtraceInterface::register_breakpoint,
            nb::arg("address"),
            "Registers a software breakpoint at a specific address.\n"
            "\n"
            "Args:\n"
            "    address (int): The address to set the software breakpoint at."
        )
        .def(
            "unregister_breakpoint",
            &LibdebugPtraceInterface::unregister_breakpoint,
            nb::arg("address"),
            "Unregisters a software breakpoint at a specific address.\n"
            "\n"
            "Args:\n"
            "    address (int): The address to remove the software breakpoint from."
        )
        .def(
            "enable_breakpoint",
            &LibdebugPtraceInterface::enable_breakpoint,
            nb::arg("address"),
            "Enables a previously registered software breakpoint at a specific address.\n"
            "\n"
            "Args:\n"
            "    address (int): The address to enable the software breakpoint at."
        )
        .def(
            "disable_breakpoint",
            &LibdebugPtraceInterface::disable_breakpoint,
            nb::arg("address"),
            "Disables a previously registered software breakpoint at a specific address.\n"
            "\n"
            "Args:\n"
            "    address (int): The address to disable the software breakpoint at."
        )
        .def(
            "detach_for_kill",
            &LibdebugPtraceInterface::detach_for_kill,
            "Detaches from the process and kills it."
        )
        .def(
            "get_fp_regs",
            &LibdebugPtraceInterface::get_fp_regs,
            nb::arg("tid"),
            "Refreshes the floating point registers for a thread.\n"
            "\n"
            "Args:\n"
            "    tid (int): The thread id to refresh the floating point registers for."
        )
        .def(
            "peek_data",
            &LibdebugPtraceInterface::peek_data,
            nb::arg("addr"),
            "Peeks memory from a specific address.\n"
            "\n"
            "Args:\n"
            "    addr (int): The address to peek memory from.\n"
            "\n"
            "Returns:\n"
            "    int: The memory value at the address."
        )
        .def(
            "poke_data",
            &LibdebugPtraceInterface::poke_data,
            nb::arg("addr"),
            nb::arg("data"),
            "Pokes memory at a specific address.\n"
            "\n"
            "Args:\n"
            "    addr (int): The address to poke memory at.\n"
            "    data (int): The data to poke at the address."
        );

    nb::set_leak_warnings(false);
}
