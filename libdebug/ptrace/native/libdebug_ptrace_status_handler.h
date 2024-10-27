#pragma once

#include <nanobind/stl/vector.h>
#include <nanobind/stl/pair.h>
#include <nanobind/nanobind.h>
#include "libdebug_ptrace_interface.h"
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
namespace nb = nanobind; 

#define SYSCALL_SIGTRAP (0x80 | SIGTRAP)
#define CLONE_EVENT (SIGTRAP | (PTRACE_EVENT_CLONE << 8))
#define SECCOMP_EVENT (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))
#define EXIT_EVENT SIGTRAP | (PTRACE_EVENT_EXIT << 8)
#define FORK_EVENT SIGTRAP | (PTRACE_EVENT_FORK << 8)

class LibdebugPtraceStatusHandler
{
private:
    bool assume_race_sigstop;
    bool forward_signal;
    nb::object liblog_debugger;
    nb::object liblog_warning;
    nb::object resume_context_instance;
    nb::object ptrace_status_handler;
    LibdebugPtraceInterface &libdebug_ptrace_interface;
    nb::object user_interrupt_event;
    nb::object breakpoint_event;
    nb::object step_event;
    nb::object invalidate_process_cache;

    void initialize(){
        // Import the Python liblog module for the loggers
        nb::object libdebug_module = nb::module_::import_("libdebug.liblog");

        // Access the liblog attribute
        nb::object liblog = libdebug_module.attr("liblog");

        // Retrieve the debugger logger from liblog
        liblog_debugger = liblog.attr("debugger");

        // Retrieve the warning logger from liblog
        liblog_warning = liblog.attr("warning");

        // Import the Python libdebug module for the user interrupt event
        libdebug_module = nb::module_::import_("libdebug.state.resume_context");

        // Access the user interrupt event attribute
        user_interrupt_event = libdebug_module.attr("EventType").attr("USER_INTERRUPT");

        // Access the breakpoint event attribute
        breakpoint_event = libdebug_module.attr("EventType").attr("BREAKPOINT");

        // Access the step event attribute
        step_event = libdebug_module.attr("EventType").attr("STEP");

        // Import the Python libdebug module for the process utils
        libdebug_module = nb::module_::import_("libdebug.utils.process_utils");

        // Access the invalidate_process_cache attribute
        invalidate_process_cache = libdebug_module.attr("invalidate_process_cache");
    }

public:
    // Constructor accepting Python objects
    LibdebugPtraceStatusHandler(nb::object resume_context_instance, nb::object ptrace_status_handler, LibdebugPtraceInterface& libdebug_ptrace_interface)
        : resume_context_instance(resume_context_instance), ptrace_status_handler(ptrace_status_handler), libdebug_ptrace_interface(libdebug_ptrace_interface)
        {
        initialize();
    }
    void manage_change(std::vector<std::pair<pid_t, int>>&);
    void handle_change(pid_t, int, std::vector<std::pair<int, int>>&);
    void internal_signal_handler(pid_t, int, int, std::vector<std::pair<int, int>>&);
    void wait_loop(const pid_t);
    void cont();
};