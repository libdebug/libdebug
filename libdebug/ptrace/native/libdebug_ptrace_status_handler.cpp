#include "libdebug_ptrace_status_handler.h"
#include <sys/types.h>


void LibdebugPtraceStatusHandler::manage_change(std::vector<std::pair<pid_t, int>>& statuses){
    // Assume that the stop depends on SIGSTOP sent by the debugger
    // This is a workaround for some race conditions that may happen

    for (auto &status : statuses) {
        if (status.first != -1) {
            // Otherwise, this is a spurious trap
            handle_change(status.first, status.second, statuses);
        }
    }
}

void LibdebugPtraceStatusHandler::handle_change(pid_t pid, int status, std::vector<std::pair<int, int>>& statuses){
    // Handle a change in the status of a traced process
    // Initialize the forward_signal flag
    forward_signal = true;

    if (WIFSTOPPED(status)) {
        nb::gil_scoped_acquire acquire;
        invalidate_process_cache();
        if (nb::cast<bool>(resume_context_instance.attr("is_startup"))) {
            // The process has just started
            return;
        }
        int signum = WSTOPSIG(status);

        // Check if the debugger needs to handle the signal internally
        internal_signal_handler(pid, signum, status, statuses);

        // Check if we need to manage the signal in the Python layer due to user-defined handlers
        ptrace_status_handler.attr("user_signal_handler")(pid, signum, forward_signal);
        nb::gil_scoped_release release;
    } 

    if (WIFEXITED(status)) {
        // The thread has exited normally
        int exit_code = WEXITSTATUS(status);

        nb::gil_scoped_acquire acquire;
        invalidate_process_cache();

        liblog_debugger("Child process %d exited with exit code %d", pid, exit_code);

        // Handle the exit in the Python layer
        ptrace_status_handler.attr("handle_exit")(pid, exit_code, nb::none());
        nb::gil_scoped_release release;
    } 
    
    if (WIFSIGNALED(status)) {
        // The thread has exited with a signal
        int exit_signal = WTERMSIG(status);

        nb::gil_scoped_acquire acquire;
        invalidate_process_cache();
        liblog_debugger("Child process %d exited with signal %d", pid, exit_signal);

        // Handle the exit in the Python layer
        ptrace_status_handler.attr("handle_exit")(pid, nb::none(), exit_signal);
        nb::gil_scoped_release release;
    }
}

void LibdebugPtraceStatusHandler::internal_signal_handler(pid_t pid, int signum, int status, std::vector<std::pair<int, int>>& statuses){
    // Handle the signal internally
    if (signum == SYSCALL_SIGTRAP){
        // We hit a syscall
        liblog_debugger("Child thread %d stopped on syscall", pid);
        
        // Handle the syscall in the Python layer
        ptrace_status_handler.attr("handle_syscall")(pid);

        forward_signal = false;
    } else if (signum == SIGSTOP && nb::cast<bool>(resume_context_instance.attr("force_interrupt"))){
        // The user has requested an interrupt, we need to stop the process despite the other signals
        liblog_debugger("Child thread %d stopped with signal %d", pid, signum);
        nb::dict event_type_dict = nb::cast<nb::dict>(resume_context_instance.attr("event_type"));
        event_type_dict[nb::int_(pid)] = user_interrupt_event;
        resume_context_instance.attr("resume") = false;
        resume_context_instance.attr("force_interrupt") = false;
        forward_signal = false;
    } else if (signum == SIGTRAP){
        // The trap decides if we hit a breakpoint. If so, it decides whether we should stop or
        // continue the execution and wait for the next trap
        forward_signal = nb::cast<bool>(ptrace_status_handler.attr("handle_breakpoints")(pid, forward_signal));
        if (nb::cast<bool>(resume_context_instance.attr("is_a_step"))){        
            // The process is stepping, we need to stop the execution
            liblog_debugger("Child thread %d stopped with signal %d", pid, signum);
            nb::dict event_type_dict = nb::cast<nb::dict>(resume_context_instance.attr("event_type"));
            event_type_dict[nb::int_(pid)] = step_event;
            resume_context_instance.attr("resume") = false;
            resume_context_instance.attr("is_a_step") = false;
            forward_signal = false;

        }

        switch(status >> 8){
            case CLONE_EVENT:
                // The process has created a new thread
                ptrace_status_handler.attr("handle_clone")(pid, statuses);
                forward_signal = false;
                break;
            case SECCOMP_EVENT:
                // The process has triggered a seccomp event
                liblog_debugger("Process %d installed a seccomp", pid);
                forward_signal = false;
                break;
            case EXIT_EVENT:
                // The tracee is still alive; it needs to be PTRACE_CONTed or PTRACE_DETACHed to finish exiting.
                // So we don't call handle_exit(pid) here. It will be called at the next wait (hopefully).
                liblog_debugger("Thread %d exited with status: %s", pid, ptrace_status_handler.attr("ptrace_interface").attr("_get_event_msg")(pid));
                forward_signal = false;
                break;
            case FORK_EVENT:
                // The process has been forked
                liblog_warning("Process %d forked. Continuing execution of the parent process. The child process will be stopped until the user decides to attach to it.", pid);
                forward_signal = false;
                break;
        }
    }
}

NB_MODULE(libdebug_ptrace_status_handler, m){
    nb::class_<LibdebugPtraceStatusHandler>(m, "LibdebugPtraceStatusHandler", "A class to handle the status of a traced process.")
        .def(nb::init<nb::object, nb::object>(), nb::arg("resume_context_instance"), nb::arg("ptrace_status_handler"))        
        .def("manage_change", &LibdebugPtraceStatusHandler::manage_change, "Manage the change in the status of a traced process.", nb::arg("statuses"))
        .def("handle_change", &LibdebugPtraceStatusHandler::handle_change, "Handle a change in the status of a traced process.", nb::arg("pid"), nb::arg("status"), nb::arg("statuses"))
        .def("internal_signal_handler", &LibdebugPtraceStatusHandler::internal_signal_handler, "Handle the signal internally.", nb::arg("pid"), nb::arg("signum"), nb::arg("status"), nb::arg("statuses"));
}