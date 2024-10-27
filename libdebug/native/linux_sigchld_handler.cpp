//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "linux_sigchld_handler.h"
#include <nanobind/nanobind.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

namespace nb = nanobind;

// Definition of the singleton instance
SigChldHandler& SigChldHandler::instance() {
    static SigChldHandler instance;
    return instance;
}

// Constructor
SigChldHandler::SigChldHandler() : handler_installed_(false) {
    sync_pipe_fd_[0] = -1;
    sync_pipe_fd_[1] = -1;
}

// Install the signal handler
void SigChldHandler::install_handler() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (handler_installed_) {
        // Handler already installed
        return;
    }

    if (pipe(sync_pipe_fd_) == -1) {
        throw std::runtime_error("Initialize synchronization with sigchld handler failed");
    }

    // Set the write end of the pipe to non-blocking
    int flags = fcntl(sync_pipe_fd_[1], F_GETFL, 0);
    fcntl(sync_pipe_fd_[1], F_SETFL, flags | O_NONBLOCK);

    // Install the signal handler
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  // Restart interrupted system calls

    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        throw std::runtime_error("Install sigchld handler failed");
    }

    handler_installed_ = true;
}

// Get the write end of the synchronization pipe
int SigChldHandler::get_sync_pipe_write_fd() const {
    return sync_pipe_fd_[1];
}

// Signal handler function
void SigChldHandler::sigchld_handler(int signum) {
    printf("read on the synchronization pipe to signal that we have performed waitpid\n");
    // Save errno to restore it after the handler
    int saved_errno = errno;

    char buffer[1];


    // Wait for the other thread to signal that it has performed waitpid
    ssize_t n = read(instance().sync_pipe_fd_[0], buffer, 1);
    if (n == -1) {
        throw std::runtime_error("Synchronization with sigchld handler failed");
    }

    // Restore errno
    errno = saved_errno;
}

NB_MODULE(linux_sigchld_handler, m) {
    nb::class_<SigChldHandler>(m, "SigChldHandler")
        .def_static("instance", &SigChldHandler::instance, nb::rv_policy::reference)
        .def("install_handler", &SigChldHandler::install_handler)
        .def("get_sync_pipe_write_fd", &SigChldHandler::get_sync_pipe_write_fd);
}
