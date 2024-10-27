//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#ifndef SIGCHLD_HANDLER_H
#define SIGCHLD_HANDLER_H

#include <mutex>

class SigChldHandler {
public:
    // Get the singleton instance
    static SigChldHandler& instance();

    // Install the SIGCHLD handler
    void install_handler();

    // Get the write end of the synchronization pipe
    int get_sync_pipe_write_fd() const;

private:
    // Private constructor
    SigChldHandler();

    // Delete copy constructor and assignment operator to prevent cloning
    SigChldHandler(const SigChldHandler&) = delete;
    SigChldHandler& operator=(const SigChldHandler&) = delete;

    // Signal handler function
    static void sigchld_handler(int signum);

    // Pipe file descriptors
    int sync_pipe_fd_[2];

    // Flag indicating if the handler is installed
    bool handler_installed_;

    // Mutex for thread safety
    std::mutex mutex_;
};

#endif // SIGCHLD_HANDLER_H
