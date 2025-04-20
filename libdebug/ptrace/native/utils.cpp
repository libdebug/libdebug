//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "utils.h"

#include <stdexcept>
#include <sys/syscall.h>
#include <unistd.h>

void thread_kill(pid_t tgid, pid_t tid, int sig)
{
    // Check that tgid, tid, and sig are valid
    if (tgid <= 0 || tid <= 0 || sig <= 0 || sig > 64) {
        throw std::invalid_argument("Invalid thread_kill arguments");
    }

    // Use syscall to send the signal to the specific thread
    syscall(SYS_tgkill, tgid, tid, sig);
}