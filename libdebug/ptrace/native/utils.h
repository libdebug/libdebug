//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <cstdint>
#include <sys/types.h>

// tgkill is not POSIX-compliant, thus we provide a reimplementation
// of it that works on all Linux systems by calling the syscall
// directly.
void thread_kill(pid_t tgid, pid_t tid, int sig);