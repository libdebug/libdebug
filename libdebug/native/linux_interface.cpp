//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <nanobind/nanobind.h>
#include <sys/personality.h>

void disable_aslr()
{
    int persona = personality(0xffffffff);
    if (persona == -1) {
        throw std::runtime_error("Reading personality failed");
    }

    persona |= ADDR_NO_RANDOMIZE;

    if (personality(persona) == -1) {
        throw std::runtime_error("Disabling ASLR failed");
    }
}

void enable_aslr()
{
    int persona = personality(0xffffffff);
    if (persona == -1) {
        throw std::runtime_error("Reading personality failed");
    }

    persona &= ~ADDR_NO_RANDOMIZE;

    if (personality(persona) == -1) {
        throw std::runtime_error("Enabling ASLR failed");
    }
}

NB_MODULE(libdebug_linux_binding, m)
{
    m.def("disable_aslr", &disable_aslr, "Disables ASLR for the current process.");
    m.def("enable_aslr", &enable_aslr, "Enables ASLR for the current process.");
}
