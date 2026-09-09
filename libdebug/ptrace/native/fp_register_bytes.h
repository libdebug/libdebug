//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <cstring>
#include <functional>
#include <nanobind/nanobind.h>

// Read/write one register without constructing a list of every register in a
// bank or boxing its individual bytes as Python integers. Returned bytes own
// their storage; no view can outlive or mutate the underlying register file.
template <auto Accessor, typename RegisterFile>
void bind_fp_register_bytes(nanobind::class_<RegisterFile> &cls,
                            const char *getter_name, const char *setter_name)
{
    namespace nb = nanobind;
    cls.def(getter_name, [](RegisterFile &file, size_t index) {
        const auto &data = std::invoke(Accessor, file).at(index).bytes;
        return nb::bytes(data.data(), data.size());
    }, nb::arg().noconvert(), "Return a single register as immutable bytes.");

    cls.def(setter_name, [](RegisterFile &file, size_t index, const nb::bytes &value) {
        auto &data = std::invoke(Accessor, file).at(index).bytes;
        if (value.size() != data.size())
            throw nb::value_error("Incorrect byte count for register");
        std::memcpy(data.data(), value.c_str(), data.size());
    }, nb::arg().noconvert(), nb::arg().noconvert(),
       "Write a single register from bytes of exactly its native width.");
}
