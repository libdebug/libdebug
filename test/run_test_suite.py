#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import platform
import sys
import os

architectures = os.listdir(".")
architectures.remove("other")

if len(sys.argv) > 1 and sys.argv[1] not in architectures:
    print("Usage: python run_test_suite.py <architecture>")
    print("Available architectures:")
    for arch in architectures:
        print(f"  {arch}")
    sys.exit(1)
elif len(sys.argv) > 1:
    arch = sys.argv[1]
else:
    arch = platform.machine()
    match arch:
        case "x86_64":
            arch = "amd64"
        case "i686":
            arch = "i386"
        case "aarch64":
            arch = "aarch64"
        case _:
            raise ValueError(f"Unsupported architecture: {arch}")

os.chdir(arch)
os.system(" ".join([sys.executable, "run_suite.py"]))
