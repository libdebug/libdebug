import os

from setuptools import find_packages, setup
from setuptools.command.build_ext import build_ext

# Check if the user has the required C libraries installed
if not (
    os.path.isfile("/usr/include/sys/ptrace.h")
    or os.path.isfile("/usr/include/x86_64-linux-gnu/sys/ptrace.h")
):
    print("Required C libraries not found. Please install ptrace or kernel headers")
    exit(1)

if not (
    os.path.isfile("/usr/include/demangle.h")
    or os.path.isfile("/usr/include/libiberty/demangle.h")
):
    print(
        "Required C libraries not found. Please install libiberty-dev or binutils-devel"
    )
    exit(1)

if not os.path.isfile("/usr/include/libelf.h"):
    print("Required C libraries not found. Please install elfutils")
    exit(1)

if os.path.isfile("/usr/include/libdwarf/dwarf.h") and os.path.isfile(
    "/usr/include/libdwarf/libdwarf.h"
):
    debug_sym_cffi = "debug_sym_cffi_build_legacy"
elif (
    os.path.isfile("/usr/include/libdwarf/libdwarf-0/dwarf.h")
    and os.path.isfile("/usr/include/libdwarf/libdwarf-0/libdwarf.h")
) or (
    os.path.isfile("/usr/include/libdwarf-0/dwarf.h")
    and os.path.isfile("/usr/include/libdwarf-0/libdwarf.h")
):
    debug_sym_cffi = "debug_sym_cffi_build"
else:
    print(
        "Required C libraries not found. Please install libdwarf-dev or libdwarf-devel"
    )
    exit(1)


class JumpstartBuildCommand(build_ext):
    def run(self):
        os.system(
            "cc -o libdebug/ptrace/jumpstart/jumpstart libdebug/ptrace/jumpstart/jumpstart.c"
        )
        build_ext.run(self)


setup(
    name="libdebug",
    version="0.3",
    author="JinBlack",
    description="A library to debug binary programs",
    packages=find_packages(include=["libdebug", "libdebug.*"]),
    install_requires=[
        "capstone",
        "pyelftools",
        "cffi",
        "requests",
    ],
    setup_requires=["cffi"],
    cffi_modules=[
        "./libdebug/cffi/ptrace_cffi_build.py:ffibuilder",
        "./libdebug/cffi/personality_cffi_build.py:ffibuilder",
        f"./libdebug/cffi/{debug_sym_cffi}.py:ffibuilder",
    ],
    cmdclass={"build_ext": JumpstartBuildCommand},
    package_data={"libdebug": ["ptrace/jumpstart/jumpstart"]},
)
