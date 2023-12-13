from setuptools import setup, find_packages
import os

# Check if the user has the required C libraries installed
if not os.path.isfile("/usr/include/sys/ptrace.h"):
    print("Required C libraries not found. Please install libptrace-dev")
    exit(1)
if not os.path.isfile("/usr/include/libelf.h"):
    print("Required C libraries not found. Please install libelf-dev")
    exit(1)
if os.path.isdir("/usr/include/libdwarf"):
    debug_sym_cffi = 'debug_sym_cffi_build_legacy'
elif os.path.isdir("/usr/include/libdwarf-0"):
    debug_sym_cffi = 'debug_sym_cffi_build_elf'
else:
    print("Required C libraries not found. Please install libdwarf-dev or libdwarf-devel")
    exit(1)

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
    ],
    setup_requires=["cffi"],
    cffi_modules=["./libdebug/cffi/ptrace_cffi_build.py:ffibuilder", f"./libdebug/cffi/{debug_sym_cffi}.py:ffibuilder"],
)
