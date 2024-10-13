cmake_minimum_required(VERSION 3.15...3.27)
project(libdebug) # Replace 'my_project' with the name of your project

if (CMAKE_VERSION VERSION_LESS 3.18)
  set(DEV_MODULE Development)
else()
  set(DEV_MODULE Development.Module)
endif()

find_package(Python 3.12 EXACT COMPONENTS Interpreter ${DEV_MODULE} REQUIRED)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Detect the installed nanobind package and import it into CMake
execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE NB_DIR)
list(APPEND CMAKE_PREFIX_PATH "${NB_DIR}")
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(
  libdebug_ptrace_binding
  NOSTRIP
  LTO
  libdebug/ptrace/native/libdebug_ptrace_binding.cpp
  libdebug/ptrace/native/amd64/libdebug_ptrace_amd64.cpp
)

nanobind_add_stub(
  libdebug_ptrace_binding_stub
  MODULE libdebug_ptrace_binding
  DEPENDS libdebug_ptrace_binding
  OUTPUT libdebug_ptrace_binding.pyi
  PYTHON_PATH "."
)

nanobind_add_module(
  libdebug_linux_binding
  NOSTRIP
  LTO
  libdebug/cffi/linux_interface.cpp
)

nanobind_add_stub(
  libdebug_linux_binding_stub
  MODULE libdebug_linux_binding
  DEPENDS libdebug_linux_binding
  OUTPUT libdebug_linux_binding.pyi
  PYTHON_PATH "."
)
