# Set the minimum CMake version and policies for the highest tested version
cmake_minimum_required(VERSION 3.15...3.27)

# Set the project name and version
project(libdebug LANGUAGES CXX C)

# Warn if the user invokes CMake directly
if (NOT SKBUILD)
  message(WARNING "\
  This CMake file is meant to be executed using 'scikit-build-core'.
  Running it directly will almost certainly not produce the desired
  result. If you are a user trying to install this package, use the
  command below, which will install all necessary build dependencies,
  compile the package in an isolated environment, and then install it.
  =====================================================================
   $ pip install .
  =====================================================================
  If you are a software developer, and this is your own package, then
  it is usually much more efficient to install the build dependencies
  in your environment once and use the following command that avoids
  a costly creation of a new virtual environment at every compilation:
  =====================================================================
   $ pip install nanobind scikit-build-core[pyproject]
   $ pip install --no-build-isolation -ve .
  =====================================================================
  You may optionally add -Ceditable.rebuild=true to auto-rebuild when
  the package is imported. Otherwise, you need to rerun the above
  after editing C++ files.")
endif()

# Ensure compatibility with older CMake versions for Development module
if (CMAKE_VERSION VERSION_LESS 3.18)
  set(DEV_MODULE Development)
else()
  set(DEV_MODULE Development.Module)
endif()

# Find required Python version and components
find_package(Python 3.10
  REQUIRED COMPONENTS Interpreter ${DEV_MODULE}
  OPTIONAL_COMPONENTS Development.SABIModule)

# Set compiler flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# Default build type to Release
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

# Add the libdebug_ptrace_binding module
nanobind_add_module(
  libdebug_ptrace_binding
  NOMINSIZE
  NOSTRIP
  LTO
  libdebug/ptrace/native/libdebug_ptrace_binding.cpp
  libdebug/ptrace/native/amd64/libdebug_ptrace_amd64.cpp
)

# Add the stub for libdebug_ptrace_binding
nanobind_add_stub(
  libdebug_ptrace_binding_stub
  MODULE libdebug_ptrace_binding
  DEPENDS libdebug_ptrace_binding
  OUTPUT libdebug_ptrace_binding.pyi
  PYTHON_PATH "."
)

# Add the libdebug_linux_binding module
nanobind_add_module(
  libdebug_linux_binding
  NOMINSIZE
  NOSTRIP
  LTO
  libdebug/native/linux_interface.cpp
)

# Add the stub for libdebug_linux_binding
nanobind_add_stub(
  libdebug_linux_binding_stub
  MODULE libdebug_linux_binding
  DEPENDS libdebug_linux_binding
  OUTPUT libdebug_linux_binding.pyi
  PYTHON_PATH "."
)

# Add the libdebug_debug_sym_parser module
nanobind_add_module(
  libdebug_debug_sym_parser
  NOMINSIZE
  NOSTRIP
  LTO
  libdebug/native/debug_sym_parser.cpp
)

# Add the stub for libdebug_debug_sym_parser
nanobind_add_stub(
  libdebug_debug_sym_parser_stub
  MODULE libdebug_debug_sym_parser
  DEPENDS libdebug_debug_sym_parser
  OUTPUT libdebug_debug_sym_parser.pyi
  PYTHON_PATH "."
)

# Link required libraries
target_link_libraries(libdebug_debug_sym_parser PRIVATE elf dwarf iberty)

# Install the binding libraries
install(TARGETS libdebug_ptrace_binding LIBRARY DESTINATION libdebug/ptrace/native)
install(TARGETS libdebug_linux_binding LIBRARY DESTINATION libdebug/native)
install(TARGETS libdebug_debug_sym_parser LIBRARY DESTINATION libdebug/native)

# Include the jumpstart.c file and add it as an executable
set(SRC_DIR "${CMAKE_SOURCE_DIR}/libdebug/ptrace/jumpstart")
set(SOURCES "${SRC_DIR}/jumpstart.c")

# Add the jumpstart executable
add_executable(jumpstart ${SOURCES})
target_link_libraries(jumpstart -static)

# Install the jumpstart executable
install(TARGETS jumpstart DESTINATION libdebug/ptrace/jumpstart)
