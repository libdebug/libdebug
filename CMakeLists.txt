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

# Look for libiberty
find_library(IBERTY_LIBRARY NAMES iberty)

# Look for libelf
find_library(ELF_LIBRARY NAMES elf)

# Look for libdwarf
find_library(DWARF_LIBRARY NAMES dwarf)

# Check if the required libraries were found
if (NOT IBERTY_LIBRARY)
  message(FATAL_ERROR "libiberty not found")
else()
  message(STATUS "libiberty found at ${IBERTY_LIBRARY}")
endif()

if (NOT ELF_LIBRARY)
  message(FATAL_ERROR "libelf not found")
else()
  message(STATUS "libelf found at ${ELF_LIBRARY}")
endif()

if (NOT DWARF_LIBRARY)
  message(FATAL_ERROR "libdwarf not found")
else()
  message(STATUS "libdwarf found at ${DWARF_LIBRARY}")
endif()

# Look for the demangle.h header
# It could be under libiberty/demangle.h
find_path(DEMANGLE_HEADER NAMES demangle.h PATHS /usr/include/libiberty)

# Look for the libdwarf.h header
# It could be under libdwarf/libdwarf.h or libdwarf-0/libdwarf.h
# or libdwarf/libdwarf-0/libdwarf.h
find_path(DWARF_HEADER NAMES libdwarf.h PATHS /usr/include/libdwarf /usr/include/libdwarf-0 /usr/include/libdwarf/libdwarf-0)

# Check if the required header was found
if (NOT DEMANGLE_HEADER)
  message(FATAL_ERROR "demangle.h not found")
else()
  message(STATUS "demangle.h found at ${DEMANGLE_HEADER}")
endif()

if (NOT DWARF_HEADER)
  message(FATAL_ERROR "libdwarf.h not found")
else()
  message(STATUS "libdwarf.h found at ${DWARF_HEADER}")
endif()

# Add the libiberty, libelf, and libdwarf libraries
add_library(iberty UNKNOWN IMPORTED)
set_target_properties(iberty PROPERTIES IMPORTED_LOCATION "${IBERTY_LIBRARY}")

add_library(elf UNKNOWN IMPORTED)
set_target_properties(elf PROPERTIES IMPORTED_LOCATION "${ELF_LIBRARY}")

add_library(dwarf UNKNOWN IMPORTED)
set_target_properties(dwarf PROPERTIES IMPORTED_LOCATION "${DWARF_LIBRARY}")

# Add the demangle.h header
include_directories(${DEMANGLE_HEADER})

# Add the libdwarf.h header
include_directories(${DWARF_HEADER})

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)

# Set the C standard
set(CMAKE_C_STANDARD 11)

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

# Define the sources for the libdebug_ptrace_binding module
set(LIBDEBUG_PTRACE_BINDING_SOURCES
  libdebug/ptrace/native/libdebug_ptrace_binding.cpp
)

# Print the architecture
message(STATUS "Detected Architecture: ${CMAKE_SYSTEM_PROCESSOR}")

# Add the architecture-specific sources for amd64
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/amd64/amd64_ptrace.cpp)
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/shared/x86_ptrace.cpp)

  # Add a definition for the x86_64 architecture
  add_definitions(-DARCH_X86_64)
endif()

# Add the architecture-specific sources for i386
if (CMAKE_SYSTEM_PROCESSOR MATCHES "i386" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686" OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86" AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/i386/i386_ptrace.cpp)
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/shared/x86_ptrace.cpp)

  # Add a definition for the i386 architecture
  add_definitions(-DARCH_X86)
endif()

# Add the libdebug_ptrace_binding module
nanobind_add_module(
  libdebug_ptrace_binding
  NOMINSIZE
  NOSTRIP
  LTO
  ${LIBDEBUG_PTRACE_BINDING_SOURCES}
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

# Check if in the libdwarf include path we find the substring libwarf-0
if (DWARF_HEADER MATCHES "libdwarf-0")
  # Add the libdebug_debug_sym_parser module, using the new libdwarf-0
  nanobind_add_module(
    libdebug_debug_sym_parser
    NOMINSIZE
    NOSTRIP
    LTO
    libdebug/native/symbols/debug_sym_parser.cpp
    libdebug/native/symbols/debug_sym_parser_new.cpp
  )
else()
  # Add the libdebug_debug_sym_parser module, using the old libdwarf
  nanobind_add_module(
    libdebug_debug_sym_parser
    NOMINSIZE
    NOSTRIP
    LTO
    libdebug/native/symbols/debug_sym_parser.cpp
    libdebug/native/symbols/debug_sym_parser_legacy.cpp
  )
endif()

# Add the stub for libdebug_debug_sym_parser
nanobind_add_stub(
  libdebug_debug_sym_parser_stub
  MODULE libdebug_debug_sym_parser
  DEPENDS libdebug_debug_sym_parser
  OUTPUT libdebug_debug_sym_parser.pyi
  PYTHON_PATH "."
)

# If architecture is amd64 or i386
if (CMAKE_SYSTEM_PROCESSOR MATCHES "i386"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")

    # Register the xsave layout generator executable
    add_executable(autogenerate_xsave_layout libdebug/ptrace/native/shared/x86_autogenerate_xsave_layout.c)

    # Define the path to the output file
    set(XSAVE_LAYOUT_OUTPUT ${CMAKE_BINARY_DIR}/generated/x86_fpregs_xsave_layout.h)

    # Define the custom command that runs the generator and writes the output
    add_custom_command(
        OUTPUT ${XSAVE_LAYOUT_OUTPUT}
        COMMAND autogenerate_xsave_layout > ${XSAVE_LAYOUT_OUTPUT}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating fpregs_xsave_layout.h using autogenerate_xsave_layout"
        VERBATIM
    )

    # Create a custom target to generate the xsave layout header
    add_custom_target(generate_xsave_layout ALL DEPENDS ${XSAVE_LAYOUT_OUTPUT})

    # Make sure your main target depends on the generated file
    add_dependencies(libdebug_ptrace_binding generate_xsave_layout)

    # Ensure the path to the generated file is included in the target's include directories
    target_include_directories(libdebug_ptrace_binding PRIVATE ${CMAKE_BINARY_DIR}/generated)

    # Print a message to the user
    message(STATUS "Generated xsave layout header at ${XSAVE_LAYOUT_OUTPUT}")
endif()

# Add libdebug/ptrace/native to the include directories
target_include_directories(libdebug_ptrace_binding PRIVATE libdebug/ptrace/native)

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
target_link_libraries(jumpstart)

# Install the jumpstart executable
install(TARGETS jumpstart DESTINATION libdebug/ptrace/jumpstart)
