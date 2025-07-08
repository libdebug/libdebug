# Set the minimum CMake version and policies for the highest tested version
cmake_minimum_required(VERSION 3.15)

# Set the project name and version
project(libdebug LANGUAGES CXX C)

# Add the cmake directory to the module path so Find<LibName>.cmake can be found
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Add the options to disable libdwarf and libelf
option(USE_LIBDWARF "Enable usage of libdwarf and its features" ON)
option(USE_LIBELF "Enable usage of libelf and its features" ON)

# Add the option to disable libiberty
option(USE_LIBIBERTY "Enable usage of libiberty and its features" ON)

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

if (NOT USE_LIBELF OR NOT USE_LIBDWARF)
  message(WARNING "Disabling libdwarf and/or libelf will disable all features that depend on them, including symbol parsing and C++ demangling.")
  set(BUILD_SYMBOLS OFF CACHE BOOL "Build symbol parsing features" FORCE)
else()
  set(BUILD_SYMBOLS ON CACHE BOOL "Build symbol parsing features" FORCE)
  message(STATUS "Building with libdwarf and libelf support enabled.")
endif()

if(BUILD_SYMBOLS)
  # Find required libraries using the custom Find modules
  find_package(LibDwarf REQUIRED)
  find_package(LibElf REQUIRED)
  find_package(LibIberty REQUIRED)

  # Check which API version of libdwarf is available
  if(LibDwarf_FOUND)
      include(cmake/DetectLibDwarfAPI.cmake)
  endif()

  # Check if we can actually compile with libiberty
  # (Alpine Linux doesn't work here)
  if(LibIberty_FOUND)
      include(cmake/CheckLibIberty.cmake)
  endif()

  # If we can use libiberty, we can set a define flag to enable C++ demangling
  if(USE_LIBIBERTY AND LibIberty_CPLUS_DEMANGLE_V3_COMPILES)
    add_definitions(-DHAS_LIBIBERTY)
  else()
    message(WARNING "Cannot use libiberty to demangle C++ symbols.")
  endif()

  # Global include directories based on variables set by Find modules
  # These are for code that might not directly link the targets or for specific checks.
  # Targets LibDwarf::LibDwarf etc. will carry their own include directories.
  if(LibDwarf_HEADER_DIR)
      message(STATUS "Adding global include directory for libdwarf: ${LibDwarf_HEADER_DIR}")
      include_directories(${LibDwarf_HEADER_DIR})
  else()
      # This should have been caught by REQUIRED_VARS in FindLibDwarf.cmake if find_package was REQUIRED
      message(FATAL_ERROR "LibDwarf_HEADER_DIR was not set by FindLibDwarf.cmake.")
  endif()

  if(LibIberty_DEMANGLE_HEADER_DIR)
      message(STATUS "Adding global include directory for demangle.h (libiberty): ${LibIberty_DEMANGLE_HEADER_DIR}")
      include_directories(${LibIberty_DEMANGLE_HEADER_DIR})
      find_file(DEMANGLE_H_FULL_PATH_CHECK demangle.h HINTS ${LibIberty_DEMANGLE_HEADER_DIR} NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
      if(NOT DEMANGLE_H_FULL_PATH_CHECK)
        message(WARNING "demangle.h was not confirmed at the resolved LibIberty_DEMANGLE_HEADER_DIR path: ${LibIberty_DEMANGLE_HEADER_DIR}.")
      else()
          message(STATUS "demangle.h confirmed at ${DEMANGLE_H_FULL_PATH_CHECK}")
      endif()
  else()
      message(FATAL_ERROR "LibIberty_DEMANGLE_HEADER_DIR was not set by FindLibIberty.cmake.")
  endif()

  add_definitions(-DHAS_SYMBOL_SUPPORT)
endif()

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
  libdebug/ptrace/native/utils.cpp
)

# Print the architecture
message(STATUS "Detected Architecture: ${CMAKE_SYSTEM_PROCESSOR}")

# Add the architecture-specific sources for amd64
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/amd64/amd64_ptrace.cpp)
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/shared/x86_ptrace.cpp)
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/shared/x86_fp_regs.cpp)

  # Add a definition for the x86_64 architecture
  add_definitions(-DARCH_X86_64)
endif()

# Add the architecture-specific sources for i386
if (CMAKE_SYSTEM_PROCESSOR MATCHES "i386" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686" OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86" AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/i386/i386_ptrace.cpp)
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/shared/x86_ptrace.cpp)
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/shared/x86_fp_regs.cpp)

  # Add a definition for the i386 architecture
  add_definitions(-DARCH_X86)
endif()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  list(APPEND LIBDEBUG_PTRACE_BINDING_SOURCES libdebug/ptrace/native/aarch64/aarch64_ptrace.cpp)

  # Add a definition for the ARM architecture
  add_definitions(-DARCH_AARCH64)
endif()

# Add the libdebug_ptrace_binding module
nanobind_add_module(
  libdebug_ptrace_binding
  LTO
  STABLE_ABI
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
  LTO
  STABLE_ABI
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

if(BUILD_SYMBOLS)
  # Check if the new libdwarf API is available
  if (LibDwarf_HAS_NEW_API)
    message(STATUS "Using new libdwarf API")

    add_library(libdebug_sym_parser_lib STATIC
      libdebug/native/symbols/debug_sym_parser.cpp
      libdebug/native/symbols/debug_sym_parser_new.cpp
    )
  else()
    message(STATUS "Using legacy libdwarf API")

    add_library(libdebug_sym_parser_lib STATIC
      libdebug/native/symbols/debug_sym_parser.cpp
      libdebug/native/symbols/debug_sym_parser_legacy.cpp
    )
  endif()

  set_target_properties(libdebug_sym_parser_lib PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
  )

  target_link_libraries(libdebug_sym_parser_lib PRIVATE LibElf::LibElf LibDwarf::LibDwarf LibIberty::LibIberty)

  nanobind_add_module(
    libdebug_debug_sym_parser
    LTO
    STABLE_ABI
    libdebug/native/symbols/debug_sym_parser_shared.cpp
  )
else()
  # We build a dummy module that does not depend on libdwarf or libelf
  nanobind_add_module(
    libdebug_debug_sym_parser
    LTO
    STABLE_ABI
    libdebug/native/symbols/debug_sym_parser_dummy.cpp
    libdebug/native/symbols/debug_sym_parser_shared.cpp
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

# Add libdebug/ptrace/native to the include directories
target_include_directories(libdebug_ptrace_binding PRIVATE libdebug/ptrace/native)

# Add libdebug/ptrace/native/shared to the include directories
target_include_directories(libdebug_ptrace_binding PRIVATE libdebug/ptrace/native/shared)

# Link required libraries using the imported targets from Find modules
if(BUILD_SYMBOLS)
  target_link_libraries(libdebug_debug_sym_parser PRIVATE libdebug_sym_parser_lib)
endif()

# Install the binding libraries
install(TARGETS libdebug_ptrace_binding LIBRARY DESTINATION libdebug/ptrace/native)
install(TARGETS libdebug_linux_binding LIBRARY DESTINATION libdebug/native)
install(TARGETS libdebug_debug_sym_parser LIBRARY DESTINATION libdebug/native)

# Install the Python stubs
install(FILES ${CMAKE_BINARY_DIR}/libdebug_ptrace_binding.pyi DESTINATION libdebug/ptrace/native)
install(FILES ${CMAKE_BINARY_DIR}/libdebug_linux_binding.pyi DESTINATION libdebug/native)
install(FILES ${CMAKE_BINARY_DIR}/libdebug_debug_sym_parser.pyi DESTINATION libdebug/native)

# Include the jumpstart.c file and add it as an executable
set(SRC_DIR "${CMAKE_SOURCE_DIR}/libdebug/ptrace/jumpstart")
set(SOURCES "${SRC_DIR}/jumpstart.c")

# If architecture is amd64 or i386
if (CMAKE_SYSTEM_PROCESSOR MATCHES "i386"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")
  # Build and include x86_autodetect_fpregs_layout.c
  set(X86_SRC_DIR "${CMAKE_SOURCE_DIR}/libdebug/ptrace/native/shared/")
  set(X86_SOURCES "${X86_SRC_DIR}/x86_autodetect_fpregs_layout.c")
  add_executable(autodetect_fpregs_layout ${X86_SOURCES})
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  # We build and include aarch64_autodetect_fpregs_layout.c, which does nothing
  set(AARCH64_SRC_DIR "${CMAKE_SOURCE_DIR}/libdebug/ptrace/native/aarch64/")
  set(AARCH64_SOURCES "${AARCH64_SRC_DIR}/aarch64_autodetect_fpregs_layout.c")
  add_executable(autodetect_fpregs_layout ${AARCH64_SOURCES})
else()
  # What architecture is this? We don't know how to handle it.
  message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}. Please open an issue on GitHub if you see this.")
endif()

# Add the jumpstart executable
add_executable(jumpstart ${SOURCES})
target_link_libraries(jumpstart)

# Install the jumpstart executable
install(TARGETS jumpstart DESTINATION libdebug/ptrace/jumpstart)

# Install the autodetect_fpregs_layout executable
install(TARGETS autodetect_fpregs_layout DESTINATION libdebug/ptrace/native)
