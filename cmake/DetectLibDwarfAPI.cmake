# DetectLibDwarfAPI.cmake
#
# This script detects if the found libdwarf library supports the "new" API,
# defined by the simultaneous presence of dwarf_next_cu_header_d,
# dwarf_siblingof_b, AND dwarf_init_b.
#
# It expects the following variables to be set before it's included, typically
# by FindLibDwarf.cmake:
#   LibDwarf_FOUND           - Must be TRUE
#   LibDwarf_INCLUDE_DIRS    - Include directories for libdwarf
#   LibDwarf_LIBRARIES       - Linkable item(s) for libdwarf (e.g. full path if manual, or names if pkg-config)
#   LibDwarf_LDFLAGS         - All linker flags from pkg-config (preferred for linking if available)
#   LibDwarf_CFLAGS_OTHER    - Other C flags from pkg-config (if any)
#
# It sets the following variable in the PARENT_SCOPE:
#   LibDwarf_HAS_NEW_API     - TRUE if all three specified symbols are detected, FALSE otherwise.

if(NOT LibDwarf_FOUND)
    message(FATAL_ERROR "DetectLibDwarfAPI.cmake called but LibDwarf was not found. Ensure FindLibDwarf runs successfully first.")
endif()

include(CheckSymbolExists)

set(LibDwarf_HAS_NEW_API FALSE) # Default in parent scope

# Store original CMAKE_REQUIRED_ variables and restore them
set(CMAKE_REQUIRED_LIBRARIES_OLD ${CMAKE_REQUIRED_LIBRARIES})
set(CMAKE_REQUIRED_FLAGS_OLD ${CMAKE_REQUIRED_FLAGS})
set(CMAKE_REQUIRED_INCLUDES_OLD ${CMAKE_REQUIRED_INCLUDES})

set(CMAKE_REQUIRED_INCLUDES ${LibDwarf_INCLUDE_DIRS})

# Initialize CMAKE_REQUIRED_FLAGS with CFLAGS from pkg-config if available
if(DEFINED LibDwarf_CFLAGS_OTHER AND LibDwarf_CFLAGS_OTHER)
    set(CMAKE_REQUIRED_FLAGS "${LibDwarf_CFLAGS_OTHER}")
else()
    set(CMAKE_REQUIRED_FLAGS "")
endif()

# Determine the correct linker flags/libraries for the checks
set(CMAKE_REQUIRED_LIBRARIES "")

set(LINK_DIRS "")
set(LINK_LIBS "")
set(COMPILE_FLAGS "")

if(DEFINED LibDwarf_LDFLAGS AND LibDwarf_LDFLAGS)
    # Treat the variable as a proper CMake list and loop through each item
    foreach(flag ${LibDwarf_LDFLAGS})
        if(flag MATCHES "^-L")
            list(APPEND LINK_DIRS ${flag})
        elseif(flag MATCHES "^-l(.+)")
            list(APPEND LINK_LIBS ${CMAKE_MATCH_1})
        else()
            # Anything else is considered a compile flag (e.g., -gnu)
            list(APPEND COMPILE_FLAGS ${flag})
        endif()
    endforeach()

    # Add compile flags to CMAKE_REQUIRED_FLAGS
    if(COMPILE_FLAGS)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${COMPILE_FLAGS}")
    endif()

    # Add library directories to CMAKE_REQUIRED_FLAGS (they need to be compile flags)
    foreach(link_dir ${LINK_DIRS})
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${link_dir}")
    endforeach()

    # Add libraries to CMAKE_REQUIRED_LIBRARIES
    if(LINK_LIBS)
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${LINK_LIBS})
    endif()

    # Clean up CMAKE_REQUIRED_FLAGS
    string(STRIP "${CMAKE_REQUIRED_FLAGS}" CMAKE_REQUIRED_FLAGS)

elseif(DEFINED LibDwarf_LIBRARIES AND LibDwarf_LIBRARIES)
    # Manual configuration, LibDwarf_LIBRARIES might be full paths or just names
    set(CMAKE_REQUIRED_LIBRARIES ${LibDwarf_LIBRARIES})
else()
    message(WARNING "DetectLibDwarfAPI: Could not determine linker items for libdwarf API check (LibDwarf_LDFLAGS and LibDwarf_LIBRARIES are empty). API detection may fail or be inaccurate.")
endif()

# Add required dependencies for libdwarf (zlib and zstd are commonly needed)
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(ZLIB QUIET zlib)
    if(ZLIB_FOUND)
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${ZLIB_LIBRARIES})
        list(JOIN ZLIB_LDFLAGS " " ZLIB_REQUIRED_FLAGS)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${ZLIB_REQUIRED_FLAGS}")
    else()
        # Fallback to standard library names
        list(APPEND CMAKE_REQUIRED_LIBRARIES z)
    endif()

    pkg_check_modules(ZSTD QUIET libzstd)
    if(ZSTD_FOUND)
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${ZSTD_LIBRARIES})
        list(JOIN ZSTD_LDFLAGS " " ZSTD_REQUIRED_FLAGS)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${ZSTD_REQUIRED_FLAGS}")
    else()
        # Fallback to standard library names
        list(APPEND CMAKE_REQUIRED_LIBRARIES zstd)
    endif()
else()
    # Fallback when pkg-config is not available
    list(APPEND CMAKE_REQUIRED_LIBRARIES z zstd)
endif()

# Clean up CMAKE_REQUIRED_FLAGS
string(STRIP "${CMAKE_REQUIRED_FLAGS}" CMAKE_REQUIRED_FLAGS)

# Remove duplicates and clean up
if(CMAKE_REQUIRED_LIBRARIES)
    list(REMOVE_DUPLICATES CMAKE_REQUIRED_LIBRARIES)
endif()

message(STATUS "DetectLibDwarfAPI: Performing API symbol checks for libdwarf.")
message(STATUS "DetectLibDwarfAPI: CMAKE_REQUIRED_INCLUDES = ${CMAKE_REQUIRED_INCLUDES}")
message(STATUS "DetectLibDwarfAPI: CMAKE_REQUIRED_LIBRARIES = ${CMAKE_REQUIRED_LIBRARIES}")
message(STATUS "DetectLibDwarfAPI: CMAKE_REQUIRED_FLAGS = ${CMAKE_REQUIRED_FLAGS}")

# Debug: Check if headers exist
foreach(include_dir ${CMAKE_REQUIRED_INCLUDES})
    if(EXISTS "${include_dir}/libdwarf.h")
        message(STATUS "DetectLibDwarfAPI: Found libdwarf.h in ${include_dir}")
    endif()
    if(EXISTS "${include_dir}/dwarf.h")
        message(STATUS "DetectLibDwarfAPI: Found dwarf.h in ${include_dir}")
    endif()
endforeach()

# Debug: Test basic compilation
file(WRITE "${CMAKE_BINARY_DIR}/CMakeTmp/test_basic.c" "
#include <libdwarf.h>
int main() { return 0; }
")

try_compile(BASIC_COMPILE_TEST
    "${CMAKE_BINARY_DIR}/CMakeTmp"
    "${CMAKE_BINARY_DIR}/CMakeTmp/test_basic.c"
    COMPILE_DEFINITIONS ${CMAKE_REQUIRED_FLAGS}
    CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${CMAKE_REQUIRED_INCLUDES}"
    OUTPUT_VARIABLE BASIC_TEST_OUTPUT
)

message(STATUS "DetectLibDwarfAPI: Basic libdwarf compile test: ${BASIC_COMPILE_TEST}")
if(NOT BASIC_COMPILE_TEST)
    message(STATUS "DetectLibDwarfAPI: Basic test failed: ${BASIC_TEST_OUTPUT}")
endif()

# Try different header combinations for different libdwarf versions
set(HEADER_COMBINATIONS
    "libdwarf.h"
    "dwarf.h"
    "libdwarf.h;dwarf.h"
    "dwarf.h;libdwarf.h"
)

set(FOUND_WORKING_HEADERS "")
foreach(headers ${HEADER_COMBINATIONS})
    check_symbol_exists(dwarf_next_cu_header_d "${headers}" TEST_HEADERS_${headers})
    if(TEST_HEADERS_${headers})
        set(FOUND_WORKING_HEADERS "${headers}")
        message(STATUS "DetectLibDwarfAPI: Using headers: ${headers}")
        break()
    endif()
endforeach()

if(NOT FOUND_WORKING_HEADERS)
    message(STATUS "DetectLibDwarfAPI: Could not find working header combination, using default")
    set(FOUND_WORKING_HEADERS "libdwarf.h;dwarf.h")
endif()

# Perform individual symbol checks with the working headers
check_symbol_exists(dwarf_next_cu_header_d "${FOUND_WORKING_HEADERS}" INTERNAL_HAS_dwarf_next_cu_header_d)
check_symbol_exists(dwarf_siblingof_b      "${FOUND_WORKING_HEADERS}" INTERNAL_HAS_dwarf_siblingof_b)
check_symbol_exists(dwarf_init_b           "${FOUND_WORKING_HEADERS}" INTERNAL_HAS_dwarf_init_b)

# Log individual findings (optional, but good for debugging)
if(INTERNAL_HAS_dwarf_next_cu_header_d)
    message(STATUS "DetectLibDwarfAPI: Found symbol: dwarf_next_cu_header_d")
else()
    message(STATUS "DetectLibDwarfAPI: Did not find symbol: dwarf_next_cu_header_d")
endif()
if(INTERNAL_HAS_dwarf_siblingof_b)
    message(STATUS "DetectLibDwarfAPI: Found symbol: dwarf_siblingof_b")
else()
    message(STATUS "DetectLibDwarfAPI: Did not find symbol: dwarf_siblingof_b")
endif()
if(INTERNAL_HAS_dwarf_init_b)
    message(STATUS "DetectLibDwarfAPI: Found symbol: dwarf_init_b")
else()
    message(STATUS "DetectLibDwarfAPI: Did not find symbol: dwarf_init_b")
endif()

# --- 2. Test if dwarf_finish(NULL) compiles ---
# In new API versions, dwarf_finish takes just a single argument
# Old versions take multiple arguments, so we check if it compiles with NULL.

# Build the header include string properly
set(HEADER_INCLUDES "")
foreach(header ${FOUND_WORKING_HEADERS})
    set(HEADER_INCLUDES "${HEADER_INCLUDES}#include <${header}>\n")
endforeach()

set(TEST_DWARF_FINISH_NULL_SOURCE "
${HEADER_INCLUDES}#include <stdio.h>

int main(void) {
    /* We only care if this specific call compiles. */
    dwarf_finish( NULL );
    return 0;
}")

file(WRITE "${CMAKE_BINARY_DIR}/CMakeTmp/test_dwarf_finish_null.c" "${TEST_DWARF_FINISH_NULL_SOURCE}")

try_compile(
    INTERNAL_DWARF_FINISH_NULL_COMPILES
    "${CMAKE_BINARY_DIR}/CMakeTmp" # Binary directory
    "${CMAKE_BINARY_DIR}/CMakeTmp/test_dwarf_finish_null.c" # Source file
    COMPILE_DEFINITIONS ${CMAKE_REQUIRED_FLAGS}
    CMAKE_FLAGS
        "-DINCLUDE_DIRECTORIES=${CMAKE_REQUIRED_INCLUDES}"
        "-DLINK_LIBRARIES=${CMAKE_REQUIRED_LIBRARIES}"
    OUTPUT_VARIABLE TRY_COMPILE_OUTPUT_FINISH_NULL
)

if(INTERNAL_DWARF_FINISH_NULL_COMPILES)
    set(LibDwarf_FINISH_NULL_COMPILES TRUE)
    message(STATUS "DetectLibDwarfAPI: dwarf_finish takes a single parameter.")
else()
    # LibDwarf_FINISH_NULL_COMPILES remains FALSE (its default)
    message(STATUS "DetectLibDwarfAPI: dwarf_finish takes multiple parameters.")
    message(STATUS "DetectLibDwarfAPI: Compile output: ${TRY_COMPILE_OUTPUT_FINISH_NULL}")
endif()

# Set LibDwarf_HAS_NEW_API to TRUE only if all three symbols are present
if(INTERNAL_HAS_dwarf_next_cu_header_d AND
   INTERNAL_HAS_dwarf_siblingof_b      AND
   INTERNAL_HAS_dwarf_init_b           AND
   INTERNAL_DWARF_FINISH_NULL_COMPILES)
    set(LibDwarf_HAS_NEW_API TRUE)
    message(STATUS "DetectLibDwarfAPI: Detected new libdwarf API.")
else()
    # LibDwarf_HAS_NEW_API remains FALSE (its default)
    message(STATUS "DetectLibDwarfAPI: Detected legacy libdwarf API (missing one or more symbols).")
endif()

# Restore original CMAKE_REQUIRED_ variables
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES_OLD})
set(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS_OLD})
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_OLD})
