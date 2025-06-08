# CheckLibIberty.cmake
#
# Checks if a specific usage of cplus_demangle_v3 from libiberty compiles
# by attempting to build a test project located in ./libiberty/.
#
# This module expects that FindLibIberty.cmake has already been run and
# the following variables are available from its scope or globally:
#   LibIberty_FOUND          - TRUE if libiberty was found by FindLibIberty.cmake
#   LibIberty_INCLUDE_DIRS   - Include directories for libiberty
#   LibIberty_LIBRARIES      - Link information for libiberty
#                              (Alternatively, LibIberty_LDFLAGS or LibIberty::LibIberty)
#
# It defines the following variable in the current (includer's) scope:
#   LibIberty_CPLUS_DEMANGLE_V3_COMPILES - TRUE if the test project compiles, FALSE otherwise.

if(NOT LibIberty_FOUND)
    message(STATUS "CheckLibIberty: LibIberty not found. Skipping cplus_demangle_v3 project compile check.")
    set(LibIberty_CPLUS_DEMANGLE_V3_COMPILES FALSE PARENT_SCOPE) # Ensure variable is defined in parent
    return()
endif()

set(LibIberty_CPLUS_DEMANGLE_V3_COMPILES FALSE) # Default

# --- Setup for project-level try_compile ---
set(SUBPROJECT_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/libiberty")
set(SUBPROJECT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/CheckLibIberty_TryCompileProject")

if(NOT EXISTS "${SUBPROJECT_SOURCE_DIR}/CMakeLists.txt")
    message(ERROR "CheckLibIberty: Test project directory '${SUBPROJECT_SOURCE_DIR}' or its CMakeLists.txt not found.")
    set(LibIberty_CPLUS_DEMANGLE_V3_COMPILES FALSE PARENT_SCOPE)
    return()
endif()

# Clean the binary directory for a fresh build attempt
file(REMOVE_RECURSE "${SUBPROJECT_BINARY_DIR}")
file(MAKE_DIRECTORY "${SUBPROJECT_BINARY_DIR}")

message(STATUS "CheckLibIberty: Attempting to compile test project in ${SUBPROJECT_SOURCE_DIR}")
message(STATUS "CheckLibIberty: Using binary directory ${SUBPROJECT_BINARY_DIR}")

# Perform the try_compile for the subproject
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL 3.27)
    try_compile(
        INTERNAL_CPLUS_DEMANGLE_V3_COMPILES_RESULT
        PROJECT    LibIbertyDemangleTest
        SOURCE_DIR "${SUBPROJECT_SOURCE_DIR}"
        BINARY_DIR "${SUBPROJECT_BINARY_DIR}"
    )
else()
    # Older CMake:     try_compile(<result> <binary-dir> <source-dir> [<project> …])
    try_compile(
        INTERNAL_CPLUS_DEMANGLE_V3_COMPILES_RESULT
        "${SUBPROJECT_BINARY_DIR}"
        "${SUBPROJECT_SOURCE_DIR}"
        LibIbertyDemangleTest
    )
endif()

if(INTERNAL_CPLUS_DEMANGLE_V3_COMPILES_RESULT)
    set(LibIberty_CPLUS_DEMANGLE_V3_COMPILES TRUE)
    message(STATUS "CheckLibIberty: Test project for cplus_demangle_v3 compiled successfully.")
else()
    # LibIberty_CPLUS_DEMANGLE_V3_COMPILES remains FALSE (its default)
    message(WARNING "CheckLibIberty: Test project for cplus_demangle_v3 FAILED to compile.")
    message(WARNING "CheckLibIberty: Build log from subproject try_compile:\n${TRY_COMPILE_OUTPUT_LOG}")
endif()

set(LibIberty_CPLUS_DEMANGLE_V3_COMPILES ${LibIberty_CPLUS_DEMANGLE_V3_COMPILES})
