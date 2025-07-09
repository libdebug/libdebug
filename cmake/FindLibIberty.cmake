# FindLibIberty.cmake
#
# Finds the libiberty library.
#
# This module defines the following variables:
#   LibIberty_FOUND                 - True if libiberty was found.
#   LibIberty_INCLUDE_DIRS          - Include directories for libiberty. (list)
#   LibIberty_LIBRARIES             - Link libraries for libiberty. (list of libs/flags)
#   LibIberty_DEMANGLE_HEADER_DIR   - Specific directory containing demangle.h (for global include)
#   LibIberty_VERSION               - Version of libiberty, if found by pkg-config.
#
# It also defines the imported target:
#   LibIberty::LibIberty            - The libiberty library if found.

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)

set(LibIberty_FOUND FALSE) # Default
set(LibIberty_INCLUDE_DIRS "")
set(LibIberty_LIBRARIES "")
set(LibIberty_DEMANGLE_HEADER_DIR "") # Specific directory for demangle.h

if(PkgConfig_FOUND)
    pkg_check_modules(PC_LibIberty QUIET libiberty) # Try common names
endif()

if(PC_LibIberty_FOUND)
    message(STATUS "FindLibIberty: Found libiberty via pkg-config.")
    set(LibIberty_INCLUDE_DIRS ${PC_LibIberty_INCLUDE_DIRS})
    set(LibIberty_LIBRARIES ${PC_LibIberty_LIBRARIES})
    set(LibIberty_LDFLAGS ${PC_LibIberty_LDFLAGS})
    set(LibIberty_CFLAGS_OTHER ${PC_LibIberty_CFLAGS_OTHER})
    set(LibIberty_VERSION ${PC_LibIberty_VERSION})

    # Determine LibIberty_DEMANGLE_HEADER_DIR
    if(LibIberty_INCLUDE_DIRS)
        foreach(inc_dir ${LibIberty_INCLUDE_DIRS})
            if(EXISTS "${inc_dir}/demangle.h")
                set(LibIberty_DEMANGLE_HEADER_DIR ${inc_dir})
                break()
            elseif(EXISTS "${inc_dir}/libiberty/demangle.h") # Common alternative path
                set(LibIberty_DEMANGLE_HEADER_DIR "${inc_dir}/libiberty")
                # Ensure the base path is also in include dirs for the target
                # list(APPEND LibIberty_INCLUDE_DIRS ${inc_dir})
                # list(REMOVE_DUPLICATES LibIberty_INCLUDE_DIRS)
                break()
            endif()
        endforeach()
        if(NOT LibIberty_DEMANGLE_HEADER_DIR) # Fallback
             find_path(LibIberty_DEMANGLE_HEADER_DIR_TEMP NAMES demangle.h PATH_SUFFIXES libiberty HINTS ${LibIberty_INCLUDE_DIRS} NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
             if(LibIberty_DEMANGLE_HEADER_DIR_TEMP)
                set(LibIberty_DEMANGLE_HEADER_DIR ${LibIberty_DEMANGLE_HEADER_DIR_TEMP})
                list(APPEND LibIberty_INCLUDE_DIRS ${LibIberty_DEMANGLE_HEADER_DIR_TEMP})
                list(REMOVE_DUPLICATES LibIberty_INCLUDE_DIRS)
             endif()
        endif()
    endif()

    if(NOT TARGET LibIberty::LibIberty)
        add_library(LibIberty::LibIberty INTERFACE IMPORTED)
        target_include_directories(LibIberty::LibIberty SYSTEM INTERFACE ${LibIberty_INCLUDE_DIRS})
        target_link_libraries(LibIberty::LibIberty INTERFACE ${LibIberty_LDFLAGS})
        if(DEFINED LibIberty_CFLAGS_OTHER AND LibIberty_CFLAGS_OTHER)
             target_compile_options(LibIberty::LibIberty INTERFACE ${LibIberty_CFLAGS_OTHER})
        endif()
    endif()
    set(LibIberty_FOUND TRUE)
else()
    message(STATUS "FindLibIberty: libiberty not found via pkg-config. Trying manual search.")
    find_path(LibIberty_MANUAL_INCLUDE_DIR NAMES demangle.h
              PATHS /usr/include/libiberty
              PATH_SUFFIXES libiberty
              HINTS ENV CPATH ENV C_INCLUDE_PATH ENV CPLUS_INCLUDE_PATH
              DOC "Directory containing demangle.h")
    find_library(LibIberty_MANUAL_LIBRARY NAMES iberty
                 DOC "libiberty library")

    if(LibIberty_MANUAL_INCLUDE_DIR AND LibIberty_MANUAL_LIBRARY)
        message(STATUS "FindLibIberty: Found libiberty manually: Lib=${LibIberty_MANUAL_LIBRARY}, HeaderDir=${LibIberty_MANUAL_INCLUDE_DIR}")
        set(LibIberty_INCLUDE_DIRS ${LibIberty_MANUAL_INCLUDE_DIR})
        set(LibIberty_LIBRARIES ${LibIberty_MANUAL_LIBRARY})
        set(LibIberty_DEMANGLE_HEADER_DIR ${LibIberty_MANUAL_INCLUDE_DIR})

        if(NOT TARGET LibIberty::LibIberty)
            add_library(LibIberty::LibIberty INTERFACE IMPORTED)
            target_include_directories(LibIberty::LibIberty SYSTEM INTERFACE ${LibIberty_INCLUDE_DIRS})
            target_link_libraries(LibIberty::LibIberty INTERFACE ${LibIberty_LIBRARIES})
        endif()
        set(LibIberty_FOUND TRUE)
    else()
        message(STATUS "FindLibIberty: Manual search for libiberty failed.")
    endif()
endif()

find_package_handle_standard_args(LibIberty
    FOUND_VAR LibIberty_FOUND
    REQUIRED_VARS LibIberty_LIBRARIES LibIberty_INCLUDE_DIRS LibIberty_DEMANGLE_HEADER_DIR
    VERSION_VAR LibIberty_VERSION)

mark_as_advanced(LibIberty_INCLUDE_DIRS LibIberty_LIBRARIES LibIberty_DEMANGLE_HEADER_DIR LibIberty_LDFLAGS LibIberty_CFLAGS_OTHER)

if(LibIberty_FOUND AND NOT TARGET LibIberty::LibIberty)
    message(WARNING "LibIberty found but target LibIberty::LibIberty not created. Please check FindLibIberty.cmake")
endif()
