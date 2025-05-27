# FindLibDwarf.cmake
#
# Finds the libdwarf library.
#
# This module defines the following variables:
#   LibDwarf_FOUND              - True if libdwarf was found.
#   LibDwarf_INCLUDE_DIRS       - Include directories for libdwarf. (list)
#   LibDwarf_LIBRARIES          - Link libraries for libdwarf. (list of libs/flags)
#   LibDwarf_HEADER_DIR         - Specific directory containing libdwarf.h (for checks/global include)
#   LibDwarf_VERSION            - Version of libdwarf, if found by pkg-config.
#
# It also defines the imported target:
#   LibDwarf::LibDwarf          - The libdwarf library if found.

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)

set(LibDwarf_FOUND FALSE) # Default
set(LibDwarf_INCLUDE_DIRS "")
set(LibDwarf_LIBRARIES "")
set(LibDwarf_HEADER_DIR "")

if(PkgConfig_FOUND)
    pkg_check_modules(PC_LibDwarf QUIET libdwarf)
endif()

if(PC_LibDwarf_FOUND)
    message(STATUS "FindLibDwarf: Found libdwarf via pkg-config.")
    set(LibDwarf_INCLUDE_DIRS ${PC_LibDwarf_INCLUDE_DIRS})
    set(LibDwarf_LIBRARIES ${PC_LibDwarf_LIBRARIES})
    set(LibDwarf_LDFLAGS ${PC_LibDwarf_LDFLAGS})
    set(LibDwarf_CFLAGS_OTHER ${PC_LibDwarf_CFLAGS_OTHER})
    set(LibDwarf_VERSION ${PC_LibDwarf_VERSION})

    # Determine LibDwarf_HEADER_DIR (specific path to dir containing libdwarf.h)
    if(LibDwarf_INCLUDE_DIRS)
        foreach(inc_dir ${LibDwarf_INCLUDE_DIRS})
            if(EXISTS "${inc_dir}/libdwarf.h")
                set(LibDwarf_HEADER_DIR ${inc_dir})
                break()
            endif()
        endforeach()
        if(NOT LibDwarf_HEADER_DIR) # Fallback if specific header not found in loop
             find_path(LibDwarf_HEADER_DIR_TEMP NAMES libdwarf.h HINTS ${LibDwarf_INCLUDE_DIRS} NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
             if(LibDwarf_HEADER_DIR_TEMP)
                set(LibDwarf_HEADER_DIR ${LibDwarf_HEADER_DIR_TEMP})
                # Ensure this path is also in LibDwarf_INCLUDE_DIRS if not already
                list(APPEND LibDwarf_INCLUDE_DIRS ${LibDwarf_HEADER_DIR_TEMP})
                list(REMOVE_DUPLICATES LibDwarf_INCLUDE_DIRS)
             endif()
        endif()
    endif()

    if(NOT TARGET LibDwarf::LibDwarf)
        add_library(LibDwarf::LibDwarf INTERFACE IMPORTED)
        target_include_directories(LibDwarf::LibDwarf SYSTEM INTERFACE ${LibDwarf_INCLUDE_DIRS})
        target_link_libraries(LibDwarf::LibDwarf INTERFACE ${LibDwarf_LDFLAGS})
        if(DEFINED LibDwarf_CFLAGS_OTHER AND LibDwarf_CFLAGS_OTHER)
             target_compile_options(LibDwarf::LibDwarf INTERFACE ${LibDwarf_CFLAGS_OTHER})
        endif()
    endif()
    set(LibDwarf_FOUND TRUE)
else()
    message(STATUS "FindLibDwarf: libdwarf not found via pkg-config. Trying manual search.")
    find_path(LibDwarf_MANUAL_INCLUDE_DIR NAMES libdwarf.h
              PATHS /usr/include/libdwarf-2 /usr/include/libdwarf/libdwarf-2 /usr/include/libdwarf-0 /usr/include/libdwarf/libdwarf-0 /usr/include/libdwarf
              HINTS ENV CPATH ENV C_INCLUDE_PATH ENV CPLUS_INCLUDE_PATH
              DOC "Directory containing libdwarf.h")
    find_library(LibDwarf_MANUAL_LIBRARY NAMES dwarf
                 DOC "libdwarf library")

    if(LibDwarf_MANUAL_INCLUDE_DIR AND LibDwarf_MANUAL_LIBRARY)
        message(STATUS "FindLibDwarf: Found libdwarf manually: Lib=${LibDwarf_MANUAL_LIBRARY}, HeaderDir=${LibDwarf_MANUAL_INCLUDE_DIR}")
        set(LibDwarf_INCLUDE_DIRS ${LibDwarf_MANUAL_INCLUDE_DIR})
        set(LibDwarf_LIBRARIES ${LibDwarf_MANUAL_LIBRARY}) # Full path to library
        set(LibDwarf_HEADER_DIR ${LibDwarf_MANUAL_INCLUDE_DIR})

        if(NOT TARGET LibDwarf::LibDwarf)
            add_library(LibDwarf::LibDwarf INTERFACE IMPORTED)
            target_include_directories(LibDwarf::LibDwarf SYSTEM INTERFACE ${LibDwarf_INCLUDE_DIRS})
            target_link_libraries(LibDwarf::LibDwarf INTERFACE ${LibDwarf_LIBRARIES})
        endif()
        set(LibDwarf_FOUND TRUE)
    else()
        message(STATUS "FindLibDwarf: Manual search for libdwarf failed.")
    endif()
endif()

find_package_handle_standard_args(LibDwarf
    FOUND_VAR LibDwarf_FOUND
    REQUIRED_VARS LibDwarf_LIBRARIES LibDwarf_INCLUDE_DIRS LibDwarf_HEADER_DIR
    VERSION_VAR LibDwarf_VERSION)

mark_as_advanced(LibDwarf_INCLUDE_DIRS LibDwarf_LIBRARIES LibDwarf_HEADER_DIR LibDwarf_LDFLAGS LibDwarf_CFLAGS_OTHER)

if(LibDwarf_FOUND AND NOT TARGET LibDwarf::LibDwarf)
    # This case should ideally not happen if logic above is correct
    message(WARNING "LibDwarf found but target LibDwarf::LibDwarf not created. Please check FindLibDwarf.cmake")
endif()
