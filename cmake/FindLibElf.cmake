# FindLibElf.cmake
#
# Finds the libelf library.
#
# This module defines the following variables:
#   LibElf_FOUND              - True if libelf was found.
#   LibElf_INCLUDE_DIRS       - Include directories for libelf. (list)
#   LibElf_LIBRARIES          - Link libraries for libelf. (list of libs/flags)
#   LibElf_HEADER_DIR         - Specific directory containing gelf.h (main libelf header)
#   LibElf_VERSION            - Version of libelf, if found by pkg-config.
#
# It also defines the imported target:
#   LibElf::LibElf              - The libelf library if found.

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)

set(LibElf_FOUND FALSE) # Default
set(LibElf_INCLUDE_DIRS "")
set(LibElf_LIBRARIES "")
set(LibElf_HEADER_DIR "") # Specific directory for gelf.h

if(PkgConfig_FOUND)
    pkg_check_modules(PC_LibElf QUIET libelf)
endif()

if(PC_LibElf_FOUND)
    message(STATUS "FindLibElf: Found libelf via pkg-config.")
    set(LibElf_INCLUDE_DIRS ${PC_LibElf_INCLUDE_DIRS})
    set(LibElf_LIBRARIES ${PC_LibElf_LIBRARIES})
    set(LibElf_LDFLAGS ${PC_LibElf_LDFLAGS})
    set(LibElf_CFLAGS_OTHER ${PC_LibElf_CFLAGS_OTHER})
    set(LibElf_VERSION ${PC_LibElf_VERSION})

    # Determine LibElf_HEADER_DIR (specific path to dir containing gelf.h)
    if(LibElf_INCLUDE_DIRS)
        foreach(inc_dir ${LibElf_INCLUDE_DIRS})
            if(EXISTS "${inc_dir}/gelf.h") # gelf.h is a common primary header for libelf
                set(LibElf_HEADER_DIR ${inc_dir})
                break()
            elseif(EXISTS "${inc_dir}/libelf.h") # Also check for libelf.h
                 set(LibElf_HEADER_DIR ${inc_dir})
                 break()
            endif()
        endforeach()
        if(NOT LibElf_HEADER_DIR) # Fallback if specific header not found in loop
             find_path(LibElf_HEADER_DIR_TEMP NAMES gelf.h libelf.h HINTS ${LibElf_INCLUDE_DIRS} NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
             if(LibElf_HEADER_DIR_TEMP)
                set(LibElf_HEADER_DIR ${LibElf_HEADER_DIR_TEMP})
                list(APPEND LibElf_INCLUDE_DIRS ${LibElf_HEADER_DIR_TEMP})
                list(REMOVE_DUPLICATES LibElf_INCLUDE_DIRS)
             endif()
        endif()
    endif()

    if(NOT TARGET LibElf::LibElf)
        add_library(LibElf::LibElf INTERFACE IMPORTED)
        target_include_directories(LibElf::LibElf SYSTEM INTERFACE ${LibElf_INCLUDE_DIRS})
        target_link_libraries(LibElf::LibElf INTERFACE ${LibElf_LDFLAGS})
        if(DEFINED LibElf_CFLAGS_OTHER AND LibElf_CFLAGS_OTHER)
             target_compile_options(LibElf::LibElf INTERFACE ${LibElf_CFLAGS_OTHER})
        endif()
    endif()
    set(LibElf_FOUND TRUE)
else()
    message(STATUS "FindLibElf: libelf not found via pkg-config. Trying manual search.")
    find_path(LibElf_MANUAL_INCLUDE_DIR NAMES gelf.h libelf.h # Common headers for libelf
              PATHS /usr/include /usr/include/elfutils
              HINTS ENV CPATH ENV C_INCLUDE_PATH ENV CPLUS_INCLUDE_PATH
              DOC "Directory containing libelf headers (gelf.h or libelf.h)")
    find_library(LibElf_MANUAL_LIBRARY NAMES elf
                 DOC "libelf library")

    if(LibElf_MANUAL_INCLUDE_DIR AND LibElf_MANUAL_LIBRARY)
        message(STATUS "FindLibElf: Found libelf manually: Lib=${LibElf_MANUAL_LIBRARY}, HeaderDir=${LibElf_MANUAL_INCLUDE_DIR}")
        set(LibElf_INCLUDE_DIRS ${LibElf_MANUAL_INCLUDE_DIR})
        set(LibElf_LIBRARIES ${LibElf_MANUAL_LIBRARY})
        set(LibElf_HEADER_DIR ${LibElf_MANUAL_INCLUDE_DIR})

        if(NOT TARGET LibElf::LibElf)
            add_library(LibElf::LibElf INTERFACE IMPORTED)
            target_include_directories(LibElf::LibElf SYSTEM INTERFACE ${LibElf_INCLUDE_DIRS})
            target_link_libraries(LibElf::LibElf INTERFACE ${LibElf_LIBRARIES})
        endif()
        set(LibElf_FOUND TRUE)
    else()
        message(STATUS "FindLibElf: Manual search for libelf failed.")
    endif()
endif()

find_package_handle_standard_args(LibElf
    FOUND_VAR LibElf_FOUND
    REQUIRED_VARS LibElf_LIBRARIES LibElf_INCLUDE_DIRS LibElf_HEADER_DIR
    VERSION_VAR LibElf_VERSION)

mark_as_advanced(LibElf_INCLUDE_DIRS LibElf_LIBRARIES LibElf_HEADER_DIR LibElf_LDFLAGS LibElf_CFLAGS_OTHER)

if(LibElf_FOUND AND NOT TARGET LibElf::LibElf)
    message(WARNING "LibElf found but target LibElf::LibElf not created. Please check FindLibElf.cmake")
endif()
