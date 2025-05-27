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

# Determine the correct linker flags/libraries for the checks
set(CMAKE_REQUIRED_LIBRARIES_FOR_CHECK "")
if(DEFINED LibDwarf_LDFLAGS AND LibDwarf_LDFLAGS) # LDFLAGS is comprehensive if pkg-config was used
    set(CMAKE_REQUIRED_LIBRARIES_FOR_CHECK ${LibDwarf_LDFLAGS})
elseif(DEFINED LibDwarf_LIBRARIES AND LibDwarf_LIBRARIES) # Full path if manual, or bare names
    set(CMAKE_REQUIRED_LIBRARIES_FOR_CHECK ${LibDwarf_LIBRARIES})
else()
    message(WARNING "DetectLibDwarfAPI: Could not determine linker items for libdwarf API check (LibDwarf_LDFLAGS and LibDwarf_LIBRARIES are empty). API detection may fail or be inaccurate.")
endif()
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES_FOR_CHECK})


if(DEFINED LibDwarf_CFLAGS_OTHER AND LibDwarf_CFLAGS_OTHER)
    set(CMAKE_REQUIRED_FLAGS "${LibDwarf_CFLAGS_OTHER}")
else()
    set(CMAKE_REQUIRED_FLAGS "")
endif()

message(STATUS "DetectLibDwarfAPI: Performing API symbol checks for libdwarf.")

# Perform individual symbol checks
check_symbol_exists(dwarf_next_cu_header_d "libdwarf.h;dwarf.h" INTERNAL_HAS_dwarf_next_cu_header_d)
check_symbol_exists(dwarf_siblingof_b      "libdwarf.h;dwarf.h" INTERNAL_HAS_dwarf_siblingof_b)
check_symbol_exists(dwarf_init_b           "libdwarf.h;dwarf.h" INTERNAL_HAS_dwarf_init_b)

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

# Set LibDwarf_HAS_NEW_API to TRUE only if all three symbols are present
if(INTERNAL_HAS_dwarf_next_cu_header_d AND
   INTERNAL_HAS_dwarf_siblingof_b      AND
   INTERNAL_HAS_dwarf_init_b)
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
