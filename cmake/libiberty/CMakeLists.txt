# In ./libiberty/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(LibIbertyDemangleTest LANGUAGES CXX)

# Add the parent directory to the include path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/..")

# Include the FindLibIberty module
include(FindLibIberty)

# Add your executable that uses cplus_demangle_v3
# Ensure this source file (e.g., test_demangle.cpp) exists in ./libiberty/
add_library(demangle_test_executable SHARED test_pic.cpp)

# Link against the LibIberty::LibIberty target
target_link_libraries(demangle_test_executable PRIVATE LibIberty::LibIberty)

# Set the output name for the shared library
set_target_properties(demangle_test_executable PROPERTIES OUTPUT_NAME "demangle_test")
