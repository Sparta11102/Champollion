cmake_minimum_required(VERSION 3.21)
# macOS 11 (Big Sur) and later. Must be set before project().
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS version")
project(champollion-jit
    LANGUAGES CXX
    VERSION 0.1.0)

set(CHAMPOLION_VERSION_MAJOR 0)
set(CHAMPOLION_VERSION_MINOR 1)
set(CHAMPOLION_VERSION_PATCH 0)

# C++20 is required (ToDo.txt Phase 0: Setup and research)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX /permissive-")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -pedantic")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ------------------------------------------------------------
# Core library: champollion-core
#   Mach-O loader, ARM64 decoder, IR, x64 JIT backend
# ------------------------------------------------------------
add_library(champollion-core
    src/macho_loader.cpp
    src/arm64_decoder.cpp
    src/ir.cpp
    src/x64_backend.cpp
)

target_include_directories(champollion-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(champollion-core PUBLIC cxx_std_20)

# ------------------------------------------------------------
# Executable: champollion-jit
# ------------------------------------------------------------
add_executable(champollion-jit
    src/main.cpp
)

target_link_libraries(champollion-jit PRIVATE champollion-core)

# ------------------------------------------------------------
# Tests (Phase 5+ differential verification)
# ------------------------------------------------------------
option(BUILD_TESTS "Build unit and differential tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------
# Install rules
# ------------------------------------------------------------
install(TARGETS champollion-jit champollion-core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

install(DIRECTORY include/ DESTINATION include)
