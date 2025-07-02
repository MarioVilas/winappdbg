cmake_minimum_required(VERSION 3.10)
project(crash_generator)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable
add_executable(crash_generator crash_generator.cpp)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add Windows-specific compile options
if(WIN32)
    target_compile_definitions(crash_generator PRIVATE _CRT_SECURE_NO_WARNINGS)
    # Disable optimization for debug builds to make debugging easier
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_options(crash_generator PRIVATE /Od)
    endif()
endif()