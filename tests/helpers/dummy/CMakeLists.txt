cmake_minimum_required(VERSION 3.10)
project(dummy)

# Add executable
add_executable(dummy dummy.c)

# Link against necessary libraries
if(WIN32)
    target_link_libraries(dummy PRIVATE user32 advapi32)
endif()