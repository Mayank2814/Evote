cmake_minimum_required(VERSION 3.10)
project(EVotingSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR})

# Add executable
add_executable(voting_system main.cpp)

# Link libraries
target_link_libraries(voting_system 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Compiler flags
target_compile_options(voting_system PRIVATE -Wall -Wextra)

# For nlohmann/json (single header)
# Download and include nlohmann/json.hpp in the project
# Or install via package manager: sudo apt-get install nlohmann-json3-dev

# Alternative: Use vcpkg or conan for dependency management
# find_package(nlohmann_json REQUIRED)
# target_link_libraries(voting_system nlohmann_json::nlohmann_json)

# Installation
install(TARGETS voting_system DESTINATION bin) 