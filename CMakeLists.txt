cmake_minimum_required(VERSION 3.16)

project(pqmpso)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/target)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE DEBUG)
set(CMAKE_CXX_FLAGS "-O0 -ggdb -Wall -fpermissive")

# Fetch the project and make it available for use.
# include(FetchContent)
# FetchContent_Declare(
#     libcoro
#     GIT_REPOSITORY https://github.com/jbaldwin/libcoro.git
#     GIT_TAG        v0.5
# )
# FetchContent_MakeAvailable(libcoro)

add_executable(pqmpso main.cpp)
target_include_directories(pqmpso PRIVATE ${CMAKE_BINARY_DIR}/include)
target_include_directories(pqmpso PUBLIC /usr/local/include/SEAL-4.0)
target_link_libraries(pqmpso PUBLIC seal-4.0 cryptopp pthread)

# MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} )

# # the compiler flags for compiling C++ sources 
# MESSAGE( STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS} )
