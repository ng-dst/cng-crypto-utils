cmake_minimum_required(VERSION 3.26)
project(lab3 C)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

add_subdirectory(cu)
add_subdirectory(gui)
