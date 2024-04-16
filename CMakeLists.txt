cmake_minimum_required(VERSION 3.26)
project(lab3 C)

set(CMAKE_C_STANDARD 23)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)


# --------------------------------- #
#  Comment this to disable unicode  #
set(UNICODE ON)
# --------------------------------- #


include_directories(src/include)
include_directories(src/lib)

if (UNICODE)
    add_compile_definitions(UNICODE _UNICODE)
endif (UNICODE)

add_library(cu STATIC
        src/lib/cu/encrypt.c
        src/lib/cu/key.c
        src/lib/cu/pubkey.c
        src/lib/cu/hash.c
        src/lib/cu/sign.c
)

add_executable(lab3
        src/main.c
        src/utils/argparse.c
        src/utils/work.c
        src/utils/error.c
)

target_link_libraries(lab3 cu bcrypt)

if (UNICODE)
    set_target_properties(lab3 PROPERTIES WIN32_EXECUTABLE FALSE)

    if (MSVC)
        set_target_properties(lab3 PROPERTIES LINK_FLAGS "/SUBSYSTEM:CONSOLE")
    endif (MSVC)

    if (MINGW)
        set_target_properties(lab3 PROPERTIES LINK_FLAGS "-municode")
    endif (MINGW)

endif (UNICODE)
