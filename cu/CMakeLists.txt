# CU command-line interface

# ----------------------------------------- #
#  Comment this to disable unicode for CLI  #
set(UNICODE ON)
# ----------------------------------------- #

set(CMAKE_C_STANDARD 23)

if (UNICODE)
    add_compile_definitions(UNICODE _UNICODE)
endif (UNICODE)

include_directories(src/include)
include_directories(src/lib)

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
