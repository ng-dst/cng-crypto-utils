# GUI wrapper for context menu


include_directories(src/include)

# Force unicode for GUI
add_compile_definitions(UNICODE _UNICODE)

add_executable(zcu
        src/main.c
        src/applets.c
        src/gui.c
        src/command.c
        src/include/command.h)

target_link_libraries(zcu shlwapi)
set_target_properties(zcu PROPERTIES WIN32_EXECUTABLE TRUE)

if (MSVC)
    set_target_properties(zcu PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS")
endif (MSVC)

if (MINGW)
    set_target_properties(zcu PROPERTIES LINK_FLAGS "-municode -mwindows")
endif (MINGW)