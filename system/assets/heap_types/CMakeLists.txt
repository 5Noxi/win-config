cmake_minimum_required(VERSION 3.20)
project(heap_types LANGUAGES C)

add_executable(heap_types heap_types.c)
target_link_libraries(heap_types PRIVATE advapi32)

if (MSVC)
    target_compile_options(heap_types PRIVATE /W4)
endif()
