cmake_minimum_required(VERSION 3.20)
project(heap_dump LANGUAGES C)

add_executable(heap_dump heap_dump.c)
target_link_libraries(heap_dump PRIVATE advapi32)

if (MSVC)
    target_compile_options(heap_dump PRIVATE /W4)
endif()
