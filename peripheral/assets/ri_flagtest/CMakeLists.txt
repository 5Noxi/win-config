cmake_minimum_required(VERSION 3.20)
project(raw_input_flag_tests C)

add_executable(ri_0100 ri_mouse.c)
target_compile_definitions(ri_0100 PRIVATE WIN32_LEAN_AND_MEAN RI_FLAGS=0x0100 RI_NAME="ri_0100")

add_executable(ri_8100 ri_mouse.c)
target_compile_definitions(ri_8100 PRIVATE WIN32_LEAN_AND_MEAN RI_FLAGS=0x8100 RI_NAME="ri_8100")
