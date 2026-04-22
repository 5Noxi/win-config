cmake_minimum_required(VERSION 3.20)
project(riflags C)

add_executable(riflags riflags.c)
target_compile_definitions(riflags PRIVATE WIN32_LEAN_AND_MEAN)

add_library(riprobe SHARED riprobe.c)
target_compile_definitions(riprobe PRIVATE WIN32_LEAN_AND_MEAN)