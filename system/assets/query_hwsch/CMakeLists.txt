cmake_minimum_required(VERSION 3.20)
project(query_hwsch C)

add_executable(query_hwsch query_hwsch.c)

if (MSVC)
  target_compile_options(query_hwsch PRIVATE /W4)
else()
  target_compile_options(query_hwsch PRIVATE -Wall -Wextra)
endif()
