cmake_minimum_required(VERSION 3.20)

project(mmcss_task C)

add_executable(mmcss_task mmcss_task.c)
target_link_libraries(mmcss_task PRIVATE avrt)
