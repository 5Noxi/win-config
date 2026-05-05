cmake_minimum_required(VERSION 3.20)

project(GameModeTools C)

add_executable(gm_effects gm_effects.c)
target_compile_definitions(gm_effects PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_options(gm_effects PRIVATE $<$<C_COMPILER_ID:MSVC>:/W4>)
target_link_libraries(gm_effects PRIVATE user32)
