cmake_minimum_required(VERSION 3.20)
project(xhci_imod LANGUAGES C)

add_executable(xhci_imod xhci_imod.c xhci_imod.rc)
target_compile_features(xhci_imod PRIVATE c_std_11)
target_compile_definitions(xhci_imod PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_link_libraries(xhci_imod PRIVATE advapi32 cfgmgr32 setupapi shell32)

if(MSVC)
    target_compile_options(xhci_imod PRIVATE /W4 /permissive- /wd5105)
    target_link_options(xhci_imod PRIVATE /MANIFEST:NO)
    set_property(TARGET xhci_imod PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_compile_options(xhci_imod PRIVATE -Wall -Wextra)
endif()

set(INPOUTX64_DRIVER "${CMAKE_CURRENT_SOURCE_DIR}/../inpoutx64.sys" CACHE FILEPATH "Path to inpoutx64.sys")
if(NOT EXISTS "${INPOUTX64_DRIVER}")
    message(FATAL_ERROR "inpoutx64.sys was not found at ${INPOUTX64_DRIVER}")
endif()

add_custom_command(TARGET xhci_imod POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${INPOUTX64_DRIVER}"
            "$<TARGET_FILE_DIR:xhci_imod>/inpoutx64.sys"
)
