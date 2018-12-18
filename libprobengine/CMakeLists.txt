cmake_minimum_required (VERSION 2.8)

set(TARGET_NAME "pysamprof-libprobengine")
set(TARGET_DEV_EXE_NAME "${TARGET_NAME}-dev")

project("libprobengine")

option(BUILD_DEV_EXE "Build the executables for development" OFF)

file (GLOB SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/*.c
)

file (GLOB HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/probengine/*.h
)

list(REMOVE_ITEM SRC "${CMAKE_CURRENT_SOURCE_DIR}/main.c")

add_library(${TARGET_NAME} ${SRC} ${HEADERS})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (UNIX)
    target_compile_definitions(${TARGET_NAME} PRIVATE "_GNU_SOURCE")
    target_compile_options(${TARGET_NAME} PUBLIC "-Wall")
    set_property(TARGET ${TARGET_NAME} PROPERTY C_STANDARD 99)
elseif(WIN32)
    #foo
endif()

if (NOT TARGET pysamprof-common)
    add_subdirectory("../common" "common")
endif()
add_dependencies(${TARGET_NAME} pysamprof-common)

target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-common)
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../build/xedkit/include)
# TODO: update to target_link_directories when CMake >= 3.13 will be everywhere
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../build/xedkit/lib)
target_link_libraries(${TARGET_NAME} PUBLIC xed)
if (UNIX)
    target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../build/libunwindkit/include)
    set(LIBUNWIND_LIBDIR "${CMAKE_CURRENT_SOURCE_DIR}/../build/libunwindkit/lib")
    link_directories(${LIBUNWIND_LIBDIR})
    execute_process(COMMAND "find" "${LIBUNWIND_LIBDIR}" "-name" "libunwind.a" "-exec" "nm" "{}" ";" OUTPUT_VARIABLE var)
    string(FIND ${var} "lzma" lzma_needed)
    target_link_libraries(${TARGET_NAME} PUBLIC unwind dl)
    if (${lzma_needed} GREATER "0")
        message(STATUS "libunwind needs lzma on this platform")
        target_link_libraries(${TARGET_NAME} PUBLIC lzma)
    endif()
endif()

if (BUILD_DEV_EXE)
    add_executable(${TARGET_DEV_EXE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/main.c ${HEADERS})
    add_dependencies(${TARGET_DEV_EXE_NAME} pysamprof-common)
    target_link_libraries(${TARGET_DEV_EXE_NAME} PUBLIC pysamprof-common ${TARGET_NAME})
endif()

