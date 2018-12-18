cmake_minimum_required (VERSION 2.8)

set(TARGET_NAME "pysamprof-ipc-ng")

project("ipc-ng")

file (GLOB SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/include/*/*.h
)

add_library(${TARGET_NAME} ${SRC})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if (NOT TARGET pysamprof-common)
    add_subdirectory("../common" "common")
endif()
add_dependencies(${TARGET_NAME} pysamprof-common)

target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-common)
if (UNIX)
    target_link_libraries(${TARGET_NAME} PUBLIC pthread rt)
endif()
