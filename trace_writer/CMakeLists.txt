cmake_minimum_required (VERSION 2.8)

set(TARGET_NAME "pysamprof-tracewriter")
set(TARGET_SERVER_NAME "pysamprof-server")

project("trace_writer")

option(BUILD_DEV_EXE "Build the executables for development" OFF)
if (BUILD_DEV_EXE)
    set(TARGET_CLIENT_NAME ${TARGET_NAME}-client)
    set(TARGET_READER_NAME ${TARGET_NAME}-reader)
endif()

file (GLOB proto_src
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/*.h
)

file (GLOB server_src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ipc_message.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/writing_thread.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server_handles.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server.c
)

if (BUILD_DEV_EXE)
    file (GLOB client_src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ipc_message.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/client_handles.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/client.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/client_test.c
    )

    file (GLOB trace_reader_src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/read_trace.c
    )
endif()

file (GLOB library_src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client_handles.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ipc_message.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/function_info.c
    )

file (GLOB HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
)

add_library(${TARGET_NAME} ${library_src} ${proto_src} ${HEADERS})
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
if (NOT TARGET pysamprof-ipc-ng)
    add_subdirectory("../libipc-ng" "libipc-ng")
endif()

add_dependencies(${TARGET_NAME} pysamprof-common)
target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-common)
add_dependencies(${TARGET_NAME} pysamprof-ipc-ng)
target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-ipc-ng)
if (WIN32)
    if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(PROTOBUFC_KIT ${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit-debug)
    else()
        set(PROTOBUFC_KIT ${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit-release)
    endif()
else()
    set(PROTOBUFC_KIT ${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit)
endif()
target_include_directories(${TARGET_NAME} PUBLIC ${PROTOBUFC_KIT}/include)
# TODO: update to target_link_directories when CMake >= 3.13 will be everywhere
link_directories(${PROTOBUFC_KIT}/lib)
target_link_libraries(${TARGET_NAME} PUBLIC protobuf-c)

add_executable(${TARGET_SERVER_NAME} ${server_src} ${proto_src} ${HEADERS})
add_dependencies(${TARGET_SERVER_NAME} ${TARGET_NAME})
target_link_libraries(${TARGET_SERVER_NAME} PUBLIC ${TARGET_NAME})

if (BUILD_DEV_EXE)
    add_executable(${TARGET_CLIENT_NAME} ${client_src} ${proto_src} ${HEADERS})
    target_include_directories(${TARGET_CLIENT_NAME} PUBLIC ${PROTOBUFC_KIT}/include)
    target_link_libraries(${TARGET_CLIENT_NAME} PUBLIC pysamprof-ipc-ng protobuf-c)

    add_executable(${TARGET_READER_NAME} ${trace_reader_src} ${proto_src} ${HEADERS})
    target_include_directories(${TARGET_READER_NAME} PUBLIC ${PROTOBUFC_KIT}/include)
    target_link_libraries(${TARGET_READER_NAME} PUBLIC pysamprof-ipc-ng protobuf-c)
endif()

