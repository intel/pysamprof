cmake_minimum_required (VERSION 2.8)

set(TARGET_NAME "pysamprof")

project("pysamprof")

if (NOT TARGET pysamprof-common)
    add_subdirectory("../common" "common")
endif()
if (NOT TARGET pysamprof-ipc-ng)
    add_subdirectory("../libipc-ng" "libipc-ng")
endif()
if (NOT TARGET pysamprof-libprobengine)
    add_subdirectory("../libprobengine" "libprobengine")
endif()
if (NOT TARGET pysamprof-tracewriter)
    add_subdirectory("../trace_writer" "trace_writer")
endif()

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../build/xedkit/lib)
if (UNIX)
    link_directories("${CMAKE_CURRENT_SOURCE_DIR}/../build/libunwindkit/lib")
    link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit/lib)
else()
    if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit-debug/lib)
    else()
        link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit-release/lib)
    endif()
endif()

find_package(PythonInterp)
find_package(PythonLibs)

set(CALLSTACK_HELPER "pysamprof-callstack-helper")
file (GLOB CALLSTACK_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/callstack_helper.*
)
set(CALLSTACK_HELPER_GEN ${CMAKE_CURRENT_BINARY_DIR}/callstack_helper_gen.h)

add_library(${CALLSTACK_HELPER} ${CALLSTACK_SRC})
target_include_directories(${CALLSTACK_HELPER} PRIVATE ${PYTHON_INCLUDE_DIR})

add_dependencies(${CALLSTACK_HELPER} pysamprof-common)
target_link_libraries(${CALLSTACK_HELPER} PUBLIC pysamprof-common)
add_dependencies(${CALLSTACK_HELPER} pysamprof-libprobengine)
target_link_libraries(${CALLSTACK_HELPER} PUBLIC pysamprof-libprobengine)

add_custom_command(
    OUTPUT
        ${CALLSTACK_HELPER_GEN}
    DEPENDS
        ${CALLSTACK_HELPER} ${CMAKE_CURRENT_SOURCE_DIR}/get_text_section_size.py
    COMMAND
        python "${CMAKE_CURRENT_SOURCE_DIR}/get_text_section_size.py" "$<TARGET_FILE:${CALLSTACK_HELPER}>" "${CMAKE_CURRENT_BINARY_DIR}/callstack_helper_gen.h" PYEVAL_PROBE_SIZE
    COMMENT
        "Generating PyEval_EvalFrame_probe size"
    VERBATIM
)

file (GLOB SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/*.c
)
list(REMOVE_ITEM SRC "${CMAKE_CURRENT_SOURCE_DIR}/callstack_helper.c")

file (GLOB HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

if (NOT WIN32)
    list(REMOVE_ITEM SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/sampling_thread.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/sampling_thread.h"
    )
else()
    list(REMOVE_ITEM SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/vdso_parser.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/vdso_parser.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/signal_manager.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/signal_manager.h"
    )
endif()

add_library(${TARGET_NAME} MODULE ${SRC} ${HEADERS} ${CALLSTACK_HELPER_GEN})
if (WIN32)
    target_link_libraries(${TARGET_NAME} PRIVATE ${PYTHON_LIBRARY} dbghelp)
endif()

add_dependencies(${TARGET_NAME} pysamprof-common)
target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-common)
add_dependencies(${TARGET_NAME} pysamprof-ipc-ng)
target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-ipc-ng)
add_dependencies(${TARGET_NAME} pysamprof-libprobengine)
target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-libprobengine)
add_dependencies(${TARGET_NAME} pysamprof-tracewriter)
target_link_libraries(${TARGET_NAME} PUBLIC pysamprof-tracewriter)

target_link_libraries(${TARGET_NAME} PRIVATE ${CALLSTACK_HELPER})
target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")
if (${CMAKE_CURRENT_SOURCE_DIR} STREQUAL "Debug")
    set(DEBUG_TAIL "_d")
else()
    set(DEBUG_TAIL "")
endif()
if (WIN32)
    set_target_properties(${TARGET_NAME} PROPERTIES SUFFIX "${DEBUG_TAIL}.pyd")
else()
    set_target_properties(${TARGET_NAME} PROPERTIES SUFFIX "${DEBUG_TAIL}.so")
endif()
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${TARGET_NAME} PRIVATE ${PYTHON_INCLUDE_DIR})
target_compile_definitions(${TARGET_NAME} PRIVATE "PYSAMPROF_BUILDING_LIB=1")

if (UNIX)
    target_compile_definitions(${TARGET_NAME} PRIVATE "_GNU_SOURCE")
    target_compile_options(${TARGET_NAME} PUBLIC "-Wall" "-Wno-multichar" "-Wno-unused-function")
    set_property(TARGET ${TARGET_NAME} PROPERTY C_STANDARD 99)
elseif(WIN32)
    #foo
endif()


#add_custom_command(
#    TARGET
#        pysamprof-server
#    POST_BUILD
#    COMMAND
#        ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pysamprof-server> ${CMAKE_CURRENT_BINARY_DIR}
#    )


#if (WIN32)
#    set(PROTOBUFC_KIT ${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit-${CMAKE_BUILD_TYPE})
#else()
#    set(PROTOBUFC_KIT ${CMAKE_CURRENT_SOURCE_DIR}/../build/protobufc-kit)
#endif()
#target_include_directories(${TARGET_NAME} PUBLIC ${PROTOBUFC_KIT}/include)

## TODO: update to target_link_directories when CMake >= 3.13 will be everywhere
#link_directories(${PROTOBUFC_KIT}/lib)
#target_link_libraries(${TARGET_NAME} PUBLIC protobuf-c)

