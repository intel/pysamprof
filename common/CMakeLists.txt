cmake_minimum_required (VERSION 2.8)

set(TARGET_NAME "pysamprof-common")

project("common")

find_package(PythonInterp)
if (UNIX)
    execute_process(
        COMMAND
            ${PYTHON_EXECUTABLE} "-c" "import sys, sysconfig; sys.stdout.write(sysconfig.get_config_var('CFLAGSFORSHARED'))"
        OUTPUT_VARIABLE
            PYTHON_CFLAGS
    )
    execute_process(
        COMMAND
            ${PYTHON_EXECUTABLE} "-c" "import sys, sysconfig; sys.stdout.write(sysconfig.get_config_var('LDFLAGS'))"
        OUTPUT_VARIABLE
            PYTHON_LDFLAGS
    )
    message(STATUS "detected CFLAGS for Python extensions: ${PYTHON_CFLAGS}")
    message(STATUS "detected LDFLAGS for Python extensions: ${PYTHON_LDFLAGS}")
else()
    set(PYTHON_CFLAGS "")
    set(PYTHON_LDFLAGS "")
endif()

file (GLOB SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/*/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/*/*.h
)

add_library(${TARGET_NAME} ${SRC})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(${TARGET_NAME} PUBLIC ${PYTHON_CFLAGS})

string(STRIP ${PYTHON_LDFLAGS} PYTHON_LDFLAGS)
target_link_libraries(${TARGET_NAME} PUBLIC ${PYTHON_LDFLAGS})

if (NOT WIN32)
    target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../3rd_party/safestringlib/include)
    target_link_libraries(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../3rd_party/safestringlib/libsafestring.a)
endif()

