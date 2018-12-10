#ifndef __PYSAMPROF_SERVER_HANDLER_TYPES_H__
#define __PYSAMPROF_SERVER_HANDLER_TYPES_H__

#include <stdlib.h>

#ifdef __linux__
#include <pthread.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include "../../common/status/status.h"
#include "../include/ipc_message.h"

#include <ipc-ng/ipc-ng.h>

#include "../include/trace_writer_api.h"

// thread handle represents message handler on each server thread
// processes messages that require writing to trace
struct thread_handle
{
    int64_t pid;
    char* result_path; // BORROWED from main server attrs, don't free
    int64_t start_time;
    int64_t period;
    FILE *trace_fp;
    FILE *symbol_trace_fp;
    ipc_server_data_t* shmem_server;
    master_handle_t* master;

#ifdef __linux__
	// symfile_mutex is needed for copying when fork happens
    pthread_mutex_t symfile_mutex;
#elif defined(_WIN32)
	// no need for symfile_mutex on Windows - it has no forks
#else
#error Unsupported platform
#endif

    thread_handle_t* prev;
    thread_handle_t* next;
};

typedef enum
{
    mss_not_started,
    mss_started,
    mss_idle,
    mss_stopping,
    mss_stopped
} main_server_state_t;

typedef struct
{
    collection_state_t state;
    char* result_path;
    int64_t period;
	int signo;
    int64_t start_time;
} collection_data_t;

#ifdef __linux__
typedef volatile int32_t atomic_int_t ;
#elif defined(_WIN32)
typedef volatile LONG atomic_int_t;
#else
#error Unsupported platform
#endif

// master handle represents message handler on main server thread
// processes command messages
struct master_handle
{
    volatile main_server_state_t state;

    atomic_int_t client_count;
    atomic_int_t has_new_client;
    ipc_server_data_t* stream_server;

    collection_data_t collection;
    thread_handle_t* threads;
#ifdef __linux__
    pthread_mutex_t thread_mutex;
#elif defined(_WIN32)
	CRITICAL_SECTION thread_mutex;
#else
#error Unsupported platform
#endif
};

#define CAST_TO_HANDLE_NODECL(type, from, to)    			\
    if (from == NULL)                                       \
    {                                                       \
        PYSAMPROF_LOG(PL_ERROR, "%s got NULL " #type " attrs", __FUNCTION__); \
        return;                                             \
    }                                                       \
    to = (type*)(from);

#define CAST_TO_HANDLE(type, from, to)						\
	type* to;                                               \
	CAST_TO_HANDLE_NODECL(type, from, to);

#define GET_SERVER_ATTRS_NODECL(from, to) CAST_TO_HANDLE_NODECL(master_handle_t, from, to)
#define GET_CLIENT_ATTRS_NODECL(from, to) CAST_TO_HANDLE_NODECL(thread_handle_t, from, to)

#define GET_SERVER_ATTRS(from, to) CAST_TO_HANDLE(master_handle_t, from, to)
#define GET_CLIENT_ATTRS(from, to) CAST_TO_HANDLE(thread_handle_t, from, to)

operation_result_t send_collection_state(master_handle_t* master,
        ipc_client_data_t* ipc_client);

#endif
