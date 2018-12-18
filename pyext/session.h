#ifndef __PYSAMPROF_SESSION_H__
#define __PYSAMPROF_SESSION_H__

#include <status/status.h>
#include <probengine/memory_regions.h>

#include <ipc-ng/ipc-ng.h>

#ifdef __linux__
#include <sys/types.h>
#include <unistd.h>
typedef pid_t ps_pid_t;
#elif defined(_WIN32)
#include <windows.h>
typedef DWORD ps_pid_t;
#else
#error Unsupported platform
#endif

typedef struct
{
    ps_pid_t pid;
} server_info_t;

// FIXME: server_info_t should be automatically "fixed" upon fork
operation_result_t get_server_info(server_info_t* result);

// server-passing implementation
operation_result_t setup_server_pointer_thread();
operation_result_t set_server_pointer_info(server_info_t info);
operation_result_t spawn_master_server(all_memory_regions_t regions, server_info_t* result);

#endif
