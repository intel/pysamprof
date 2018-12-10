#ifndef __PYSAMPROF_MAIN_PYEXT_MODULE__
#define __PYSAMPROF_MAIN_PYEXT_MODULE__

#include "collector_state.h"
#include "session.h"
#include "os_abstract.h"

#include <common/utilities/inttype_helper.h>

operation_result_t pysamprof_stop_collection(int has_gil, collection_state_t next_state);
operation_result_t pysamprof_enable_collection(collection_state_t state, const char* path, int period_msec, int signo, int64_t forked_parent_pid);

// TODO: make server_info pid part of collector_state_t
extern server_info_t g_server_info;

// API for talking with server from C side
// TODO: move to separate library
#define API_OKAY 0
#define API_REQUEST_PID_TARGET_IS_SERVER -1
#define API_IPC_ERROR -2
#define API_CANNOT_CONNECT -3
#define API_BAD_RESPONSE -4
#define API_NO_MEMORY -5
#define API_INTERNAL_ERROR -6
#define API_INVALID_PARAMETER -7


PYSAMPROF_API_FUNC(long long) pysamprof_api_request_server_pid(long long target_pid);
PYSAMPROF_API_FUNC(int) pysamprof_api_start_collection(long long target_pid, const char* result_path, int sampling_period_msec, int signo);
PYSAMPROF_API_FUNC(int) pysamprof_api_pause_collection(long long target_pid);
PYSAMPROF_API_FUNC(int) pysamprof_api_resume_collection(long long target_pid);
PYSAMPROF_API_FUNC(int) pysamprof_api_stop_collection(long long target_pid);

#endif