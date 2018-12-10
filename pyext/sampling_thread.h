#ifndef __PYSAMPROF_SAMPLING_THREAD_H__
#define __PYSAMPROF_SAMPLING_THREAD_H__

#ifndef _WIN32
#error sampling_thread.h is Windows-only
#endif

#include <windows.h>

#include <common/status/status.h>
#include "workspace.h"

typedef operation_result_t (*sampling_func_t)(workspace_t* wsp, CONTEXT* ctx);

operation_result_t setup_wsp_thread(workspace_t* wsp, int sampling_rate_msec, sampling_func_t func);
operation_result_t free_wsp_thread(workspace_t* wsp);

#endif