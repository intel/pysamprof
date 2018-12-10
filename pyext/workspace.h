#ifndef __PYSAMPROF_WORKSPACE_H__
#define __PYSAMPROF_WORKSPACE_H__

#include <Python.h>

#ifdef __linux__
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
typedef pid_t wsp_tid_t;
#elif defined(_WIN32)
#include <windows.h>
typedef DWORD wsp_tid_t;
#define inline __inline
#else
#error Unsupported platform
#endif

#include <common/status/status.h>
#include <common/utilities/inttype_helper.h>

#include "time_utils.h"
#include "os_abstract.h"

typedef struct workspace_t workspace_t; // for pointer declarations

typedef enum
{
    pes_native = 0,
    pes_will_be_python,
    pes_is_python,
    pes_service_thread
} python_enabled_state_t;

typedef operation_result_t (*wsp_callback_t)(workspace_t* wsp);

struct workspace_t
{
    workspace_t* next; // double-linked list
    workspace_t* prev;

    PyThreadState* tstate; // pointer to Python thread state for given thread
    volatile python_enabled_state_t python_enabled; // whether thread might have PyThreadState at all
	atomic_int_t is_sampling_unsafe; // 0 when safe to sample the thread

    long python_tid;

#ifdef __linux__
    void* altstack; // space allocated for signal handlers
    size_t altstack_size;

    timer_t timer;
#elif defined(_WIN32)
	HANDLE sampling_thread;
	HANDLE target_thread;
	volatile int stop_sampling;

#else
#error Unsupported platform
#endif
	timeunit_t prev_cpu_value;

    wsp_callback_t on_free;
    wsp_tid_t tid;

    uint16_t last_shmem_index;
};

operation_result_t allocate_workspace(workspace_t** wsp);
operation_result_t free_workspace(workspace_t* wsp, int current_thread);
operation_result_t get_workspace_by_tid(wsp_tid_t tid, workspace_t** result);
typedef operation_result_t (*iterate_workspace_callback_t)(workspace_t* wsp, void* data);
/* return or_continue_iterating to continue iterating,
   everything else will stop iteration and will be returned as result from
   iterate_workspaces() function */
operation_result_t iterate_workspaces(iterate_workspace_callback_t callback, void* data);

operation_result_t init_workspace_machinery();
operation_result_t free_workspace_machinery();

static inline operation_result_t set_wsp_service_thread(workspace_t* wsp)
{
	if (wsp == NULL) return or_fail;
	wsp->python_enabled = pes_service_thread;
	return or_okay;
}

static int is_wsp_service_thread(workspace_t* wsp)
{
	return wsp != NULL && wsp->python_enabled == pes_service_thread;
}

#define IS_SAMPLING_SAFE(wsp) (((wsp) != NULL) && ((wsp)->is_sampling_unsafe == 0))

#define MARK_WSP_SAMPLING_UNSAFE(wsp) {if ((wsp) != NULL) ATOMIC_INC((wsp)->is_sampling_unsafe);}
#define MARK_WSP_SAMPLING_SAFE(wsp) {if ((wsp) != NULL) ATOMIC_DEC((wsp)->is_sampling_unsafe);}

#endif
