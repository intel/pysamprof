#ifndef __PYSAMPROF_CODE_REPORTING_H__
#define __PYSAMPROF_CODE_REPORTING_H__

#include <Python.h>

#include <common/status/status.h>

#include "os_abstract.h"
#include "ringbuffer.h"

#include "../trace_writer/include/client_handles.h"
#include "../trace_writer/include/function_info.h"

struct collector_state_t;

// NOTE: this concept of hijacking PyCodeObject.co_flags field to
// see if code object was reported could lead to "unknown funcs"
// in dumb stop-start scenario
#define CO_CODEOBJECT_REPORTED ((int)(1 << (sizeof(int) * 8 - 2)))

#define CO_LIST_ENTRY_SIZE 1000
typedef struct code_object_list_t code_object_list_t;
struct code_object_list_t
{
	PyCodeObject* objects[CO_LIST_ENTRY_SIZE];
	code_object_list_t* next;
};

typedef enum
{
    crts_not_stared,
    crts_running,
    crts_stop_requested
} code_reporting_thread_state_t;

typedef struct
{
	thread_t symbol_thread;
#ifdef __linux__
	int symbol_thread_started;
	volatile int pystate_ready;
#elif defined(_WIN32)
	CRITICAL_SECTION dbghelp_lock;
#else
#error Unsupported platform
#endif
	volatile code_reporting_thread_state_t state;
	ring_buffer_t symbol_ring;
	// FIXME: symbol ring mutex should be a spinlock as working with pthread from signal handler is unsafe
	mutex_t symbol_ring_mutex;
	code_object_list_t* reported;
} code_reporting_state_t;

#ifdef _WIN32
#define LOCK_DBGHELP(p_code_reporting) EnterCriticalSection(&((p_code_reporting)->dbghelp_lock))
#define UNLOCK_DBGHELP(p_code_reporting) LeaveCriticalSection(&((p_code_reporting)->dbghelp_lock))
#endif

#define LOCK_CODE_RING(p_code_reporting) LOCK_MUTEX(&((p_code_reporting)->symbol_ring_mutex))
#define UNLOCK_CODE_RING(p_code_reporting) UNLOCK_MUTEX(&((p_code_reporting)->symbol_ring_mutex))

operation_result_t init_code_reporting();

operation_result_t start_code_reporting();
operation_result_t stop_code_reporting();

// utility functions
operation_result_t make_function_info(Perftools__Symbols__FunctionInfo** info);
operation_result_t send_function_info(thread_handle_t* myself,
		Perftools__Symbols__FunctionInfo* info);

#endif
