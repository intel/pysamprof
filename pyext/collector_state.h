#ifndef __PYSAMPROF_COLLECTOR_STATE_H__
#define __PYSAMPROF_COLLECTOR_STATE_H__

#include <status/status.h>

#include "../trace_writer/include/trace_writer_api.h"

#include "session.h"
#include "code_reporting.h"

typedef struct collector_state_t collector_state_t;

operation_result_t init_collector_state();
operation_result_t finalize_collector_state(int has_gil, collection_state_t next_state);

operation_result_t get_code_reporting(code_reporting_state_t** result);
operation_result_t grab_collector_handles(
		thread_handle_t** myself, master_handle_t** master);
operation_result_t release_collector_handles();

// NOTE: function is unsafe, call only when collection is running
operation_result_t grab_myself_handle_nolock(thread_handle_t** myself);

operation_result_t grab_sampling_params(int* rate_msec, int* signo);
operation_result_t grab_collection_state(collection_state_t* result);

operation_result_t set_sampling_params(int rate_msec, int signo);
operation_result_t set_collection_state(collection_state_t state);

// Handles must be grabbed before calling this function
// and released after it is called
operation_result_t set_collector_handles(thread_handle_t* myself,
		master_handle_t* master);

#endif

