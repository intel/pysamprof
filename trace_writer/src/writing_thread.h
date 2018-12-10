#ifndef __PYSAMPROF_WRITING_THREADS_H__
#define __PYSAMPROF_WRITING_THREADS_H__

#define RAW_FILE_EXT ".raw"
#define SYMRAW_FILE_EXT ".symraw"
#define MAX_PID_LEN 20
#define TRACE_NUMBER_LEN 5

#include <stdio.h>
#include "../../common/utilities/inttype_helper.h"

#include <ipc-ng/ipc-ng.h>
#include "../../common/status/status.h"
#include "../include/trace_writer_api.h"

operation_result_t lock_symfile(thread_handle_t* thread);
operation_result_t unlock_symfile(thread_handle_t* thread);

operation_result_t open_trace_files(thread_handle_t *attrs);
operation_result_t close_trace_files(thread_handle_t* attrs);

#endif
