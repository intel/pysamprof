#ifndef __PYSAMPROF_CLIENT_HANDLER_TYPES_H__
#define __PYSAMPROF_CLIENT_HANDLER_TYPES_H__

#include <stdlib.h>

#include "../../common/status/status.h"
#include "trace_writer_api.h"

operation_result_t init_master_handle_client(master_handle_t **master, int64_t pid_master);
operation_result_t init_thread_handle_client(master_handle_t* master, int64_t my_pid,
        thread_handle_t **p_thread_handle);
void free_master_handle_client(master_handle_t *master);
void free_thread_handle_client(thread_handle_t *p_thread_handle);

#endif
