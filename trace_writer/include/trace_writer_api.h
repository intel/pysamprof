#ifndef __PYSAMPROF_TRACE_WRITER_API_H__
#define __PYSAMPROF_TRACE_WRITER_API_H__

#include "../../common/utilities/inttype_helper.h"

#include "../../common/status/status.h"
#include "ipc_message.h"
/* 
 Client thread creates thread handle and collects data.
 First it registers its thread handle in master trace writer.
 Second asks its own thread_handle to execute functions 
 write_sample and write_function_info;
 */
typedef struct thread_handle thread_handle_t;
/*
 Master thread stores trace names and general profile.
 Also has array of threads writing samples and func info.
 */
typedef struct master_handle master_handle_t;

operation_result_t start_collection(master_handle_t *server_thread, int64_t time_start,
        int64_t sampling_period, int signo, const char *result_path);
operation_result_t stop_collection(master_handle_t *server_thread);
operation_result_t pause_collection(master_handle_t *server_thread);
operation_result_t resume_collection(master_handle_t *server_thread);
operation_result_t write_sample(thread_handle_t *server_thread,
        ipc_message_sample_t *sample_collected);
operation_result_t alloc_sample_message(thread_handle_t* server_thread, int try_loop_count,
        uint16_t* last_index, ipc_message_sample_t** message, uint32_t* max_size);
operation_result_t push_sample_message(thread_handle_t* server, ipc_message_sample_t* message,
        uint32_t max_size);
operation_result_t discard_sample_message(thread_handle_t* server,
        ipc_message_sample_t* message, uint32_t max_size);
operation_result_t write_function_info(thread_handle_t *server_thread,
        ipc_message_function_info_t *function_info_collected);
operation_result_t write_mapping_info(thread_handle_t *server_thread, uint64_t start,
        uint64_t limit, uint64_t offset, int64_t loadtime, const char* file);
operation_result_t register_process(master_handle_t *master_thread,
        thread_handle_t *server_thread, int64_t parent_pid);
operation_result_t unregister_process(master_handle_t *master_thread,
        thread_handle_t *server_thread);

operation_result_t get_collection_state(master_handle_t* master_thread,
        collection_state_t* state, int64_t* period, int* signo, char** result_path);

#endif
