#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#include <safe_str_lib.h>
#include <signal.h>
#elif defined(_WIN32)
// don't need anything specific :)
#else
#error Unsupported platform
#endif

#ifdef _MSC_VER
#define strdup(x) _strdup(x)
#endif

#include "../../common/logging/logging.h"

#include <ipc-ng/ipc-ng.h>

#include "../../common/status/status.h"
#include "../include/trace_writer_api.h"
#include "../include/ipc_message.h"
#include "../include/client_handles.h"
#include "internal_client_handles.h"

#define SEND_MESSAGE(master_thread, message, typename, status) \
{                                                              \
    status = ipc_send_message((master_thread)->stream_handle, &((message)->head)); \
    if (status != or_okay)                                     \
    {                                                          \
        PYSAMPROF_LOG(PL_ERROR, "Failed to send %s: %s",       \
                (typename), get_operation_result_str(status)); \
    }                                                          \
}

operation_result_t write_sample(thread_handle_t *server_thread, ipc_message_sample_t *message)
{
    operation_result_t status;
    SEND_MESSAGE(server_thread->master, message, "sample", status);
    return status;
}

operation_result_t alloc_sample_message(thread_handle_t* server_thread, int try_loop_count,
        uint16_t* last_index, ipc_message_sample_t** message, uint32_t* max_size)
{
    operation_result_t status = or_fail;
    ipc_message_header_t* header;
    uint32_t got_size;
    uint16_t index;
    int i;

    if (server_thread == NULL || last_index == NULL || message == NULL || max_size == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got some NULL args", __FUNCTION__);
        return or_fail;
    }
    index = *last_index;
    for (i = 0; i < try_loop_count; i++)
    {
        status = ipc_prepare_buffer(server_thread->shmem_handle, &header, &got_size, &index);
        if (status == or_okay)
        {
            *last_index = index;
            *message = (ipc_message_sample_t*)header;
            *max_size = got_size;
            return or_okay;
        }
    }
    PYSAMPROF_LOG(PL_WARNING, "Cannot acquire buffer for sample message "
            "with try_count=%d and index=%d: %s", try_loop_count, *last_index,
            get_operation_result_str(status));
    return status;
}
operation_result_t push_sample_message(thread_handle_t* server, ipc_message_sample_t* message,
        uint32_t max_size)
{
    operation_result_t status = ipc_push_buffer(server->shmem_handle, &(message->head),
            max_size);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot push sample message to shmem: %s",
                get_operation_result_str(status));
    }
    return status;
}

operation_result_t discard_sample_message(thread_handle_t* server,
        ipc_message_sample_t* message, uint32_t max_size)
{
    operation_result_t status = ipc_discard_buffer(server->shmem_handle, &(message->head),
            max_size);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot discard sample message: %s",
                get_operation_result_str(status));
    }
    return status;
}

operation_result_t write_function_info(thread_handle_t *server_thread,
        ipc_message_function_info_t *message)
{
    operation_result_t status;
    SEND_MESSAGE(server_thread->master, message, "function info", status);
    return status;
}

// mapping is small and has defined size, so we compose it here
operation_result_t write_mapping_info(thread_handle_t *server_thread, uint64_t start,
        uint64_t limit, uint64_t offset, int64_t loadtime, const char* file)
{
    operation_result_t result = or_okay;
    uint32_t size = sizeof(ipc_message_mapping_info_t) + sizeof(char) * strlen(file);
    ipc_message_mapping_info_t *message = (ipc_message_mapping_info_t*)malloc(size);
    if (message == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: cannot allocate ipc message for mapping info");
        return or_insufficient_memory;
    }

    message->head.size = size;
    message->head.version = IPC_NG_HEADER_VERSION;
    message->head.type = ipc_message_mapping_info_type;
    message->head.data_offset = offsetof(ipc_message_mapping_info_t, body);

    message->body.start = start;
    message->body.limit = limit;
    message->body.offset = offset;
    message->body.loadtime = loadtime;

    strcpy_s(message->body.filename, size - sizeof(ipc_message_mapping_info_t) + 1, file);

    SEND_MESSAGE(server_thread->master, message, "mapping info", result);
    free(message);
    return result;
}

operation_result_t start_collection(master_handle_t *master_thread, int64_t time,
        int64_t period, int signo, const char* result_path)
{
    operation_result_t result = or_okay;
    uint32_t size = sizeof(ipc_message_start_command_t) + sizeof(char) * strlen(result_path);
    ipc_message_start_command_t *message = (ipc_message_start_command_t*)malloc(size);
    if (message == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate ipc message for start cmd");
        return or_insufficient_memory;
    }

    message->head.size = size;
    message->head.version = IPC_NG_HEADER_VERSION;
    message->head.type = ipc_message_start_command_type;
    message->head.data_offset = offsetof(ipc_message_start_command_t, body);

    message->body.start_time = time;
    message->body.period = period;
    message->body.signo = signo;

    strcpy_s(message->body.result_path, size - sizeof(ipc_message_start_command_t) + 1, result_path);

    SEND_MESSAGE(master_thread, message, "mapping info", result);
    free(message);
    return result;
}

operation_result_t send_command_with_pid(master_handle_t *master_thread, int64_t pid,
        command_kind_t command)
{
    operation_result_t result = or_okay;
    ipc_message_command_with_pid_t message;
    message.head.size = sizeof(message);
    message.head.version = IPC_NG_HEADER_VERSION;
    message.head.type = ipc_message_command_with_pid_type;
    message.head.data_offset = offsetof(ipc_message_command_with_pid_t, body);

    message.body.command = command;
    message.body.pid = pid;

    SEND_MESSAGE(master_thread, &message, "command with pid", result);
    return result;
}

operation_result_t send_command_no_args(master_handle_t *master_thread, command_kind_t command)
{
    return send_command_with_pid(master_thread, 0, command);
}

operation_result_t register_process(master_handle_t *master_thread,
        thread_handle_t *server_thread, int64_t parent_pid)
{
    ipc_message_register_process_t message;
    operation_result_t result = or_okay;
    ipc_message_header_t* response = NULL;
    ipc_message_shmem_connect_body_t* shmem_body;
    ipc_client_data_t* shmem_handle = NULL;

    message.head.size = sizeof(message);
    message.head.version = IPC_NG_HEADER_VERSION;
    message.head.type = ipc_message_register_process_type;
    message.head.data_offset = offsetof(ipc_message_register_process_t, body);

    message.body.pid = server_thread->pid;
    message.body.parent_pid = parent_pid;

    SEND_MESSAGE(master_thread, &message, "register process", result);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot register process %lld (parent: %lld): %s",
                (long long )server_thread->pid, (long long )parent_pid,
                get_operation_result_str(result));
        return result;
    }

    result = send_command_with_pid(master_thread, server_thread->pid, ck_get_shmem_connect);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send 'get shmem connect' message to server: %s",
                get_operation_result_str(result));
        return result;
    }

    result = ipc_receive_message(master_thread->stream_handle, &response);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot receive 'shmem connect' details: %s",
                get_operation_result_str(result));
        ipc_free_message(response);
        return result;
    }
    GET_MESSAGE_BODY(response, shmem_connect, shmem_body, result);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot parse 'shmem connect' details: %s",
                get_operation_result_str(result));
        ipc_free_message(response);
        return result;
    }
    {
        long long max_len = GET_MAX_VARSIZE(response, shmem_connect, path);
        shmem_body->path[max_len - 1] = 0;
    }

    result = ipc_connect_to_shmem_server((const char*)shmem_body->path,
            shmem_body->channel_count, shmem_body->channel_size, server_thread, &shmem_handle);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot connect to shmem server via '%s': %s",
                (const char* )shmem_body->path, get_operation_result_str(result));
        ipc_free_message(response);
        return result;
    }
    ipc_free_message(response);
    server_thread->shmem_handle = shmem_handle;
    return or_okay;
}

operation_result_t unregister_process(master_handle_t *master_thread,
        thread_handle_t *server_thread)
{
    return send_command_with_pid(master_thread, server_thread->pid, ck_unregister_process);
}

static operation_result_t free_ipc_message_on_invalid_param(ipc_message_header_t* message)
{
	ipc_free_message(message);
	return or_invalid_parameter;
}

#define VALIDATE_PARAMS_AND_FREE_MESSAGE(condition, ipc_msg, message, ...) \
    VALIDATE_PARAMS3(condition, free_ipc_message_on_invalid_param(ipc_msg), message, __VA_ARGS__)

operation_result_t get_collection_state(master_handle_t* master_thread,
        collection_state_t* state, int64_t* period, int* signo, char** result_path)
{
    operation_result_t res;
    ipc_message_header_t* response;
    ipc_message_collection_status_body_t* body;

    if (master_thread == NULL) return or_fail;

    res = send_command_with_pid(master_thread, 0, ck_get_collection_state);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send 'get collection state' request: %s",
                get_operation_result_str(res));
        return res;
    }

    res = ipc_receive_message(master_thread->stream_handle, &response);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get response for 'get collection state' request: %s",
                get_operation_result_str(res));
        return res;
    }

    GET_MESSAGE_BODY(response, collection_status, body, res);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot parse 'collection_status' details: %s",
                get_operation_result_str(res));
        ipc_free_message(response);
        return res;
    }
    VALIDATE_PARAMS_AND_FREE_MESSAGE(body->state == cs_stopped || body->state == cs_running || body->state == cs_paused,
        response, "ipc get_collection_state got unknown state: %d", (int)body->state);
    VALIDATE_PARAMS_AND_FREE_MESSAGE(body->period > 0,
        response, "ipc get_collection_state got non-positive period: %lld", (long long)body->period);
#ifdef _WIN32
    VALIDATE_PARAMS_AND_FREE_MESSAGE(body->signo == 0,
        response, "ipc get_collection_state got non-zero signo (%d) on Windows", body->signo);
#elif defined(__linux__)
    VALIDATE_PARAMS_AND_FREE_MESSAGE(body->signo >= 1 && body->signo <= SIGRTMAX,
        response, "ipc get_collection_state got invalid signo (%d) on Linux", body->signo);
#else
#error Unsupported platform
#endif

    if (result_path != NULL)
    {
        char* result_path_copy = NULL;
        long long max_len = GET_MAX_VARSIZE(response, collection_status, result_path);
        body->result_path[max_len - 1] = 0;

        result_path_copy = strdup((char*)body->result_path);
        if (result_path_copy == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR,
                    "Not enough memory: cannot copy result path during getting collection state");
            ipc_free_message(response);
            return or_insufficient_memory;
        }
        *result_path = result_path_copy;
    }
    if (state != NULL) *state = body->state;
    if (period != NULL) *period = body->period;
    if (signo != NULL) *signo = body->signo;

    ipc_free_message(response);
    return or_okay;
}

operation_result_t stop_collection(master_handle_t *server_thread)
{
    return send_command_no_args(server_thread, ck_stop_collection);
}

operation_result_t pause_collection(master_handle_t *server_thread)
{
    return send_command_no_args(server_thread, ck_pause_collection);
}

operation_result_t resume_collection(master_handle_t *server_thread)
{
    return send_command_no_args(server_thread, ck_resume_collection);
}
