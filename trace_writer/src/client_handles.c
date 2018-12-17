#define _DEFAULT_SOURCE

#include <string.h>

#include "../../common/logging/logging.h"
#include "../../common/status/status.h"

#include "../include/client_handles.h"
#include "internal_client_handles.h"

#include "../include/ipc_message.h"

operation_result_t init_master_handle_client(master_handle_t **master, int64_t pid_master)
{
	master_handle_t *master_tmp;
    char url[256];
	operation_result_t result;

    if (master == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Argument is NULL instead of pointer to "
                "master handle in init master handle on client");
        return or_fail;
    }
    master_tmp = (master_handle_t*)malloc(sizeof(master_handle_t));
    if (master_tmp == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: failed to allocate master_handle on client");
        return or_insufficient_memory;
    }

    result = get_master_socket_url(url, sizeof(url) - 1, pid_master);
    if (result != or_okay)
    {
        free(master_tmp);
        PYSAMPROF_LOG(PL_ERROR, "Failed to create interprocess client url, error %s",
                get_operation_result_str(result));
        return or_fail;
    }

    result = ipc_connect_to_stream_server(url, master_tmp, &(master_tmp->stream_handle));
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot connect to server via '%s': %s", url,
                get_operation_result_str(result));
        free(master_tmp);
        return result;
    }

    *master = master_tmp;
    return or_okay;
}

void free_master_handle_client(master_handle_t *master)
{
    if (!master) return;
    if (master->stream_handle)
    {
        operation_result_t status = ipc_disconnect_from_server(master->stream_handle);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Failed to disconnect from stream server, error %s",
                    get_operation_result_str(status));
        }
    }
    free(master);
}

operation_result_t init_thread_handle_client(master_handle_t* master, int64_t my_pid,
        thread_handle_t **p_thread_handle)
{
	thread_handle_t *p_thread_handle_tmp;

    if (master == NULL || p_thread_handle == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "One or more arguments are NULL instead of pointer "
                "to handle in init thread handle on client");
        return or_fail;
    }

    p_thread_handle_tmp = (thread_handle_t *)malloc(sizeof(thread_handle_t));
    if (p_thread_handle_tmp == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: failed to allocate thread_handle on client");
        return or_insufficient_memory;
    }
    p_thread_handle_tmp->master = master;
    p_thread_handle_tmp->pid = my_pid;

    *p_thread_handle = p_thread_handle_tmp;
    return or_okay;
}

void free_thread_handle_client(thread_handle_t *p_thread_handle)
{
    if (!p_thread_handle) return;
    if (p_thread_handle->shmem_handle)
    {
        operation_result_t status = ipc_disconnect_from_server(p_thread_handle->shmem_handle);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Failed to disconnect from shmem server, error %s",
                    get_operation_result_str(status));
        }
    }
    free(p_thread_handle);
}
