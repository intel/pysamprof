#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#elif defined(_WIN32)
// don't need anything special :)
#else
#error Unsupported platform
#endif

#include <ipc-ng/ipc-ng.h>

#include "../../common/logging/logging.h"
#include "../../common/status/status.h"
#include "../../common/utilities/utilities.h"

#include "../include/trace_writer_api.h"
#include "../include/ipc_message.h"
#include "../include/client_handles.h"

static operation_result_t make_connection_pair(master_handle_t** master,
        thread_handle_t** thread, int64_t master_pid, int64_t thread_pid)
{
	operation_result_t operation_result;

    if (master == NULL || thread == NULL) return or_fail;

    operation_result = init_master_handle_client(master, master_pid);
    if (operation_result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Master thread handle initialization failed with status: %s",
                get_operation_result_str(operation_result));
        return operation_result;
    }

    operation_result = init_thread_handle_client(*master, thread_pid, thread);
    if (operation_result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Thread handle for %lld initialization failed with status: %s",
                (long long )thread_pid, get_operation_result_str(operation_result));
        return operation_result;
    }

    return operation_result;
}

#define CHECK_STATUS_AND_RETURN(status, msg, retval)    \
    if (status != or_okay)                              \
    {                                                   \
        PYSAMPROF_LOG(PL_ERROR, msg ": %s",             \
                get_operation_result_str(status));      \
        return retval;                                  \
    }

int main(int argc, char *argv[])
{
	int64_t master_pid;
	operation_result_t operation_result;

	master_handle_t *master = NULL;
    thread_handle_t *p_thread_handle = NULL;

	master_handle_t *master2 = NULL;
    thread_handle_t *p_thread_handle2 = NULL;

    operation_result = init_logging();
    if (operation_result != or_okay)
    {
        fprintf(stderr, "Cannot init logging: %s", get_operation_result_str(operation_result));
        return 5;
    }
    operation_result = init_ipc_innards();
    CHECK_STATUS_AND_RETURN(operation_result, "Cannot init IPC innards", 6);

	if (argc != 2)
    {
        printf("usage: %s <pid_of_master>\n", argv[0]);
        return 1;
    }
#ifdef _WIN32
    master_pid = strtol(argv[1], NULL, 10);
#else
    master_pid = strtoll(argv[1], NULL, 10);
#endif
    if (master_pid <= 0)
    {
        printf("pid of master is invalid: %s", argv[1]);
        return 1;
    }

    operation_result = make_connection_pair(&master, &p_thread_handle,
            master_pid, 1234);
    CHECK_STATUS_AND_RETURN(operation_result, "Cannot make connection pair 1", operation_result);

    operation_result = register_process(master, p_thread_handle, 0);
    PYSAMPROF_LOG(PL_INFO, "register_process 1: %s", get_operation_result_str(operation_result));

    operation_result = start_collection(master, 1496999385936999936, 10000,
            38, "/tmp/pysamprof-result-test");
    PYSAMPROF_LOG(PL_INFO, "start_collection: %s", get_operation_result_str(operation_result));

    operation_result = make_connection_pair(&master2, &p_thread_handle2, master_pid, 5431);
    CHECK_STATUS_AND_RETURN(operation_result, "Cannot make connection pair 2", operation_result);

    {
        char* result_path = NULL;
        int64_t period;
		int signo;
        collection_state_t state;
        operation_result = get_collection_state(master2, &state, &period, &signo, &result_path);
        if (operation_result != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot get collection state: %s",
                    get_operation_result_str(operation_result));
        }
        else
        {
            PYSAMPROF_LOG(PL_INFO, "Got collection state: state=%d, period=%lld, signo=%d, path='%s'",
                    (int)state, (long long)period, signo, result_path);
            free(result_path);
        }
    }

    operation_result = register_process(master2, p_thread_handle2, 555);
    PYSAMPROF_LOG(PL_INFO, "register_process 2: %s", get_operation_result_str(operation_result));

    {
        ipc_message_sample_t* sample_msg;
        uint32_t size, sample_msg_size;
        uint16_t index = 0;
		uint64_t* stack_data;

        do
        {
            operation_result = alloc_sample_message(p_thread_handle2, 16, &index, &sample_msg,
                    &size);
        }
        while (operation_result != or_okay);

        sample_msg_size = sizeof(ipc_message_sample_t) + sizeof(uint64_t) * 2;
        sample_msg->head.size = sample_msg_size;
        sample_msg->head.data_offset = offsetof(ipc_message_sample_t, body);
        sample_msg->head.type = ipc_message_sample_type;
        sample_msg->head.version = IPC_NG_HEADER_VERSION;

        sample_msg->body.stack_offset = offsetof(ipc_message_sample_body_t, data);
        sample_msg->body.stack_size = 2;
        sample_msg->body.stack_type = mixed;
        sample_msg->body.duration = 10000;
        sample_msg->body.timestamp = 1496999385936999936;
        sample_msg->body.tid = 1234;

        stack_data = (uint64_t*)((char*)(&sample_msg->body)
                + sample_msg->body.stack_offset);
        stack_data[0] = 18434;
        stack_data[1] = 22254;

        operation_result = push_sample_message(p_thread_handle2, sample_msg, size);
        if (operation_result != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot push sample message: %s",
                    get_operation_result_str(operation_result));
            return 2;
        }
    }

    msleep(200); // sleep two sampling periods just in case

    PYSAMPROF_LOG(PL_INFO, "write_sample: %s", get_operation_result_str(operation_result));
    operation_result = unregister_process(master, p_thread_handle);
    PYSAMPROF_LOG(PL_INFO, "unregister_process 1: %s",
            get_operation_result_str(operation_result));
    operation_result = unregister_process(master2, p_thread_handle2);
    PYSAMPROF_LOG(PL_INFO, "unregister_process 2: %s",
            get_operation_result_str(operation_result));

    operation_result = stop_collection(master);
    PYSAMPROF_LOG(PL_INFO, "stop_collection: %s", get_operation_result_str(operation_result));
    free_thread_handle_client(p_thread_handle);
    free_thread_handle_client(p_thread_handle2);
    free_master_handle_client(master);
    free_master_handle_client(master2);
    finish_logging();
    return 0;
}
