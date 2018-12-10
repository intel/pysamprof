#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <safe_str_lib.h>
#include <signal.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include "../../common/status/status.h"
#include "../../common/logging/logging.h"
#include "../../common/utilities/utilities.h"

#include "../include/ipc_message.h"
#include "server_handles.h"
#include "writing_thread.h"

#include "../proto/functionInfo.pb-c.h"
#include "../proto/sample_t.pb-c.h"

#ifndef FULL_MEMORY_BARRIER
#ifdef __GNUC__
#define FULL_MEMORY_BARRIER() __sync_synchronize()
#elif defined(_MSC_VER)
#define FULL_MEMORY_BARRIER() MemoryBarrier()
#else
#error Unsupported compiler
#endif
#endif

void on_register_process(master_handle_t* master, ipc_message_header_t* raw_message,
        thread_handle_t* client, ipc_client_data_t* msg_from)
{
    operation_result_t result;
    ipc_message_register_process_body_t* message;
    GET_MESSAGE_BODY(raw_message, register_process, message, result);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get 'register process' command body: %s",
                get_operation_result_str(result));
    }
    else
    {
        VALIDATE_PARAMS3(message->pid > 0, ,
            "ipc register_process got non-positive current pid: %lld", (long long)message->pid);
        VALIDATE_PARAMS3(message->parent_pid >= 0, ,
            "ipc register_process got negative parent pid: %lld", (long long)message->parent_pid);
        PYSAMPROF_LOG(PL_INFO, "got 'register process' message for %lld pid and %lld parent",
                (long long )message->pid, (long long )message->parent_pid);
        client->pid = message->pid;
        result = register_process(master, client, message->parent_pid);
        if (result != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot register process %lld: %s",
                    (long long )message->pid, get_operation_result_str(result));
        }
        else
        {
            PYSAMPROF_LOG(PL_INFO, "Successfully registered process %lld",
                    (long long )message->pid);
        }
    }
}

void on_start_command(master_handle_t* master, ipc_message_header_t* raw_message)
{
    operation_result_t result;
    ipc_message_start_command_body_t* message;

    PYSAMPROF_LOG(PL_INFO, "got start command message");
    GET_MESSAGE_BODY(raw_message, start_command, message, result);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get 'start command' body: %s",
                get_operation_result_str(result));
    }
    else
    {
        // make sure result_path is NULL-terminated no matter what
        long long max_len = GET_MAX_VARSIZE(raw_message, start_command, result_path);
        message->result_path[max_len - 1] = 0;

        VALIDATE_PARAMS3(message->period > 0, ,
            "ipc start_command received non-positive sampling period: %lld", (long long)message->period);
#ifdef _WIN32
        VALIDATE_PARAMS3(message->signo == 0, ,
            "ipc start_command got non-zero signo (%d) on Windows", message->signo);
#elif defined(__linux__)
        VALIDATE_PARAMS3(message->signo >= 1 && message->signo <= SIGRTMAX, ,
            "ipc start_command got incorrect signo (%d) on Linux", message->signo);
#else
#error Unsupported platform
#endif
        result = start_collection(master, message->start_time, message->period,
                message->signo, (const char*)message->result_path);
        if (result != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot execute 'start command': %s",
                    get_operation_result_str(result));
        }
        else
        {
            PYSAMPROF_LOG(PL_INFO, "'start command' executed");
        }
    }
}

operation_result_t send_shmem_connect_details(master_handle_t* master, thread_handle_t* thread,
        ipc_client_data_t* ipc_client)
{
    const char* path;
    uint16_t channel_count, channel_size;
    operation_result_t status;
    size_t msg_size;
    ipc_message_shmem_connect_t* message;

    if (!thread->shmem_server)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send shmem details - shmem not started");
        return or_fail;
    }
    status = ipc_get_shmem_connection(thread->shmem_server, &path,
            &channel_count, &channel_size);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get shmem details on server side: %s",
                get_operation_result_str(status));
        return status;
    }

    msg_size = sizeof(ipc_message_shmem_connect_t) + strlen(path);
    if ((uint32_t)msg_size != msg_size)
    {
        PYSAMPROF_LOG(PL_ERROR, "Too big message for sending shmem details");
        return or_insufficient_memory;
    }
    message = (ipc_message_shmem_connect_t*)malloc(msg_size);
    if (message == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory");
        return or_insufficient_memory;
    }
    message->head.size = (uint32_t)msg_size;
    message->head.version = IPC_NG_HEADER_VERSION;
    message->head.type = ipc_message_shmem_connect_type;
    message->head.data_offset = offsetof(ipc_message_shmem_connect_t, body);

    message->body.channel_count = channel_count;
    message->body.channel_size = channel_size;

    strcpy_s(message->body.path, msg_size - sizeof(ipc_message_shmem_connect_t) + 1, path);

    status = ipc_send_message(ipc_client, &(message->head));
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send shmem details from server: %s",
                get_operation_result_str(status));
    }
    free(message);

    return status;
}

operation_result_t on_write_mapping_info(thread_handle_t* thread,
        ipc_message_header_t* raw_message)
{
    operation_result_t result;
    ipc_message_mapping_info_body_t* message;
    GET_MESSAGE_BODY(raw_message, mapping_info, message, result);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get 'mapping info' body: %s",
                get_operation_result_str(result));
    }
    else
    {
        // make sure filename is NULL-terminated no matter what
        long long max_fname_len = GET_MAX_VARSIZE(raw_message, mapping_info, filename);
        message->filename[max_fname_len - 1] = 0;
        result = write_mapping_info(thread, message->start, message->limit, message->offset,
                message->loadtime, message->filename);
        if (result != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot write mapping info for '%s' (%p:+%p): %s",
                    message->filename, (void* )(message->start), (void* )(message->limit),
                    get_operation_result_str(result));
        }
    }
    return result;
}

static operation_result_t respond_to_get_server_pid(ipc_client_data_t* client)
{
    ipc_message_command_with_pid_t msg;
    msg.head.version = IPC_NG_HEADER_VERSION;
    msg.head.type = ipc_message_command_with_pid_type;
    msg.head.size = sizeof(msg);
    msg.head.data_offset = offsetof(ipc_message_command_with_pid_t, body);

    msg.body.command = ck_set_server_pid;
    msg.body.pid = -1;

    return ipc_send_message(client, &(msg.head));
}

void on_command_with_pid(master_handle_t* master, ipc_message_header_t* raw_message,
        thread_handle_t* thread, ipc_client_data_t* ipc_client)
{
    operation_result_t result;
    ipc_message_command_with_pid_body_t* message;

    PYSAMPROF_LOG(PL_INFO, "got 'command with pid' message");
    GET_MESSAGE_BODY(raw_message, command_with_pid, message, result);
    if (result != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get 'command with pid' body: %s",
                get_operation_result_str(result));
    }
    else
    {
        VALIDATE_PARAMS3(message->pid >= 0, ,
            "ipc command_with_pid got negative target pid: %lld", (long long)message->pid);
        switch (message->command)
        {
        case ck_unregister_process:
            PYSAMPROF_LOG(PL_INFO, "[pid:%lld] got 'unregister progess' command",
                    (long long )message->pid);
            result = unregister_process(master, thread);
            break;
        case ck_get_shmem_connect:
            PYSAMPROF_LOG(PL_INFO, "[pid:%lld] got 'shmem connect' command",
                    (long long )message->pid);
            result = send_shmem_connect_details(master, thread, ipc_client);
            break;
        case ck_stop_collection:
            PYSAMPROF_LOG(PL_INFO, "[pid:%lld] got 'stop collection' command",
                    (long long )message->pid);
            result = stop_collection(master);
            break;
        case ck_pause_collection:
            PYSAMPROF_LOG(PL_INFO, "[pid:%lld] got 'pause collection' command",
                    (long long )message->pid);
            result = pause_collection(master);
            break;
        case ck_resume_collection:
            PYSAMPROF_LOG(PL_INFO, "[pid:%lld] got 'resume collection' command",
                    (long long )message->pid);
            result = resume_collection(master);
            break;
        case ck_get_collection_state:
            PYSAMPROF_LOG(PL_INFO, "[pid:%lld] got 'get collection state' command",
                    (long long )message->pid);
            result = send_collection_state(master, ipc_client);
            break;
        case ck_get_server_pid:
            PYSAMPROF_LOG(PL_INFO, "[pid:%lld] got 'get server PID' command",
                    (long long )message->pid);
            result = respond_to_get_server_pid(ipc_client);
            break;
        default:
            PYSAMPROF_LOG(PL_ERROR, "Got unknown command: %d", message->command);
            return;
        }

        if (result != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Error processing %d command_with_pid: %s",
                    message->command, get_operation_result_str(result));
        }
    }
}

void on_main_server_start(ipc_server_data_t* server, void* data)
{
    GET_SERVER_ATTRS(data, attrs);
    attrs->state = mss_started;
    FULL_MEMORY_BARRIER();
    PYSAMPROF_LOG(PL_INFO, "Main server thread started");
}

void on_main_server_stop(ipc_server_data_t* server, void* data)
{
    GET_SERVER_ATTRS(data, attrs);
    attrs->state = mss_stopped;
    FULL_MEMORY_BARRIER();
    PYSAMPROF_LOG(PL_INFO, "Main server thread stopped");
}

void on_main_server_new_client(ipc_server_data_t* server, ipc_client_data_t* new_client,
        void* user_data, void** client_user_data)
{
    thread_handle_t* client_data;

    GET_SERVER_ATTRS(user_data, attrs);
    PYSAMPROF_LOG(PL_INFO, "New client connected to stream server");
    client_data = (thread_handle_t*)malloc(sizeof(thread_handle_t));
    if (client_data == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate client area in main server");
        *client_user_data = NULL;
        return;
    }
    memset(client_data, 0, sizeof(thread_handle_t));

    *client_user_data = (void*)client_data;
#ifdef __GNUC__
    __atomic_add_fetch(&(attrs->client_count), 1, __ATOMIC_SEQ_CST);
#elif defined(_MSC_VER)
    InterlockedIncrement(&(attrs->client_count));
#else
#error Unsupported compiler
#endif
    attrs->has_new_client = 1;
}

void on_main_server_client_disconnect(ipc_server_data_t* server, ipc_client_data_t* client,
        void* server_data, void* client_data)
{
    int32_t new_count;
    GET_SERVER_ATTRS(server_data, attrs);
#ifdef __GNUC__
    new_count = __atomic_add_fetch(&(attrs->client_count), -1, __ATOMIC_SEQ_CST);
#elif defined(_MSC_VER)
    new_count = InterlockedDecrement(&(attrs->client_count));
#else
#error Unsupported compiler
#endif
    if (new_count < 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Negative amount of clients connected!");
    }

    if (client_data != NULL)
    {
        operation_result_t status;
        GET_CLIENT_ATTRS(client_data, client_attrs);
        status = unregister_process(attrs, client_attrs);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot unregister client on exit: %s",
                    get_operation_result_str(status));
        }
        free(client_data);
    }
}

void on_main_server_new_message(ipc_server_data_t* server, ipc_client_data_t* from,
        ipc_message_header_t* message, void* server_data, void* client_data)
{
    master_handle_t* attrs;
    thread_handle_t* client_attrs;
    operation_result_t status = or_okay;

    GET_SERVER_ATTRS_NODECL(server_data, attrs);
    GET_CLIENT_ATTRS_NODECL(client_data, client_attrs);
    if (message->version < IPC_NG_HEADER_VERSION)
    {
        PYSAMPROF_LOG(PL_WARNING, "IPC message version too old: %d, expected at least %d",
                message->version, IPC_NG_HEADER_VERSION);
        return;
    }

    switch (message->type)
    {
    case ipc_message_sample_type:
        PYSAMPROF_LOG(PL_WARNING,
                "got sample message via stream, can now handle only via shmem");
        break;
    case ipc_message_function_info_type:
        // FIXME: check that trace file handles are not NULL before trying to write there
        PYSAMPROF_LOG(PL_INFO, "got function_info message");
        status = write_function_info(client_attrs, (ipc_message_function_info_t*)message);
        break;
    case ipc_message_mapping_info_type:
        PYSAMPROF_LOG(PL_INFO, "got mapping info message");
        status = on_write_mapping_info(client_attrs, message);
        break;
    case ipc_message_start_command_type:
        on_start_command(attrs, message);
        break;
    case ipc_message_command_with_pid_type:
        on_command_with_pid(attrs, message, client_attrs, from);
        break;
    case ipc_message_collection_status_type:
        PYSAMPROF_LOG(PL_INFO, "got status message");
        break;
    case ipc_message_shmem_connect_type:
        PYSAMPROF_LOG(PL_INFO, "got shmem connect message");
        break;
    case ipc_message_register_process_type:
        on_register_process(attrs, message, client_attrs, from);
        break;
    default:
        PYSAMPROF_LOG(PL_WARNING, "Got unknown message type %d", message->type);
    }

    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot proceed %d-typed message: %s", message->type,
                get_operation_result_str(status));
    }
}

#define CHECK_STATUS_AND_RETURN(status, msg, retval)    \
    if (status != or_okay)                              \
    {                                                   \
        PYSAMPROF_LOG(PL_ERROR, msg ": %s",             \
                get_operation_result_str(status));      \
        return retval;                                  \
    }

#ifdef _WIN32
long long __inline getpid()
{
    return GetCurrentProcessId();
}
#endif

#define SLEEP_INTERVAL 100
#define IDLE_INTERVAL (100 * SLEEP_INTERVAL)

int main()
{
    char url[256];
    master_handle_t server_attrs;
    ipc_server_callbacks_t callbacks;
    ipc_server_data_t* server;
    ipc_server_join_data_t* join_data;
    int sleep_counter = 0;

    operation_result_t status = init_logging();
    if (status != or_okay)
    {
        fprintf(stderr, "Cannot init logging: %s", get_operation_result_str(status));
        return 5;
    }

    PYSAMPROF_LOG(PL_INFO, "Server started with pid %lld", (long long)getpid());

    status = init_ipc_innards();
    CHECK_STATUS_AND_RETURN(status, "Cannot init IPC innards", 6);

    status = get_master_socket_url(url, sizeof(url) - 1, getpid());
    CHECK_STATUS_AND_RETURN(status, "Cannot create master socket url", 7);

    memset(&server_attrs, 0, sizeof(server_attrs));
    server_attrs.state = mss_not_started;
    FULL_MEMORY_BARRIER();
#ifdef __linux__
    {
        int res = pthread_mutex_init(&server_attrs.thread_mutex, NULL);
        if (res != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot init server mutex: %d", res);
            return 6;
        }
    }
#elif defined(_WIN32)
    InitializeCriticalSection(&(server_attrs.thread_mutex));
#else
#error Unsupported platform
#endif

    memset(&callbacks, 0, sizeof(callbacks));

    callbacks.on_server_start = on_main_server_start;
    callbacks.on_server_start_data = &server_attrs;
    callbacks.on_server_stop = on_main_server_stop;
    callbacks.on_server_stop_data = &server_attrs;
    callbacks.on_client_connect = on_main_server_new_client;
    callbacks.on_client_connect_data = &server_attrs;
    callbacks.on_client_disconnect = on_main_server_client_disconnect;
    callbacks.on_client_disconnect_data = &server_attrs;
    callbacks.on_new_message = on_main_server_new_message;
    callbacks.on_new_message_data = &server_attrs;

    status = ipc_start_stream_server(url, callbacks, &server);
    if (status == or_okay) status = ipc_get_join_data(server, &join_data);
    if (status != or_okay) {
#ifdef __linux__
        {
            int res = pthread_mutex_destroy(&server_attrs.thread_mutex);
            if (res != 0)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot destroy server mutex: %d", res);
                return 7;
            }
        }
#elif defined(_WIN32)
        DeleteCriticalSection(&(server_attrs.thread_mutex));
#else
#error Unsupported platform
#endif
    }

    CHECK_STATUS_AND_RETURN(status, "Cannot start stream IPC server", 8);

    // FIXME: make access to state atomic
    while (1)
    {
        FULL_MEMORY_BARRIER();
        if (server_attrs.state == mss_stopped) break;

        if (server_attrs.state == mss_started)
        {
            if (server_attrs.client_count == 0)
            {
#ifdef _WIN32
                if (InterlockedCompareExchange(&(server_attrs.has_new_client), 0, 1) == 0)
#elif defined(__linux__)
                if (__sync_val_compare_and_swap(&(server_attrs.has_new_client), 1, 0) == 0)
#else
#error Unsupported platform
#endif
                {
                    // server_attrs.has_new_client == 0
                    // it means there are no clients (and none came during sleep), see if we should stop the server
                    sleep_counter++;
                    if (sleep_counter * SLEEP_INTERVAL >= IDLE_INTERVAL)
                    {
                        PYSAMPROF_LOG(PL_INFO, "No clients for %d msec, stopping", IDLE_INTERVAL);
                        ipc_stop_server(server);
                        break;
                    }
                }
                else
                {
                    // atomic CAS succeeded, that means that there was "1" in server_attrs.has_new_client,
                    // so some clients attached and were gone during sleep, reset the timer.
                    sleep_counter = 0;
                }
            }
        }
        msleep(SLEEP_INTERVAL);
    }
    // server is stopping, just wait for it

    FULL_MEMORY_BARRIER();
    while (server_attrs.state != mss_stopped)
    {
        msleep(SLEEP_INTERVAL);
        FULL_MEMORY_BARRIER();
    }
    status = ipc_join_server(join_data);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot join main ipc server thread: %s",
                get_operation_result_str(status));
    }

#ifdef __linux__
    {
        int res = pthread_mutex_destroy(&server_attrs.thread_mutex);
        if (res != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot destroy server mutex: %d", res);
            return 7;
        }
    }
#elif defined(_WIN32)
    DeleteCriticalSection(&(server_attrs.thread_mutex));
#else
#error Unsupported platform
#endif

    return 0;
}
