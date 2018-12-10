#define _BSD_SOURCE

#include <string.h>
#include <errno.h>

#include "../../common/logging/logging.h"
#include "../../common/utilities/utilities.h"

#include "server_handles.h"
#include "writing_thread.h"
#include "../include/ipc_message.h"

#ifdef __linux__
#include <pthread.h>
#include <safe_str_lib.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#define LOCK_UNLOCK_MUTEX(mutex, func, type_name, okresult, action_name)    \
{                                                                           \
    type_name res = func((mutex));                                          \
    if (res != okresult)                                                    \
    {                                                                       \
        PYSAMPROF_LOG(PL_ERROR, "Cannot %s mutex: %d", action_name, (int)res);  \
        return or_fail;                                                     \
    }                                                                       \
}

#ifdef __linux__
#define LOCK_MASTER(master)     \
    LOCK_UNLOCK_MUTEX(&(master->thread_mutex), pthread_mutex_lock, int, 0, "lock master")
#define UNLOCK_MASTER(master)   \
    LOCK_UNLOCK_MUTEX(&(master->thread_mutex), pthread_mutex_unlock, int, 0, "unlock master")
#elif defined(_WIN32)
#define LOCK_MASTER(master)     \
    EnterCriticalSection(&(master->thread_mutex))
#define UNLOCK_MASTER(master)   \
    LeaveCriticalSection(&(master->thread_mutex))
#else
#error Unsupported platform
#endif

#ifdef _MSC_VER
#define inline __inline
#define strdup(x) _strdup(x)
#endif

static inline operation_result_t lock_master(master_handle_t* master)
{
    LOCK_MASTER(master);
    return or_okay;
}

static inline operation_result_t unlock_master(master_handle_t* master)
{
    UNLOCK_MASTER(master);
    return or_okay;
}

static inline uint32_t compute_latency(master_handle_t* master)
{
    // NB: collection->period is in nanoseconds while ipc_start_shmem_server()
    //     expects latency in microseconds; convert them and make latency half the period (or less)
    uint64_t latency = master->collection.period / (2 * 1000);
    if (latency > 100000) latency = 100000; // hard cap latency at 100 msec
    if (latency <= 0) latency = 10000; // if collection not running set latency at 10 msec

    return (uint32_t)latency;
}

static void insert_thread_to_list(master_handle_t* master, thread_handle_t* thread)
{
    thread->next = master->threads;
    if (master->threads) master->threads->prev = thread;
    master->threads = thread;
}

static void remove_thread_from_list(master_handle_t* master, thread_handle_t* thread)
{
    if (master->threads == thread) master->threads = thread->next;
    if (thread->prev) thread->prev->next = thread->next;
    if (thread->next) thread->next->prev = thread->prev;
    thread->prev = thread->next = NULL;
}

static void on_shmem_message(ipc_server_data_t* server, ipc_client_data_t* from,
        ipc_message_header_t* message, void* server_data, void* client_data)
{
    operation_result_t status = or_okay;
    GET_CLIENT_ATTRS(server_data, thread);
    if (message->version < IPC_NG_HEADER_VERSION)
    {
        PYSAMPROF_LOG(PL_WARNING, "IPC message version too old: %d, expected at least %d",
                message->version, IPC_NG_HEADER_VERSION);
        return;
    }

    switch (message->type)
    {
    case ipc_message_sample_type:
        PYSAMPROF_LOG(PL_INFO, "(shmem %p) got sample message", server);
        /* NB: accessing "master->collection" is slightly dangerous here
         as we did not take the synchronization lock, thus it might be
         out of sync with "real world". So no samples should be sent
         when collection is not running. Taking a lock here would be
         too expensieve.
         */
        if (thread->master->collection.state == cs_running)
        {
            status = write_sample(thread, (ipc_message_sample_t*)message);
        }
        else
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot write sample to non-running collection. "
                    "Collection state: %d", thread->master->collection.state);
        }
        break;
    case ipc_message_function_info_type:
        PYSAMPROF_LOG(PL_INFO, "(shmem) got function_info message")
        ;
        break;
    case ipc_message_mapping_info_type:
        PYSAMPROF_LOG(PL_INFO, "(shmem) got mapping info message")
        ;
        break;
    case ipc_message_start_command_type:
        PYSAMPROF_LOG(PL_INFO, "(shmem) got start collection message")
        ;
        break;
    case ipc_message_command_with_pid_type:
        PYSAMPROF_LOG(PL_INFO, "(shmem) got command with pid message")
        ;
        break;
    case ipc_message_collection_status_type:
        PYSAMPROF_LOG(PL_INFO, "(shmem) got status message")
        ;
        break;
    case ipc_message_shmem_connect_type:
        PYSAMPROF_LOG(PL_INFO, "(shmem) got shmem connect message")
        ;
        break;

    default:
        PYSAMPROF_LOG(PL_WARNING, "(shmem) Got unknown message type %d", message->type)
        ;
    }

    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Error processing %d command: %s", message->type,
                get_operation_result_str(status));
    }
}

static operation_result_t send_message_to_client(int64_t target_pid, ipc_message_header_t* msg)
{
    ipc_client_data_t* client;
    char buf[256];
    operation_result_t status, close_status;

    if (target_pid <= 0 || msg == NULL) return or_fail;
    PYSAMPROF_LOG(PL_INFO, "Sending a message to %lld client", (long long)target_pid);
    status = get_master_socket_url(&buf[0], sizeof(buf) - 1, target_pid);
    CHECK_AND_REPORT_ERROR(status, "Cannot compose stream url while sending message to client", status);
    status = ipc_connect_to_stream_server(buf, NULL, &client);
    CHECK_AND_REPORT_ERROR(status, "Cannot connect to client", status);

    status = ipc_send_message(client, msg);
    close_status = ipc_disconnect_from_server(client);
    if (close_status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot disconnect from %lld client", (long long)target_pid);
    }
    return status;
}

operation_result_t start_collection(master_handle_t *server_thread, int64_t time_start,
        int64_t sampling_period, int signo, const char *result_path)
{
    operation_result_t status;

    if (server_thread == NULL || result_path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got some NULL args", __FUNCTION__);
        return or_fail;
    }

    status = lock_master(server_thread);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot start collection: cannot lock master: %s",
                get_operation_result_str(status));
        return status;
    }

    if (server_thread->collection.state != cs_stopped)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot start not stopped collection; current state: %d",
                server_thread->collection.state);
        unlock_master(server_thread);
        return or_inconsistent_state;
    }

    status = mkdir_recoursive(result_path);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot make result dir '%s': %s", result_path,
                get_operation_result_str(status));
        unlock_master(server_thread);
        return status;
    }

    {
        char* result_path_copy = strdup(result_path);
        if (result_path_copy == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot copy result path from message");
            unlock_master(server_thread);
            return or_insufficient_memory;
        }
        server_thread->collection.result_path = result_path_copy;
    }
    server_thread->collection.state = cs_running;
    server_thread->collection.period = sampling_period;
    server_thread->collection.signo = signo;
    server_thread->collection.start_time = time_start;

    PYSAMPROF_LOG(PL_INFO, "Starting collection into '%s' with %lld period at %d signo",
            result_path, (long long )sampling_period, signo);

    // now loop over all already registered processes and create trace files for them
    {
        thread_handle_t* client = server_thread->threads;
        ipc_message_start_command_t *start_msg;
        size_t start_msg_size = sizeof(ipc_message_start_command_t);

        if (server_thread->collection.result_path != NULL)
        {
            start_msg_size += strlen(server_thread->collection.result_path);
        }
        if ((uint32_t)start_msg_size != start_msg_size)
        {
            unlock_master(server_thread);
            PYSAMPROF_LOG(PL_ERROR, "Too big 'start collection' message");
            return or_insufficient_memory;
        }
        start_msg = (ipc_message_start_command_t*)malloc(start_msg_size);
        if (start_msg == NULL)
        {
            unlock_master(server_thread);
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate 'start collection' message");
            return or_insufficient_memory;
        }

        start_msg->head.version = IPC_NG_HEADER_VERSION;
        start_msg->head.type = ipc_message_start_command_type;
        start_msg->head.data_offset = offsetof(ipc_message_start_command_t, body);
        start_msg->head.size = start_msg_size;

        start_msg->body.period = server_thread->collection.period;
        start_msg->body.start_time = server_thread->collection.start_time;
        start_msg->body.signo = server_thread->collection.signo;
        if (server_thread->collection.result_path != NULL)
        {
                strcpy_s(&(start_msg->body.result_path[0]),
                start_msg_size - sizeof(ipc_message_start_command_t) + 1,
                server_thread->collection.result_path);
        }

        for (; client != NULL; client =
                client->next)
        {
            status = open_trace_files(client);
            if (status != or_okay)
            {
                unlock_master(server_thread);
                free(start_msg);
                PYSAMPROF_LOG(PL_ERROR, "Cannot create trace files for client pid %lld: %s",
                    (long long)client->pid, get_operation_result_str(status));
                return status;
            }
            status = send_message_to_client(client->pid, &(start_msg->head));
            if (status != or_okay)
            {
                unlock_master(server_thread);
                free(start_msg);
                PYSAMPROF_LOG(PL_ERROR, "Cannot send message to client pid %lld: %s",
                    (long long)client->pid, get_operation_result_str(status));
                return status;
            }
            ipc_set_shmem_minimal_latency(client->shmem_server, compute_latency(server_thread));
        }
        free(start_msg);
    }

    status = unlock_master(server_thread);
    return status;
}

typedef operation_result_t (*check_update_master_t)(master_handle_t* server_thread, command_kind_t command);

static operation_result_t send_broadcast_command(master_handle_t* server_thread, command_kind_t command,
        check_update_master_t callback)
{
    operation_result_t status;
    ipc_message_command_with_pid_t msg;

    if (server_thread == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got some NULL args", __FUNCTION__);
        return or_fail;
    }

    status = lock_master(server_thread);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send broad command: cannot lock master: %s",
                get_operation_result_str(status));
        return status;
    }

    status = callback(server_thread, command);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot check or update collection state: %s",
            get_operation_result_str(status));
        unlock_master(server_thread);
        return status;
    }

    msg.head.type = ipc_message_command_with_pid_type;
    msg.head.version = IPC_NG_HEADER_VERSION;
    msg.head.size = sizeof(msg);
    msg.head.data_offset = offsetof(ipc_message_command_with_pid_t, body);
    msg.body.command = command;
    msg.body.pid = 0;

    // now loop over all already registered processes and send them a message
    {
        thread_handle_t* client = server_thread->threads;
        for (; client != NULL; client = client->next)
        {
            operation_result_t ipc_status = send_message_to_client(client->pid, &(msg.head));
            if (ipc_status != or_okay)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot send command to %lld client", (long long)client->pid);
                if (status == or_okay) status = ipc_status;
            }
        }
    }

    unlock_master(server_thread);
    return status;
}

static operation_result_t check_and_update_on_state_change(master_handle_t* server_thread, command_kind_t command)
{
    collection_state_t *state;
    if (server_thread == NULL) return or_fail;
    state = &(server_thread->collection.state);

    switch (command)
    {
    case ck_stop_collection:
        if (*state != cs_running && *state != cs_paused)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot stop non-running or non-paused collection (current state: %d)",
                *state);
            return or_inconsistent_state;
        }
        *state = cs_stopped;
        break;
    case ck_pause_collection:
        if (*state != cs_running)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot pause non-running collection (current state: %d)",
                *state);
            return or_inconsistent_state;
        }
        *state = cs_paused;
        break;
    case ck_resume_collection:
        if (*state != cs_paused)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot resume non-paused collection (current state: %d)",
                *state);
            return or_inconsistent_state;
        }
        *state = cs_running;
        break;
    default:
        PYSAMPROF_LOG(PL_ERROR, "Unexpected command passed to %s: %d", __FUNCTION__, command);
        return or_fail;
    }
    return or_okay;
}

operation_result_t stop_collection(master_handle_t *server_thread)
{
    operation_result_t status = send_broadcast_command(server_thread, ck_stop_collection, check_and_update_on_state_change); 
    CHECK_AND_REPORT_ERROR(status, "Cannot send 'stop' to clients", status);
    PYSAMPROF_LOG(PL_INFO, "Sent 'stop' to clients");
    return or_okay;
}

operation_result_t pause_collection(master_handle_t *server_thread)
{
    operation_result_t status = send_broadcast_command(server_thread, ck_pause_collection, check_and_update_on_state_change); 
    CHECK_AND_REPORT_ERROR(status, "Cannot send 'pause' to clients", status);
    PYSAMPROF_LOG(PL_INFO, "Sent 'pause' to clients");
    return or_okay;
}

operation_result_t resume_collection(master_handle_t *server_thread)
{
    operation_result_t status = send_broadcast_command(server_thread, ck_resume_collection, check_and_update_on_state_change); 
    CHECK_AND_REPORT_ERROR(status, "Cannot send 'resume' to clients", status);
    PYSAMPROF_LOG(PL_INFO, "Sent 'resume' to clients");
    return or_okay;
}

static operation_result_t duplicate_symbol_info(thread_handle_t* parent, thread_handle_t* fork)
{
    long original_pos;
    int res;
    char buf[1024];
    size_t total = 0;
    operation_result_t status, unlock_status;

    status = lock_symfile(parent);
    if (status != or_okay) return status;

    original_pos = ftell(parent->symbol_trace_fp);
    if (original_pos == -1)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Cannot read current position of symbol trace of %lld parent, errno: %d",
                (long long )parent->pid, errno);
        unlock_symfile(parent);
        return or_io_fail;
    }

    res = fseek(parent->symbol_trace_fp, 0, SEEK_SET);
    if (res == -1)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Cannot seek to start of symbol trace of %lld parent, errno: %d",
                (long long )parent->pid, errno);
        unlock_symfile(parent);
        return or_io_fail;
    }
    PYSAMPROF_LOG(PL_INFO, "Sought symbol trace of %lld parent to beginning",
            (long long )parent->pid);

    while (1)
    {
        size_t read_bytes, written_bytes;

        read_bytes = fread(&buf[0], 1, sizeof(buf), parent->symbol_trace_fp);
        if (read_bytes == 0)
        {
            if (ferror(parent->symbol_trace_fp) != 0)
            {
                PYSAMPROF_LOG(PL_ERROR, "Error reading from symbol trace of %lld parent",
                        (long long )parent->pid);
                clearerr(parent->symbol_trace_fp);
                status = or_io_fail;
            }
            break;
        }
        written_bytes = fwrite(&buf[0], 1, read_bytes, fork->symbol_trace_fp);
        if (written_bytes != read_bytes)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot write bytes to fork %lld symbol trace",
                    (long long )fork->pid);
            status = or_io_fail;
            break;
        }
        total += written_bytes;
    }
    PYSAMPROF_LOG(PL_INFO, "Copied %lld bytes of symbol trace of %lld parent to %lld fork",
            (long long )total, (long long )parent->pid, (long long )fork->pid);

    res = fseek(parent->symbol_trace_fp, original_pos, SEEK_SET);
    if (res == -1)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Cannot return position in symbol trace of %lld parent, errno: %d",
                (long long )parent->pid, errno);
        unlock_symfile(parent);
        return or_io_fail;
    }
    PYSAMPROF_LOG(PL_INFO, "Sought symbol trace of %lld parent to original position",
            (long long )parent->pid);

    unlock_status = unlock_symfile(parent);

    PYSAMPROF_LOG(PL_INFO, "Copied symbol trace of %lld parent to %lld fork",
            (long long )parent->pid, (long long )fork->pid);
    return (status != or_okay) ? status : unlock_status;
}

operation_result_t register_process(master_handle_t *master_thread,
        thread_handle_t *server_thread, int64_t parent_pid)
{
    char path_hint[256];
    operation_result_t status;

    // FIXME: don't hardcode channel count and size, determine at runtime
    const uint16_t hardcoded_count = 16, hardcoded_size = 16 * 1024;

    if (master_thread == NULL || server_thread == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got some NULL args", __FUNCTION__);
        return or_fail;
    }

    status = get_shmem_path_hint(path_hint, sizeof(path_hint) - 1,
            server_thread->pid);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot make path hint for shmem server: %s",
                get_operation_result_str(status));
        return status;
    }

    status = lock_master(master_thread);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get synchronized collection state: %s",
                get_operation_result_str(status));
        return status;
    }

    insert_thread_to_list(master_thread, server_thread);

    server_thread->trace_fp = NULL;
    server_thread->symbol_trace_fp = NULL;
    server_thread->master = master_thread;

    if (master_thread->collection.state == cs_running
            || master_thread->collection.state == cs_paused)
    {
        status = open_trace_files(server_thread);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot open trace files: %s",
                    get_operation_result_str(status));
            remove_thread_from_list(master_thread, server_thread);
            unlock_master(master_thread);
            return status;
        }

        if (parent_pid != 0)
        {
#ifdef __linux__
            // search for parent
            int found = 0;
            for (thread_handle_t* client = master_thread->threads; client != NULL; client =
                    client->next)
            {
                if (client->pid == parent_pid)
                {
                    found = 1;
                    operation_result_t dupstatus = duplicate_symbol_info(client, server_thread);
                    if (dupstatus != or_okay)
                    {
                        PYSAMPROF_LOG(PL_ERROR,
                                "Cannot duplicate symbol info from %lld parent to %lld fork: %s",
                                (long long )parent_pid, (long long )server_thread->pid,
                                get_operation_result_str(dupstatus));
                    }
                    break;
                }
            }
            if (!found)
            {
                PYSAMPROF_LOG(PL_ERROR,
                        "Cannot duplicate symbol info for %lld fork: parent %lld not currently registered",
                        (long long )server_thread->pid, (long long )parent_pid);
            }
#elif defined(_WIN32)
            PYSAMPROF_LOG(PL_ERROR, "Got non-zero parent pid on Windows, should happen only when forking");
#else
#error Unsupported platform
#endif
        }
    }

    {
        ipc_server_callbacks_t callbacks;

        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.on_new_message = on_shmem_message;
        callbacks.on_new_message_data = server_thread;

        // FIXME: wait till server starts before returning
        status = ipc_start_shmem_server(path_hint, hardcoded_count, hardcoded_size,
                compute_latency(master_thread), callbacks, &(server_thread->shmem_server));
        if (status == or_okay)
        {
            status = ipc_detach_server(server_thread->shmem_server);
            if (status != or_okay) ipc_stop_server(server_thread->shmem_server);
        }
    }
    if (status != or_okay)
    {
        operation_result_t temp_status;
        PYSAMPROF_LOG(PL_ERROR, "Cannot start shmem server for transferring samples: %s",
                get_operation_result_str(status));
        temp_status = close_trace_files(server_thread);
        if (temp_status != or_okay)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot close file handles while erroring out "
                    "in register_process: %s", get_operation_result_str(temp_status));
        }
        remove_thread_from_list(master_thread, server_thread);
        temp_status = unlock_master(master_thread);
        if (temp_status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot unlock master while erroring out "
                    "in register_process: %s", get_operation_result_str(temp_status));
        }
        return status;
    }

    status = unlock_master(master_thread);
    return status;
}

operation_result_t unregister_process(master_handle_t *master_thread,
        thread_handle_t *server_thread)
{
    operation_result_t status;
    
    if (master_thread == NULL || server_thread == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got some NULL args", __FUNCTION__);
        return or_fail;
    }
    status = lock_master(master_thread);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot unregister process: failed to lock master: %s",
                get_operation_result_str(status));
        return status;
    }
    status = close_trace_files(server_thread);

    if (server_thread->shmem_server)
    {
        operation_result_t ipc_status = ipc_stop_server(server_thread->shmem_server);
        if (ipc_status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot stop shmem server for %lld app thread: %s",
                    (long long )server_thread->pid, ipc_status);
            if (status == or_okay) status = ipc_status;
        }
        server_thread->shmem_server = NULL;
    }

    remove_thread_from_list(master_thread, server_thread);
    {
        operation_result_t unlock_status = unlock_master(master_thread);
        if (unlock_status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot unlock master: %s",
                    get_operation_result_str(unlock_status));
            if (status == or_okay) status = unlock_status;
        }
    }

    return status;
}

operation_result_t get_collection_state(master_handle_t* master_thread,
        collection_state_t* state, int64_t* period, int* signo, char** result_path)
{
    PYSAMPROF_LOG(PL_ERROR, "%s not implemented on server side", __FUNCTION__);
    return or_fail;
}

operation_result_t send_collection_state(master_handle_t* master, ipc_client_data_t* ipc_client)
{
    ipc_message_collection_status_t* message;
    uint32_t size = sizeof(ipc_message_collection_status_t);

    // TODO: extract master lock management to wrapping function so that master lock is
    //       always unlocked properly regardless of how called function is returning
    operation_result_t status = lock_master(master);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send collection state: failed to lock master: %s",
                get_operation_result_str(status));
        return status;
    }

    if (master->collection.result_path != NULL) size += strlen(master->collection.result_path);

    message = (ipc_message_collection_status_t*)malloc(size);
    if (message == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: cannot allocate message for sending 'collection state'");
        unlock_master(master);
        return or_insufficient_memory;
    }
    message->head.size = size;
    message->head.type = ipc_message_collection_status_type;
    message->head.version = IPC_NG_HEADER_VERSION;
    message->head.data_offset = offsetof(ipc_message_collection_status_t, body);

    message->body.period = master->collection.period;
    message->body.signo = master->collection.signo;
    message->body.start_time = master->collection.start_time;
    message->body.state = master->collection.state;
    if (master->collection.result_path != NULL)
    {
        strcpy_s(&(message->body.result_path[0]), size - sizeof(ipc_message_collection_status_t) + 1, master->collection.result_path);
    }

    status = ipc_send_message(ipc_client, &(message->head));
    free(message);

    {
        operation_result_t unlock_status = unlock_master(master);

        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot send 'collection state' to requester: %s",
                    get_operation_result_str(status));
            return status;
        }
        return unlock_status;
    }
}
