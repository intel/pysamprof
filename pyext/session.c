#ifdef __linux__
// for readlink
#define _BSD_SOURCE
#include <unistd.h>
// for lstat
#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#endif

#include "session.h"
#include "threading_follow.h"
#include "time_utils.h"
#include "os_abstract.h"
#include "collector_state.h"

#include "_pysamprof.h"

#include <common/logging/logging.h>
#include <common/utilities/utilities.h>

#include "../trace_writer/include/ipc_message.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#ifdef _WIN32
#include <tlhelp32.h>
#define inline __inline
#endif

#if defined(_WIN32) && defined(snprintf)
// snprintf is re-defined by Python.h on Windows, but we don't care in this file and define own version
#undef snprintf
#define snprintf(buffer, count, format, ...) _snprintf_s(buffer, count, _TRUNCATE, format, ##__VA_ARGS__)
#endif

#ifdef _WIN32
static __inline ps_pid_t getpid()
{
    return GetCurrentProcessId();
}
#elif !defined(__linux__)
#error Unsupported platform
#endif

#ifdef __linux__
static operation_result_t get_parent_pid(ps_pid_t current, ps_pid_t* result)
{
    if (result == NULL) return or_fail;
    char path_buf[64];
    if (snprintf(path_buf, sizeof(path_buf) - 1,
                "/proc/%lld/stat", (long long)current) <= 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "cannot make 'proc/<pid>/stat' string");
        return or_fail;
    }
    FILE* stat_file = fopen(path_buf, "r");
    if (stat_file == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "cannot open '%s'", path_buf);
        return or_no_such_process;
    }
    long long ppid;
    int read_count = fscanf(stat_file, "%*d %*s %*c %lld", &ppid);
    fclose(stat_file);
    if (read_count != 1)
    {
        PYSAMPROF_LOG(PL_ERROR, "cannot get ppid for '%lld'", (long long)current);
        return or_cannot_read_file;
    }

    *result = (ps_pid_t)ppid;

    return or_okay;
}
#elif defined(_WIN32)

static __inline operation_result_t get_process_creation_time(ps_pid_t target, FILETIME* result)
{
    FILETIME creation_time, exit_time, kernel_time, user_time;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target);
    if (process == NULL)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot open a handle to %ld process, error: %ld", target, GetLastError());
        return or_no_such_process;
    }
    if (!GetProcessTimes(process, &creation_time, &exit_time, &kernel_time, &user_time))
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get process %ld times, error: %ld", target, GetLastError());
        CloseHandle(process);
        return or_cannot_read_file;
    }

    CloseHandle(process);
    *result = creation_time;
    return or_okay;
}

static operation_result_t get_parent_pid(ps_pid_t current, ps_pid_t* result)
{
    HANDLE snapshot;
    FILETIME own_time, parent_time;
    ps_pid_t parent = 0;
    operation_result_t status;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    if (result == NULL) return or_fail;

    status = get_process_creation_time(current, &own_time);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot get process %ld creation time: %s", current, get_operation_result_str(status));
        return status;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get a snapshot of running processes, error: %ld", GetLastError());
        return or_cannot_open_file;
    }

    if (Process32First(snapshot, &pe))
    {
        do
        {
            if (pe.th32ProcessID == current)
            {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);

    if (parent != 0)
    {
        status = get_process_creation_time(parent, &parent_time);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot get process (%ld) parent (%ld) creation time: %s",
                current, parent, get_operation_result_str(status));
            return or_no_such_process;
        }
        if (CompareFileTime(&own_time, &parent_time) != 1)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot find process (%ld) parent as parent pid (%ld) is reused", current, parent);
            return or_no_such_process;
        }
        *result = parent;
        return or_okay;
    }
    else
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot find a parent for %ld process", current);
        return or_no_such_process;
    }
}
#else
#error Unsupported platform
#endif

typedef enum
{
    pts_not_started = 0,
    pts_no_server_info,
    pts_complete,
    pts_spawning_master
} pointer_thread_state_t;

typedef struct
{
    pointer_thread_state_t state;
    ipc_server_data_t* app2app_server;
} server_pointer_arg_t;
static volatile server_pointer_arg_t s_server_pointer_arg = \
        {pts_not_started, NULL};

static operation_result_t request_server_info(ps_pid_t from, ps_pid_t* result)
{
    ipc_client_data_t* client;
    char buf[256];
    operation_result_t status;
    ipc_message_command_with_pid_t msg;
    ipc_message_command_with_pid_body_t* response_body;
    ipc_message_header_t* response;

    if (result == NULL) return or_fail;

    status = get_master_socket_url(buf, sizeof(buf) - 1, from);
    if (status != or_okay) return status;
    status = ipc_connect_to_stream_server(buf, NULL, &client);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_INFO, "Cannot connect to %lld via '%s': %s",
                (long long)from, buf, get_operation_result_str(status));
        return status;
    }
    PYSAMPROF_LOG(PL_INFO, "app2app connected to %lld via '%s'", (long long)from, buf);

    msg.head.size = sizeof(msg);
    msg.head.version = IPC_NG_HEADER_VERSION;
    msg.head.type = ipc_message_command_with_pid_type;
    msg.head.data_offset = offsetof(ipc_message_command_with_pid_t, body);

    msg.body.command = ck_get_server_pid;
    msg.body.pid = 0;

    status = ipc_send_message(client, &(msg.head));
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send message via '%s': %s",
                buf, get_operation_result_str(status));
        ipc_disconnect_from_server(client);
        return status;
    }
    PYSAMPROF_LOG(PL_INFO, "app2app sent server pid request to %lld", (long long)from);

    status = ipc_receive_message(client, &response);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get response from '%s': %s",
                buf, get_operation_result_str(status));
        ipc_disconnect_from_server(client);
        return status;
    }

    GET_MESSAGE_BODY(response, command_with_pid, response_body, status);
    if (status == or_okay)
    {
        if (response_body->command != ck_set_server_pid)
        {
            PYSAMPROF_LOG(PL_ERROR, "Unexpected response command: %d", response_body->command);
            status = or_ipc_bad_message;
        }
        else if (response_body->pid <= 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Non-positive server pid: %lld", (long long)response_body->pid);
            status = or_invalid_parameter;
        }
        else
        {
            *result = (ps_pid_t)(response_body->pid);
            PYSAMPROF_LOG(PL_INFO, "app2app got server pid from %lld, server: %lld",
                (long long)from, (long long)(*result));
        }
    }
    ipc_free_message(response);
    ipc_disconnect_from_server(client);
    return status;
}

operation_result_t get_server_info(server_info_t* result)
{
    operation_result_t res = or_okay;
    ps_pid_t pid, ppid, server_pid;
    int found_parent = 0;

    if (result == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "get_server_info() got result == NULL");
        return or_fail;
    }

    pid = getpid();

    while (found_parent == 0)
    {
        res = get_parent_pid(pid, &ppid);
        if (res != or_okay)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot get parent pid: %s",
                    get_operation_result_str(res));
            if (res == or_no_such_process) break; // process <pid> or its parent does not exist
            return res;
        }

        // TODO: check that this 'if' is valid on Windows
        if (ppid == 1 || ppid == 0) break;

        PYSAMPROF_LOG(PL_INFO, "Sending 'get server' request to %lld", (long long)ppid);
        res = request_server_info(ppid, &server_pid);
        switch (res)
        {
            case or_ipc_socket_failure:
                // this parent has no communication set up, go higher in the tree
                pid = ppid;
                continue;
            case or_okay:
                found_parent = 1;
                break;
            default:
                // something bad happened :(
                PYSAMPROF_LOG(PL_ERROR, "Unexpected result of requesting " \
                        "server pid from parent: %s", get_operation_result_str(res));
                return res;
        }
    }

    if (found_parent == 0)
    {
        // no server present
        PYSAMPROF_LOG(PL_INFO, "no server present in current session");
        result->pid = 0;
    }
    else
    {
        result->pid = server_pid;
        PYSAMPROF_LOG(PL_INFO, "Found pysamprof server in current session, pid: %lld", (long long)server_pid);
        return res;

    }

    return or_okay;
}

static void on_app2app_server_start(ipc_server_data_t* server, void* user_data)
{
    // mark thread as a service one
    mark_current_thread_as_service();
}

void on_app2app_server_new_client(ipc_server_data_t* server,
        ipc_client_data_t* new_client, void* user_data, void** client_user_data)
{
    // mark thread as a service one
    mark_current_thread_as_service();
}

static void app2app_pause_resume_stop(collection_state_t next_state)
{
    operation_result_t status;
    collection_state_t current_state;

    PYSAMPROF_LOG(PL_INFO, "Handling pause/resume/stop, next state=%d", next_state);

    status = grab_collection_state(&current_state);
    CHECK_AND_REPORT_ERROR(status, "Cannot grab collection state from collector",);

    switch (current_state)
    {
    case cs_stopped:
        PYSAMPROF_LOG(PL_ERROR, "Cannot pause/resume/stop from stopped state");
        break;
    case cs_running:
        switch (next_state)
        {
        case cs_paused: // FALLTHROUGH
        case cs_stopped:
            status = pysamprof_stop_collection(0, next_state);
            CHECK_AND_REPORT_ERROR(status, "Cannot pause or stop collection",);
            PYSAMPROF_LOG(PL_INFO, "Collection successfully %s",  (next_state == cs_paused) ? "paused" : "stopped");
            break;
        default:
            PYSAMPROF_LOG(PL_ERROR, "Cannot change state from running to %d", next_state);
        }
    case cs_paused:
        switch (next_state)
        {
        case cs_paused:
            PYSAMPROF_LOG(PL_ERROR, "Cannot pause from paused state");
            break;
        case cs_running:
            {
                int rate_msec, signo;
                status = grab_sampling_params(&rate_msec, &signo);
                CHECK_AND_REPORT_ERROR(status, "Cannot grab sampling params from collector",);
                status = pysamprof_enable_collection(cs_running, NULL, rate_msec, signo, 0);
                CHECK_AND_REPORT_ERROR(status, "Cannot resume collection",);
                PYSAMPROF_LOG(PL_INFO, "Collection successfully resumed");
                break;
            }
        case cs_stopped:
            status = pysamprof_stop_collection(0, cs_stopped);
            CHECK_AND_REPORT_ERROR(status, "Cannot stop collection",);
            PYSAMPROF_LOG(PL_INFO, "Collection successfully stopped");
            break;
        }
    default:
        PYSAMPROF_LOG(PL_ERROR, "Got unexpected current state=%d", current_state);
    }
}

static void on_app2app_command(ipc_message_command_with_pid_body_t* msg,
        ipc_client_data_t* requester)
{
    PYSAMPROF_LOG(PL_INFO, "Got app2app command message, command=%d, pid=%lld", msg->command, (long long)msg->pid);
    switch (msg->command)
    {
    case ck_get_server_pid:
        {
            ipc_message_command_with_pid_t msg;
            operation_result_t status;

            PYSAMPROF_LOG(PL_INFO, "Processing 'get server' request");

            msg.head.size = sizeof(msg);
            msg.head.version = IPC_NG_HEADER_VERSION;
            msg.head.type = ipc_message_command_with_pid_type;
            msg.head.data_offset = offsetof(ipc_message_command_with_pid_t, body);

            msg.body.command = ck_set_server_pid;
            msg.body.pid = (int64_t)(g_server_info.pid);

            status = ipc_send_message(requester, &(msg.head));
            if (status != or_okay)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot send 'set server' response: %s",
                        get_operation_result_str(status));
            }
            break;
        }
    case ck_set_server_pid:
        PYSAMPROF_LOG(PL_ERROR, "Cannot set server from outside for now");
        break;
    case ck_pause_collection:
        app2app_pause_resume_stop(cs_paused);
        break;
    case ck_resume_collection:
        app2app_pause_resume_stop(cs_running);
        break;
    case ck_stop_collection:
        app2app_pause_resume_stop(cs_stopped);
    default:
        PYSAMPROF_LOG(PL_ERROR, "Got unexpected app2app command");
    }
}

static void on_app2app_start_command(ipc_message_start_command_body_t* msg)
{
    operation_result_t status = pysamprof_enable_collection(cs_running, &(msg->result_path[0]),
        msg->period / 1000000LL /* convert nano to milli */, msg->signo, 0);
    CHECK_AND_REPORT_ERROR(status, "Cannot start collection per remote request",);
    PYSAMPROF_LOG(PL_INFO, "Collection started per remote request to '%s' with %d ms period",
        &(msg->result_path[0]), msg->period / 1000000LL);
}

static void on_app2app_server_message(ipc_server_data_t* server,
        ipc_client_data_t* from, ipc_message_header_t* message,
        void* server_data, void* client_data)
{
    if (message->version < IPC_NG_HEADER_VERSION)
    {
        PYSAMPROF_LOG(PL_ERROR, "Message version too old: %d, expect at least %d",
                message->version, IPC_NG_HEADER_VERSION);
    };

    switch (message->type)
    {
    case ipc_message_command_with_pid_type:
        {
            ipc_message_command_with_pid_body_t* body = \
                (ipc_message_command_with_pid_body_t*)((char*)message + message->data_offset);
            on_app2app_command(body, from);
            break;
        }
    case ipc_message_start_command_type:
        {
            ipc_message_start_command_body_t* body = \
                (ipc_message_start_command_body_t*)((char*)message + message->data_offset);
            on_app2app_start_command(body);
        }
        break;
    default:
        PYSAMPROF_LOG(PL_ERROR, "Unexpected message type %d", message->type);
    }
}

static void close_handle_on_exit(void)
{
    if (s_server_pointer_arg.app2app_server != NULL)
    {
        operation_result_t res = ipc_stop_server(s_server_pointer_arg.app2app_server);
        if (res != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot stop app2app server: %s",
                    get_operation_result_str(res));
        }
    }
}

#ifdef __linux__
static void after_fork_in_child()
{
    if (s_server_pointer_arg.state == pts_spawning_master)
    {
        // service fork(), will become master server soon, don't setup any threads
        return;
    }
    if (s_server_pointer_arg.state != pts_complete)
    {
        PYSAMPROF_LOG(PL_ERROR, "fork() before server whereabouts were known");
        return;
    }
    operation_result_t res = setup_server_pointer_thread();
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot re-establish app2app server after fork: %s",
                get_operation_result_str(res));

    }
}

static int s_atexit_is_setup = 0;
static int s_atfork_is_setup = 0;
#endif

operation_result_t setup_server_pointer_thread()
{
    char buf[256];
    operation_result_t res;
    ipc_server_data_t* server;
    ipc_server_callbacks_t callbacks;

    s_server_pointer_arg.state = pts_not_started;
    s_server_pointer_arg.app2app_server = NULL;
#ifdef __linux__
    if (s_atexit_is_setup == 0)
#endif
    {
        if (atexit(close_handle_on_exit) != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot register atexit handle cleanup");
            return or_fail;
        }
    }
#ifdef __linux__
    s_atexit_is_setup = 1;
    if (s_atfork_is_setup == 0)
    {
        int err = pthread_atfork(NULL, NULL, after_fork_in_child);
        if (err != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "cannot register atfork handler "\
                    "for pointer thread, err: %d", err);
            return or_fail;
        }
        s_atfork_is_setup = 1;
    }
#endif

    res = get_master_socket_url(buf, sizeof(buf) - 1, getpid());
    if (res != or_okay) return res;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.on_server_start = on_app2app_server_start;
    callbacks.on_client_connect = on_app2app_server_new_client;
    callbacks.on_new_message = on_app2app_server_message;

    res = ipc_start_stream_server(buf, callbacks, &server);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot start app2app server: %s",
                get_operation_result_str(res));
        return res;
    }
    res = ipc_detach_server(server);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot detach app2app server thread: %s",
                get_operation_result_str(res));
        return res;
    }
    s_server_pointer_arg.app2app_server = server;
    s_server_pointer_arg.state = pts_no_server_info;

    return or_okay;
}

operation_result_t set_server_pointer_info(server_info_t info)
{
    if (s_server_pointer_arg.state != pts_no_server_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Pointer thread in unexpected state %d",
                (int)s_server_pointer_arg.state);
        return or_fail;
    }
    g_server_info = info;
    s_server_pointer_arg.state = pts_complete;
    return or_okay;
}

static operation_result_t start_master_server_process(server_info_t* result, const char* server_path)
{
    if (result == NULL) return or_fail;
#ifdef __linux__
    // TODO: do double-fork trick so server is never a zombie
    pointer_thread_state_t old_state = s_server_pointer_arg.state;
    s_server_pointer_arg.state = pts_spawning_master;
    pid_t pid = fork();
    PYSAMPROF_LOG(PL_INFO, "forked to spawn a server, resulting pid=%lld", (long long)pid);
    s_server_pointer_arg.state = old_state;
    char* const argv[] = {strdup(server_path), NULL};
    if (argv[0] == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot strdup() path to server");
        return or_insufficient_memory;
    }
    switch (pid)
    {
        case 0:
            // child, do exec
            execv(server_path, argv);
            PYSAMPROF_LOG(PL_ERROR, "failed to execv a '%s' as pysamprof server", server_path);
            // should not return
            return or_fail;
        case -1:
            // error
            PYSAMPROF_LOG(PL_ERROR, "Cannot fork() to spawn server, errno: %d", errno);
            free(argv[0]);
            return or_fail;
        default:
            // parent
            break;
    }
    free(argv[0]);

    // ignore SIGCHLD so server dont become a zombie
    // this is BAD, just a hack around current bugs
    struct sigaction sigchld_action = {
        .sa_handler = SIG_DFL,
        .sa_flags = SA_NOCLDWAIT
    };
    sigaction(SIGCHLD, &sigchld_action, NULL);

    result->pid = pid;
#elif defined(_WIN32)
    {
        PROCESS_INFORMATION pi;
        STARTUPINFO si;

        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);

        if (!CreateProcess(server_path, NULL, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi))
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot spawn server '%s', error: %ld", server_path, GetLastError());
            return or_fail;
        }
        result->pid = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
#else
#error Unsupported platform
#endif

    // FIXME: really wait for server to become available, maybe by (again) trying to connect to it.
    //        for now just sleeping for a bit. UGLY HACK!!
    msleep(200);

    return or_okay;
}

operation_result_t spawn_master_server(all_memory_regions_t regions, server_info_t* result)
{
    int index, written;
    char *pyext_path, *buf, *last_slash;
#ifndef _WIN32
    const char pathsep = '/';
    char server_name[] = "/pysamprof-server";
#else
    const char pathsep = '\\';
    char server_name[] = "\\pysamprof-server.exe";
#endif
    size_t needed;
    operation_result_t res;

    if (regions.regions == NULL || regions.count <= 0 || result == NULL) return or_fail;

    res = find_memory_region(spawn_master_server, regions, &index);
    CHECK_AND_REPORT_ERROR(res, "Cannot find pysamprof-containing region", res);
    pyext_path = strdup(regions.regions[index].filename);
    if (pyext_path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot copy pysamprof path");
        return or_insufficient_memory;
    }
#ifdef _WIN32
    // replace '/' with pathsep on Windows
    {
        char* current;
        for (current = pyext_path; *current != '\0'; current++)
        {
            if (*current == '/') *current = pathsep;
        }
    }
#endif

    PYSAMPROF_LOG(PL_INFO, "Pysamprof path: %s", pyext_path);
    last_slash = strrchr(pyext_path, pathsep);
    if (last_slash == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Path to pysamprof ('%s') is not absolute", pyext_path);
        free(pyext_path);
        return or_cannot_open_file;
    }
    *last_slash = '\0';
    needed = strlen(pyext_path) + sizeof(server_name) + 1 /* for NULL */;
    buf = (char*)malloc(needed);
    if (buf == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate buffer "
                "for path to server");
        free(pyext_path);
        return or_insufficient_memory;
    }
    written = snprintf(buf, needed, "%s%s", pyext_path, server_name);
    free(pyext_path);
    if (written < 0 || buf[written] != '\0')
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot compose path to server");
        free(buf);
        return or_cannot_open_file;
    }
    PYSAMPROF_LOG(PL_INFO, "Composed path to server: %s", buf);

    // no server present, create one
    res = start_master_server_process(result, buf);
    free(buf);
    CHECK_AND_REPORT_ERROR(res, "Cannot start master server process", res);
    res = set_server_pointer_info(*result);
    CHECK_AND_REPORT_ERROR(res, "Cannot set pointer thread server info", res);

    return or_okay;
}