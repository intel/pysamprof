#define _POSIX_C_SOURCE 201709L

#include <ipc-ng/ipc-ng.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef __linux__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <safe_str_lib.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include "../common/logging/logging.h"
#include "../common/utilities/inttype_helper.h"
#include "../common/utilities/utilities.h"

#ifdef _MSC_VER
// shut up about strdup() warning
#define strdup(x) _strdup(x)
#endif

#ifdef __linux__
static pthread_mutex_t s_list_lock;
#define LOCK_LIST pthread_mutex_lock(&s_list_lock)
#define UNLOCK_LIST pthread_mutex_unlock(&s_list_lock)

static long s_pagesize = -2;
#define ENSURE_PAGESIZE     \
    if (s_pagesize == -2) s_pagesize = sysconf(_SC_PAGESIZE);

#define THREADFUNC(func, argname) void* func(void* argname)
#define RETURN_THREAD return NULL;

typedef pthread_t thread_handle_t;

#elif defined(_WIN32)
static CRITICAL_SECTION s_list_lock;
#define LOCK_LIST EnterCriticalSection(&s_list_lock)
#define UNLOCK_LIST LeaveCriticalSection(&s_list_lock)
static long s_pagesize = -2;
#define ENSURE_PAGESIZE                         \
    if (s_pagesize == -2)                       \
    {                                           \
        SYSTEM_INFO si;                         \
        GetSystemInfo(&si);                     \
        s_pagesize = si.dwAllocationGranularity;\
    }

#define THREADFUNC(func, argname) DWORD WINAPI func(void* argname)
#define RETURN_THREAD return 0;

typedef HANDLE thread_handle_t;

#else
#error Unsupported platform
#endif

typedef struct
{
    void* addr;
    uint16_t channel_count;
    uint16_t channel_size;
} shmem_data_t;

struct ipc_client_data_t
{
    ipc_server_type_t type;
    ipc_server_data_t* server;
    char* path;
    shmem_data_t shmem;
    uint16_t last_shmem_index;
#ifdef __linux__
    int client_fd;
#elif defined(_WIN32)
    HANDLE client_fd;
#else
#error Unsupported platform
#endif
    thread_handle_t thread;
    volatile int stop_flag;
    void* client_data;

    ipc_client_data_t* prev;
    ipc_client_data_t* next;
};

struct ipc_server_data_t
{
    ipc_server_type_t type;
    char* path;
    shmem_data_t shmem;
    uint32_t minimal_latency_usec;
#ifdef __linux__
    int server_fd;
#elif defined(_WIN32)
    HANDLE server_fd;
    CRITICAL_SECTION fd_mutex;
#else
#error Unsupported platform
#endif
    thread_handle_t thread;
    ipc_server_callbacks_t callbacks;
    volatile int stop_flag;

    ipc_client_data_t* clients;
    ipc_server_data_t* next;
};

struct ipc_server_join_data_t {
    thread_handle_t thread;
};

typedef enum
{
    scs_empty = 0,
    scs_taken,
    scs_ready
} shmem_channel_state_t;

#pragma pack(push, 1)
// Use the following structure to descibe a channel.
// Note that its size must not be more than ALIGNMENT_BYTES.
typedef struct
{
    volatile shmem_channel_state_t state;
} shmem_channel_header_t;
#pragma pack(pop)
#define ALIGNMENT_BYTES 16

static ipc_server_data_t* s_servers = NULL;

static operation_result_t disconnect_from_stream_server(ipc_client_data_t* client);
static void stop_all_clients(ipc_server_data_t* server, int immediate_stop);

static void free_ipc_server(ipc_server_data_t* server)
{
    if (server == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "argument is NULL");
        return;
    }
    if (server->clients != NULL || server->next != NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Freeing server that was not properly stopped");
    }
#ifdef __linux__
    if (server->type == ist_shmem)
    {
        size_t buffer_size = server->shmem.channel_count * server->shmem.channel_size;
        if (munmap(server->shmem.addr, buffer_size) == -1)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot munmap shmem, errno: %d", errno);
        }
        else
        {
            PYSAMPROF_LOG(PL_INFO, "Unmapped shmem during server freeing");
        }
    }
    close(server->server_fd);
#elif defined(_WIN32)
    if (server->type == ist_stream)
    {
        DeleteCriticalSection(&(server->fd_mutex));
    }
#else
#error Unsupported platform
#endif
    free(server->path);
    free(server);
}

#ifdef __linux__
static void before_fork()
{
    LOCK_LIST;
}
static void after_fork_in_parent()
{
    UNLOCK_LIST;
}
static void after_fork_in_child()
{
    PYSAMPROF_LOG(PL_INFO, "Handling fork in child: stopping and removing IPC servers");
    ipc_server_data_t *server = s_servers, *next = NULL;
    while (server != NULL)
    {
        next = server->next;
        PYSAMPROF_LOG(PL_INFO, "Removing %p IPC server", server);
        stop_all_clients(server, 1);
        server->next = NULL;
        free_ipc_server(server);
        server = next;
    }
    s_servers = NULL;
    UNLOCK_LIST;
    PYSAMPROF_LOG(PL_INFO, "All IPC servers cleaned up");
}
#endif

operation_result_t init_ipc_innards()
{
#ifdef __linux__
    int res = pthread_mutex_init(&s_list_lock, NULL);
    if (res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot initialize mutex for ipc, result: %d",
                res);
        return or_fail;
    }

    res = pthread_atfork(before_fork, after_fork_in_parent, after_fork_in_child);
    if (res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot register atfork() callbacks in " \
                "ipc, result: %d", res);
        return or_fail;
    }
#elif defined(_WIN32)
    InitializeCriticalSection(&s_list_lock);
#else
#error Unsupported platform
#endif
    return or_okay;
}

// Unsynchronized function; call with list lock taken
static void remove_client_from_lists(ipc_client_data_t* client)
{
    if (client == NULL) return;
    // make sure we don't mess the pointer at the list in the server
    if (client->server != NULL && client->server->clients == client)
    {
        client->server->clients = (client->next != NULL) ? client->next : client->prev;
    }
    // remove ourselves from the list of clients
    if (client->prev != NULL) client->prev->next = client->next;
    if (client->next != NULL) client->next->prev = client->prev;
}

// Unsynchronized function; call with list lock taken
static void add_client_to_lists(ipc_client_data_t* client)
{
    if ((client != NULL) && (client->server != NULL))
    {
        client->next = client->server->clients;
        client->prev = NULL;
        if (client->server->clients != NULL)
        {
            client->server->clients->prev = client;
        }
        client->server->clients = client;
    }
}

// Unsynchronized function; call with list lock taken
// NOTE: immediate_stop != 0 only on fork
static void stop_all_clients(ipc_server_data_t* server, int immediate_stop)
{
    ipc_client_data_t* client;

    if (server == NULL) return;
    client = server->clients;
    while (client != NULL)
    {
        ipc_client_data_t* next = client->next;
        remove_client_from_lists(client);
        client->stop_flag = 1;
#ifdef __linux__
        if (immediate_stop)
        {
            int res = close(client->client_fd);
            if (res == -1)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot close client %p socket %d, " \
                        "errno: %d", client, client->client_fd, errno);
            }
            free(client->path);
            free(client);
        }
        else
        {
            int res = shutdown(client->client_fd, SHUT_RDWR);
            if (res == -1)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot stop client %p: error " \
                        "shutting down socket: errno %d", client, errno);
            }
        }
#elif defined(_WIN32)
#define PERFORM_ACTION(func)            \
        if (!func(client->client_fd))   \
        {                               \
            PYSAMPROF_LOG(PL_ERROR, "Error calling " #func " on pipe %p, error: %d", client->client_fd, GetLastError()); \
        }
        PERFORM_ACTION(DisconnectNamedPipe)
        PERFORM_ACTION(CloseHandle)
        client->client_fd = NULL;
#undef PERFORM_ACTION
#else
#error Unsupported platform
#endif
        // cannot do "client->next" here as remove_client_from_lists()
        // will invalidate "client->next"
        client = next;
    }
    server->clients = NULL;
}

// Synchronized function; DO NOT LOCK LIST yourself
static void add_server_to_list(ipc_server_data_t* server)
{
    LOCK_LIST;
    if (server != NULL) {
        server->next = s_servers;
        s_servers = server;
    }
    UNLOCK_LIST;
}

#ifdef __linux__
static operation_result_t read_till_full(int fd, void* buf, uint32_t size,
        const char* client_name)
{
    char* target = (char*)buf;
    uint32_t offset = 0;
    while (offset < size)
    {
        ssize_t got_amount = read(fd, (void*)(target + offset),
                size - offset);
        if (got_amount == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            PYSAMPROF_LOG(PL_INFO, "Cannot read data for '%s' client, " \
                    "errno: %d", client_name, errno);
            return or_ipc_socket_failure;
        }
        if (got_amount == 0)
        {
            PYSAMPROF_LOG(PL_INFO, "EOF reached when reading " \
                    "data from '%s' => client disconnected", client_name);
            return or_ipc_unexpected_eof;
        }
        offset += got_amount;
    }
    return or_okay;
}
#elif defined(_WIN32)
static operation_result_t read_till_full(HANDLE pipe, void* buf, uint32_t size,
        const char* client_name)
{
    char* target = buf;
    uint32_t offset = 0;
    while (offset < size)
    {
        DWORD got_amount;
        BOOL read_okay = ReadFile(pipe, (void*)(target + offset), size - offset, &got_amount, NULL);
        if (!read_okay || got_amount == 0)
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                PYSAMPROF_LOG(PL_INFO, "EOF reached when reading " \
                        "data from '%s' => client disconnected", client_name);
                return or_ipc_unexpected_eof;
            }
            else
            {
                PYSAMPROF_LOG(PL_INFO, "Cannot read data for '%s' client, " \
                        "error: %ld", client_name, GetLastError());
                return or_ipc_socket_failure;
            }
        }
        offset += got_amount;
    }
    return or_okay;
}
#else
#error Unsupported platform
#endif

static operation_result_t receive_from_stream(ipc_client_data_t* client,
        const char* path, ipc_message_header_t** result)
{
    uint32_t message_size;
    ipc_message_header_t* message = NULL;

    operation_result_t status = read_till_full(client->client_fd,
            &message_size, sizeof(message_size), path);
    if (status != or_okay) return status;
    message = (ipc_message_header_t*)malloc(message_size);
    if (message == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory (%d) for new message " \
                "for '%s' client", message_size, path);
        // TODO: handle this better, e.g. by reading (and losing) this message;
        //       current implementation will break reading further messages.
        return or_insufficient_memory;
    }
    message->size = message_size;
    status = read_till_full(client->client_fd,
            (void*)((char*)message + sizeof(message_size)),
            message_size - sizeof(message_size), path);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot read message for '%s' client: %s",
                path, get_operation_result_str(status));
        free(message);
        return status;
    }
    if (message->data_offset > message_size)
    {
        PYSAMPROF_LOG(PL_ERROR, "Got invalid message for '%s' client: data_offset (%lld) > message_size (%lld)",
                path, (long long)message->data_offset, (long long)message_size);
        free(message);
        return or_invalid_parameter;
    }

    *result = message;
    return or_okay;
}

static THREADFUNC(client_thread, arg)
{
    ipc_client_data_t* data = (ipc_client_data_t*)arg;
    if (data != NULL)
    {
        if (data->server != NULL)
        {
            operation_result_t status = or_okay;

            LOCK_LIST;
            add_client_to_lists(data);
            UNLOCK_LIST;

            if (data->server->callbacks.on_client_connect)
            {
                data->server->callbacks.on_client_connect(data->server,
                                data, data->server->callbacks.on_client_connect_data,
                                &(data->client_data));
            }

            while (1)
            {
                ipc_message_header_t* message = NULL;
                status = receive_from_stream(data, data->server->path, &message);
                if (status != or_okay) break;
                if (data->server->callbacks.on_new_message && message)
                {
                    data->server->callbacks.on_new_message(data->server,
                                    data, message,
                                    data->server->callbacks.on_new_message_data,
                                    data->client_data);
                }
                free(message);
            }
            if (data->stop_flag && status == or_ipc_socket_failure)
            {
                PYSAMPROF_LOG(PL_INFO, "Processing 'stop request' for client");
            }
            else if (status == or_ipc_unexpected_eof)
            {
                PYSAMPROF_LOG(PL_INFO, "Got EOF");
            }
            else
            {
                PYSAMPROF_LOG(PL_ERROR, "Got unexpected status while reading " \
                          "for stream client: %s", get_operation_result_str(status));
            }

            if (data->server->callbacks.on_client_disconnect)
            {
                data->server->callbacks.on_client_disconnect(data->server,
                                data, data->server->callbacks.on_client_disconnect_data,
                                data->client_data);
            }
        }
            LOCK_LIST;
            disconnect_from_stream_server(data);
            UNLOCK_LIST;
    }
    RETURN_THREAD;
}

static void remove_server_from_lists(ipc_server_data_t* server)
{
    ipc_server_data_t *leaf, *prev = NULL;

    LOCK_LIST;
    leaf = s_servers;
    while (leaf != NULL && leaf != server && leaf->next != NULL)
    {
        prev = leaf;
        leaf = leaf->next;
    }
    if (leaf != server)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot find server in the list");
    }
    else
    {
        if (prev == NULL)
        {
            s_servers = server->next;
        }
        else
        {
            prev->next = server->next;
        }
    }
    UNLOCK_LIST;
}

static THREADFUNC(stream_service_thread, arg)
{
#ifdef _WIN32
    pysamprof_security_attrs_t sattrs;
    operation_result_t status;

    status = create_tight_security_attrs(&sattrs);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create security attributes for named pipe: %s", get_operation_result_str(status));
        RETURN_THREAD;
    }
#endif
    if (arg != NULL)
    {
        ipc_server_data_t* data = (ipc_server_data_t*)arg;
        if (data->callbacks.on_server_start)
        {
            data->callbacks.on_server_start(data, data->callbacks.on_server_start_data);
        }
        while (1)
        {
// TODO: lots of copy-paste below, try to generalize a bit
#ifdef __linux__
            struct sockaddr_un from_addr;
            socklen_t from_len = sizeof(from_addr);
            int client_fd = accept(data->server_fd, (struct sockaddr*)&from_addr, &from_len);
            if (client_fd == -1)
            {
                PYSAMPROF_LOG(PL_INFO, "client_fd==-1, stop_flag: %d", data->stop_flag);
                if (data->stop_flag)
                {
                    PYSAMPROF_LOG(PL_INFO, "Processing 'server stop' request");
                    break;
                }

                int saved_errno = errno;
                PYSAMPROF_LOG(PL_WARNING, "Cannot accept() a connection, errno: %d",
                        saved_errno);
                switch (saved_errno)
                {
                    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
                    case EWOULDBLOCK:
#endif
                    case EINTR:
                    case EMFILE:
                    case ENFILE:
                    case ENOBUFS:
                    case ENOMEM:
                    case EPROTO:
                    case ENETDOWN:
                    case ENOPROTOOPT:
                    case EHOSTDOWN:
                    case ENONET:
                    case EHOSTUNREACH:
                    case EOPNOTSUPP:
                    case ENETUNREACH:
                    case ECONNRESET:
                        // just retry accepting
                        continue;
                    default:
                        break;
                }
                break;
            }

            ipc_client_data_t* client = (ipc_client_data_t*)malloc(sizeof(ipc_client_data_t)); 
            if (client == NULL)
            {
                PYSAMPROF_LOG(PL_ERROR, "Not enough memory to allocate client data " \
                        "in main stream ipc thread");
                close(client_fd);
                continue;
            }
            memset(client, 0, sizeof(ipc_client_data_t));
            client->type = ist_stream;
            client->client_fd = client_fd;
            client->path = strdup(from_addr.sun_path);
            if (client->path == NULL)
            {
                free(client);
                close(client_fd);
                PYSAMPROF_LOG(PL_ERROR, "Not enough memory to copy path to client data");
                continue;
            }
            client->server = data;
            int res = pthread_create(&client->thread, NULL, client_thread, client);
            if (res != 0)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot spawn thread for communicating " \
                        "with client, result: %d", res);
                free(client->path);
                free(client);
                close(client_fd);
                continue;
            }
#elif defined(_WIN32)
#define BREAK_IF_STOP(msg)                       \
    if (data->stop_flag)                         \
    {                                            \
        PYSAMPROF_LOG(PL_INFO, "Processing 'server stop' request from <%s> block", msg); \
        if (data->server_fd != NULL) CloseHandle(data->server_fd);                       \
        data->server_fd = NULL;                  \
        LeaveCriticalSection(&(data->fd_mutex)); \
        break;                                   \
    }

            // main pipe loop
            HANDLE pipe;
            {
                // this block is synchronized over data->fd_mutex
                EnterCriticalSection(&(data->fd_mutex));
                BREAK_IF_STOP("loop start");

                pipe = CreateNamedPipe(data->path,
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES, 512, 512, 0, &(sattrs.attrs));
                if (pipe == INVALID_HANDLE_VALUE)
                {
                    PYSAMPROF_LOG(PL_ERROR, "Cannot create named pipe '%s', error: %ld", data->path, GetLastError());
                    LeaveCriticalSection(&(data->fd_mutex));
                    break;
                }
                PYSAMPROF_LOG(PL_INFO, "Created named pipe '%s'", data->path);
                data->server_fd = pipe;
                BREAK_IF_STOP("pipe just created");
                LeaveCriticalSection(&(data->fd_mutex));
            }

            if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED)
            {
                ipc_client_data_t* client;

                {
                    // this block is synchronized over data->fd_mutex
                    EnterCriticalSection(&(data->fd_mutex));
                    BREAK_IF_STOP("client connected");
                    data->server_fd = NULL;
                    LeaveCriticalSection(&(data->fd_mutex));
                }

                client = (ipc_client_data_t*)malloc(sizeof(ipc_client_data_t));
                if (client == NULL)
                {
                    PYSAMPROF_LOG(PL_ERROR, "Not enough memory to allocate client data " \
                            "in main stream ipc thread");
                    CloseHandle(pipe);
                    continue;
                }
                memset(client, 0, sizeof(ipc_client_data_t));
                client->type = ist_stream;
                client->client_fd = pipe;
                client->path = strdup(data->path);
                if (client->path == NULL)
                {
                    free(client);
                    CloseHandle(pipe);
                    PYSAMPROF_LOG(PL_ERROR, "Not enough memory to copy path to client data");
                    continue;
                }
                client->server = data;

                client->thread = CreateThread(NULL, 0, client_thread, (void*)client, 0, NULL);
                if (client->thread == NULL)
                {
                    PYSAMPROF_LOG(PL_ERROR, "Cannot spawn thread for communicating with client, error: %d", GetLastError());
                    free(client->path);
                    free(client);
                    CloseHandle(pipe);
                    continue;
                }
            }
            else
            {
                DWORD lastError = GetLastError();
                // failed to wait for client to connect to the pipe
                EnterCriticalSection(&(data->fd_mutex));
                BREAK_IF_STOP("client failed to connect");
                LeaveCriticalSection(&(data->fd_mutex));
                PYSAMPROF_LOG(PL_WARNING, "Cannot wait for client to connect to pipe '%s', error: %ld", data->path, lastError);
                CloseHandle(pipe);
            }
#undef BREAK_IF_STOP

#else
#error Unsupported platform
#endif
        }

        LOCK_LIST;

        {
            int client_count = 0;
            ipc_client_data_t* client = NULL;
            thread_handle_t* threads = NULL;

            for(client = data->clients; client != NULL; client = client->next) client_count++;
            if (client_count > 0)
            {
                threads = (thread_handle_t*)malloc((sizeof(thread_handle_t) * client_count));
                if (threads == NULL)
                {
                    PYSAMPROF_LOG(PL_ERROR, "Insufficient memory: cannot gather " \
                            "client threads to wait for");
                }
                else
                {
                    thread_handle_t* thread = threads;
                    for(client = data->clients; client != NULL; client = client->next, thread++)
                    {
                        *thread = client->thread;
#ifdef _WIN32
                        // If client->thread != NULL disconnect_from_server() will close that handle
                        // during stopping, so after we have waited for it to stopthe handle becomes
                        // invalid, thus CloseHandle() cannot be called on it.
                        // So we explicitly set this handle to NULL to indicate we'll close it ourselves
                        client->thread = NULL;
#endif
                    }
                }
            }

            stop_all_clients(data, 0);
            UNLOCK_LIST;

            if (threads != NULL)
            {
                thread_handle_t* current = threads;
                int i;
                for (i = 0; i < client_count; i++, current++)
                {
                    long long res = 0;
#ifdef __linux__
                    res = pthread_join(*current, NULL);
#elif defined(_WIN32)
                    if (WaitForSingleObject(*current, INFINITE) == WAIT_FAILED)
                    {
                        res = GetLastError();
                    }
                    CloseHandle(*current);
#else
#error Unsupported platform
#endif
                    if (res != 0)
                    {
                        PYSAMPROF_LOG(PL_ERROR, "Cannot join client thread, result: %lld", res);
                    }
                }
                free(threads);
            }
        }

        if (data->callbacks.on_server_stop)
        {
            data->callbacks.on_server_stop(data, data->callbacks.on_server_stop_data);
        }

#ifdef __linux__
        int res = close(data->server_fd);
        if (res == -1)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot close socket %d during " \
                    "stream server stop, errno :%d", data->server_fd, errno);
        }
        res = unlink(data->path);
        if (res == -1)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot remove socket file '%s' " \
                    "during stream server stop, errno: %d", data->path, errno);
        }
        else
        {
            PYSAMPROF_LOG(PL_INFO, "Removed socket file '%s' during " \
                    "stream server stop", data->path);
        }
#elif defined(_WIN32)
        DeleteCriticalSection(&(data->fd_mutex));
        status = free_security_attrs(&sattrs);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot free security attributes for named pipe: %s", get_operation_result_str(status));
        }
#else
#error Unsupported platform
#endif
        remove_server_from_lists(data);

        free(data->path);
        free(data);
    }

    RETURN_THREAD;
}

#ifdef __linux__
static int start_new_service_thread(pthread_t *thread,
        void *(*start_routine) (void *), void *arg)
{
    //TODO: generalize with same concept made in pyext/signal_manager.c:install_signal_handler
    // block all signals except a few key ones
  if (thread == NULL) return EINVAL;
    sigset_t mask, old_mask;
    sigfillset(&mask);
    sigdelset(&mask, SIGSEGV);
    sigdelset(&mask, SIGBUS);
    sigdelset(&mask, SIGFPE);
    sigdelset(&mask, SIGILL);

    // block almost every signal in service thread and unblock after spawning
    sigprocmask(SIG_SETMASK, &mask, &old_mask);
    int result = pthread_create(thread, NULL, start_routine, arg);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    return result;
}
#endif

#ifdef _WIN32
static const char* s_pipe_start = "\\\\.\\pipe\\LOCAL\\";
#define CHECK_STREAM_PATH(path)                                 \
    if (strncmp(path, s_pipe_start, strlen(s_pipe_start)) != 0) \
    {                                                           \
        PYSAMPROF_LOG(PL_ERROR, "Stream path should start with '%s', got '%s' instead", s_pipe_start, path); \
        return or_cannot_open_file;                             \
    }
#elif defined(__linux__)
#define CHECK_STREAM_PATH(path)                                     \
    if (strlen(path) >= sizeof(((struct sockaddr_un*)0)->sun_path)) \
    {                                                               \
        PYSAMPROF_LOG(PL_ERROR, "Too long path '%s' specified, should be shorter than %d", \
                path, sizeof(((struct sockaddr_un*)0)->sun_path));  \
        return or_cannot_open_file;                                 \
    }
#else
#error Unsupported platform
#endif

static operation_result_t start_stream_server(const char* path,
        ipc_server_callbacks_t callbacks, ipc_server_data_t** result)
{
    ipc_server_data_t* server;

    CHECK_STREAM_PATH(path);
    server = (ipc_server_data_t*)malloc(sizeof(ipc_server_data_t));
    if (server == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for ipc_server_data_t");
        return or_insufficient_memory;
    }
    memset(server, 0, sizeof(ipc_server_data_t));
    server->type = ist_stream;
    server->callbacks = callbacks;
    server->path = strdup(path);
    if (server->path == NULL)
    {
        free(server);
        PYSAMPROF_LOG(PL_ERROR, "Cannot copy path '%s' for starting ipc_server", path);
        return or_insufficient_memory;
    }
#ifdef __linux__
    int res = unlink(path);
    if (res == 0)
    {
        PYSAMPROF_LOG(PL_INFO, "Removed '%s' for creating socket server", path);
    }
    else if (errno == ENOENT)
    {
        PYSAMPROF_LOG(PL_INFO, "Socket '%s' did not exist, no need to remove", path);
    }
    else
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot remove socket '%s', errno: %d", path, errno);
        free(server->path);
        free(server);
        return or_ipc_alloc_failure;
    }

    server->server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server->server_fd == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create ipc server socket, errno: %d", errno);
        free(server->path);
        free(server);
        return or_ipc_socket_failure;
    }
    if (fchmod(server->server_fd, 0600) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot set 0600 permissions on socket, errno: %d", errno);
        close(server->server_fd);
        free(server->path);
        free(server);
        return or_ipc_socket_failure;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy_s(addr.sun_path,  sizeof(addr.sun_path) - 1, path);
    res = bind(server->server_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (res == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot bind to socket %d pointing to '%s': errno %d",
                server->server_fd, path, errno);
        close(server->server_fd);
        free(server->path);
        free(server);
        return or_ipc_socket_failure;
    }
    res = listen(server->server_fd, 256);
    if (res == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot move socket to listen mode, errno: %d", errno);
        close(server->server_fd);
        free(server->path);
        free(server);
        return or_ipc_socket_failure;
    }

    res = start_new_service_thread(&server->thread, stream_service_thread, server);
    if (res != 0)
    {
        close(server->server_fd);
        free(server->path);
        free(server);
        PYSAMPROF_LOG(PL_ERROR, "Cannot spawn service thread for ipc, result: %d", res);
        return or_ipc_alloc_failure;
    }
#elif defined(_WIN32)
    InitializeCriticalSection(&(server->fd_mutex));
    {
        server->thread = CreateThread(NULL, 0, stream_service_thread, (void*)server, 0, NULL);
        if (server->thread == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot spawn service thread for ipc, error: %ld", GetLastError());
            DeleteCriticalSection(&(server->fd_mutex));
            free(server->path);
            free(server);
            return or_ipc_alloc_failure;
        }
    }
#else
#error Unsupported platform
#endif

    *result = server;
    return or_okay;
}

static THREADFUNC(shmem_service_thread, arg)
{
    ipc_server_data_t* data = (ipc_server_data_t*)arg;
#ifdef _WIN32
    static LARGE_INTEGER s_qpc_frequency = {0};
    LARGE_INTEGER last_time;

    if (s_qpc_frequency.QuadPart == 0)
    {
        if (!QueryPerformanceFrequency(&s_qpc_frequency))
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot get QPC frequency, shmem could eat CPU, error: %ld\n", GetLastError());
            s_qpc_frequency.QuadPart = 0;
        }
    }
#endif
    if (data != NULL)
    {
        if (data->callbacks.on_server_start)
        {
            data->callbacks.on_server_start(data, data->callbacks.on_server_start_data);
        }
#ifdef __linux__
        struct timeval current_time;
        int time_res = gettimeofday(&current_time, NULL);
        int64_t current_time_usec = 0;
        if (time_res == -1)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot call gettimeofday(), " \
                    "shmem could eat CPU; errno: %d", errno);
        }
        else
        {
            current_time_usec = (int64_t)current_time.tv_sec * 1000000L + \
                                (int64_t)current_time.tv_usec;
        }
#elif defined(_WIN32)
        if (!QueryPerformanceCounter(&last_time))
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot get current performance counter, shmem could eat CPU; error: %ld", GetLastError());
            last_time.QuadPart = 0;
        }
#else
#error Unsupported platform
#endif
        while (!data->stop_flag)
        {
            char* channel;
            int ch;
#ifdef __GNUC__
            __sync_synchronize();
#elif defined(_MSC_VER)
            MemoryBarrier();
#else
#error Unsupported compiler
#endif
            channel = (char*)data->shmem.addr;
            for (ch = 0; ch < data->shmem.channel_count;
                    ch++, channel += data->shmem.channel_size)
            {
                shmem_channel_header_t* header = (shmem_channel_header_t*)channel;
                if (header->state == scs_ready)
                {
                    if (data->callbacks.on_new_message)
                    {
                        ipc_message_header_t* message = \
                                (ipc_message_header_t*)(channel + ALIGNMENT_BYTES);
                        if (message->data_offset > message->size)
                        {
                            PYSAMPROF_LOG(PL_ERROR, "Got invalid shmem message: data_offset (%lld) > message_size (%lld)",
                                    (long long)message->data_offset, (long long)message->size);
                        }
                        else
                        {
                            data->callbacks.on_new_message(data,
                                    NULL, message, data->callbacks.on_new_message_data, NULL);
                        }
                    }
                    header->state = scs_empty;
                }
            }

#ifdef __linux__
            int64_t next_time_usec;
            time_res = gettimeofday(&current_time, NULL);
            if (time_res != -1)
            {
                next_time_usec = (int64_t)current_time.tv_sec * 1000000L + \
                                 (int64_t)current_time.tv_usec;
                int64_t sleep_usec = data->minimal_latency_usec - (next_time_usec - current_time_usec);
                if (sleep_usec > 0)
                {
                    struct timespec sleep_timeout;
                    sleep_timeout.tv_sec = sleep_usec / 1000000L;
                    sleep_timeout.tv_nsec = (sleep_usec % 1000000L) * 1000;
                    nanosleep(&sleep_timeout, NULL);
                }
                current_time_usec = next_time_usec;
            }
#elif defined(_WIN32)
            if (last_time.QuadPart != 0 && s_qpc_frequency.QuadPart != 0)
            {
                LARGE_INTEGER current_time;
                if (QueryPerformanceCounter(&current_time))
                {
                    int64_t diff = (int64_t)current_time.QuadPart - (int64_t)last_time.QuadPart;
                    if (diff > 0)
                    {
                        int64_t remaining_sleep;
                        diff *= 1000; // convert to millisecs
                        diff /= s_qpc_frequency.QuadPart;

                        /* convert "remaining sleep" to microseconds as Sleep() has ms-level precision,
                           and other sleep functions are either not documented or hard to use and pointless here. */
                        remaining_sleep = data->minimal_latency_usec / 1000 - diff;
                        if (remaining_sleep > 0)
                        {
                            Sleep((DWORD)remaining_sleep);
                        }
                    }

                    last_time.QuadPart = current_time.QuadPart;
                }
            }
#else
#error Unsupported platform
#endif
        }
        if (data->callbacks.on_server_stop)
        {
            data->callbacks.on_server_stop(data, data->callbacks.on_server_stop_data);
        }
#ifdef __linux__
        size_t buffer_size = data->shmem.channel_count * data->shmem.channel_size;
        if (munmap(data->shmem.addr, buffer_size) == -1)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot munmap shmem, errno: %d", errno);
        }
        close(data->server_fd);
#elif defined(_WIN32)
        if (!UnmapViewOfFile(data->shmem.addr))
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot unmap shmem, error: %ld", GetLastError());
        }
        CloseHandle(data->server_fd);
#else
#error Unsupported platform
#endif
        remove_server_from_lists(data);

        free(data->path);
        free(data);
    }

    RETURN_THREAD;
}

static operation_result_t start_shmem_server(const char* path_hint,
        uint16_t channel_count, uint16_t channel_size, uint32_t minimal_latency_usec,
        ipc_server_callbacks_t callbacks, ipc_server_data_t** result)
{
    int64_t buffer_size;
    ipc_server_data_t* server;
#ifdef _WIN32
    DWORD buffer_size_low, buffer_size_high;
#endif

    ENSURE_PAGESIZE;
    if (s_pagesize < 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get page size");
        return or_fail;
    }
    buffer_size = (int64_t)channel_count * (int64_t)channel_size;
    if (buffer_size % s_pagesize != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Buffer size (channels:%d * size:%d) must be multiple of page size (%d)",
            (int)channel_count, (int)channel_size, (int)s_pagesize);
        return or_fail;
    }
#ifdef __linux__
    if ((off_t)buffer_size != buffer_size)
    {
        PYSAMPROF_LOG(PL_ERROR, "Too big buffer requested for shmem server");
        return or_fail;
    }
#elif defined(_WIN32)
    buffer_size_high = (DWORD)(buffer_size >> (sizeof(DWORD) * 8));
    buffer_size_low = (DWORD)buffer_size;
#else
#error Unsupported platform
#endif

    server = (ipc_server_data_t*)malloc(sizeof(ipc_server_data_t));
    if (server == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for IPC server data");
        return or_insufficient_memory;
    }
    memset(server, 0, sizeof(ipc_server_data_t));
    server->shmem.channel_count = channel_count;
    server->shmem.channel_size = channel_size;
    server->minimal_latency_usec = minimal_latency_usec;
    server->type = ist_shmem;
    server->callbacks = callbacks;

#ifdef __linux__
    server->server_fd = shm_open(path_hint,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, S_IRWXU);
    if (server->server_fd == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot open '%s' for creating " \
                "shmem server, errno: %d", path_hint, errno);
        free(server);
        return or_cannot_open_file;
    }
    if (shm_unlink(path_hint) == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot remove symbolic path " \
                "to shmem, errno: %d", errno);
        close(server->server_fd);
        free(server);
        return or_io_fail;
    }
    if (ftruncate(server->server_fd, (off_t)buffer_size) == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot set shmem size to %lld, errno: %d",
                (long long)buffer_size, errno);
        close(server->server_fd);
        free(server);
        return or_insufficient_memory;
    }
    server->shmem.addr = mmap(NULL, buffer_size, PROT_READ | PROT_WRITE,
            MAP_SHARED, server->server_fd, 0);
    if (server->shmem.addr == MAP_FAILED)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot mmap shmem, errno: %d", errno);
        close(server->server_fd);
        free(server);
        return or_io_fail;
    }
    char target[256];
    memset(target, 0, sizeof(target));
    if (snprintf(target, sizeof(target) - 1, "/proc/%lld/fd/%d",
                (long long)getpid(), server->server_fd) < 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot generate path to shmem");
        munmap(server->shmem.addr, buffer_size);
        close(server->server_fd);
        free(server);
        return or_fail;
    }
    server->path = strdup(target);
    if (server->path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Insufficient memory: cannot copy " \
                "path to shmem to server");
        munmap(server->shmem.addr, buffer_size);
        close(server->server_fd);
        free(server);
        return or_insufficient_memory;
    }

    int res = start_new_service_thread(&server->thread, shmem_service_thread, server);
    if (res != 0)
    {
        munmap(server->shmem.addr, buffer_size);
        close(server->server_fd);
        free(server->path);
        free(server);
        PYSAMPROF_LOG(PL_ERROR, "Cannot spawn service thread for ipc, result: %d", res);
        return or_cannot_start_thread;
    }
#elif defined(_WIN32)
    {
        pysamprof_security_attrs_t sattrs;
        operation_result_t status = create_tight_security_attrs(&sattrs);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot create security attributes for shared memory: %s",
                    get_operation_result_str(status));
            free(server);
            return or_cannot_open_file;
        }
        server->server_fd = CreateFileMapping(INVALID_HANDLE_VALUE, &(sattrs.attrs), PAGE_READWRITE | SEC_COMMIT,
            buffer_size_high, buffer_size_low, path_hint);
        status = free_security_attrs(&sattrs);
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot free security attributes for shared memory: %s",
                    get_operation_result_str(status));
        }
    }
    if (server->server_fd == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create '%s' file mapping, error: %ld", path_hint, GetLastError());
        free(server);
        return or_cannot_open_file;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create '%s' file mapping: it already exists", path_hint);
        CloseHandle(server->server_fd);
        free(server);
        return or_cannot_open_file;
    }
    server->shmem.addr = MapViewOfFile(server->server_fd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (server->shmem.addr == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot map '%s' into memory, error: %ld", GetLastError());
        CloseHandle(server->server_fd);
        free(server);
        return or_io_fail;
    }
    server->path = strdup(path_hint);
    if (server->path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot copy path to memory mapping");
        UnmapViewOfFile(server->shmem.addr);
        CloseHandle(server->server_fd);
        free(server);
        return or_insufficient_memory;
    }
    server->thread = CreateThread(NULL, 0, shmem_service_thread, server, 0, NULL);
    if (server->thread == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot spawn shmem service thread, error: %ld", GetLastError());
        free(server->path);
        UnmapViewOfFile(server->shmem.addr);
        CloseHandle(server->server_fd);
        free(server);
        return or_cannot_start_thread;
    }
#else
#error Unsupported platform
#endif
    *result = server;
    return or_okay;
}

operation_result_t ipc_start_stream_server(const char* path,
        ipc_server_callbacks_t callbacks, ipc_server_data_t** result)
{
    operation_result_t status;

    if (path == NULL || result == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "ipc_start_stream_server() got some NULL arguments");
        return or_fail;
    }
    status = start_stream_server(path, callbacks, result);
    if (status == or_okay) add_server_to_list(*result);
    return status;
}

operation_result_t ipc_start_shmem_server(const char* path_hint,
        uint16_t channel_count, uint16_t channel_size, uint32_t minimal_latency_usec,
        ipc_server_callbacks_t callbacks, ipc_server_data_t** result)
{
    operation_result_t status;

    if (path_hint == NULL || channel_count == 0 || channel_size == 0 ||
            result == NULL) return or_fail;
    status = start_shmem_server(path_hint,
            channel_count, channel_size, minimal_latency_usec, callbacks, result);
    if (status == or_okay) add_server_to_list(*result);
    return status;
}

operation_result_t ipc_get_shmem_connection(const ipc_server_data_t* server,
        const char** path, uint16_t* channel_count, uint16_t* channel_size)
{
    if (server == NULL || path == NULL || channel_count == NULL || channel_size == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "ipc_get_shmem_connection() got some NULL arguments");
        return or_fail;
    }
    if (server->type != ist_shmem)
    {
        PYSAMPROF_LOG(PL_ERROR, "Trying to get shmem connection for non-shmem server");
        return or_fail;
    }
    *path = server->path;
    *channel_count = server->shmem.channel_count;
    *channel_size = server->shmem.channel_size;
    return or_okay;
}

uint32_t ipc_get_shmem_minimal_latency(const ipc_server_data_t* server)
{
    return server->minimal_latency_usec;
}
void ipc_set_shmem_minimal_latency(ipc_server_data_t* server, uint32_t minimal_latency_usec)
{
    server->minimal_latency_usec = minimal_latency_usec;
}

static operation_result_t stop_stream_server(ipc_server_data_t* server)
{
    server->stop_flag = 1;
#ifdef __linux__
    int res = shutdown(server->server_fd, SHUT_RDWR);
    if (res == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot shut down stream socket, errno: %d",
                errno);
        return or_fail;
    }
#elif defined(_WIN32)
    EnterCriticalSection(&(server->fd_mutex));
    if (server->server_fd != NULL)
    {
        HANDLE pipe = CreateFile(server->path, FILE_GENERIC_READ | FILE_WRITE_DATA, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot post 'stop request' for '%s' stream server, error: %ld", server->path, GetLastError());
            LeaveCriticalSection(&(server->fd_mutex));
            return or_io_fail;
        }
        if (!CloseHandle(pipe))
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot close 'stop request'-opened pipe for '%s' stream server, error: %ld", server->path, GetLastError());
        }
    }
    else
    {
        PYSAMPROF_LOG(PL_INFO, "server has NULL pipe handle");
    }
    LeaveCriticalSection(&(server->fd_mutex));
#else
#error Unsupported platform
#endif
    return or_okay;
}

static operation_result_t stop_shmem_server(ipc_server_data_t* server)
{
    server->stop_flag = 1;
    return or_okay;
}

operation_result_t ipc_stop_server(ipc_server_data_t* server)
{
    operation_result_t result;
    if (server == NULL) return or_fail;
    PYSAMPROF_LOG(PL_INFO, "Posting 'stop request' for '%s' server", server->path);
    switch (server->type)
    {
        case ist_stream:
            result = stop_stream_server(server);
            break;
        case ist_shmem:
            result = stop_shmem_server(server);
            break;
        default:
            PYSAMPROF_LOG(PL_ERROR, "Unknown server type passed: %d", (int)(server->type));
            return or_fail;
    }

    return result;
}

operation_result_t ipc_detach_server(ipc_server_data_t* server)
{
    if (server == NULL) return or_fail;
#ifdef __linux__
    int res = pthread_detach(server->thread);
    if (res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot detach ipc service thread, result: %d", res);
        return or_fail;
    }
#elif defined(_WIN32)
    if (server->thread == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "NULL server handle");
        return or_fail;
    }
    if (!CloseHandle(server->thread))
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot close handle to ipc service thread, error: %d", GetLastError());
        return or_fail;
    }
#else
#error Unsupported platform
#endif
    return or_okay;
}

operation_result_t ipc_get_join_data(ipc_server_data_t* server, ipc_server_join_data_t** join_data)
{
    ipc_server_join_data_t* data;

    if (server == NULL || join_data == NULL) return or_fail;
    data = (ipc_server_join_data_t*)malloc(sizeof(ipc_server_join_data_t));
    if (data == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for ipc join_data");
        return or_insufficient_memory;
    }
    data->thread = server->thread;
    *join_data = data;
    return or_okay;
}

operation_result_t ipc_join_server(ipc_server_join_data_t* join_data)
{
    long long res = 0;
    if (join_data == NULL) return or_fail;

    #ifdef __linux__
    res = pthread_join(join_data->thread, NULL);
#elif defined(_WIN32)
    if (WaitForSingleObject(join_data->thread, INFINITE) == WAIT_FAILED)
    {
        res = GetLastError();
    }
    if (!CloseHandle(join_data->thread))
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot close handle for ipc service thread, error: %u", GetLastError());
    }
#else
#error Unsupported platform
#endif
    free(join_data);
    if (res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot join ipc service thread, error: %lld", res);
        return or_fail;
    }
    return or_okay;
}

operation_result_t ipc_connect_to_stream_server(const char* path,
        void* client_data, ipc_client_data_t** result)
{
    ipc_client_data_t* client;

    if (path == NULL || result == NULL) return or_fail;
    CHECK_STREAM_PATH(path);
    client = (ipc_client_data_t*)malloc(sizeof(ipc_client_data_t));
    if (client == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for ipc_client_data_t");
        return or_insufficient_memory;
    }
    memset(client, 0, sizeof(ipc_client_data_t));
    client->type = ist_stream;
    client->client_data = client_data;
    client->path = strdup(path);
    if (client->path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot copy path '%s' for connecting to ipc_server", path);
        free(client);
        return or_insufficient_memory;
    }
#ifdef __linux__
    client->client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client->client_fd == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create ipc client socket, errno: %d", errno);
        free(client->path);
        free(client);
        return or_ipc_socket_failure;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy_s(addr.sun_path, sizeof(addr.sun_path) - 1, path);
    int res = connect(client->client_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (res == -1)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot connect to ipc server, errno: %d", errno);
        close(client->client_fd);
        free(client->path);
        free(client);
        return or_ipc_socket_failure;
    }
#elif defined(_WIN32)
    {
        HANDLE pipe = INVALID_HANDLE_VALUE;
        do
        {
            DWORD lastError;
            pipe = CreateFile(path, FILE_GENERIC_READ | FILE_WRITE_DATA, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (pipe != INVALID_HANDLE_VALUE) break;
            lastError = GetLastError();
            if (lastError == ERROR_PIPE_BUSY)
            {
                // all pipe instances busy, wait a bit
                WaitNamedPipe(path, 500);
            }
            else
            {
                // something bad happened
                PYSAMPROF_LOG(PL_ERROR, "Cannot connect to '%s' pipe, error: %ld", path, lastError);
                free(client->path);
                free(client);
                return or_ipc_socket_failure;
            }
        }
        while (1);
        client->client_fd = pipe;
    }
#else
#error Unsupported platform
#endif
    *result = client;
    return or_okay;
}

operation_result_t ipc_connect_to_shmem_server(const char* path,
        uint16_t channel_count, uint16_t channel_size,
        void* client_data, ipc_client_data_t** result)
{
    ipc_client_data_t* client;
    int64_t buffer_size = (int64_t)channel_count * (int64_t)channel_size;

    if (path == NULL || channel_count == 0 || channel_size == 0 || result == NULL) return or_fail;
    ENSURE_PAGESIZE;
    if (s_pagesize < 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get page size");
        return or_fail;
    }
    if (buffer_size % s_pagesize != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Buffer size (channels:%d * size:%d) must be multiple of page size (%d)",
            (int)channel_count, (int)channel_size, (int)s_pagesize);
        return or_fail;
    }
#ifdef __linux__
    struct stat file_stat;
    if (stat(path, &file_stat) == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get stats for '%s', errno: %d",
                path, errno);
        return or_io_fail;
    }
    if (file_stat.st_size != buffer_size)
    {
        PYSAMPROF_LOG(PL_ERROR, "Size of shmem server does not match passed channels");
        return or_fail;
    }
#elif defined(_WIN32)
    // TODO: check mapping size somehow
#else
#error Unsupported platform
#endif

    client = (ipc_client_data_t*)malloc(sizeof(ipc_client_data_t));
    if (client == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for ipc_client_data_t");
        return or_insufficient_memory;
    }
    memset(client, 0, sizeof(ipc_client_data_t));
    client->type = ist_shmem;
    client->client_data = client_data;
    client->path = strdup(path);
    client->shmem.channel_count = channel_count;
    client->shmem.channel_size = channel_size;
    if (client->path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot copy path '%s' for connecting to ipc_server", path);
        free(client);
        return or_insufficient_memory;
    }

#ifdef __linux__
    client->client_fd = open(path, O_RDWR | O_CLOEXEC);
    if (client->client_fd == -1)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot open shmem '%s' in client, errno: %d",
                path, errno);
        free(client->path);
        free(client);
        return or_cannot_open_file;
    }
    client->shmem.addr = mmap(NULL, buffer_size, PROT_READ | PROT_WRITE,
            MAP_SHARED, client->client_fd, 0);
    if (client->shmem.addr == MAP_FAILED)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot mmap shmem '%s' in client, errno: %d",
                path, errno);
        close(client->client_fd);
        free(client->path);
        free(client);
        return or_io_fail;
    }
#elif defined(_WIN32)
    client->client_fd = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, path);
    if (client->client_fd == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot open shmem '%s' in client, error: %ld", path, GetLastError());
        free(client->path);
        free(client);
        return or_cannot_open_file;
    }
    client->shmem.addr = MapViewOfFile(client->client_fd, FILE_MAP_ALL_ACCESS, 0, 0, buffer_size);
    if (client->shmem.addr == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot map shmem '%s' in client, error: %ld", path, GetLastError());
        CloseHandle(client->client_fd);
        free(client->path);
        free(client);
        return or_io_fail;
    }
#else
#error Unsupported platform
#endif
    *result = client;
    return or_okay;
}


// Unsynchronized function; call with list lock owned
static operation_result_t disconnect_from_stream_server(ipc_client_data_t* client)
{
  if (client == NULL) return or_fail;
    remove_client_from_lists(client);

#ifdef __linux__
    close(client->client_fd);
#elif defined(_WIN32)
    if (client->client_fd != NULL) CloseHandle(client->client_fd);
    if (client->thread != NULL) CloseHandle(client->thread);
#else
#error Unsupported platform
#endif
    free(client->path);
    free(client);
    return or_okay;
}

// Unsynchronized function; call with list lock owned
static operation_result_t disconnect_from_shmem_server(ipc_client_data_t* client)
{
  if (client == NULL) return or_fail;
    remove_client_from_lists(client);

#ifdef __linux__
    size_t buffer_size = (int64_t)client->shmem.channel_count * \
                         (int64_t)client->shmem.channel_size;
    if (munmap(client->shmem.addr, buffer_size) == -1)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot munmap shmem, errno: %d", errno);
    }
    close(client->client_fd);
#elif defined(_WIN32)
    if (!UnmapViewOfFile(client->shmem.addr))
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot unmap shmem %p, error: %ld", client->shmem.addr, GetLastError());
    }
    CloseHandle(client->client_fd);
#else
#error Unsupported platform
#endif
    free(client->path);
    free(client);
    return or_okay;
}

operation_result_t ipc_disconnect_from_server(ipc_client_data_t* client)
{
    operation_result_t status = or_okay;
    if (client == NULL) return or_fail;
    if (client->server != NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Do not manually call ipc_disconnect_from_server() " \
                "on clients from callbacks");
        return or_fail;
    }
    switch (client->type)
    {
        case ist_stream:
            LOCK_LIST;
            status = disconnect_from_stream_server(client);
            UNLOCK_LIST;
            break;
        case ist_shmem:
            LOCK_LIST;
            status = disconnect_from_shmem_server(client);
            UNLOCK_LIST;
            break;
        default:
            PYSAMPROF_LOG(PL_ERROR, "Unknown client type passed: %d", (int)client->type);
            return or_fail;
    }
    return status;
}

operation_result_t ipc_send_message(ipc_client_data_t* client, ipc_message_header_t* message)
{
    if (client == NULL || message == NULL) return or_fail;
    if (client->type != ist_stream)
    {
        PYSAMPROF_LOG(PL_ERROR, "Sending to non-stream not supported");
        return or_fail;
    }
#ifdef __linux__
    char* buf = (char*)message;
    uint32_t remaining = message->size;
    while (remaining > 0)
    {
        ssize_t written = write(client->client_fd, buf, remaining);
        if (written == -1)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot send message from '%s', errno: %d",
                    client->path, errno);
            return or_ipc_socket_failure;
        }

        if (written == 0) break;
        buf += written;
        remaining -= written;
    }
    if (remaining > 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot send message from '%s' " \
                "- at some point was not able to write", client->path);
        return or_ipc_socket_failure;
    }
#elif defined(_WIN32)
    {
        DWORD written;
        char* buf = (char*)message;
        uint32_t remaining = message->size;
        while (remaining > 0)
        {
            if (!WriteFile(client->client_fd, (void*)buf, remaining, &written, NULL))
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot send message from '%s', error: %ld", client->path, GetLastError());
                return or_ipc_socket_failure;
            }
            if (written == 0) break;
            buf += written;
            remaining -= written;
        }
        if (remaining > 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot send message from '%s' " \
                    "- at some point was not able to write", client->path);
            return or_ipc_socket_failure;
        }
    }
#else
#error Unsupported platform
#endif
    return or_okay;
}


operation_result_t ipc_receive_message(ipc_client_data_t* client,
        ipc_message_header_t** message)
{
    if (client == NULL || message == NULL) return or_fail;
    if (client->type != ist_stream)
    {
        PYSAMPROF_LOG(PL_ERROR, "Receiving from non-stream not supported");
        return or_fail;
    }
    if (client->server != NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot manually call ipc_receive_message() " \
                "on clients managed by server");
        return or_fail;
    }
    return receive_from_stream(client, NULL, message);
}

operation_result_t ipc_prepare_buffer(ipc_client_data_t* client,
        ipc_message_header_t** buffer, uint32_t* size, uint16_t* last_index)
{
    uint16_t shmem_index, shmem_index_stop;

    if (client == NULL || buffer == NULL || size == NULL || last_index == NULL) return or_fail;
    if (client->type != ist_shmem)
    {
        PYSAMPROF_LOG(PL_ERROR, "ipc_prepare_buffer() works for shmem only");
        return or_fail;
    }

    shmem_index = *last_index;
    shmem_index_stop = shmem_index + client->shmem.channel_count;
    for(; shmem_index < shmem_index_stop; shmem_index++)
    {
#define GET_SHMEM_CHANNEL(addr, index, count, size)    \
        ((shmem_channel_header_t*)((char*)(addr) + ((index) % (count)) * (size)))
        shmem_channel_header_t* header = GET_SHMEM_CHANNEL(
                client->shmem.addr, shmem_index,
                client->shmem.channel_count, client->shmem.channel_size);
        if (header->state == scs_empty)
        {
#ifdef __GNUC__
            if (!(__sync_bool_compare_and_swap(&(header->state), scs_empty, scs_taken)))
            {
                continue;
            }
#elif defined(_MSC_VER)
            if (InterlockedCompareExchange((volatile LONG*)(&(header->state)), scs_taken, scs_empty) != scs_empty)
            {
                continue;
            }
#else
#error Unsupported compiler
#endif
            *buffer = (ipc_message_header_t*)((char*)header + ALIGNMENT_BYTES);
            *size = client->shmem.channel_size - ALIGNMENT_BYTES;
            *last_index = shmem_index;
            return or_okay;
        }
    }
    // if we got here it means that we did a full loop and
    // checked all channels but none were available... bail out
    return or_ipc_alloc_failure;
}

static operation_result_t ipc_set_buffer_state(ipc_client_data_t* client,
        ipc_message_header_t* buffer, uint32_t size,
        shmem_channel_state_t state, const char* func_name)
{
    shmem_channel_header_t* header;

    if (client == NULL || buffer == NULL) return or_fail;
    if (client->type != ist_shmem)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s() works for shmem only", func_name);
        return or_fail;
    }
    if (size > (uint32_t)(client->shmem.channel_size - ALIGNMENT_BYTES))
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got bad buffer size", func_name);
        return or_fail;
    }
    if (((char*)buffer < (char*)(client->shmem.addr) + ALIGNMENT_BYTES) ||
        ((char*)buffer + size > (char*)(client->shmem.addr) +
                     client->shmem.channel_count * client->shmem.channel_size))
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got buffer not in range", func_name);
        return or_fail;
    }
    if (buffer->size > size)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got too big a message, " \
                "this might have broken the IPC", func_name);
        return or_fail;
    }

    header = (shmem_channel_header_t*)((char*)buffer - ALIGNMENT_BYTES);
    if (header->state != scs_taken)
    {
        PYSAMPROF_LOG(PL_ERROR, "shmem channel was not taken before pushing");
        return or_io_fail;
    }
    header->state = state;
#ifdef __GNUC__
    __sync_synchronize();
#elif defined(_MSC_VER)
    MemoryBarrier();
#else
#error Unsupported compiler
#endif
    return or_okay;
}

operation_result_t ipc_push_buffer(ipc_client_data_t* client,
        ipc_message_header_t* buffer, uint32_t size)
{
    return ipc_set_buffer_state(client, buffer, size, scs_ready, __FUNCTION__);
}

operation_result_t ipc_discard_buffer(ipc_client_data_t* client,
        ipc_message_header_t* buffer, uint32_t size)
{
    return ipc_set_buffer_state(client, buffer, size, scs_empty, __FUNCTION__);
}

void ipc_free_message(ipc_message_header_t* message)
{
    if (message) free(message);
}
