#define _BSD_SOURCE
#include <string.h>

#ifdef __linux__
#include <pthread.h>
#include <safe_mem_lib.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include "../../common/logging/logging.h"

#include "writing_thread.h"
#include "../include/ipc_message.h"
#include "server_handles.h"
#include "../../common/status/status.h"

#include "../proto/functionInfo.pb-c.h"
#include "../proto/sample_t.pb-c.h"

#ifdef _MSC_VER
// FIXME: such macroes should be part of OS abstraction layer
#define snprintf(buffer, count, format, ...) _snprintf_s(buffer, count, _TRUNCATE, format, ##__VA_ARGS__)
#define strdup(x) _strdup(x)
#endif

#include <errno.h>
#include <stddef.h>

#define LOCK_UNLOCK_MUTEX(mutex, action, name, pid, rettype, okvalue)               \
    {                                                                               \
        rettype res = action((mutex));                                              \
        if (res != okvalue)                                                         \
        {                                                                           \
            PYSAMPROF_LOG(PL_ERROR, "Cannot %s mutex for %lld thread, error: %d",   \
                    (long long)(pid), (int)res);                                    \
            return or_mutex_error;                                                  \
        }                                                                           \
    }

#ifdef __linux__
#define LOCK_SYMFILE(thread)    \
    LOCK_UNLOCK_MUTEX((&(thread).symfile_mutex), pthread_mutex_lock, "lock symfile", (thread).pid, int, 0)
#define UNLOCK_SYMFILE(thread)    \
    LOCK_UNLOCK_MUTEX((&(thread).symfile_mutex), pthread_mutex_unlock, "unlock symfile", (thread).pid, int, 0)
#define SYMFILE_NEEDS_LOCKING 1
#elif defined(_WIN32)
#define SYMFILE_NEEDS_LOCKING 0
#define LOCK_SYMFILE(thread)
#define UNLOCK_SYMFILE(thread)
#else
#error Unsupported platform
#endif

#if SYMFILE_NEEDS_LOCKING
operation_result_t lock_symfile(thread_handle_t* thread)
{
    LOCK_SYMFILE(*thread);
    return or_okay;
}

operation_result_t unlock_symfile(thread_handle_t* thread)
{
    UNLOCK_SYMFILE(*thread);
    return or_okay;
}
#endif

#ifdef _WIN32
static FILE* my_fopen(const char* filename, const char* mode)
{
    FILE* result;
    if (fopen_s(&result, filename, mode) != 0) result = NULL;
    return result;
}
#else
#define my_fopen(fname, mode) fopen(fname, mode)
#endif

operation_result_t open_trace_files(thread_handle_t *attrs)
{
    int trace_length;
    char *trace_path;
    FILE* trace_fp;
    long long trace_number;

    int symbol_trace_length;
    char *symbol_trace_path;
    FILE* symbol_trace_fp;

    if (attrs == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "%s got some NULL args", __FUNCTION__);
        return or_fail;
    }

    attrs->result_path = attrs->master->collection.result_path;
    attrs->start_time = attrs->master->collection.start_time;
    attrs->period = attrs->master->collection.period;

    if (!(attrs->result_path))
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create trace files on NULL result path");
        return or_fail;
    }
    if (attrs->trace_fp != NULL || attrs->symbol_trace_fp != NULL)
    {
        if (attrs->trace_fp != NULL && attrs->symbol_trace_fp != NULL)
        {
            PYSAMPROF_LOG(PL_INFO, "Not opening trace files for %lld pid: already opened",
                    (long long )attrs->pid);
            return or_okay;
        }
        PYSAMPROF_LOG(PL_ERROR,
                "Inconsistent state of trace files for %lld pid: trace_fp=%p, symbol_fp=%p",
                (long long )attrs->pid, attrs->trace_fp, attrs->symbol_trace_fp);
        return or_inconsistent_state;
    }
#ifdef __linux__
    {
        int res = pthread_mutex_init(&(attrs->symfile_mutex), NULL);
        if (res != 0)
        {
            PYSAMPROF_LOG(PL_ERROR,
                    "Cannot create mutex for thread_handle_t for %lld pid, error: %d",
                    (long long )attrs->pid, res);
            return or_mutex_error;
        }
    }
#elif SYMFILE_NEEDS_LOCKING
#error Unsupported platform: symfile needs locking but locking is not implemented
#endif

    trace_length = strlen(attrs->result_path) + sizeof(RAW_FILE_EXT) + MAX_PID_LEN
            + TRACE_NUMBER_LEN + 2;
    trace_path = (char*)malloc(trace_length);
    if (trace_path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate trace_path");
        return or_insufficient_memory;
    }

    for (trace_fp = NULL, trace_number = 0; trace_fp == NULL; trace_number++)
    {
        FILE* fp;
        int status = snprintf(trace_path, trace_length, "%s/%lld.%lld%s", attrs->result_path,
                (long long)attrs->pid, trace_number, RAW_FILE_EXT);
        if (status < 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Snprintf returned %d trying to write %d characters",
                    status, trace_length);
            free(trace_path);
            return or_fail;
        }
        // check if file exists by trying to open for reading
        fp = my_fopen(trace_path, "r");
        if (fp != NULL)
        {
            fclose(fp);
        }
        else
        {
            fp = my_fopen(trace_path, "wb+");
            if (fp == NULL)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot create trace file, errno: %d", errno);
                free(trace_path);
                return or_io_fail;
            }
            trace_fp = fp;
            break;
        }
    }

#define WRITE_ITEM(item)                                    \
    if (fwrite(&(item), sizeof(item), 1, trace_fp) != 1)    \
    {                                                       \
        PYSAMPROF_LOG(PL_ERROR, "Cannot write to trace file %s, errno: %d", \
            trace_path, errno);                             \
        free(trace_path);                                   \
        fclose(trace_fp);                                   \
        return or_io_fail;                                  \
    }
    WRITE_ITEM(attrs->start_time);
    WRITE_ITEM(attrs->period);
#undef WRITE_ITEM
    PYSAMPROF_LOG(PL_INFO, "Created and initialized '%s' trace file", trace_path);
    free(trace_path);

    symbol_trace_length = strlen(attrs->result_path) + sizeof(SYMRAW_FILE_EXT) + MAX_PID_LEN
            + TRACE_NUMBER_LEN + 2;
    symbol_trace_path = (char*)malloc(symbol_trace_length);
    if (symbol_trace_path == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate symbol_trace_path");
        fclose(trace_fp);
        return or_insufficient_memory;
    }
    {
        int status = snprintf(symbol_trace_path, symbol_trace_length, "%s/%lld.%lld%s",
                attrs->result_path, (long long)attrs->pid, trace_number, SYMRAW_FILE_EXT);
        if (status < 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Snprintf returned %d trying to write %d characters", status,
                    symbol_trace_path);
            fclose(trace_fp);
            free(symbol_trace_path);
            return or_fail;
        }
    }
    symbol_trace_fp = my_fopen(symbol_trace_path, "wb+");
    if (symbol_trace_fp == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot open symbol trace '%s', errno: %d", symbol_trace_path,
                errno);
        fclose(trace_fp);
        free(symbol_trace_path);
        return or_io_fail;
    }
    free(symbol_trace_path);

    attrs->trace_fp = trace_fp;
    attrs->symbol_trace_fp = symbol_trace_fp;

    return or_okay;
}

operation_result_t close_trace_files(thread_handle_t* thread)
{
    operation_result_t status = or_okay;
#define CLOSE_HANDLE(handle, name)                          \
    if (handle != NULL)                                     \
    {                                                       \
        int result = fclose(handle);                        \
        if (result != 0)                                    \
        {                                                   \
            PYSAMPROF_LOG(PL_ERROR, "Cannot close %s for %lld app thread: %d", \
                name, (long long)thread->pid, result);                  \
            status = or_io_fail;                            \
        }                                                   \
        else                                                \
        {                                                   \
            PYSAMPROF_LOG(PL_INFO, "Closed %s handle for %lld app thread", \
                name, (long long)thread->pid);              \
        }                                                   \
        handle = NULL;                                      \
    }
    CLOSE_HANDLE(thread->trace_fp, "trace");
    CLOSE_HANDLE(thread->symbol_trace_fp, "symbol trace");
#undef CLOSE_HANDLE

#ifdef __linux__
    {
        int res = pthread_mutex_destroy(&(thread->symfile_mutex));
        if (res != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot destory symfile mutex for %lld thread, error: %d",
                    (long long )thread->pid, res);
            if (status == or_okay) status = or_mutex_error;
        }
    }
#elif SYMFILE_NEEDS_LOCKING
#error Unsupported platform: symfile needs locking but locking is not implemented
#endif

    return status;
}

static operation_result_t create_proto_sample_t(ipc_message_sample_body_t *sample_collected,
        Perftools__Samples__SampleT *sampleT);

operation_result_t write_sample(thread_handle_t *server_thread,
        ipc_message_sample_t *raw_message)
{
    operation_result_t status;
    ipc_message_sample_body_t* message;
    Perftools__Samples__SampleT *sampleT;
    void *buf_src;
    uint32_t proto_len_src, buf_len_src, proto_offset, packed;

    static message_type_t type = type_sample;

    if (!server_thread)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot write sample, server thread is NULL");
        return or_fail;
    }
    if (!raw_message)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot write sample, message is NULL");
        return or_fail;
    }
    GET_MESSAGE_BODY(raw_message, sample, message, status);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot parse sample message: %s",
                get_operation_result_str(status));
        return status;
    }
    VALIDATE_PARAMS(raw_message->body.stack_offset + raw_message->head.data_offset <= raw_message->head.size,
        "ipc write_sample got too big stack offset (%lld) - out of message bounds (%lld)",
        raw_message->body.stack_offset, raw_message->head.size);
    VALIDATE_PARAMS(message->stack_type == PERFTOOLS__SAMPLES__SAMPLE_T__STACK_TYPE_T__native ||
                    message->stack_type == PERFTOOLS__SAMPLES__SAMPLE_T__STACK_TYPE_T__python ||
                    message->stack_type == PERFTOOLS__SAMPLES__SAMPLE_T__STACK_TYPE_T__mixed,
        "ips write_sample got unknown stack type: %d", (int)message->stack_type);
    VALIDATE_PARAMS(message->duration >= 0,
        "ipc write_sample got negative duration: %lld", (long long)message->duration);

    // create protobuf analog of structure
    /* NB: probably cannot create sampleT on stack as
     perftools__samples__sample_t__free_unpacked expects pointer to be acquired from malloc
     */
    sampleT = (Perftools__Samples__SampleT *)malloc(sizeof(Perftools__Samples__SampleT));
    if (sampleT == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: failed to allocate proto sample structure");
        return or_insufficient_memory;
    }

    status = create_proto_sample_t(message, sampleT);
    if (status != or_okay)
    {
        perftools__samples__sample_t__free_unpacked(sampleT, NULL);
        PYSAMPROF_LOG(PL_ERROR, "Failed to create proto sample structure with %s",
                get_operation_result_str(status));
        return status;
    }

    // determine length of message and pack to buffer
    proto_len_src = perftools__samples__sample_t__get_packed_size(sampleT);
    if (proto_len_src == 0)
    {
        free(sampleT);
        PYSAMPROF_LOG(PL_ERROR, "Calculated packed protobuf size is 0");
        return or_protobuf_fail;
    }
    proto_offset = sizeof(message_type_t) + sizeof(uint32_t);
    buf_len_src = proto_len_src + proto_offset;
    buf_src = malloc(buf_len_src);
    if (buf_src == NULL)
    {
        free(sampleT);
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: failed to allocate buffer for proto sample");
        return or_insufficient_memory;
    }
    // write type and length and then message to buffer
   
    memcpy_s(buf_src, buf_len_src, &type, sizeof(message_type_t));
    memcpy_s((char*)buf_src + sizeof(message_type_t), buf_len_src - sizeof(message_type_t), &proto_len_src, sizeof(uint32_t));

    packed = perftools__samples__sample_t__pack(sampleT, (unsigned char*)buf_src + proto_offset);
    if (packed != proto_len_src)
    {
        PYSAMPROF_LOG(PL_ERROR, "Writing sample: packed size mismatch, go: %ul, expected: %ul",
                (unsigned long ) packed, (unsigned long ) proto_len_src);
        status = or_protobuf_fail;
    }
    else
    {
        size_t written = fwrite(buf_src, buf_len_src, 1, server_thread->trace_fp);
        if (written != 1)
        {
            PYSAMPROF_LOG(PL_ERROR, "Writing sample: failed to write data to file");
            status = or_io_fail;
        }
    }
    free(buf_src);
    free(sampleT->locations);
    free(sampleT);
    return status;
}

operation_result_t alloc_sample_message(thread_handle_t* server_thread, int try_loop_count,
        uint16_t* last_index, ipc_message_sample_t** message, uint32_t* max_size)
{
    PYSAMPROF_LOG(PL_ERROR, "%s is client-only function, not implemented on server",
            __FUNCTION__);
    return or_fail;
}
operation_result_t push_sample_message(thread_handle_t* server, ipc_message_sample_t* message,
        uint32_t max_size)
{
    PYSAMPROF_LOG(PL_ERROR, "%s is client-only function, not implemented on server",
            __FUNCTION__);
    return or_fail;
}

operation_result_t discard_sample_message(thread_handle_t* server,
        ipc_message_sample_t* message, uint32_t max_size)
{
    PYSAMPROF_LOG(PL_ERROR, "%s is client-only function, not implemented on server",
            __FUNCTION__);
    return or_fail;
}

operation_result_t write_function_info(thread_handle_t *server_thread,
        ipc_message_function_info_t *raw_message)
{
    operation_result_t status = or_okay;
    ipc_message_function_info_body_t* message;
    static message_type_t type = type_function_info;
    uint32_t proto_len;

    if (!server_thread)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot write function info, server thread is NULL");
        return or_fail;
    }
    if (!raw_message)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot write function info, message is NULL");
        return or_fail;
    }
    GET_MESSAGE_BODY(raw_message, function_info, message, status);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot parse function_info message: %s",
                get_operation_result_str(status));
        return status;
    }
    VALIDATE_PARAMS(message->protobuf_size <= raw_message->head.size - raw_message->head.data_offset,
        "Invalid 'function info' message - protobuf_size (%lld) more than fits in the message (%lld)",
        (long long)message->protobuf_size, (long long)(raw_message->head.size - raw_message->head.data_offset));

#define WRITE_ITEM(item, item_size)                                    \
    {                                                                  \
        size_t written = fwrite((item), (item_size), 1,                \
                server_thread->symbol_trace_fp);                       \
        if (written != 1)                                              \
        {                                                              \
            PYSAMPROF_LOG(PL_ERROR, "Writing function info: "          \
                    "failed to write data to file, errno: %d", errno); \
            UNLOCK_SYMFILE(*server_thread);                            \
            return or_io_fail;                                         \
        }                                                              \
    }
#define WRITE_SIMPLE_ITEM(item) WRITE_ITEM(&item, sizeof(item))

    proto_len = message->protobuf_size;

    LOCK_SYMFILE(*server_thread);

    WRITE_SIMPLE_ITEM(type);
    WRITE_SIMPLE_ITEM(proto_len);
    WRITE_ITEM(message->protobuf_data, proto_len);

    UNLOCK_SYMFILE(*server_thread);

#undef WRITE_SIMPLE_ITEM
#undef WRITE_ITEM

    return or_okay;
}

#pragma pack(push, 1)
typedef struct
{
    message_type_t type;
    uint32_t size;
    char data[1];
} message_with_size_t;
#pragma pack(pop)

operation_result_t write_mapping_info(thread_handle_t *server_thread, uint64_t start,
        uint64_t limit, uint64_t offset, int64_t loadtime, const char* filename)
{
    operation_result_t status = or_okay;
    Perftools__Symbols__Mapping *mapping;
    message_with_size_t* buf_src;
    uint32_t proto_len_src, buf_len_src, proto_offset, packed;

    if (!server_thread)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot write mapping, server thread is NULL");
        return or_fail;
    }
    if (!filename)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot write mapping, filename is NULL");
        return or_fail;
    }

    // create protobuf analog of structure
    mapping = (Perftools__Symbols__Mapping*)malloc(sizeof(Perftools__Symbols__Mapping));
    if (mapping == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate buffer for mapping serialization");
        return or_insufficient_memory;
    }

    perftools__symbols__mapping__init(mapping);
    mapping->start = start;
    mapping->limit = limit;
    mapping->offset = offset;
    mapping->loadtime = loadtime;
    mapping->file = strdup(filename);
    if (!mapping->file)
    {
        PYSAMPROF_LOG(PL_ERROR, "Failed to strdup mapping file name");
        free(mapping);
        return or_insufficient_memory;
    }
    mapping->has_start = 1;
    mapping->has_limit = 1;
    mapping->has_offset = 1;
    mapping->has_loadtime = 1;

    // determine length of message and pack to buffer
    proto_len_src = perftools__symbols__mapping__get_packed_size(mapping);
    if (proto_len_src == 0)
    {
        free(mapping->file);
        free(mapping);
        PYSAMPROF_LOG(PL_ERROR, "Calculated length of mapping is 0");
        return or_protobuf_fail;
    }

    proto_offset = offsetof(message_with_size_t, data);
    buf_len_src = proto_len_src + proto_offset;
    buf_src = (message_with_size_t*)malloc(buf_len_src);
    if (buf_src == NULL)
    {
        free(mapping->file);
        free(mapping);
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate buffer for mapping serialization");
        return or_insufficient_memory;
    }
    // write type and length and then message to buffer
    buf_src->type = type_mapping;
    buf_src->size = proto_len_src;

    packed = perftools__symbols__mapping__pack(mapping, (uint8_t*)&(buf_src->data[0]));
    if (packed != proto_len_src)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Writing mapping: packed size mismatch, got: %ul, expected: %ul",
                (unsigned long )packed, (unsigned long )proto_len_src);
        status = or_protobuf_fail;
    }
    else
    {
#if SYMFILE_NEEDS_LOCKING
        operation_result_t lock_status = lock_symfile(server_thread);
#else
        operation_result_t lock_status = or_okay;
#endif
        if (lock_status == or_okay)
        {
            size_t written = fwrite(buf_src, buf_len_src, 1, server_thread->symbol_trace_fp);
#if SYMFILE_NEEDS_LOCKING
            lock_status = unlock_symfile(server_thread);
#endif
            if (written != 1)
            {
                PYSAMPROF_LOG(PL_ERROR, "Writing mapping: failed to write data to file");
                status = or_io_fail;
            }
            else
            {
                status = lock_status;
            }
        }
        else
        {
            status = lock_status;
        }
    }
    free(buf_src);
    free(mapping->file);
    free(mapping);
    return status;
}

static operation_result_t create_proto_sample_t(ipc_message_sample_body_t *sample_collected,
        Perftools__Samples__SampleT *sampleT)
{
    uint64_t* locations;

    if (!sample_collected)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Cannot create proto sample, argument pointer on collected sample is NULL");
        return or_fail;
    }
    if (!sampleT)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create proto sample, init failed, sample is NULL");
        return or_fail;
    }

    perftools__samples__sample_t__init(sampleT);
    sampleT->stack_size = sample_collected->stack_size;
    sampleT->stack_type = sample_collected->stack_type;
    sampleT->duration = sample_collected->duration;
    sampleT->timestamp = sample_collected->timestamp;
    sampleT->tid = sample_collected->tid;
    sampleT->n_locations = sample_collected->stack_size;
    locations = (uint64_t *)malloc(sizeof(uint64_t) * sampleT->n_locations);

    if (locations == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate buffer for locations in proto sample creation");
        return or_insufficient_memory;
    }

    sampleT->locations = locations;
    sampleT->has_stack_size = 1;
    sampleT->has_stack_type = 1;
    sampleT->has_duration = 1;
    sampleT->has_timestamp = 1;
    sampleT->has_tid = 1;

    memcpy_s(sampleT->locations, sizeof(uint64_t) * sampleT->n_locations, (char*)sample_collected + sample_collected->stack_offset,
        sizeof(uint64_t) * sampleT->n_locations);

    return or_okay;
}
