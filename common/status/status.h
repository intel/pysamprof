#ifndef __PYSAMPROF_STATUS_H__
#define __PYSAMPROF_STATUS_H__

/* The following macro is expected to be used with another macro
 * named "MAKE_ENTRY" to be able to define different things with same
 * entries. This particular one is used to define a enum and a
 * string table for converting enum to string. */

#define MAKE_OPERATION_RESULT_LIST(first)   \
    MAKE_ENTRY(or_okay) first,              \
    MAKE_ENTRY(or_fail),                    \
    MAKE_ENTRY(or_insufficient_memory),     \
    MAKE_ENTRY(or_cannot_open_file),        \
    MAKE_ENTRY(or_unknown_region),          \
    MAKE_ENTRY(or_cannot_find_image),       \
    MAKE_ENTRY(or_bad_image_file),          \
    MAKE_ENTRY(or_invalid_function),        \
    MAKE_ENTRY(or_xed_error),               \
    MAKE_ENTRY(or_cannot_probe),            \
    MAKE_ENTRY(or_inconsistent_state),      \
    MAKE_ENTRY(or_small_altstack),          \
    MAKE_ENTRY(or_signal_taken),            \
    MAKE_ENTRY(or_thread_not_found),        \
    MAKE_ENTRY(or_continue_iterating),      \
    MAKE_ENTRY(or_cannot_read_file),        \
    MAKE_ENTRY(or_cannot_start_thread),     \
    MAKE_ENTRY(or_cannot_write_file),       \
    MAKE_ENTRY(or_send_recv_fail),          \
    MAKE_ENTRY(or_protobuf_fail),           \
    MAKE_ENTRY(or_io_fail),                 \
    MAKE_ENTRY(or_ipc_alloc_failure),       \
    MAKE_ENTRY(or_ipc_socket_failure),      \
    MAKE_ENTRY(or_ipc_bad_message),         \
    MAKE_ENTRY(or_ipc_unexpected_eof),      \
    MAKE_ENTRY(or_ipc_version_too_old),     \
    MAKE_ENTRY(or_unknown_message),         \
    MAKE_ENTRY(or_pid_not_found),           \
    MAKE_ENTRY(or_time_utils_fail),         \
    MAKE_ENTRY(or_cannot_change_collection_state), \
    MAKE_ENTRY(or_mutex_error),             \
    MAKE_ENTRY(or_bad_permissions),         \
    MAKE_ENTRY(or_region_taken),            \
    MAKE_ENTRY(or_ring_buffer_full),        \
    MAKE_ENTRY(or_ring_buffer_empty),       \
    MAKE_ENTRY(or_stackwalk_failure),       \
    MAKE_ENTRY(or_stop_sampling_service),   \
    MAKE_ENTRY(or_no_such_process),         \
    MAKE_ENTRY(or_cannot_make_security_descr),    \
    MAKE_ENTRY(or_no_env_variable),         \
    MAKE_ENTRY(or_invalid_parameter)

#define MAKE_ENTRY(name) name
typedef enum
{
    MAKE_OPERATION_RESULT_LIST( = 0)
} operation_result_t;
#undef MAKE_ENTRY

const char* get_operation_result_str(operation_result_t res);

#define CHECK_AND_REPORT_ERROR(res, msg, retval)        \
    do {                                                \
        if (res != or_okay)                             \
        {                                               \
            PYSAMPROF_LOG(PL_ERROR, "%s: %s",           \
                    msg, get_operation_result_str(res));\
            return retval;                              \
        }                                               \
    } while(0)

#define VALIDATE_PARAMS3(condition, retcode, message, ...)   \
    {                                                        \
        if (!(condition))                                    \
        {                                                    \
            PYSAMPROF_LOG(PL_ERROR, message, __VA_ARGS__);   \
            return retcode;                                  \
        }                                                    \
    }

#define VALIDATE_PARAMS(condition, message, ...)    \
    VALIDATE_PARAMS3(condition, or_invalid_parameter, message, __VA_ARGS__)

#endif
