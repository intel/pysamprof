#ifndef __PYSAMPROF_IPC_MESSAGE_H__
#define __PYSAMPROF_IPC_MESSAGE_H__

#include <stdlib.h>
#include "../../common/utilities/inttype_helper.h"

#include "proto_message_types.h"

#include <ipc-ng/ipc-ng.h>

// TODO: Make offset field for char[] fields

#define BEGIN_MESSAGE_DECL(name, type)                                  \
typedef struct ipc_message_##name##_body_t ipc_message_##name##_body_t; \
enum { ipc_message_##name##_type = type };								\
struct ipc_message_##name##_body_t

#define END_MESSAGE_DECL(name)              \
typedef struct                              \
{                                           \
    ipc_message_header_t head;              \
    ipc_message_##name##_body_t body;       \
} ipc_message_##name##_t;

#define GET_MESSAGE_BODY(msg, msgtype, body, status)                            \
    do {                                                                        \
        if (((ipc_message_header_t*)(msg))->version < IPC_NG_HEADER_VERSION)    \
        {                                                                       \
            PYSAMPROF_LOG(PL_WARNING, "IPC message version too old: %d, expected at least %d",  \
                    ((ipc_message_header_t*)(msg))->version, IPC_NG_HEADER_VERSION);            \
            status = or_ipc_version_too_old;                                    \
            break;                                                              \
        }                                                                       \
        if (((ipc_message_header_t*)(msg))->type != ipc_message_##msgtype##_type)               \
        {                                                                       \
            PYSAMPROF_LOG(PL_WARNING, "Unexpected IPC message type: %d, expected %d",           \
                    ((ipc_message_header_t*)(msg))->type, ipc_message_##msgtype##_type);        \
            status = or_ipc_bad_message;                                        \
            break;                                                              \
        }                                                                       \
        body = (ipc_message_##msgtype##_body_t*)                                \
                ((char*)msg + ((ipc_message_header_t*)(msg))->data_offset);     \
        status = or_okay;                                                       \
    } while (0);

#define GET_MAX_VARSIZE(raw_msg, msgtype, field)	\
	((raw_msg)->size - (raw_msg)->data_offset - offsetof(ipc_message_##msgtype##_body_t, field))

typedef enum
{
    ck_unregister_process,
    ck_get_shmem_connect,
    ck_stop_collection,
    ck_pause_collection,
    ck_resume_collection,
    ck_get_collection_state,
	ck_get_server_pid,
	ck_set_server_pid
} command_kind_t;

typedef enum
{
    cs_stopped, cs_running, cs_paused
} collection_state_t;

#pragma pack(push, 1)
BEGIN_MESSAGE_DECL(sample, 1)
{
    uint32_t stack_offset;
    uint32_t stack_size;
    stack_type_t stack_type;
    int64_t duration;
    int64_t timestamp;
    int64_t tid;
    char data[1];
};
END_MESSAGE_DECL(sample)

BEGIN_MESSAGE_DECL(function_info, 2)
{
    uint32_t protobuf_size;
    uint8_t protobuf_data[1];
};
END_MESSAGE_DECL(function_info)

BEGIN_MESSAGE_DECL(mapping_info, 3)
{
    uint64_t start;
    uint64_t limit;
    uint64_t offset;
    int64_t loadtime;
    char filename[1];
};
END_MESSAGE_DECL(mapping_info)

BEGIN_MESSAGE_DECL(start_command, 4)
{
    int64_t start_time;
    int64_t period;
	int signo;
    char result_path[1];
};
END_MESSAGE_DECL(start_command)

BEGIN_MESSAGE_DECL(command_with_pid, 5)
{
    command_kind_t command;
    int64_t pid;
};
END_MESSAGE_DECL(command_with_pid)

BEGIN_MESSAGE_DECL(collection_status, 6)
{
    collection_state_t state;
    int64_t start_time;
    int64_t period;
	int signo;
    char result_path[1];
};
END_MESSAGE_DECL(collection_status)

BEGIN_MESSAGE_DECL(shmem_connect, 7)
{
    uint16_t channel_count;
    uint16_t channel_size;
    char path[1];
};
END_MESSAGE_DECL(shmem_connect)

BEGIN_MESSAGE_DECL(register_process, 8)
{
    int64_t pid;
    int64_t parent_pid;
};
END_MESSAGE_DECL(register_process)
#pragma pack(pop)

operation_result_t get_master_socket_url(char *buf, uint32_t size, int64_t pid_master);
operation_result_t get_shmem_path_hint(char *buf, uint32_t size, int64_t pid_target);

#endif
