#ifndef __PYSAMPROF_IPCNG_H__
#define __PYSAMPROF_IPCNG_H__

/* Module providing two types of IPC:
   1) "slow", packet-typed, most likely socket-based, looking like a stream;
      guaranteed delivery, etc.
   2) "fast", based on shared memory; local-only; safe for sending messages
      from signal handler

   Note that server will automatically close all connections upon fork.
   It is up to code using this IPC to restart serving after fork.
 */

#include "../../common/status/status.h"
#include "../../common/utilities/inttype_helper.h"

typedef enum
{
    ist_invalid = 0,
    ist_stream,
    ist_shmem
} ipc_server_type_t;

#pragma pack(push, 1)
// Extend message header via ADDING to the end of the structure
typedef struct
{
    uint32_t size; // MUST always be first
    uint32_t version;
    uint32_t type;
    uint32_t data_offset;
} ipc_message_header_t;
#pragma pack(pop)

#define IPC_NG_HEADER_VERSION 1

typedef struct ipc_server_data_t ipc_server_data_t;
typedef struct ipc_client_data_t ipc_client_data_t;
typedef struct ipc_server_join_data_t ipc_server_join_data_t;

/* DO NOT store pointer to server_t or client_t outside of
   pair of "start"/"connect" and "stop"/"disconnect",
   as memory is managed internally.
   Also DO NOT mix clients returned from callbacks and acquired by
   "ipc_connect_to_*_server" - do not call "ipc_disconnect_from_server" on
   client returned by callback, it's managed internally.

   DO NOT free memory obtained from any of the callbacks.
*/
typedef void (*ipc_server_started_cb)(ipc_server_data_t* server,
        void* user_data);
typedef void (*ipc_server_stopped_cb)(ipc_server_data_t* server,
        void* user_data);
typedef void (*ipc_client_connected_cb)(ipc_server_data_t* server,
        ipc_client_data_t* new_client, void* user_data, void** client_user_data);
typedef void (*ipc_new_message_cb)(ipc_server_data_t* server,
        ipc_client_data_t* from, ipc_message_header_t* message, void* server_data,
        void* client_data);
typedef void (*ipc_client_disconnected_cb)(ipc_server_data_t* server,
        ipc_client_data_t* client, void* server_data, void* client_data);
typedef struct
{
    ipc_server_started_cb on_server_start;
    void* on_server_start_data;

    ipc_server_stopped_cb on_server_stop;
    void* on_server_stop_data;

    ipc_client_connected_cb on_client_connect;
    void* on_client_connect_data;

    ipc_new_message_cb on_new_message;
    void* on_new_message_data;

    ipc_client_disconnected_cb on_client_disconnect;
    void* on_client_disconnect_data;
} ipc_server_callbacks_t;

// call only once; will init inner mechanisms like locks.
// do not call after forking.
operation_result_t init_ipc_innards();

operation_result_t ipc_start_stream_server(const char* path,
        ipc_server_callbacks_t callbacks, ipc_server_data_t** result);
/* Allocate a shared memory-based server with "channel_count" channels 
   "channel_size" bytes each.
   minimal_latency_usec is minimal accepted time for processing incoming message
   (measured in microseconds). This means that if processing all channels
   is taking less than given the server may sleep for remaining time for
   reducing CPU load. */
operation_result_t ipc_start_shmem_server(const char* path_hint,
        uint16_t channel_count, uint16_t channel_size, uint32_t minimal_latency_usec,
        ipc_server_callbacks_t callbacks, ipc_server_data_t** result);
operation_result_t ipc_stop_server(ipc_server_data_t* server);
operation_result_t ipc_detach_server(ipc_server_data_t* server);

operation_result_t ipc_get_join_data(ipc_server_data_t* server, ipc_server_join_data_t** join_data);
operation_result_t ipc_join_server(ipc_server_join_data_t* join_data);

// returns "borrowed" path (owned by server), DO NOT FREE
operation_result_t ipc_get_shmem_connection(const ipc_server_data_t* server,
        const char** path, uint16_t* channel_count, uint16_t* channel_size);
uint32_t ipc_get_shmem_minimal_latency(const ipc_server_data_t* server);
void ipc_set_shmem_minimal_latency(ipc_server_data_t* server,
        uint32_t minimal_latency_usec);

operation_result_t ipc_connect_to_stream_server(const char* path,
        void* client_data, ipc_client_data_t** result);
operation_result_t ipc_connect_to_shmem_server(const char* path,
        uint16_t channel_count, uint16_t channel_size,
        void* client_data, ipc_client_data_t** result);
operation_result_t ipc_disconnect_from_server(ipc_client_data_t* client);

// send/receive for stream type
// TODO: change signature and stuff to receive ACK on sending message;
//       this would also imply locking before ACK is received
operation_result_t ipc_send_message(ipc_client_data_t* client,
        ipc_message_header_t* message);
operation_result_t ipc_receive_message(ipc_client_data_t* client,
        ipc_message_header_t** message);

// sending for shmem type; receiving is not public, as the only way
// to receive something from ist_shmem is via callback from server
operation_result_t ipc_prepare_buffer(ipc_client_data_t* client,
        ipc_message_header_t** buffer, uint32_t* size, uint16_t* last_index);
operation_result_t ipc_push_buffer(ipc_client_data_t* client,
        ipc_message_header_t* buffer, uint32_t size);
// ipc_discard_buffer marks buffer as free for further preparations
// but unlike ipc_push_buffer it does NOT "send" it to the listener.
operation_result_t ipc_discard_buffer(ipc_client_data_t* client,
        ipc_message_header_t* buffer, uint32_t size);

void ipc_free_message(ipc_message_header_t* message);

#endif
