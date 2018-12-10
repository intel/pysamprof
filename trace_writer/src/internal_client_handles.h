#ifndef __PYSAMPROF_INTERNAL_CLIENT_HANDLER_TYPES_H__
#define __PYSAMPROF_INTERNAL_CLIENT_HANDLER_TYPES_H__

#include <ipc-ng/ipc-ng.h>

struct master_handle
{
    ipc_client_data_t* stream_handle;
};

struct thread_handle
{
    int64_t pid;
    master_handle_t* master;
    ipc_client_data_t* shmem_handle;
};

#endif
