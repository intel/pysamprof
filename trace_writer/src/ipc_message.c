#define _BSD_SOURCE

#include <string.h>
#include <stdio.h>

#include "../../common/utilities/inttype_helper.h"

#ifdef __linux__
#include <sys/stat.h>
#include <unistd.h>
#elif defined(_WIN32)
#define snprintf(buffer, count, format, ...) _snprintf_s(buffer, count, _TRUNCATE, format, ##__VA_ARGS__)
#else
#error Unsupported platform
#endif

#include "../../common/utilities/utilities.h"
#include "../../common/status/status.h"
#include "../../common/logging/logging.h"

#ifdef __linux__
#define SOCKET_PREFIX "/tmp/.pysamprof"
#define SHMEM_PREFIX "/pysamprof"
#elif defined(_WIN32)
#define SOCKET_PREFIX "\\\\.\\pipe\\LOCAL\\pysamprof"
#define SHMEM_PREFIX "Local\\pysamprof"
#else
#error Unsupported platform
#endif

static operation_result_t make_url_to_something(char *buf, uint32_t size, int64_t master_pid,
        const char* prefix)
{
    int status = snprintf(buf, size, "%s-%lld", prefix, (long long)master_pid);
    if (status < 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Failed to form socket file name (prefix: %s), "
                "snprintf returned %d", prefix, status);
        return or_fail;
    }
    return or_okay;
}

operation_result_t get_master_socket_url(char *buf, uint32_t size, int64_t pid_master)
{
    return make_url_to_something(buf, size, pid_master, SOCKET_PREFIX);
}

operation_result_t get_shmem_path_hint(char *buf, uint32_t size, int64_t pid_target)
{
    return make_url_to_something(buf, size, pid_target, SHMEM_PREFIX);
}
