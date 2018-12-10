#define _POSIX_C_SOURCE 201707L

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "logging.h"
#include "../sal_common.h"

FILE* g_pysamprof_logfile = NULL;
pysamprof_loglevel_t g_pysamprof_loglevel = PL_INFO;

#define MAX_LOGLINE_SIZE 1024

#ifdef _WIN32
LARGE_INTEGER g_qpc_frequency;
#endif

static const char* s_level_names[] = {
    "no logging",
    "ERROR",
    "WARNING",
    "INFO"
};

#ifdef _WIN32
static operation_result_t get_performance_frequency(sal_time_t* time)
{
    if (time == NULL) return or_fail;
    if (!QueryPerformanceFrequency(time))
    {
        fprintf(stderr, "Cannot get QPC frequency, error: %ld\n", GetLastError());
        return or_time_utils_fail;
    }
    return or_okay;
}
static operation_result_t sal_getenv_s(const char* name, char** result)
{
    size_t required_size;
    char* value;
    errno_t status;
    if ((name == NULL) || (result == NULL)) return or_fail;
    
    status = getenv_s(&required_size, NULL, 0, name);
    if (status != 0)
    {
        fprintf(stderr, "Error: %d when getting buffer size for value of an env variable: %s", status, name);
        return or_fail;
    }
    if (required_size == 0)
    {
        return or_no_env_variable;
    }

    value = (char*) malloc(required_size * sizeof(char));
    if (!value)
    {
        fprintf(stderr, "Failed to allocate memory for env value buffer");
        return or_insufficient_memory;
    }
    status = getenv_s(&required_size, value, required_size, name);
    if (status != 0)
    {
        fprintf(stderr, "Error: %d when getting the value of an env variable: %s", status, name);
        free(value);
        return or_fail;
    }
    *result = value;
    return or_okay;
}

#elif defined(__linux__)

static operation_result_t sal_getenv_s(const char* name, char** result)
{
    char* value;
    if ((name == NULL) || (result == NULL)) return or_fail;
    
    value = getenv(name);
    if (!value)
    {
        return or_no_env_variable;
    }
    
    value = strdup(value);
    if (!value)
    {
        fprintf(stderr, "Failed to allocate memory for env value buffer");
        return or_insufficient_memory;
    }
    *result = value;
    return or_okay;
}
#else
#error Unsupported platform
#endif

void pysamprof_log(FILE* f, pysamprof_loglevel_t level, const char* fmt, ...)
{
    char fmt_buf[MAX_LOGLINE_SIZE + 1];
    char result_buf[MAX_LOGLINE_SIZE + 1];
    int fmt_buf_valid = 0;
    va_list va;
    int written;
    sal_time_t current_time;

    if (sal_get_time(&current_time))
    {
        const char* level_str;
        if (level < PL_ERROR ||
                level >= (sizeof(s_level_names) / sizeof(s_level_names[0])))
        {
            level_str = "UNKNOWN";
        }
        else
        {
            level_str = s_level_names[(int)level];
        }
        fmt_buf_valid = 1;
        if (sal_snprintf_s(fmt_buf, MAX_LOGLINE_SIZE, "[%ld.%06ld][%s:%lld] %s",
                sal_seconds(current_time), sal_microseconds(current_time),
                level_str, sal_current_pid, fmt) <= 0)
        {
            fmt_buf_valid = 0;
        }
    }

    va_start(va, fmt);
    written = sal_vsnprintf(result_buf, MAX_LOGLINE_SIZE, (fmt_buf_valid != 0) ? fmt_buf : fmt, va);
    va_end(va);
    if (written <= 0)
    {
        return;
    }
    result_buf[written] = '\n';
    fwrite(result_buf, written + 1, 1, f);
}

operation_result_t init_logging(void)
{
    char* log_path = NULL;
    operation_result_t status;
    if (sal_get_performance_frequency_win(&g_qpc_frequency) != or_okay) return or_time_utils_fail;

    // TODO: parse log level from somewhere
    if (g_pysamprof_loglevel < PL_ERROR) return or_okay;

    status = sal_getenv_s(PYSAMPROF_LOGGING_ENV, &log_path);
    if (status == or_okay)
    {
        if (strcmp(log_path, "-") == 0)
        {
            g_pysamprof_logfile = stderr;
        }
        else
        {
            g_pysamprof_logfile = sal_fopen_s(&g_pysamprof_logfile, log_path, "a");
            if (g_pysamprof_logfile == NULL)
            {
                free(log_path);
                return or_fail;
            }
        }
    }
    else 
    {
        return (status == or_no_env_variable) ? or_okay: status;
    }
    free(log_path);
    return status;
}

operation_result_t finish_logging(void)
{
    if (g_pysamprof_logfile != NULL && g_pysamprof_logfile != stderr)
    {
        fclose(g_pysamprof_logfile);
    }
    return or_okay;
}
