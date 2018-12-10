/*system abstraction layer for common component*/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#ifdef __linux__
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <safe_str_lib.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include "status/status.h"

#ifdef _WIN32
extern LARGE_INTEGER g_qpc_frequency;
#endif

#ifdef _WIN32
typedef DWORD sal_file_attrs_t;
typedef LARGE_INTEGER sal_time_t;
#elif defined(__linux__)
typedef struct stat sal_file_attrs_t;
typedef struct timespec sal_time_t;
#else
#error Unsupported platform
#endif

#ifdef _WIN32
void normalize_path(char *dir);
operation_result_t get_performance_frequency(sal_time_t* time);
#endif

#ifdef _WIN32
#define sal_strdup(dir)             _strdup(dir)
#define sal_last_error              (GetLastError())
#define sal_seconds(time)           ((long)((time).QuadPart / g_qpc_frequency.QuadPart))
#define sal_current_pid             ((long long)GetCurrentProcessId())

#define sal_microseconds(time)      ((long)((((time).QuadPart * 1000000L) / g_qpc_frequency.QuadPart) % 1000000L))
#define sal_get_time(time_struct)   QueryPerformanceCounter(time_struct)
#define sal_normalize_path_win(dir) normalize_path(dir)
#define sal_file_is_dir(file_attrs) (((file_attrs) & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)

#define sal_strtok_s(s, s_delimiter, rest_s)           (strtok_s((s), (s_delimiter), (rest_s)))
#define sal_fopen_s(p_file, p_path, cp_flag)           ((fopen_s((p_file), (p_path), (cp_flag)) != 0) ? NULL : *(p_file))
#define sal_get_file_attributes(where, created_dir)    (((where) = GetFileAttributes(created_dir)) != INVALID_FILE_ATTRIBUTES)
#define sal_get_performance_frequency_win(time_struct) get_performance_frequency(time_struct)

#define sal_vsnprintf(result_buf, result_buf_max_size, fmt, va) \
    vsnprintf_s((result_buf), (result_buf_max_size), _TRUNCATE, (fmt), (va))

#define sal_snprintf_s(buffer, buf_max_size, string_format, sec, microsec, level_str, process_id, fmt) \
    _snprintf_s((buffer), (buf_max_size), _TRUNCATE, (string_format), (sec), (microsec), (level_str), (process_id), (fmt))

#elif defined(__linux__)
#define sal_strdup(dir)     strdup(dir)
#define sal_last_error      ((long)errno)
#define sal_seconds(time)   ((time).tv_sec)
#define sal_current_pid     ((long long)getpid())

#define sal_microseconds(time)      ((time).tv_nsec / 1000)
#define sal_get_time(time_struct)   (!clock_gettime(CLOCK_MONOTONIC, (time_struct)))
#define sal_normalize_path_win(dir)
#define sal_file_is_dir(file_attrs) (S_ISDIR((file_attrs).st_mode))

#define sal_strtok_s(s, s_delimiter, rest_s)           (strtok_r((s), (s_delimiter), (rest_s)))
#define sal_fopen_s(p_file, p_path, cp_flag)           fopen((p_path), (cp_flag))
#define sal_get_file_attributes(where, created_dir)    (stat((created_dir), &(where)) != -1)
#define sal_get_performance_frequency_win(time_struct) or_okay

#define sal_vsnprintf(result_buf, result_buf_max_size, fmt, va) \
    vsnprintf((result_buf), (result_buf_max_size), (fmt), (va))

#define sal_snprintf_s(buffer, buf_max_size, string_format, sec, microsec, level_str, process_id, fmt) \
    snprintf((buffer), (buf_max_size), (string_format), (sec), (microsec), (level_str), (process_id), (fmt))

#else
#error Unsupported platform
#endif
