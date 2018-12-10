#ifndef __PYSAMPROF_TIME_UTILS_H__
#define __PYSAMPROF_TIME_UTILS_H__

#include <common/utilities/inttype_helper.h>
#include <common/status/status.h>

#ifdef __linux__
#include <time.h>
typedef struct timespec timeunit_t;
#elif defined(_WIN32)
#include <windows.h>
typedef FILETIME timeunit_t;
#else
#error Unsupported platform
#endif

operation_result_t get_mono_time_nanosec(int64_t* result);
int64_t get_time_diff(timeunit_t old, timeunit_t current);

#ifdef _WIN32
operation_result_t get_cpu_time(HANDLE thread, timeunit_t* result);
#endif

#endif
