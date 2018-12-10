#include "time_utils.h"
#include "../common/logging/logging.h"

#ifdef __linux__
#include <time.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include <errno.h>

#define NANO_IN_SECOND 1000000000LL

#ifdef __linux__
operation_result_t get_mono_time_nanosec(int64_t* result)
{
    if (result == NULL) return or_fail;
    struct timespec val;
    if (clock_gettime(CLOCK_MONOTONIC, &val) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get current time, errno: %d", errno);
        return or_time_utils_fail;
    }
    *result = ((int64_t)val.tv_sec) * NANO_IN_SECOND + (int64_t)val.tv_nsec;
    return or_okay;
}
#elif defined(_WIN32)
operation_result_t get_mono_time_nanosec(int64_t* result)
{
	static LARGE_INTEGER s_qpc_freq = {0};
	LARGE_INTEGER counter;

    if (result == NULL) return or_fail;

	if (s_qpc_freq.QuadPart == 0)
	{
		LARGE_INTEGER freq;
		if (!QueryPerformanceFrequency(&freq))
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot call QueryPerformanceFrequency(), error: %ld", GetLastError());
			return or_time_utils_fail;
		}
		s_qpc_freq = freq;
	}

	if (!QueryPerformanceCounter(&counter))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get current time, error: %ld", GetLastError());
		return or_time_utils_fail;
	}

	{
		int64_t seconds = counter.QuadPart / s_qpc_freq.QuadPart;
		int64_t remain = counter.QuadPart % s_qpc_freq.QuadPart;
		*result = seconds * NANO_IN_SECOND + (remain * NANO_IN_SECOND / s_qpc_freq.QuadPart);
	}
	return or_okay;
}
#else
#error Unsupported platform
#endif

#ifdef __linux__
int64_t get_time_diff(timeunit_t old, timeunit_t current)
{
    int64_t deltanano = current.tv_nsec - old.tv_nsec;
    int64_t deltasec = current.tv_sec - old.tv_sec;
    while (deltanano < 0)
    {
        deltanano += NANO_IN_SECOND;
        deltasec -= 1;
    }
    return deltasec * NANO_IN_SECOND + deltanano;
}
#elif defined(_WIN32)
int64_t get_time_diff(timeunit_t old, timeunit_t current)
{
	ULARGE_INTEGER i_old, i_current;
	int64_t diff;

	i_old.HighPart = old.dwHighDateTime;
	i_old.LowPart = old.dwLowDateTime;

	i_current.HighPart = current.dwHighDateTime;
	i_current.LowPart = current.dwLowDateTime;

	diff = i_current.QuadPart - i_old.QuadPart;
	return diff * 100 /* FILETIME is measured in 100-nanosec intervals */;
}
#else
#error Unsupported platform
#endif

#ifdef _WIN32
operation_result_t get_cpu_time(HANDLE thread, timeunit_t* result)
{
	FILETIME creation_time, exit_time, user_time, kernel_time;
	LARGE_INTEGER user_time_int, kernel_time_int, cpu_time_int;

	if (result == NULL || thread == NULL || thread == INVALID_HANDLE_VALUE) return or_fail;

	if (!GetThreadTimes(thread, &creation_time, &exit_time, &kernel_time, &user_time))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get thread times for thread handle %p, error: %ld", (void*)thread, GetLastError());
		return or_time_utils_fail;
	}

	user_time_int.HighPart = user_time.dwHighDateTime;
	user_time_int.LowPart = user_time.dwLowDateTime;

	kernel_time_int.HighPart = kernel_time.dwHighDateTime;
	kernel_time_int.LowPart = kernel_time.dwLowDateTime;

	cpu_time_int.QuadPart = user_time_int.QuadPart + kernel_time_int.QuadPart;

	result->dwHighDateTime = cpu_time_int.HighPart;
	result->dwLowDateTime = cpu_time_int.LowPart;
	return or_okay;
}

#endif