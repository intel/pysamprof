#ifndef __PYSAMPROF_OS_ABSTRACT_H__
#define __PYSAMPROF_OS_ABSTRACT_H__

#include <common/status/status.h>
#include <common/logging/logging.h>

#ifdef __linux__
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_gettid definition */

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef void* module_handle_t;
#define LOCK_MUTEX(m) pthread_mutex_lock(m)
#define UNLOCK_MUTEX(m) pthread_mutex_unlock(m)
#define GET_ERROR_AS_LL() ((long long)errno)
#define JOIN_THREAD(thread) pthread_join((thread), NULL)
typedef volatile int32_t atomic_int_t;
#define ATOMIC_CAS(target, old_value, new_value) (__sync_val_compare_and_swap(&(target), old_value, new_value))
#define ATOMIC_INC(target) (__sync_add_and_fetch(&(target), 1))
#define ATOMIC_DEC(target) (__sync_sub_and_fetch(&(target), 1))
#define GETTID() ((pid_t)(syscall(SYS_gettid)))

#elif defined(_WIN32)
#include <Windows.h>

typedef HANDLE thread_t;
typedef CRITICAL_SECTION mutex_t;
typedef HMODULE module_handle_t;
#define LOCK_MUTEX(m) EnterCriticalSection(m)
#define UNLOCK_MUTEX(m) LeaveCriticalSection(m)
#define GET_ERROR_AS_LL() ((long long)GetLastError())
#define JOIN_THREAD(thread) WaitForSingleObject((thread), INFINITE)
typedef volatile LONG atomic_int_t;
#define ATOMIC_CAS(target, old_value, new_value) (InterlockedCompareExchange(&(target), new_value, old_value))
#define ATOMIC_INC(target) (InterlockedIncrement(&(target)))
#define ATOMIC_DEC(target) (InterlockedDecrement(&(target)))
#define GETTID() ((DWORD)GetCurrentThreadId())

#else
#error Unsupported platform
#endif

#define CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(res, msg, retval) \
    do {                                                \
        if (res != or_okay)                             \
        {                                               \
            PYSAMPROF_LOG(PL_ERROR, "%s: %s",           \
                    msg, get_operation_result_str(res));\
			mark_thread_sampling_safe();                       \
            return retval;                              \
        }                                               \
    } while(0)

#ifdef _WIN32
#define strdup(x) _strdup(x)
#define inline __inline
#endif

#ifdef PYSAMPROF_BUILDING_LIB
#ifdef _WIN32
#define PYSAMPROF_API_FUNC(rtype) __declspec(dllexport) rtype
#elif defined(__linux__)
#define PYSAMPROF_API_FUNC(rtype) rtype
#else
#error Unsupported platform
#endif

#else
#ifdef _WIN32
#define PYSAMPROF_API_FUNC(rtype) __declspec(dllimport) rtype
#elif defined(__linux__)
#define PYSAMPROF_API_FUNC(rtype) extern rtype
#else
#error Unsupported platform
#endif
#endif

#ifdef __GNUC__
#define FULL_MEMORY_BARRIER() __sync_synchronize()
#elif defined(_MSC_VER)
#define FULL_MEMORY_BARRIER() MemoryBarrier()
#else
#error Unsupported compiler
#endif


#endif

