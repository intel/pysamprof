#ifndef __PYSAMPROF_THREADING_FOLLOW_H__
#define __PYSAMPROF_THREADING_FOLLOW_H__

#include <common/status/status.h>
#include <probengine/memory_regions.h>

#include "workspace.h"
#include "os_abstract.h"

#ifdef __linux__
#include <pthread.h>

extern pthread_key_t g_wsp_key;
#define get_thread_wsp() ((workspace_t*)(pthread_getspecific(g_wsp_key)))
#elif defined(_WIN32)
#include <windows.h>

extern DWORD g_wsp_key;
#define get_thread_wsp() ((workspace_t*)(TlsGetValue(g_wsp_key)))
#else
#error Unsupported platform
#endif

typedef operation_result_t (*thread_callback_t)(workspace_t* wsp);

// NOTE: workspace machinery must be initialized before following threads
operation_result_t start_following_threads(const all_memory_regions_t regions,
        thread_callback_t on_thread_start, thread_callback_t on_thread_stop);
operation_result_t mark_current_thread_as_service();

#ifdef __linux__
typedef void (*forkexec_callback_t)(void);
// for meaning of first 3 arguments see pthread_atfork()
// pyready() is called after PyOS_AfterFork() returns
// before_exec is called right before calling execve() from libc
operation_result_t register_forkexec_callbacks(forkexec_callback_t prepare,
        forkexec_callback_t parent, forkexec_callback_t child, forkexec_callback_t pyready,
        forkexec_callback_t before_exec);
#endif

#ifdef __linux__
static inline int set_thread_wsp(void* wsp)
{
	return pthread_setspecific(g_wsp_key, wsp);
}
#elif defined(_WIN32)
static inline int set_thread_wsp(void* wsp)
{
	return TlsSetValue(g_wsp_key, wsp) ? 1 : 0;
}
#else
#error Unsupported platform
#endif

#ifdef _WIN32
HANDLE WINAPI CreateThread_nofollow(LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
#elif defined(__linux__)
int pthread_create_nofollow(pthread_t* thread, const pthread_attr_t* attr,
        void*(*start_routine)(void*), void* arg);
#else
#error Unsupported platform
#endif

#if defined(_WIN32) && defined(_DEBUG) && !defined(DISABLE_WSP_CHECK_WHEN_MARKING_THREAD)
#define WSP_ASSERT(wsp) {if ((wsp) == NULL) DebugBreak();}
#else
#define WSP_ASSERT(wsp) {}
#endif

static inline void mark_thread_sampling_unsafe()
{
	workspace_t* wsp = get_thread_wsp();
	WSP_ASSERT(wsp);
	MARK_WSP_SAMPLING_UNSAFE(wsp);
}

static inline void mark_thread_sampling_safe()
{
	workspace_t* wsp = get_thread_wsp();
	WSP_ASSERT(wsp);
	MARK_WSP_SAMPLING_SAFE(wsp);
}


#endif
