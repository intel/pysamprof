#include "threading_follow.h"

#include <Python.h>
#ifndef WITH_THREAD
#error Python without threading not supported for profiling so far
#endif
#include <pythread.h>

#include <errno.h>

#include <probengine/prober.h>
#include <common/logging/logging.h>
#include <common/utilities/utilities.h>

#ifdef __linux__
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_gettid definition */

pthread_key_t g_wsp_key;

typedef int (*pthread_create_t)(pthread_t* thread, const pthread_attr_t* attr,
        void* (*start_routine)(void*), void* arg);
static pthread_create_t s_original_pthread_create = NULL;
typedef struct
{
    void* (*start_routine)(void*);
    void* arg;
} pthread_create_probe_data_t;

typedef void (*PyOS_AfterFork_t)(void);
static PyOS_AfterFork_t s_PyOS_AfterFork_original = NULL;

typedef int (*execve_t)(const char *filename, char *const argv[],
        char *const envp[]);
static execve_t s_execve_original = NULL;

static void before_fork_in_parent();
static void after_fork_in_parent();
static void after_fork_in_child();

static forkexec_callback_t s_prepare_callback = NULL;
static forkexec_callback_t s_parent_callback = NULL;
static forkexec_callback_t s_child_callback = NULL;
static forkexec_callback_t s_pyready_callback = NULL;
static forkexec_callback_t s_before_exec = NULL;
#elif defined(_WIN32)
#include <windows.h>

DWORD g_wsp_key;

typedef HANDLE (WINAPI *CreateThread_t)(
		_In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		_In_      SIZE_T                 dwStackSize,
		_In_      LPTHREAD_START_ROUTINE lpStartAddress,
		_In_opt_  LPVOID                 lpParameter,
		_In_      DWORD                  dwCreationFlags,
		_Out_opt_ LPDWORD                lpThreadId);
static CreateThread_t s_CreateThread_original = NULL;
typedef struct
{
    LPTHREAD_START_ROUTINE start_routine;
    void* arg;
} CreateThread_probe_data_t;
#else
#error Unsupported platform
#endif

static void before_process_exit(void);

static int g_wsp_key_created = 0;
static thread_callback_t s_on_thread_start = NULL;
static thread_callback_t s_on_thread_stop = NULL;

typedef long (*PyThread_start_new_thread_t)(void(*func)(void*), void* arg);
static PyThread_start_new_thread_t s_original_pythread_start = NULL;
typedef struct
{
    void (*func)(void*);
    void *arg;
} pythread_start_thread_data_t;

#include "workspace.h"

static operation_result_t on_wsp_free(workspace_t* wsp)
{
	operation_result_t result = or_okay;
    if (s_on_thread_stop != NULL) result = s_on_thread_stop(wsp);
#ifdef _WIN32
	if (wsp != NULL && wsp->target_thread != NULL) CloseHandle(wsp->target_thread);
#endif
    return result;
}

static void on_new_thread()
{
	operation_result_t res;
    workspace_t* wsp = NULL;
    wsp_tid_t tid = -1;
#ifdef __linux__
    tid = syscall(SYS_gettid);
#elif defined(_WIN32)
	tid = GetCurrentThreadId();
#else
#error Unsupported platform
#endif
    res = get_workspace_by_tid(tid, &wsp);
    switch (res)
    {
        case or_okay:
			PYSAMPROF_LOG(PL_ERROR, "Workspace %p leaked, was assigned to %lld tid before and now is assigned to %lld",
				wsp, (long long)wsp->tid, (long long)tid);
            break;
        case or_thread_not_found:
            res = allocate_workspace(&wsp);
            if (res != or_okay)
            {
				PYSAMPROF_LOG(PL_ERROR, "Cannot allocate workspace for %lld tid: %s",
					(long long)tid, get_operation_result_str(res));
                return;
            }
            break;
        default:
            // TODO: report error
            return;
    }

    wsp->tid = tid;
    wsp->on_free = on_wsp_free;
#ifdef _WIN32
	wsp->target_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (wsp->target_thread == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot open thread handle for %ld thread, error: %ld", tid, GetLastError());
	}
#endif
    set_thread_wsp(wsp);
	mark_thread_sampling_unsafe();
    if (s_on_thread_start != NULL)
    {
        res = s_on_thread_start(wsp);
        if (res != or_okay)
        {
            // TODO: report error
            return;
        }
    }
    PYSAMPROF_LOG(PL_INFO, "Detected new thread with tid %lld", (long long)tid);
	mark_thread_sampling_safe();
}

static void on_new_python_thread()
{
    workspace_t* wsp = get_thread_wsp();
    if (wsp == NULL)
    {
        // TODO: report error
        return;
    }
    wsp->python_enabled = pes_will_be_python;
    wsp->python_tid = PyThread_get_thread_ident();
}

#ifdef __linux__
/* Wrapper to be placed instead of real function argument
   for pthread_create(), so that each pthread-spawned thread
   actually starts with our function, so we know about
   each thread that is created. */
static void* pthread_start_wrapper(void* data)
{
    if (data == NULL) return NULL;
    // copy startup data to stack-backed variable so we can free the one on heap
    pthread_create_probe_data_t real_data = *(pthread_create_probe_data_t*)data;
    free(data);
    // notify collector about new thread
    on_new_thread();
    // call original function
    return real_data.start_routine(real_data.arg);
}
static int pthread_create_probe(pthread_t* thread, const pthread_attr_t* attr,
        void*(*start_routine)(void*), void* arg)
{
    if (s_original_pthread_create == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "missing pthread_create probe");
        return -1;
    }
    pthread_create_probe_data_t* data = \
        (pthread_create_probe_data_t*)malloc(sizeof(pthread_create_probe_data_t));
    if (data == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory to allocate pthread_probe_data");
        return -1;
    }
    data->start_routine = start_routine;
    data->arg = arg;
    // TODO: don't track threads with "start_routine" belonging to pysamprof itself
    return s_original_pthread_create(thread, attr, pthread_start_wrapper, (void*)data);
}
#elif defined(_WIN32)
 /* Wrapper to be placed instead of real function argument
   for CreateThread(), so that each win32-spawned thread
   actually starts with our function, so we know about
   each thread that is created. */
static DWORD WINAPI thread_start_wrapper(void* data)
{
	CreateThread_probe_data_t real_data;

    if (data == NULL) return 0;
    // copy startup data to stack-backed variable so we can free the one on heap
    real_data = *(CreateThread_probe_data_t*)data;
    free(data);
    // notify collector about new thread
    on_new_thread();
    // call original function
    return real_data.start_routine(real_data.arg);
}

HANDLE WINAPI CreateThread_probe(
  _In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  _In_      SIZE_T                 dwStackSize,
  _In_      LPTHREAD_START_ROUTINE lpStartAddress,
  _In_opt_  LPVOID                 lpParameter,
  _In_      DWORD                  dwCreationFlags,
  _Out_opt_ LPDWORD                lpThreadId
)
{
	CreateThread_probe_data_t* data;

    if (s_CreateThread_original == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "missing CreateThread probe");
        return NULL;
    }
    data = (CreateThread_probe_data_t*)malloc(sizeof(CreateThread_probe_data_t));
    if (data == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory to allocate CreateThread_probe_data_t");
        return NULL;
    }
    data->start_routine = lpStartAddress;
    data->arg = lpParameter;
    // TODO: don't track threads with "start_routine" belonging to pysamprof itself
	return s_CreateThread_original(lpThreadAttributes, dwStackSize,
		thread_start_wrapper, (void*)data, dwCreationFlags, lpThreadId);
}
#else
#error Unsupported platform
#endif


// TODO: intercept "PyThreadState_Create" as well, needed to detect Python state
//       when thread is initially spawned as native but then gets Python-ized

/* Wrapper to be placed instead of real function argument
   for PyThread_start_new_thread(), so that each python-spawned thread
   actually starts with our function, so we know about
   each thread that is supposed to have Python thread state. */
static void pythread_wrapper(void* data)
{
	pythread_start_thread_data_t real_data;

    if (data == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "NULL data received in pythread_wrapper");
        return;
    }
	mark_thread_sampling_unsafe();
    // copy startup data to stack-backed variable so we can free the one on heap
    real_data = *(pythread_start_thread_data_t*)data;
    free(data);
    // notify collector about new thread
    on_new_python_thread();
    // call original function
	mark_thread_sampling_safe();
    real_data.func(real_data.arg);
}
static long PyThread_start_new_thread_probe(void(*func)(void*), void* arg)
{
	pythread_start_thread_data_t* data;

    if (s_original_pythread_start == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "missing PyThread_start_new_thread_probe");
        return -1;
    }
    data = (pythread_start_thread_data_t*)malloc(sizeof(pythread_start_thread_data_t));
    if (data == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory to allocate pythread_start_thread_data");
        return -1;
    }
    data->func = func;
    data->arg = arg;
    return s_original_pythread_start(pythread_wrapper, (void*)data);
}

static void on_thread_finish(void* wsp, int current_thread)
{
	if (current_thread)
	{
		long long tid;
#ifdef __linux__
		tid = (long long)syscall(SYS_gettid);
#elif defined(_WIN32)
		tid = GetCurrentThreadId();
#else
#error Unsupported platform
#endif
		PYSAMPROF_LOG(PL_INFO, "Called on_thread_finish for %lld tid", tid);
	}
	else
	{
		PYSAMPROF_LOG(PL_INFO, "Called on_thread_finish for %p wsp (%lld tid)",
			wsp, (wsp != NULL) ? (long long)(((workspace_t*)wsp)->tid) : -1LL);
	}
    if (wsp != NULL)
    {
        free_workspace((workspace_t*)wsp, current_thread);
    }
    else
    {
        if (s_on_thread_stop != NULL)
        {
            operation_result_t intermediate = s_on_thread_stop(NULL);
            if (intermediate != or_okay)
            {
                // TODO: report the error
            }
        }
    }
}

#ifdef __linux__
static void tls_destructor(void* wsp)
{
	on_thread_finish(wsp, 1);
}
#elif defined(_WIN32)
#define MAX_DEAD_WSP 16
typedef struct
{
	int count;
	workspace_t* dead[MAX_DEAD_WSP];
} dead_threads_t;

static operation_result_t check_thread_alive(workspace_t* wsp, void* data)
{
	if (wsp != NULL && wsp->target_thread != NULL && data != NULL)
	{
		dead_threads_t* dead = (dead_threads_t*)data;
		DWORD wait_result = WaitForSingleObject(wsp->target_thread, 0);
		switch (wait_result)
		{
		case WAIT_TIMEOUT:
			// thread alive
			break;
		case WAIT_OBJECT_0:
			// thread stopped
			if (dead->count < MAX_DEAD_WSP)
			{
				dead->dead[dead->count] = wsp;
				dead->count++;
				if (dead->count >= MAX_DEAD_WSP) return or_okay; // notify outer loop that space is full
			}
			else
			{
				PYSAMPROF_LOG(PL_INFO, "Cannot report dead thread %lld for now - buffer full, will report next time",
					(long long)wsp->tid);
				return or_okay;
			}
			break;
		case WAIT_FAILED:
			PYSAMPROF_LOG(PL_ERROR, "Cannot check if %lld thread is alive, error: %ld",
				(long long)wsp->tid, GetLastError());
			break;
		default:
			PYSAMPROF_LOG(PL_ERROR, "Unexpected result %ld while checking if %lld thread is alive, error: %ld",
				wait_result, (long long)wsp->tid, GetLastError());
			break;
		}
	}
	return or_continue_iterating;
}

static DWORD WINAPI monitor_alive_threads(void* arg)
{
	operation_result_t res;
	int i;
	dead_threads_t dead;
	workspace_t** pwsp;

	mark_current_thread_as_service();

	while (1)
	{
		dead.count = 0;
		res = iterate_workspaces(check_thread_alive, &dead);
		if (res != or_thread_not_found && res != or_okay)
		{
			PYSAMPROF_LOG(PL_WARNING, "Unexpected result from checking if threads are alive: %s",
				get_operation_result_str(res));
		}
		for (i = 0, pwsp = dead.dead; i < dead.count; i++, pwsp++) on_thread_finish(*pwsp, 0);
		if (res != or_okay) msleep(100);
	}
}
#endif

#ifdef __linux__
void PyOS_AfterFork_probe()
{
    if (s_PyOS_AfterFork_original != NULL) s_PyOS_AfterFork_original();
	mark_thread_sampling_unsafe();
    if (s_pyready_callback != NULL) s_pyready_callback();
	mark_thread_sampling_safe();
}

int execve_probe(const char *filename, char *const argv[],
                  char *const envp[])
{
	mark_thread_sampling_unsafe();
    if (s_before_exec != NULL) s_before_exec();
	mark_thread_sampling_safe();
    if (s_execve_original != NULL) return s_execve_original(filename, argv, envp);
    return -1;
}
#endif

#define CHECK_RES_AND_REPORT(res, message)              \
    do {                                                \
        if (res != or_okay)                             \
        {                                               \
            PYSAMPROF_LOG(PL_ERROR, "%s: %s", message, get_operation_result_str(res));   \
            return res;                                 \
        }                                               \
    } while(0);

operation_result_t start_following_threads(const all_memory_regions_t regions,
        thread_callback_t on_thread_start, thread_callback_t on_thread_stop)
{
    operation_result_t res = or_okay;
	workspace_t* wsp = NULL;

#ifdef _WIN32
	{
		HANDLE monitor = CreateThread(NULL, 0, monitor_alive_threads, NULL, 0, NULL);
		if (monitor == NULL)
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot create thread for monitoring other threads, error: %ld", GetLastError());
			return or_cannot_start_thread;
		}
		CloseHandle(monitor);
	}
#endif

#ifdef __linux__
    if (s_original_pthread_create == NULL)
    {
        res = probe_function(pthread_create, (void*)pthread_create_probe,
                regions, (void**)&s_original_pthread_create);
        CHECK_RES_AND_REPORT(res, "Cannot probe pthread_create");
    }
#elif defined(_WIN32)
	if (s_CreateThread_original == NULL)
	{
		res = probe_function(CreateThread, (void*)CreateThread_probe,
                regions, (void**)&s_CreateThread_original);
        CHECK_RES_AND_REPORT(res, "Cannot probe CreateThread");
	}
#else
#error Unsupported platform
#endif
    if (s_original_pythread_start == NULL)
    {
        res = probe_function(PyThread_start_new_thread, (void*)PyThread_start_new_thread_probe,
                regions, (void**)&s_original_pythread_start);
        CHECK_RES_AND_REPORT(res, "Cannot probe PyThread_start_new_thread");
    }
#ifdef __linux__
    if (s_PyOS_AfterFork_original == NULL)
    {
        res = probe_function(PyOS_AfterFork, (void*)PyOS_AfterFork_probe,
                regions, (void**)&s_PyOS_AfterFork_original);
        CHECK_RES_AND_REPORT(res, "Cannot probe PyOS_AfterFork");
    }

    if (s_execve_original == NULL)
    {
        res = probe_function(execve, (void*)execve_probe, regions, (void**)&s_execve_original);
        CHECK_RES_AND_REPORT(res, "Cannot probe execve");
    }
#endif

    if (g_wsp_key_created == 0)
    {
#ifdef __linux__
        if (pthread_key_create(&g_wsp_key, tls_destructor) != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot create wsp key, errno: %d", errno);
            return or_fail;
        }
        if (pthread_atfork(before_fork_in_parent, after_fork_in_parent,
                           after_fork_in_child) != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot register callbacks for " \
                    "pthread_atfork, errno: %d", errno);
            return or_fail;
        }
#elif defined(_WIN32)
		g_wsp_key = TlsAlloc();
		if (g_wsp_key == TLS_OUT_OF_INDEXES)
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot create wsp key, out of tls indexes, error: %ld", GetLastError());
			return or_fail;
		}
#else
#error Unsupported platform
#endif
        if (atexit(before_process_exit) != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot register atexit callback, errno: %d",
                    errno);
            return or_fail;
        }
        g_wsp_key_created = 1;
    }

    s_on_thread_start = on_thread_start;
    s_on_thread_stop = on_thread_stop;

    // register main (==current) thread, too
    on_new_thread();
    on_new_python_thread();
    PYSAMPROF_LOG(PL_INFO, "Marking main thread as workspace-known");
    res = get_workspace_by_tid(
#ifdef __linux__
            syscall(SYS_gettid),
#elif defined(_WIN32)
			GetCurrentThreadId(),
#else
#error Unsupported platform
#endif
            &wsp);
    CHECK_RES_AND_REPORT(res, "Cannot get wsp for main thread");
    if (wsp == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "wsp for main thread is NULL");
        return or_fail;
    }

    return or_okay;
}

operation_result_t mark_current_thread_as_service()
{
	workspace_t* wsp = get_thread_wsp();
	if (wsp == NULL)
	{
#ifdef __linux__
		long long tid = syscall(SYS_gettid);
#elif defined(_WIN32)
		long long tid = GetCurrentThreadId();
#else
#error Unsupported platform
#endif
		PYSAMPROF_LOG(PL_WARNING, "Tried to mark thread %lld as service but thread has no workspace", tid);
		return or_thread_not_found;
	}
	mark_thread_sampling_unsafe();
	return set_wsp_service_thread(wsp);
}

#ifdef __linux__
operation_result_t register_forkexec_callbacks(forkexec_callback_t prepare,
        forkexec_callback_t parent, forkexec_callback_t child, forkexec_callback_t pyready,
        forkexec_callback_t before_exec)
{
    s_prepare_callback = prepare;
    s_parent_callback = parent;
    s_child_callback = child;
    s_pyready_callback = pyready;
    s_before_exec = before_exec;

    return or_okay;
}
#endif

#ifdef __linux__
static void before_fork_in_parent()
{
    if (s_prepare_callback != NULL) s_prepare_callback();
}

static void after_fork_in_parent()
{
    if (s_parent_callback != NULL) s_parent_callback();
}

static void after_fork_in_child()
{
    if (s_child_callback != NULL) s_child_callback();
    on_new_thread();
}
#endif

static void before_process_exit(void)
{
    free_workspace_machinery();
}

#ifdef _WIN32
HANDLE WINAPI CreateThread_nofollow(LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	if (s_CreateThread_original != NULL) return s_CreateThread_original(
		lpThreadAttributes, dwStackSize, lpStartAddress,
		lpParameter, dwCreationFlags, lpThreadId);
	return NULL;
}
#elif defined(__linux__)
int pthread_create_nofollow(pthread_t* thread, const pthread_attr_t* attr,
        void*(*start_routine)(void*), void* arg)
{
    if (s_original_pthread_create != NULL) return s_original_pthread_create(
            thread, attr, start_routine, arg);
    return -1;
}
#else
#error Unsupported platform
#endif
