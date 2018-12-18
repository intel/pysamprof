#include "workspace.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <logging/logging.h>

#ifdef __linux__
#include <pthread.h>

#include "signal_manager.h"

static pthread_mutex_t s_workspace_list_mutex;

#define TAKE_LIST_MUTEX                                         \
    do {                                                        \
        int res = pthread_mutex_lock(&s_workspace_list_mutex);  \
        if (res != 0)                                           \
            {                                                   \
                /* TODO: report the error */                    \
                break;                                          \
            }                                                   \
    } while (0);

#define RELEASE_LIST_MUTEX                                      \
    do {                                                        \
        int res = pthread_mutex_unlock(&s_workspace_list_mutex);\
        if (res != 0)                                           \
            {                                                   \
                /* TODO: report the error */                    \
                break;                                          \
            }                                                   \
    } while (0);
#elif defined(_WIN32)
static CRITICAL_SECTION s_workspace_list_mutex;
#define TAKE_LIST_MUTEX EnterCriticalSection(&s_workspace_list_mutex)
#define RELEASE_LIST_MUTEX LeaveCriticalSection(&s_workspace_list_mutex)

#include "sampling_thread.h"
#else
#error Unsupported platform
#endif

static workspace_t* s_workspace_list_head = NULL;

static enum
{
    ws_ready = 0,
    ws_dead
} s_workspace_status = ws_dead;

operation_result_t allocate_workspace(workspace_t** wsp)
{
	workspace_t* res;
    operation_result_t intermediate = or_okay;

    if (wsp == NULL) return or_fail;

    res = (workspace_t*)malloc(sizeof(workspace_t));
    if (res == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate workspace");
        return or_insufficient_memory;
    }
    memset(res, 0, sizeof(workspace_t));
	res->is_sampling_unsafe = 0;
#ifdef __linux__
    do
    {
        intermediate = allocate_wsp_altstack(res, MINIMUM_ALTSTACK);
        if (intermediate != or_okay) break;
    } while(0);
    if (intermediate != or_okay)
    {
        free(res);
        return intermediate;
    }
#elif defined(_WIN32)
	// nothing special on Windows
#else
#error Unsupported platform
#endif
    res->next = NULL;
    res->prev = NULL;
    res->tstate = NULL;
    res->python_enabled = pes_native;

    TAKE_LIST_MUTEX;
    if (s_workspace_status != ws_ready)
    {
        RELEASE_LIST_MUTEX;
#ifdef __linux__
        free_wsp_altstack(res, 1);
        free_wsp_timer(res);
#elif defined(_WIN32)
	// nothing special on Windows
#else
#error Unsupported platform
#endif
        free(res);
        PYSAMPROF_LOG(PL_ERROR, "Workspace list not ready for new workspaces");
        return or_inconsistent_state;
    }

    res->next = s_workspace_list_head;
    if (s_workspace_list_head != NULL)
    {
        res->prev = s_workspace_list_head->prev;
        s_workspace_list_head->prev = res;
    }
    s_workspace_list_head = res;

    RELEASE_LIST_MUTEX;
    *wsp = res;
    return or_okay;
}

static operation_result_t free_workspace_unguarded(workspace_t* wsp, int current_thread, int handling_fork)
{
    /* NOTE: must be called with s_workspace_list_mutex held! */
    operation_result_t intermediate = or_okay;
    operation_result_t result = or_okay;

    // remove wsp from the list first
    if (wsp->prev != NULL) wsp->prev->next = wsp->next;
    if (wsp->next != NULL) wsp->next->prev = wsp->prev;
    if (wsp == s_workspace_list_head)
    {
        s_workspace_list_head = wsp->next;
    }
    wsp->prev = wsp->next = NULL;

    if (wsp->on_free != NULL)
    {
        operation_result_t intermediate = wsp->on_free(wsp);
        if (intermediate != or_okay)
        {
            PYSAMPROF_LOG(PL_WARNING, "wsp(tid:%lld)->on_free returned %s",
                    (long long)wsp->tid, get_operation_result_str(intermediate));
        }
    }

    // now destroy the workspace itself
#ifdef __linux__
    intermediate = free_wsp_altstack(wsp, current_thread);
    if (intermediate != or_okay && result == or_okay) result = intermediate;
    if (!handling_fork)
    {
        intermediate = free_wsp_timer(wsp);
        if (intermediate != or_okay && result == or_okay) result = intermediate;
    }
#elif defined(_WIN32)
	intermediate = free_wsp_thread(wsp);
    if (intermediate != or_okay && result == or_okay) result = intermediate;
#else
#error Unsupported platform
#endif
    free(wsp);

    return result;
}

operation_result_t free_workspace(workspace_t* wsp, int current_thread)
{
	operation_result_t res;

    TAKE_LIST_MUTEX;
    if (s_workspace_status != ws_ready)
    {
        RELEASE_LIST_MUTEX;
        PYSAMPROF_LOG(PL_ERROR, "Workspace list not ready for operation, " \
                "cannot free workspace");
        return or_inconsistent_state;
    }

    res = free_workspace_unguarded(wsp, current_thread, 0);
    RELEASE_LIST_MUTEX;
    return res;
}

typedef struct
{
    wsp_tid_t tid;
    workspace_t* result;
} get_workspace_by_tid_callback_param_t;

static operation_result_t get_workspace_by_tid_callback(workspace_t* wsp, void* data)
{
    if (wsp == NULL || data == NULL) return or_fail;
    if (wsp->tid == ((get_workspace_by_tid_callback_param_t*)data)->tid)
    {
        ((get_workspace_by_tid_callback_param_t*)data)->result = wsp;
        return or_okay;
    }
    return or_continue_iterating;
}

operation_result_t get_workspace_by_tid(wsp_tid_t tid, workspace_t** result)
{
    get_workspace_by_tid_callback_param_t param;
	operation_result_t res;

	if (tid == -1 || result == NULL) return or_fail;
    param.tid = tid;
    param.result = NULL;
    PYSAMPROF_LOG(PL_INFO, "Searching workspace for tid %lld", (long long)tid);
    res = iterate_workspaces(get_workspace_by_tid_callback, &param);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot find workspace for tid %lld: %s",
                (long long)tid, get_operation_result_str(res));
        return res;
    }
    *result = param.result;
    return or_okay;
}

operation_result_t iterate_workspaces(iterate_workspace_callback_t callback, void* data)
{
    operation_result_t res = or_continue_iterating;
	workspace_t* wsp;

	if (callback == NULL) return or_fail;
    TAKE_LIST_MUTEX;
    if (s_workspace_status != ws_ready)
    {
        RELEASE_LIST_MUTEX;
        PYSAMPROF_LOG(PL_ERROR, "Workspace list not ready, cannot iterate over it");
        return or_inconsistent_state;
    }
    for (wsp = s_workspace_list_head; wsp != NULL; wsp = wsp->next)
    {
        res = callback(wsp, data);
        if (res != or_continue_iterating) break;
    }
    RELEASE_LIST_MUTEX;
    return (res == or_continue_iterating) ? or_thread_not_found : res;
}

#ifdef __linux__
static void before_fork();
static void after_fork_in_parent();
static void after_fork_in_child();
#endif

operation_result_t init_workspace_machinery()
{
#ifdef __linux__
    if (pthread_mutex_init(&s_workspace_list_mutex, NULL) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot init workspace list mutex, errno: %d",
                errno);
        return or_fail;
    }
    if (pthread_atfork(before_fork, after_fork_in_parent,
                       after_fork_in_child) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot register atfork callbacks for " \
                "workspace machinery, errno: %d", errno);
        return or_fail;
    }
#elif defined(_WIN32)
	InitializeCriticalSection(&s_workspace_list_mutex);
#else
#error Unsupported platform
#endif
    s_workspace_status = ws_ready;
    return or_okay;
}

static operation_result_t free_workspace_list_unguarded(int handling_fork)
{
    operation_result_t intermediate = or_okay;
    // TODO: think if below could be refactored as
    //       "while (s_workspace_list_head != NULL) free_item(....)"
    if (s_workspace_list_head != NULL)
    {
        while (s_workspace_list_head->next != NULL)
        {
            intermediate = free_workspace_unguarded(s_workspace_list_head->next, 0, handling_fork);
            if (intermediate != or_okay)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot free workspace list element: %s, " \
                        "stopping list freeing", get_operation_result_str(intermediate));
                return intermediate;
            }
        }
        intermediate = free_workspace_unguarded(s_workspace_list_head, 0, handling_fork);
        if (intermediate != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot free workspace list element: %s, " \
                    "stopping list freeing", get_operation_result_str(intermediate));
            return intermediate;
        }
        s_workspace_list_head = NULL;
    }
    return or_okay;
}

operation_result_t free_workspace_machinery()
{
    operation_result_t result = or_okay;
    TAKE_LIST_MUTEX;
    if (s_workspace_status != ws_ready)
    {
        RELEASE_LIST_MUTEX;
        PYSAMPROF_LOG(PL_ERROR, "Cannot free workspace machinery - list not ready");
        return or_inconsistent_state;
    }
    result = free_workspace_list_unguarded(0);
    s_workspace_status = ws_dead;
    RELEASE_LIST_MUTEX;
    PYSAMPROF_LOG(PL_INFO, "workspace machinery freed");
#ifdef __linux__
	int status = pthread_mutex_destroy(&s_workspace_list_mutex);
	if (status != 0)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot destroy workspace list mutex, error: %d", status);
		if (result == or_okay) result = or_mutex_error;
	}
#elif defined(_WIN32)
	DeleteCriticalSection(&s_workspace_list_mutex);
#else
#error Unsupported platform
#endif
    return result;
}

#ifdef __linux__
static void before_fork()
{
    /* Must aqcuire s_workspace_list_mutex so it is in consistent state after forking.
       Note that calling async-unsafe functions (like most pthread ones) is not
       recommended by POSIX standard, and mixing threads and fork is a bad idea, but
       in reality nobody cares :( */
    TAKE_LIST_MUTEX;
}

static void after_fork_in_parent()
{
    // release mutex back
    RELEASE_LIST_MUTEX;
}

static void after_fork_in_child()
{
    /* no need to lock the list as we're already owning the lock pre-fork */
    operation_result_t intermediate = free_workspace_list_unguarded(1);
    if (intermediate != or_okay)
    {
        // Still mark the list as empty, it's invalid at this point.
        // Note that it potentially leaks some resources :(
        // But this is expected not to happen.
        PYSAMPROF_LOG(PL_WARNING, "Cannot free workspace machinery after fork: %s",
                get_operation_result_str(intermediate));
        s_workspace_list_head = NULL;
    }
    RELEASE_LIST_MUTEX;
}
#endif

