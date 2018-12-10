#include <Python.h>

#include "collector_state.h"
#include "code_reporting.h"
#include "os_abstract.h"
#include "workspace.h"
#include "_pysamprof.h"

#ifdef _WIN32
#include "sampling_thread.h"
#endif

#include "../trace_writer/include/client_handles.h"
#include "../trace_writer/include/ipc_message.h"

#include <common/utilities/utilities.h>

struct collector_state_t
{
	thread_handle_t* myself;
	master_handle_t* master;

	collection_state_t collection_state;

	mutex_t lock;

	int sampling_rate_msec;
#ifdef __linux__
	int sampling_signo;
#endif

	code_reporting_state_t code_reporting;
};

static collector_state_t s_collector_state;

operation_result_t init_collector_state()
{
	operation_result_t status;

	memset(&s_collector_state, 0, sizeof(collector_state_t));
	s_collector_state.collection_state = cs_stopped;

	// setting default sampling rate and signal number
	s_collector_state.sampling_rate_msec = 10;
#ifdef __linux__
	s_collector_state.sampling_signo = 38;
#endif

#ifdef __linux__
    int pthread_res = pthread_mutex_init(&(s_collector_state.lock), NULL);
    if (pthread_res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot init ring buffer mutex: %d", pthread_res);
        return or_mutex_error;
    }
#elif defined(_WIN32)
	InitializeCriticalSectionAndSpinCount(&(s_collector_state.lock), 4000);
#else
#error Unsupported platform
#endif

	status = init_code_reporting(&s_collector_state);
	if (status != or_okay) return status;

	return or_okay;
}

#ifdef _WIN32
static operation_result_t stop_sampling_thread(workspace_t* wsp, void* data)
{
	operation_result_t res = free_wsp_thread(wsp);
	if (res != or_okay)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot stop sampling thread for %p wsp (%ld tid)",
			wsp, (wsp != NULL) ? (wsp->tid) : 0);
	}
	else
	{
		PYSAMPROF_LOG(PL_INFO, "Stopped sampling thread for %p wsp (%ld tid)",
			wsp, (wsp != NULL) ? (wsp->tid) : 0);
	}
	return or_continue_iterating;
}
#endif

operation_result_t finalize_collector_state(int has_gil, collection_state_t next_state)
{
	operation_result_t res = or_okay;
	PyThreadState* old_tstate = NULL;
	if (next_state == cs_running)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot finalize collector state when next state is running");
		return or_inconsistent_state;
	}

	LOCK_MUTEX(&(s_collector_state.lock));

	if (s_collector_state.collection_state != cs_stopped)
    {
#ifdef __linux__
		// TODO: should be a symmetric destructor function to setup_signal_handler
        {
            struct sigaction sa;
            sa.sa_handler = SIG_IGN;
            sa.sa_flags = 0;
            if (sigaction(s_collector_state.sampling_signo, &sa, NULL) != 0)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot unregister signal action");
            }
			// sleep one sampling period so that all running signal handlers finish
			msleep(s_collector_state.sampling_rate_msec);
        }
#elif defined(_WIN32)
		res = iterate_workspaces(stop_sampling_thread, NULL);
		if (res != or_thread_not_found)
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot stop sampling threads: %s", get_operation_result_str(res));
		}
#else
#error Unsupported platform
#endif
		if (has_gil)
		{
			// release GIL so that symbol thread can grab it and quit by reading global flag
			old_tstate = PyEval_SaveThread();
			if (old_tstate == NULL)
			{
				PYSAMPROF_LOG(PL_WARNING, "Supposed to own GIL, thus tstate must not be NULL, but it is NULL");
			}
		}

		res = stop_code_reporting(&s_collector_state);
		if (res != or_okay)
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot stop code reporting: %s",
				get_operation_result_str(res));
		}

		if (has_gil && old_tstate != NULL)
		{
			PyEval_RestoreThread(old_tstate);
		}

        if (next_state == cs_stopped)
        {
			// only unregister on stop, don't unregister on pause
            res = unregister_process(s_collector_state.master, s_collector_state.myself);
            if (res != or_okay)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot unregister myself: %s",
                        get_operation_result_str(res));
            }
			if (s_collector_state.master != NULL) free_master_handle_client(s_collector_state.master);
			if (s_collector_state.myself != NULL) free_thread_handle_client(s_collector_state.myself);
			s_collector_state.master = NULL;
			s_collector_state.myself = NULL;
			g_server_info.pid = 0;
        }
    }

	s_collector_state.collection_state = next_state;
	UNLOCK_MUTEX(&(s_collector_state.lock));
	return res;
}

operation_result_t get_code_reporting(code_reporting_state_t** result)
{
	if (result == NULL) return or_fail;
	*result = &(s_collector_state.code_reporting);
	return or_okay;
}

operation_result_t grab_collector_handles(
		thread_handle_t** myself, master_handle_t** master)
{
	LOCK_MUTEX(&(s_collector_state.lock));
	if (myself != NULL) *myself = s_collector_state.myself;
	if (master != NULL) *master = s_collector_state.master;
	return or_okay;
}

operation_result_t release_collector_handles()
{
	UNLOCK_MUTEX(&(s_collector_state.lock));
	return or_okay;
}

operation_result_t grab_myself_handle_nolock(thread_handle_t** myself)
{
	assert(s_collector_state.collection_state == cs_running);
	if (s_collector_state.collection_state != cs_running)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot grab own handle without locks when collection is not running (current state: %d)",
			s_collector_state.collection_state);
		return or_inconsistent_state;
	}
	if (myself != NULL) *myself = s_collector_state.myself;
	return or_okay;
}

operation_result_t grab_sampling_params(int* rate_msec, int* signo)
{
	LOCK_MUTEX(&(s_collector_state.lock));
	if (rate_msec != NULL) *rate_msec = s_collector_state.sampling_rate_msec;
#ifdef __linux__
	if (signo != NULL) *signo = s_collector_state.sampling_signo;
#elif defined(_WIN32)
	if (signo != NULL) *signo = 0;
#else
#error Unsupported platform
#endif
	UNLOCK_MUTEX(&(s_collector_state.lock));
	return or_okay;
}

operation_result_t grab_collection_state(collection_state_t* result)
{
	LOCK_MUTEX(&(s_collector_state.lock));
	if (result != NULL) *result = s_collector_state.collection_state;
	UNLOCK_MUTEX(&(s_collector_state.lock));
	return or_okay;
}

operation_result_t set_sampling_params(int rate_msec, int signo)
{
	LOCK_MUTEX(&(s_collector_state.lock));
	if (s_collector_state.collection_state == cs_running)
	{
		UNLOCK_MUTEX(&(s_collector_state.lock));
		PYSAMPROF_LOG(PL_ERROR, "Cannot change sampling params when collection is running");
		return or_inconsistent_state;
	}

	s_collector_state.sampling_rate_msec = rate_msec;
#ifdef __linux__
	s_collector_state.sampling_signo = signo;
#endif
	UNLOCK_MUTEX(&(s_collector_state.lock));
	return or_okay;
}

operation_result_t set_collection_state(collection_state_t state)
{
	LOCK_MUTEX(&(s_collector_state.lock));
	s_collector_state.collection_state = state;
	UNLOCK_MUTEX(&(s_collector_state.lock));
	return or_okay;
}

operation_result_t set_collector_handles(thread_handle_t* myself, master_handle_t* master)
{
	if (s_collector_state.collection_state != cs_stopped)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot set collector handles when collection is not stopped");
		return or_inconsistent_state;
	}

	s_collector_state.myself = myself;
	s_collector_state.master = master;

	return or_okay;
}
