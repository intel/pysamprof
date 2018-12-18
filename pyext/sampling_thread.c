#include "sampling_thread.h"
#include "time_utils.h"
#include "threading_follow.h"

#include <logging/logging.h>

typedef struct
{
	workspace_t* wsp;
	sampling_func_t sampling_func;
	int sampling_rate_msec;
} wsp_thread_func_arg_t;

static DWORD WINAPI wsp_thread_func(void* data)
{
	operation_result_t status;
	workspace_t* wsp;
	sampling_func_t sampling_func;
	int sampling_rate_msec;
	CONTEXT ctx;
	DWORD wait_status;

	mark_current_thread_as_service();

	if (data == NULL) return 1;
	wsp = ((wsp_thread_func_arg_t*)data)->wsp;
	sampling_func = ((wsp_thread_func_arg_t*)data)->sampling_func;
	sampling_rate_msec = ((wsp_thread_func_arg_t*)data)->sampling_rate_msec;
	free(data);
	if (wsp == NULL) return 1;

	while (1)
	{
		MemoryBarrier();
		if (wsp->stop_sampling) return 0;

		if (SuspendThread(wsp->target_thread) != (DWORD)-1)
		{
			// thread paused successfully
			if (is_wsp_service_thread(wsp))
			{
				wsp->stop_sampling = 1;
			} else if (IS_SAMPLING_SAFE(wsp))
			{
				memset(&ctx, 0, sizeof(ctx));
				ctx.ContextFlags = CONTEXT_CONTROL;

				if (GetThreadContext(wsp->target_thread, &ctx))
				{
					status = sampling_func(wsp, &ctx);
					switch (status)
					{
					case or_stop_sampling_service:
						wsp->stop_sampling = 1;
						// Note: we cannot just return here as target_thread is suspended, we need to resume it first
						break;
					case or_okay:
						break;
					default:
						PYSAMPROF_LOG(PL_WARNING, "Cannot collect one sample for %ld tid: %s",
							wsp->tid, get_operation_result_str(status));
					}
				}
				else
				{
					PYSAMPROF_LOG(PL_WARNING, "Cannot get thread context for %ld tid, error: %ld",
						wsp->tid, GetLastError());
				}
			}

			if (ResumeThread(wsp->target_thread) == (DWORD)-1)
			{
				PYSAMPROF_LOG(PL_ERROR, "Cannot resume suspended thread %ld, error: %ld",
					wsp->tid, GetLastError());
			}
		}

		MemoryBarrier();
		if (wsp->stop_sampling) return 0;

		wait_status = WaitForSingleObject(wsp->target_thread, sampling_rate_msec);
		switch (wait_status)
		{
		case WAIT_OBJECT_0:
			PYSAMPROF_LOG(PL_INFO, "Sampled thread %ld stopped, sampler thread quitting", wsp->tid);
			return 0;
		case WAIT_TIMEOUT:
			// target thread is alive, continue sampling
			break;
		default:
			PYSAMPROF_LOG(PL_ERROR, "Unexpected result %ld of waiting for target thread %ld tid, error: %ld",
				wait_status, wsp->tid, wait_status, GetLastError());
			return 5;
		}
	}

	return 0;
}

operation_result_t setup_wsp_thread(workspace_t* wsp, int sampling_rate_msec, sampling_func_t func)
{
	operation_result_t status;
	HANDLE sampler;
	wsp_thread_func_arg_t* arg = (wsp_thread_func_arg_t*)malloc(sizeof(wsp_thread_func_arg_t));
	if (arg == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate wsp_thread argument");
		return or_insufficient_memory;
	}
	arg->wsp = wsp;
	arg->sampling_func = func;
	arg->sampling_rate_msec = sampling_rate_msec;
	wsp->stop_sampling = 0;
	MemoryBarrier();

	sampler = CreateThread_nofollow(NULL, 0, wsp_thread_func, arg, CREATE_SUSPENDED, NULL);

	if (sampler == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot create sampler thread for %ld tid, error: %ld", wsp->tid, GetLastError());
		free(arg);
		return or_cannot_start_thread;
	}

	if (!SetThreadPriority(sampler, THREAD_PRIORITY_HIGHEST))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot set highest thread priority for samper thread for %ld tid, error: %ld", wsp->tid, GetLastError());
	}

	status = get_cpu_time(wsp->target_thread, &wsp->prev_cpu_value);
	if (status != or_okay)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get initial CPU value for %ld tid: %s", wsp->tid, get_operation_result_str(status));
		TerminateThread(sampler, 0);
		CloseHandle(sampler);
		free(arg);
		return status;
	}

	wsp->sampling_thread = sampler;
	if (!ResumeThread(sampler))
	{
		wsp->sampling_thread = NULL;
		PYSAMPROF_LOG(PL_ERROR, "Cannot resume sampler thread for %ld tid, error: %ld", wsp->tid, GetLastError());
		TerminateThread(sampler, 0);
		CloseHandle(sampler);
		free(arg);
		return or_cannot_start_thread;
	}

	return or_okay;
}

operation_result_t free_wsp_thread(workspace_t* wsp)
{
	operation_result_t status = or_okay;
	if (wsp != NULL && wsp->sampling_thread != NULL)
	{
		DWORD wait;

		wsp->stop_sampling = 1;
		MemoryBarrier();

		wait = WaitForSingleObject(wsp->sampling_thread, INFINITE);
		switch (wait)
		{
		case WAIT_OBJECT_0:
			PYSAMPROF_LOG(PL_INFO, "Sampler thread for %ld tid stopped normally", wsp->tid);
			break;
		case WAIT_FAILED:
			PYSAMPROF_LOG(PL_ERROR, "Cannot wait for sampler thread for %ld tid to stop, error: %ld", wsp->tid, GetLastError());
			status = or_fail;
			break;
		default:
			PYSAMPROF_LOG(PL_ERROR, "Unexpected result %ld while waiting for sampler thread for %ld tid to stop, error: %ld",
				wait, wsp->tid, GetLastError());
			status = or_fail;
			break;
		}
		CloseHandle(wsp->sampling_thread);
		wsp->sampling_thread = NULL;
	}
	return status;
}
