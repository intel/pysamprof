#ifndef __PYSAMPROF_SIGNAL_MANAGER_H__
#define __PYSAMPROF_SIGNAL_MANAGER_H__

#ifndef __linux__
#error Supposed to be included on Linux only
#endif

#include <signal.h>
#include <time.h>

#include "../common/status/status.h"
#include "workspace.h"

#define MINIMUM_ALTSTACK (128 * 1024)

operation_result_t allocate_wsp_altstack(workspace_t* wsp, size_t minimum_size);
operation_result_t free_wsp_altstack(workspace_t* wsp, int current_thread);

operation_result_t setup_wsp_timer(workspace_t* wsp, int msec_interval, int signo);
operation_result_t free_wsp_timer(workspace_t* wsp);

typedef void (*signal_handler_t)(int, siginfo_t*, void*);
operation_result_t setup_signal_handler(signal_handler_t handler, int signo, int use_altstack);

operation_result_t block_sampling_signal(sigset_t *old_sigset);

#define BLOCK_SAMPLING_SIGNAL(status, old_set)    \
    {                                             \
        status = block_sampling_signal(&old_set); \
    }

#define UNBLOCK_SAMPLING_SIGNAL(old_set)                \
    {                                                   \
        pthread_sigmask(SIG_SETMASK, &(old_set), NULL); \
    }

#endif
