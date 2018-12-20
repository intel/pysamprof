#define _POSIX_C_SOURCE 201706L

#include "signal_manager.h"

#include <time.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include <logging/logging.h>
#include "collector_state.h"

operation_result_t allocate_wsp_altstack(workspace_t* wsp, size_t minimum_size)
{
    if (wsp == NULL) return or_fail;
    if (wsp->altstack != NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Workspace for tid %lld already has altstack",
                (long long )wsp->tid);
        return or_fail;
    }
    stack_t ss;
    if (sigaltstack(NULL, &ss) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get altstack for %lld thread, errno: %d",
                (long long )wsp->tid, errno);
        return or_fail;
    }
    // TODO: change to mmap/munmap and protect pages for better safety
    if (!(ss.ss_flags & SS_DISABLE))
    {
        if (ss.ss_size >= minimum_size)
        {
            wsp->altstack_size = ss.ss_size;
            return or_okay;
        }
        else if (syscall(SYS_gettid) != getpid())
        {
            // this is not a first thread, we cannot be sure it is safe to override
            PYSAMPROF_LOG(PL_ERROR, "Altstack for %lld thread already set but "
                    "it is too small: it has %lld size while minimum is %lld",
                    (long long )wsp->tid, (long long )ss.ss_size, (long long )minimum_size);
            return or_small_altstack;
        }
        else
        {
            PYSAMPROF_LOG(PL_INFO, "Found that main thread has too small altstack, overriding");
        }
    }

    // no alt. stack used or it is too small and we deemed safe to override it
    ss.ss_sp = malloc(minimum_size);
    if (ss.ss_sp == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate %lld-sized altstack",
                (long long )minimum_size);
        return or_insufficient_memory;
    }
    ss.ss_size = minimum_size;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot set new altstack for %lld thread, errno: %d",
                (long long )wsp->tid, errno);
        return or_fail;
    }
    wsp->altstack = ss.ss_sp;
    wsp->altstack_size = minimum_size;
    return or_okay;
}

operation_result_t free_wsp_altstack(workspace_t* wsp, int current_thread)
{
    if (wsp == NULL) return or_fail;
    if (wsp->altstack == NULL)
    {
        // altstack not managed by us
        return or_okay;
    }
    if (current_thread)
    {
        stack_t ss;
        if (sigaltstack(NULL, &ss) != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot get altstack for %lld thread, errno: %d",
                    (long long )wsp->tid, errno);
            return or_fail;
        }
        if (ss.ss_sp != wsp->altstack || ss.ss_size != wsp->altstack_size)
        {
            // something changed altstack without our notice :(
            PYSAMPROF_LOG(PL_ERROR, "Inconsistent altstack for %lld thread"
                    " - changed outside of pysamprof", (long long )wsp->tid);
            return or_inconsistent_state;
        }
        ss.ss_sp = NULL;
        ss.ss_size = 0;
        ss.ss_flags = SS_DISABLE;
        if (sigaltstack(&ss, NULL) != 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot disable altstack for %lld thread, "
                    "errno: %d", (long long )wsp->tid, errno);
            return or_fail;
        }
    }
    // now we can free the memory
    // TODO: change to mmap/munmap with protecting pages for better safety
    free(wsp->altstack);
    wsp->altstack = NULL;
    wsp->altstack_size = 0;
    return or_okay;
}

operation_result_t setup_wsp_timer(workspace_t* wsp, int msec_interval, int signo)
{
    if (wsp == NULL) return or_fail;

    struct sigevent sev;
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = signo;
    sev.sigev_value.sival_ptr = wsp;
    sev._sigev_un._tid = wsp->tid;

    if (timer_create(CLOCK_MONOTONIC, &sev, &wsp->timer) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create monotonic timer for %lld thread, "
                "errno: %d", (long long )wsp->tid, errno);
        return or_fail;
    }

    struct itimerspec ival;
    ival.it_interval.tv_sec = msec_interval / 1000;
    ival.it_interval.tv_nsec = ((long long)msec_interval * 1000000L) % 1000000000ULL;

    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ival.it_value) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get CPU time for %lld thread, errno: %d",
                (long long )wsp->tid, errno);
        return or_fail;
    }
    wsp->prev_cpu_value = ival.it_value;

    ival.it_value = ival.it_interval;
    if (timer_settime(wsp->timer, 0, &ival, NULL) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot start timer for %lld thread, errno: %d",
                (long long )wsp->tid, errno);
        return or_fail;
    }

    return or_okay;
}

operation_result_t free_wsp_timer(workspace_t* wsp)
{
    if (wsp == NULL) return or_fail;
    if (wsp->prev_cpu_value.tv_sec == 0 && wsp->prev_cpu_value.tv_nsec == 0)
    {
        // timer not set, nothing to be done for the freeing request
        return or_okay;
    }
    if (timer_delete(wsp->timer) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot delete timer for %lld thread, errno: %d",
                (long long )wsp->tid, errno);
        return or_fail;
    }
    wsp->prev_cpu_value.tv_sec = 0;
    wsp->prev_cpu_value.tv_nsec = 0;
    return or_okay;
}

operation_result_t setup_signal_handler(signal_handler_t handler, int signo, int use_altstack)
{
    if (handler == NULL) return or_fail;
    struct sigaction sact;
    if (sigaction(signo, NULL, &sact) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get sigaction info for %d signal", signo);
        return or_fail;
    }

    int desired_flags = SA_SIGINFO | SA_RESTART;
    if (use_altstack)
    {
        // alt.stack enabled
        desired_flags |= SA_ONSTACK;
    }

    if (sact.sa_sigaction == handler)
    {
        if ((sact.sa_flags & desired_flags) == desired_flags)
        {
            PYSAMPROF_LOG(PL_INFO, "Signal handler already set up as requested");
            return or_okay;
        }
        PYSAMPROF_LOG(PL_ERROR,
                "Signal handler points to desired handler but flags are wrong: flags=%d, expected=%d",
                sact.sa_flags, desired_flags);
        return or_inconsistent_state;
    }

    if (sact.sa_handler != SIG_DFL && sact.sa_handler != SIG_IGN)
    {
        PYSAMPROF_LOG(PL_ERROR, "Signal %d is already taken by the application, "
                "handler: %p", signo, sact.sa_handler);
        return or_signal_taken;
    }

    sact.sa_handler = NULL;
    sact.sa_sigaction = handler;
    sact.sa_flags = desired_flags;
    sact.sa_restorer = NULL;
    if (sigfillset(&sact.sa_mask) != 0 || sigdelset(&sact.sa_mask, SIGSEGV) != 0
            || sigdelset(&sact.sa_mask, SIGBUS) != 0 || sigdelset(&sact.sa_mask, SIGFPE) != 0
            || sigdelset(&sact.sa_mask, SIGILL) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot make signal mask, errno: %d", errno);
        return or_fail;
    }

    if (sigaction(signo, &sact, NULL) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot install new handler for %d signal, errno: %d", signo,
                errno);
        return or_fail;
    }
    return or_okay;
}

operation_result_t block_sampling_signal(sigset_t *old_sigset)
{
    if (old_sigset == NULL) return or_fail;
    sigset_t set;
    int signo;
    operation_result_t status = grab_sampling_params(NULL, &signo);
    if (status == or_okay)
    {
        sigemptyset(&set);
        sigaddset(&set, signo);
        pthread_sigmask(SIG_BLOCK, &set, old_sigset);
    }
    else
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot grab sampling signo in dlopen probe: %s",
               get_operation_result_str(status));
    }
    return status;
}
