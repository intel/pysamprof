/* This is a test program used to perform different experiments.
 * Could be used as a crude example of how to use the libprobengine itself. */

#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#include <DbgHelp.h>
#else
#error Unsupported platform
#endif

#include "include/probengine/memory_regions.h"
#include "include/probengine/image_data.h"
#include "include/probengine/trampoline_mgr.h"
#include "include/probengine/prober.h"

#include "../common/logging/logging.h"

#ifdef __linux__
#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include <signal.h>

#include <sys/types.h> // for kill() mostly
#endif

#include <errno.h>

#ifdef __linux__
void handler(int signum, siginfo_t* info, void* ctx)
{
    printf("[DEBUG] handler(sig:%d) called\n", signum);
    unw_cursor_t cursor;
    unw_word_t ip, sp;
    /* ctx is a (void*)-casted (ucontext_t*), which is backwards-compatible
     * with libunwind (unw_context_t*) on IA-64 at least */
    int err = unw_init_local(&cursor, (unw_context_t*)ctx);
    if (err != 0) return;
    while (unw_step(&cursor) > 0)
    {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        printf("ip: %lx, sp: %lx\n", (long)ip, (long)sp);
    };
    printf("[DEBUG] handler(sig:%d) finishing\n", signum);
}

typedef ssize_t (*recv_t)(int sockfd, void *buf, size_t len, int flags);

static recv_t original_recv = NULL;
ssize_t recv_probe(int sockfd, void *buf, size_t len, int flags)
{
    printf("[DEBUG] recv called! (sock=%d, buf=%p, len=%ld, flags=%x)\n",
            sockfd, buf, len, flags);
    if (original_recv != NULL)
    {
        ssize_t result = original_recv(sockfd, buf, len, flags);
        printf("[DEBUG] recv returned, result=%ld\n", result);
        return result;
    }
    else
    {
        return -1;
    }
}

void do_unwind(void)
{
    unw_context_t ctx;
    unw_cursor_t cursor;
    unw_word_t ip, sp;
    if (unw_getcontext(&ctx) != 0)
    {
        printf("[DEBUG] unw_getcontext error\n");
        return;
    }
    int err = unw_init_local(&cursor, &ctx);
    switch (err)
    {
        case UNW_EINVAL:
            printf("[DEBUG] unw_init_local - can only do remote\n");
            return;
        case UNW_EUNSPEC:
            printf("[DEBUG] unw_init_local - something bad happened\n");
            return;
        case UNW_EBADREG:
            printf("[DEBUG] unw_init_local - needed register inaccessible\n");
            return;
        default:
            break;
    }

    do
    {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        printf("ip: %lx, sp: %lx\n", (long)ip, (long)sp);
    } while (unw_step(&cursor) > 0);
}
#elif defined(_WIN32)

CRITICAL_SECTION s_thread_mutex;
CONDITION_VARIABLE s_thread_var;

static HANDLE s_unwind_thread;

DWORD WINAPI do_unwind_other_thread(void* param)
{
    CONTEXT ctx;
    STACKFRAME64 frame;
    HANDLE thread = (HANDLE)param;

    /* s_thread_mutex is released by the thread we want to unwind when it has suspended itself.
       This release is handled atomically by SleepConditionVariableCS().
       So when we acquire s_thread_mutex it means it's safe to get thread context and stackwalk it. */
    EnterCriticalSection(&s_thread_mutex);

    do
    {
        if (!SymInitialize(GetCurrentProcess(), NULL, TRUE))
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot do SymInitialize, error: %ld", GetLastError());
            break;
        }

        memset(&ctx, 0, sizeof(ctx));
        memset(&frame, 0, sizeof(frame));

        ctx.ContextFlags = CONTEXT_CONTROL;

        if (!GetThreadContext(thread, &ctx))
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot get thread ctx, error: %ld", GetLastError());
            break;
        }

        frame.AddrPC.Mode      = AddrModeFlat;
        frame.AddrStack.Mode   = AddrModeFlat;
        frame.AddrFrame.Mode   = AddrModeFlat;
#ifndef _WIN64
        frame.AddrPC.Offset    = ctx.Eip;
        frame.AddrStack.Offset = ctx.Esp;
        frame.AddrFrame.Offset = ctx.Ebp;
#else
        frame.AddrPC.Offset    = ctx.Rip;
        frame.AddrStack.Offset = ctx.Rsp;
        frame.AddrFrame.Offset = ctx.Rbp;
#endif

        // TODO: use RtlVirtualUnwind on x64 for unwinding

        // NOTE: stackwalk64 must be lock-protected to avoid concurrent calls
        while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(), thread, &frame, &ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
        {
            PYSAMPROF_LOG(PL_INFO, "ip = %p", (void*)frame.AddrPC.Offset);
        }

    } 
    while (0);
    LeaveCriticalSection(&s_thread_mutex);
    WakeConditionVariable(&s_thread_var);	
    CloseHandle(s_unwind_thread);
    CloseHandle(thread);
    return 0;
}

void do_unwind(void)
{
    HANDLE target = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
    InitializeCriticalSection(&s_thread_mutex);
    InitializeConditionVariable(&s_thread_var);

    EnterCriticalSection(&s_thread_mutex);

    // spawn the thread
    s_unwind_thread = CreateThread(NULL, 0, do_unwind_other_thread, target, 0, NULL);
    if (s_unwind_thread == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Failed to create thread, error: %ld", GetLastError());
        LeaveCriticalSection(&s_thread_mutex);
        DeleteCriticalSection(&s_thread_mutex);
        CloseHandle(target);
        return;
    };
    SleepConditionVariableCS(&s_thread_var, &s_thread_mutex, INFINITE);

    LeaveCriticalSection(&s_thread_mutex);
    DeleteCriticalSection(&s_thread_mutex);
}

typedef HANDLE (WINAPI *CreateThread_t)(LPSECURITY_ATTRIBUTES  lpThreadAttributes,
                                        SIZE_T                 dwStackSize,
                                        LPTHREAD_START_ROUTINE lpStartAddress,
                                        LPVOID                 lpParameter,
                                        DWORD                  dwCreationFlags,
                                        LPDWORD                lpThreadId);
static CreateThread_t original_CreateThread = NULL;

HANDLE WINAPI CreateThread_probe(LPSECURITY_ATTRIBUTES  lpThreadAttributes,
                                 SIZE_T                 dwStackSize,
                                 LPTHREAD_START_ROUTINE lpStartAddress,
                                 LPVOID                 lpParameter,
                                 DWORD                  dwCreationFlags,
                                 LPDWORD                lpThreadId)
{
    printf("CreateThread() called\n");
    if (original_CreateThread != NULL) return original_CreateThread(lpThreadAttributes,
        dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    return NULL;
}

#else
#error Unsupported platform
#endif

void bar(int* q, double* p, void* proc);
int main(int argc, char* argv[]);

#ifdef __linux__
void foo(int a, double b)
{
    printf("[DEBUG] foo(%d, %f) called\n", a, b);
    printf("[DEBUG] expected stack:\n%s - %lx\n%s - %lx\n%s - %lx\n%s - %lx\n",
            "do_unwind", (long)(&do_unwind),
            "foo", (long)(&foo),
            "bar", (long)(&bar),
            "main", (long)(&main));
    //do_unwind();
    pid_t self_pid = getpid();
    kill(self_pid, 38);
}
#elif defined(_WIN32)
__declspec(dllexport) 
void foo(int a, double b)
{
    printf("[DEBUG] foo(%d, %f) called\n", a, b);
    printf("[DEBUG] expected stack:\n%s - %p\n%s - %p\n%s - %p\n%s - %p\n",
            "do_unwind", (void*)(&do_unwind),
            "foo", (void*)(&foo),
            "bar", (void*)(&bar),
            "main", (void*)(&main));
    do_unwind();
}
#else
#error Unsupported platform
#endif

typedef void (*foo_t)(int a, double b);

void bar(int* q, double* p, void* proc)
{
    ((foo_t)proc)(*q, *p);
}

foo_t foo_original;
void foo_probe(int a, double b)
{
    printf("[DEBUG] foo_probe called, calling foo()\n");
    foo_original(a, b);
    printf("[DEBUG] foo() call finished\n");
}

void simple1(void)
{
    printf("simple1 called\n");
}

#ifdef _WIN32
__declspec(dllexport) 
#endif
void simple2(void)
{
    simple1();
}

#ifdef _WIN32
__declspec(dllexport) 
#endif
int process(const char* libpath, const char* funcname,
        void* func, void* probe, void**original, all_memory_regions_t regions)
{
#ifdef __linux__
    void* lib = NULL;
#define FREE_LIB if (lib != NULL) dlclose(lib);
#elif defined(_WIN32)
    HMODULE lib = NULL;
#define FREE_LIB if (lib != NULL) FreeLibrary(lib);
#else
#error Unsupported platform
#endif
    if (func == NULL)
    {
#ifdef __linux__
        lib = dlopen(libpath, RTLD_LAZY);
        if (lib == NULL)
        {
            fprintf(stderr, "Cannot load lib %s: %s\n", libpath, dlerror());
            return 1;
        }

        func = dlsym(lib, funcname);
#elif defined(_WIN32)
        lib = LoadLibrary(libpath);
        if (lib == NULL)
        {
            fprintf(stderr, "Cannot load lib %s: %ld", libpath, GetLastError());
            return 1;
        }
        func = (void*)GetProcAddress(lib, funcname);
        if (func == NULL)
        {
            fprintf(stderr, "Cannot load function %s from lib %s: %ld", funcname, libpath, GetLastError());
            FREE_LIB;
            return 1;
        }
#else
#error Unsupported platform
#endif
    }

    {
        size_t func_size = 0;
        operation_result_t res = get_function_region_size(func, regions, &func_size);
        printf("[DEBUG] get_function_size('%s'): %s, size:%d\n", funcname, get_operation_result_str(res), (int)func_size);
        if (res != or_okay)
        {
            FREE_LIB;
            return 1;
        }
    }

    {
        void* tramp = NULL;
        operation_result_t res = allocate_nearest_trampoline(func, 0, regions, &tramp);
        printf("[DEBUG] got trampoline %p, res:%d\n", tramp, res);

        res = probe_function(func, probe, regions, original);
        printf("[DEBUG] probe_function(%s): %s\n", funcname, get_operation_result_str(res));
        FREE_LIB;

        return (res != or_okay) ? 1 : 0;
    }
}

#ifdef __linux__
#define PR_SIZET "zu"
#elif defined(_WIN64)
#define PR_SIZET "llu"
#else
#error Unsupported platform
#endif

int main(int argc, char* argv[])
{
#ifdef __linux__
    stack_t ss;
    ss.ss_size = 0x10000; // 64 KB
    ss.ss_sp = malloc(ss.ss_size);
    ss.ss_flags = SS_ONSTACK;
    if (ss.ss_sp == NULL)
    {
        fprintf(stderr, "[DEBUG] cannot allocate altstack\n");
        return 5;
    }
    if (sigaltstack(&ss, NULL) != 0)
    {
        fprintf(stderr, "[DEBUG] cannot call sigaltstack(), errno: %d, \n", errno);
        perror("msg");
        return 5;
    }
    struct sigaction sa;
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    if (sigemptyset(&sa.sa_mask) != 0)
    {
        perror("[DEBUG] cannot empty sa_mask");
        return 5;
    }
    if (sigaction(38, &sa, NULL) != 0)
    {
        perror("[DEBUG] cannot set signal action");
        return 5;
    }
#endif

    int a0 = 10;
    double b0 = 100.0;
    all_memory_regions_t regions;
    operation_result_t res;

    res = init_logging();
    if (res != or_okay)
    {
        fprintf(stderr, "Cannot init pysamprof logging: %s\n", get_operation_result_str(res));
        return 10;
    }

    res = parse_memory_regions(&regions, 0);
    printf("[DEBUG] parsed regions, got %d items, result: %s\n", regions.count, get_operation_result_str(res));
    if (res == or_okay)
    {
        int i;
        memory_region_info_t* current = regions.regions;
        for (i = 0; i < regions.count; i++, current++)
        {
#define FLAG_YESNO(perms, flag) ((((perms) & (flag)) == (flag)) ? "yes" : "no")
            printf("[DEBUG] %s: %p +%" PR_SIZET " read:%s write:%s exec:%s private:%s\n",
                   current->filename,
                   current->base, current->size,
                   FLAG_YESNO(current->permissions, PERMISSIONS_READ),
                   FLAG_YESNO(current->permissions, PERMISSIONS_WRITE),
                   FLAG_YESNO(current->permissions, PERMISSIONS_EXECUTE),
                   FLAG_YESNO(current->permissions, PERMISSIONS_PRIVATE)
                   );
#undef FLAG_YESNO
        }

    }
    else
    {
        return 1;
    }

    xed_initialize();
    {
#ifdef __linux__
        int rcode = process("libc.so.6", "recv", NULL, recv_probe, (void**)&original_recv, regions);
        if (rcode != 0) return rcode;

        int recv_res = recv(-1, NULL, 0, MSG_WAITALL);
        printf("[DEBUG] recv(<incorrect arg>) returned %d\n", recv_res);
#elif defined(_WIN32)
        int rcode = process("kernel32.dll", "CreateThread", NULL, CreateThread_probe, (void**)&original_CreateThread, regions);
#else
#error Unsupported platform
#endif

        void* simple2_orig;
#ifdef __linux__
        rcode = process(NULL, "simple2", simple2, send, &simple2_orig, regions);
#elif defined(_WIN32)
        rcode = process(NULL, "simple2", simple2, VirtualQuery, &simple2_orig, regions);
#else
#error Unsupported platform
#endif
        //if (rcode != 0) return rcode;

        rcode = process(NULL, "foo", foo, foo_probe, (void**)&foo_original, regions);
        if (rcode == 0)
        {
            bar(&a0, &b0, &foo);
        }
    }

    free_memory_regions(regions);
    free_all_image_data();
    free_all_trampolines();

    return 0;
}
