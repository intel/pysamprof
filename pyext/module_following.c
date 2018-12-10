#include "module_following.h"

#ifdef _WIN32
#include <Winbase.h>
#elif defined(__linux__)
#include <link.h>
#include <dlfcn.h>
#else
#error Unsupported platform
#endif

#include <probengine/prober.h>
#include "collector_state.h"
#ifdef __linux__
#include "signal_manager.h"
#endif

static on_new_lib_callback_t s_on_new_lib = NULL;

#ifdef __linux__
typedef void* (*dlopen_t)(const char* filename, int flags);
typedef void* (*dlmopen_t)(Lmid_t lmid, const char* filename, int flags);
static dlopen_t s_dlopen_original = NULL;
static dlmopen_t s_dlmopen_original = NULL;

#define BLOCK_SIGNAL(status, old_set)       \
    sigset_t old_set;                       \
    operation_result_t status;              \
    BLOCK_SAMPLING_SIGNAL(status, old_set);

#define UNBLOCK_SIGNAL(block_status, old_set)                            \
    {                                                                    \
        if ((block_status) == or_okay) UNBLOCK_SAMPLING_SIGNAL(old_set); \
    }

void* dlopen_probe(const char* filename, int flags)
{
    BLOCK_SIGNAL(status, old);
    if (s_dlopen_original != NULL)
    {
        void* result = s_dlopen_original(filename, flags);
        if (result != NULL && s_on_new_lib != NULL) s_on_new_lib(result);
        UNBLOCK_SIGNAL(status, old);
        return result;
    }
    UNBLOCK_SIGNAL(status, old);
    return NULL;
}

void* dlmopen_probe(Lmid_t lmid, const char* filename, int flags)
{
    BLOCK_SIGNAL(status, old);
    if (s_dlmopen_original != NULL)
    {
        void* result = s_dlmopen_original(lmid, filename, flags);
        if (result != NULL && s_on_new_lib != NULL) s_on_new_lib(result);
        UNBLOCK_SIGNAL(status, old);
        return result;
    }
    UNBLOCK_SIGNAL(status, old);
    return NULL;
}

#elif defined(_WIN32)
typedef HMODULE (WINAPI *LoadLibraryA_t)(const char* name);
typedef HMODULE (WINAPI *LoadLibraryW_t)(const wchar_t* name);
typedef HMODULE (WINAPI *LoadLibraryExA_t)(const char* name, HANDLE hFile, DWORD dwFlags);
typedef HMODULE (WINAPI *LoadLibraryExW_t)(const wchar_t* name, HANDLE hFile, DWORD dwFlags);

static LoadLibraryA_t s_LoadLibraryA_original = NULL;
static LoadLibraryW_t s_LoadLibraryW_original = NULL;
static LoadLibraryExA_t s_LoadLibraryExA_original = NULL;
static LoadLibraryExW_t s_LoadLibraryExW_original = NULL;

#define MAKE_PROBE(funcname, params_with_type, param_names)                   \
    HMODULE WINAPI funcname##_probe params_with_type                          \
    {                                                                         \
        if (s_##funcname##_original != NULL)                                  \
        {                                                                     \
            HMODULE result = s_##funcname##_original param_names;             \
            if (result != NULL && s_on_new_lib != NULL) s_on_new_lib(result); \
            return result;                                                    \
        }                                                                     \
        return NULL;                                                          \
    }

MAKE_PROBE(LoadLibraryA, (const char* name), (name))
MAKE_PROBE(LoadLibraryW, (const wchar_t* name), (name))
MAKE_PROBE(LoadLibraryExA, (const char* name, HANDLE hFile, DWORD dwFlags), (name, hFile, dwFlags))
MAKE_PROBE(LoadLibraryExW, (const wchar_t* name, HANDLE hFile, DWORD dwFlags), (name, hFile, dwFlags))

#else
#error Unsupported platform
#endif

#define PROBE_FUNC(func, regions, res)                                                  \
{                                                                                       \
    res = probe_function(func, func##_probe, regions, (void**)(&s_##func##_original));  \
    CHECK_AND_REPORT_ERROR(res, "Cannot probe " # func, res);                           \
}

operation_result_t init_module_following(all_memory_regions_t regions, 
        on_new_lib_callback_t on_new_lib)
{
    operation_result_t res;
#ifdef __linux__
    PROBE_FUNC(dlopen, regions, res);
    // FIXME: for some reason cannot probe dlmopen so far
    //PROBE_FUNC(dlmopen, regions, res);
#elif defined(_WIN32)
    PROBE_FUNC(LoadLibraryA, regions, res);
    PROBE_FUNC(LoadLibraryW, regions, res);
    PROBE_FUNC(LoadLibraryExA, regions, res);
    PROBE_FUNC(LoadLibraryExW, regions, res);
#else
#error Unsupported platform
#endif

    s_on_new_lib = on_new_lib;
    return or_okay;
}
