#include <Python.h>
#ifndef WITH_THREAD
#error Python without threading not supported for profiling so far
#endif
#include <patchlevel.h>

#if PY_VERSION_HEX < 0x03000000
// Python 2.x
#define GET_CURRENT_PYSTATE (_PyThreadState_Current)
#elif PY_VERSION_HEX < 0x03060000
// Python 3.0 - 3.5
#define Py_BUILD_CORE
#include <pystate.h>
#undef Py_BUILD_CORE
#define GET_CURRENT_PYSTATE (PyThreadState_GET())
#else
// Python 3.6 or newer
#include <pystate.h>
#define GET_CURRENT_PYSTATE (_PyThreadState_UncheckedGet())
#endif

#ifndef PYSAMPROF_BUILDING_LIB
#error PYSAMPROF_BUILDING_LIB must be defined
#endif

#if defined(_WIN32) && !defined(Py_ENABLE_SHARED) && !defined(__CYGWIN__)
#error Cannot work when interpreter is completely static
#endif

#include <frameobject.h>
#include <pythread.h>

#include <stdlib.h>
#include <stddef.h>

#ifdef __linux__
#include <link.h>
#include <dlfcn.h>
#include <safe_str_lib.h>
typedef void* context_ptr_t;

#elif defined(_WIN32)
#include <Windows.h>
typedef CONTEXT* context_ptr_t;

#else
#error Unsupported platform
#endif

#include "os_abstract.h"

// for ring buffer
#include "ringbuffer.h"

#ifdef __linux__
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#elif defined(_WIN32)
#include <DbgHelp.h>
#endif

#include <probengine/memory_regions.h>
#include <probengine/prober.h>
#include <ipc-ng/ipc-ng.h>

#include <logging/logging.h>
#include <utilities/utilities.h>

#include "threading_follow.h"
#include "workspace.h"
#include "callstack_helper.h"
#include "callstack_helper_gen.h"

#ifdef __linux__
#include "signal_manager.h"
#include "vdso_parser.h"
#elif defined(_WIN32)
#include "sampling_thread.h"
#endif

#include "session.h"
#include "time_utils.h"
#include "collector_state.h"
#include "code_reporting.h"
#include "module_following.h"
#include "hang_protection.h"

#include "../trace_writer/include/trace_writer_api.h"
#include "../trace_writer/include/client_handles.h"
#include "../trace_writer/include/ipc_message.h"
#include "../trace_writer/include/function_info.h"

#include "_pysamprof.h"

static char module_docstring[] = "Pysamprof collector module";
static char start_docstring[] = "start(path) starts collecting session and puts data to 'path'";
static char pause_current_docstring[] = "pause_current() pauses collection in current process";
static char resume_current_docstring[] = "resume_current() resumes collection in current process";

static char request_server_pid_docstring[] = "request_server_pid() tries to get server PID from target process; " \
    "returns None if target process does not support pysamprof, 0 if no server present, -1 if this is server, or server pid";
// TODO: implement start_by_pid, pause_by_pid, resume_by_pid and stop_by_pid

// TODO: Most of stuff below should be put in one entity describing the collection.
//       Make sure access to entity is lock-protected.

static all_memory_regions_t s_memory_regions = { 0, NULL };

#ifdef __linux__
static vdso_table_t s_vdso_table = { 0, NULL };
static wsp_tid_t s_forking_tid = 0;
#endif

server_info_t g_server_info;
static char* s_collect_path = NULL;
static int64_t s_forked_parent_pid = 0;

operation_result_t collect_one_sample(workspace_t* wsp, context_ptr_t ctx, timeunit_t cpu_time)
{
    long long totaldeltanano = get_time_diff(wsp->prev_cpu_value, cpu_time);
    PyFrameObject* frame = NULL;
    uint32_t max_buf_size, stack_buf_size;
    ipc_message_sample_t *sample_msg;
    operation_result_t status;
    uint64_t* stack_data;

    thread_handle_t* myself;
    code_reporting_state_t* code_reporting;

#ifdef _WIN32
    STACKFRAME64 unwind_frame;
    DWORD64 prev_ip, ip;
#endif

    // fill in PyThreadState first
    switch (wsp->python_enabled)
    {
    case pes_will_be_python:
        {
            /* XXX: this is potentially unsafe. Most Python functions working
             with both PyInterpreterState and PyThreadState use locking for
             a good reason, so if handler is meddling with those variables
             when they're modified by some thread this may be disastrous.
             For now ignore such possibility.
             FIXME: place probes on unsafe functions so as to NOT try to
             get current thread's state when it's unsafe. */
            PyInterpreterState* interp = PyInterpreterState_Head();
            for (; interp != NULL && wsp->python_enabled != pes_is_python; interp = interp->next)
            {
                PyThreadState* tstate = interp->tstate_head;
                for (; tstate != NULL; tstate = tstate->next)
                {
                    if (tstate->thread_id == wsp->python_tid)
                    {
                        /* FIXME: tstate will become invalid pointer when
                         thread state is destroyed. Probe all functions
                         that destroy states to ensure we clean up this field. */
                        wsp->tstate = tstate;
                        wsp->python_enabled = pes_is_python;
                    }
                }
            }
        }
        break;
    case pes_service_thread:
        // thread became service, stop profiling
#ifdef __linux__
        free_wsp_timer(wsp);
#endif
        return or_stop_sampling_service;
    case pes_native: // fallthrough
    case pes_is_python:
        break;
    default:
        PYSAMPROF_LOG(PL_ERROR, "Got unexpected value of wsp->python_enabled: %d", (int)wsp->python_enabled);
        return or_fail;
    }

#ifdef __linux__
    unw_cursor_t cursor, prev;
    int err = unw_init_local(&cursor, (unw_context_t*)ctx);
    switch (err)
    {
    case UNW_EINVAL:
        PYSAMPROF_LOG(PL_ERROR, "unw_init_local: can only do remote");
        return or_stackwalk_failure;
    case UNW_EUNSPEC:
        PYSAMPROF_LOG(PL_ERROR, "unw_init_local: something bad happened");
        return or_stackwalk_failure;
    case UNW_EBADREG:
        PYSAMPROF_LOG(PL_ERROR, "unw_init_local: needed register inaccessible");
        return or_stackwalk_failure;
    default:
        break;
    }
#elif defined(_WIN32)

#else
#error Unsupported platform
#endif

    if (wsp->python_enabled == pes_is_python) frame = wsp->tstate->frame;

    status = grab_myself_handle_nolock(&myself);
    CHECK_AND_REPORT_ERROR(status, "Cannot grab handles from collector", status);
    status = get_code_reporting(&code_reporting);
    CHECK_AND_REPORT_ERROR(status, "Cannot get code reporting from collector", status);
    status = alloc_sample_message(myself,
        8 /* number of loops; FIXME: don't hardcode */,
        &(wsp->last_shmem_index), &sample_msg, &max_buf_size);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot allocate buffer for sample: %s",
                get_operation_result_str(status));
        return status;
    }

#define DISCARD_SAMPLE_MESSAGE                                                  \
    {                                                                           \
        operation_result_t discard_status = discard_sample_message(             \
                myself, sample_msg, max_buf_size);                              \
        if (discard_status != or_okay)                                          \
        {                                                                       \
            PYSAMPROF_LOG(PL_WARNING, "Cannot discard sample message: %s",      \
                    get_operation_result_str(discard_status));                  \
        }                                                                       \
    }

    if (max_buf_size < sizeof(ipc_message_sample_t))
    {
        PYSAMPROF_LOG(PL_ERROR, "Maximum buffer size (%d) is less than "
                "minimally needed for sample collection (%d)", max_buf_size,
                (int )sizeof(ipc_message_sample_t));
        DISCARD_SAMPLE_MESSAGE;
        return or_ipc_alloc_failure;
    }
    stack_buf_size = (max_buf_size - sizeof(ipc_message_sample_t)) / sizeof(uint64_t);

    // TODO: move some of ipc_message filling in a macro
    sample_msg->head.data_offset = offsetof(ipc_message_sample_t, body);
    sample_msg->head.type = ipc_message_sample_type;
    sample_msg->head.size = max_buf_size;
    sample_msg->head.version = IPC_NG_HEADER_VERSION;

    sample_msg->body.stack_offset = offsetof(ipc_message_sample_body_t, data);
    sample_msg->body.stack_size = 0;
    sample_msg->body.stack_type = mixed;
    sample_msg->body.duration = totaldeltanano;

    status = get_mono_time_nanosec(&(sample_msg->body.timestamp));
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get mono time: %s", get_operation_result_str(status));
        DISCARD_SAMPLE_MESSAGE;
        return or_time_utils_fail;
    }

    sample_msg->body.tid = wsp->tid;

    stack_data = (uint64_t*)((char*)(&sample_msg->body) + sample_msg->body.stack_offset);

#define ADD_STACK_ENTRY(addr, status)                                   \
    {                                                                   \
        if (sample_msg->body.stack_size >= stack_buf_size)              \
        {                                                               \
            status = or_insufficient_memory;                            \
        }                                                               \
        else                                                            \
        {                                                               \
            stack_data[sample_msg->body.stack_size] = (uint64_t)(addr); \
            sample_msg->body.stack_size++;                              \
            status = or_okay;                                           \
        }                                                               \
    }

#ifdef __linux__
    prev = cursor;
    unw_word_t prev_ip, ip;
    unw_get_reg(&prev, UNW_REG_IP, &prev_ip);
#elif defined(_WIN32)
    memset(&unwind_frame, 0, sizeof(unwind_frame));

    unwind_frame.AddrPC.Mode      = AddrModeFlat;
    unwind_frame.AddrStack.Mode   = AddrModeFlat;
    unwind_frame.AddrFrame.Mode   = AddrModeFlat;

#ifndef _WIN64
#define CURRENT_MACHINE_TYPE IMAGE_FILE_MACHINE_I386
    unwind_frame.AddrPC.Offset    = ctx->Eip;
    unwind_frame.AddrStack.Offset = ctx->Esp;
    unwind_frame.AddrFrame.Offset = ctx->Ebp;
#else
#define CURRENT_MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
    unwind_frame.AddrPC.Offset    = ctx->Rip;
    unwind_frame.AddrStack.Offset = ctx->Rsp;
    unwind_frame.AddrFrame.Offset = ctx->Rbp;
#endif
    prev_ip = unwind_frame.AddrPC.Offset;
    // StackWalk64 on first iteration only fills in missing portions of frame,
    // it does not walk down, while unw_step() walks down, 
    // so call StackWalk64 once more to mimick libunwind.
    LOCK_DBGHELP(code_reporting);
    if (!StackWalk64(CURRENT_MACHINE_TYPE, GetCurrentProcess(), wsp->target_thread,
        &unwind_frame, ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot stackwalk once, error: %ld", GetLastError());
        UNLOCK_DBGHELP(code_reporting);
        DISCARD_SAMPLE_MESSAGE;
        return or_stackwalk_failure;
    }
    UNLOCK_DBGHELP(code_reporting);
#else
#error Unsupported platform
#endif

#ifdef __linux__
    int unw_status = 0;
    while ((unw_status = unw_step(&cursor)) > 0)
#elif defined(_WIN32)
    while (1)
#else
#error Unsupported platform
#endif
    {
#ifdef _WIN32
        LOCK_DBGHELP(code_reporting);
        if (!StackWalk64(CURRENT_MACHINE_TYPE, GetCurrentProcess(), wsp->target_thread,
            &unwind_frame, ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
        {
            UNLOCK_DBGHELP(code_reporting);
            break;
        }
        UNLOCK_DBGHELP(code_reporting);
#endif

#ifdef __linux__
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
#elif defined(_WIN32)
        ip = unwind_frame.AddrPC.Offset;
#else
#error Unsupported platform
#endif
        if (IS_PYEVAL_PROBE(ip))
        {
            if (frame != NULL)
            {
                PyCodeObject* code = (PyCodeObject*)(frame->f_code);
                if (!(code->co_flags & CO_CODEOBJECT_REPORTED))
                {
                    ring_buffer_element_t element;
                    Py_INCREF((PyObject* )code);
                    element.data = (void*)code;
                    element.timestamp = sample_msg->body.timestamp;
                    LOCK_CODE_RING(code_reporting);
                    status = ring_buffer_push(&(code_reporting->symbol_ring), element);
                    switch (status)
                    {
                    case or_ring_buffer_full:
                        // not enough space in ring buffer, drop this sample and try later
                        UNLOCK_CODE_RING(code_reporting);
                        PYSAMPROF_LOG(PL_WARNING, "Cannot put PyCodeObject in ring buffer, buffer full");
                        DISCARD_SAMPLE_MESSAGE;
                        Py_DECREF((PyObject* )code);
                        return or_ring_buffer_full;
                    case or_okay:
                        break;
                    default:
                        UNLOCK_CODE_RING(code_reporting);
                        PYSAMPROF_LOG(PL_ERROR, "Unexpected result of putting in ring buffer: %s", get_operation_result_str(status));
                        DISCARD_SAMPLE_MESSAGE;
                        Py_DECREF((PyObject* )code);
                        return status;
                    }
                    code->co_flags |= CO_CODEOBJECT_REPORTED;
                    UNLOCK_CODE_RING(code_reporting);
                }

                ADD_STACK_ENTRY((char* )(code->co_code) + frame->f_lasti, status);
                if (status == or_insufficient_memory) break;
                frame = frame->f_back;
            }
        }
        else
        {
            if (!(IS_PYEVAL_PROBE(prev_ip)))
            {
                ADD_STACK_ENTRY(prev_ip, status);
                if (status == or_insufficient_memory) break;
            }
        }
#ifdef __linux__
        prev = cursor;
#endif
        prev_ip = ip;
    };
#ifdef __linux__
    if (unw_status < 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Stack unwinding for tid %ld stopped prematurely, unwind error: %d",
                wsp->tid, unw_status);
    }
#endif
    if (!(IS_PYEVAL_PROBE(ip)))
    {
        ADD_STACK_ENTRY(ip, status);
    }
    if (status == or_insufficient_memory)
    {
        PYSAMPROF_LOG(PL_WARNING, "Stack for tid %ld truncated during unwinding: "
                "did not fit in buffer, maximum %d entries", wsp->tid, stack_buf_size);
    }

    sample_msg->head.size = sizeof(ipc_message_sample_t)
            + sizeof(uint64_t) * sample_msg->body.stack_size;
    if (sample_msg->body.stack_size < 3)
    {
        PYSAMPROF_LOG(PL_WARNING, "Callstack for tid %ld has depth=%d which is lower than 3, "
                "discarding it as invalid", wsp->tid, (int)(sample_msg->body.stack_size));
        DISCARD_SAMPLE_MESSAGE;
        return or_okay;
    }

    status = push_sample_message(myself, sample_msg, max_buf_size);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot write sample: %s", get_operation_result_str(status));
        return status;
    }

    // adjust "old CPU time" value
    wsp->prev_cpu_value = cpu_time;
    return or_okay;
}

#ifdef __linux__
void handler(int signum, siginfo_t* info, void* ctx)
{
    workspace_t* wsp = get_thread_wsp();
    if (wsp == NULL)
    {
        PYSAMPROF_LOG(PL_WARNING, "Got NULL workspace when trying to profile in signal handler");
        return;
    }
    if (!IS_SAMPLING_SAFE(wsp)) return;

    struct timespec val;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &val) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "cannot get CPU time value in signal handler");
        return;
    }

    operation_result_t status = collect_one_sample(wsp, ctx, val);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot collect a sample for %ld: %s", wsp->tid, get_operation_result_str(status));
    }
}
#elif defined(_WIN32)
operation_result_t sampling_func(workspace_t* wsp, CONTEXT* ctx)
{
    timeunit_t cpu_time;

    operation_result_t status = get_cpu_time(wsp->target_thread, &cpu_time);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot get CPU time for %ld thread: %s", wsp->tid, get_operation_result_str(status));
        return status;
    }

    status = collect_one_sample(wsp, (void*)ctx, cpu_time);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot collect a sample for %ld: %s", wsp->tid, get_operation_result_str(status));
    }
    return status;
}
#else
#error Unsupported platform
#endif


static operation_result_t setup_thread_profiling(workspace_t* wsp)
{
    operation_result_t res = or_okay;
    int sampling_rate_msec, signo = 0;
    collection_state_t col_state;

    res = grab_collection_state(&col_state);
    CHECK_AND_REPORT_ERROR(res, "Cannot grab collection state from collector", res);

    if (col_state == cs_stopped || is_wsp_service_thread(wsp))
    {
        PYSAMPROF_LOG(PL_INFO, "Not setting up thread profiling for %p wsp: " \
            "either collection stopped (current state=%d) or thread is a service one", wsp, col_state);
        return or_okay;
    }
    res = grab_sampling_params(&sampling_rate_msec, &signo);
    CHECK_AND_REPORT_ERROR(res, "Cannot get sampling parameters from collector", res);

#ifdef __linux__
    res = setup_wsp_timer(wsp, sampling_rate_msec, signo);
#elif defined(_WIN32)
    res = setup_wsp_thread(wsp, sampling_rate_msec, sampling_func);
#else
#error Unsupported platform
#endif
    PYSAMPROF_LOG(PL_INFO, "setup_thread_profiling(wsp=%p): state=%d, rate=%d ms, signo=%d, res=%s",
            wsp, col_state, sampling_rate_msec, signo, get_operation_result_str(res));
    return res;
}

static operation_result_t on_new_thread(workspace_t* wsp)
{
    return setup_thread_profiling(wsp);
}

static operation_result_t create_timers(workspace_t* wsp, void* data)
{
    operation_result_t res = setup_thread_profiling(wsp);
    return (res != or_okay) ? res : or_continue_iterating;
}

operation_result_t pysamprof_stop_collection(int has_gil, collection_state_t next_state)
{
    operation_result_t res;
    VALIDATE_PARAMS(next_state == cs_stopped || next_state == cs_running || next_state == cs_paused,
        "pysamprof_stop_collection got invalid 'next_state' parameter: %d", (int)next_state);
    res = finalize_collector_state(has_gil, next_state);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot finalize collector state: %s",
            get_operation_result_str(res));
    }

    if (next_state == cs_stopped)
    {
#ifdef __linux__
        if (s_vdso_table.entries != NULL)
        {
            free(s_vdso_table.entries);
            s_vdso_table.entries = NULL;
        }
#endif
        if (s_memory_regions.regions != NULL)
        {
            free_memory_regions(s_memory_regions);
            s_memory_regions.regions = NULL;
        }
    }
    return res;
}

static void pysamprof_stop_collection_atextit(void)
{
    pysamprof_stop_collection(0, cs_stopped);
}

static void on_new_lib(module_handle_t handle)
{
    char* module_name = NULL;
#ifdef _WIN32
    char module_name_on_stack[2048];
#endif

    all_memory_regions_t new_regions;
    operation_result_t res;
    collection_state_t col_state;

    mark_thread_sampling_unsafe();

    res = grab_collection_state(&col_state);
    CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(res, "Cannot get collection state from collector",);

    {
#ifdef __linux__
        struct link_map* mapping;
        if (dlinfo(handle, RTLD_DI_LINKMAP, (void*)&mapping) == 0)
        {
            module_name = mapping->l_name;
        }
        else
        {
            PYSAMPROF_LOG((col_state == cs_stopped) ? PL_WARNING : PL_ERROR,
                "Cannot call dlinfo() on newly loaded library, dlerror: %s", dlerror());
        }
#elif defined(_WIN32)
        if (GetModuleFileName(handle, &module_name_on_stack[0], sizeof(module_name_on_stack) - 1) <= sizeof(module_name_on_stack) - 1)
        {
            module_name = &module_name_on_stack[0];
        }
        else
        {
            PYSAMPROF_LOG((col_state == cs_stopped) ? PL_WARNING : PL_ERROR,
                "Cannot call GetModuleName() on newly loaded library, error: %ld", GetLastError());
        }
#else
#error Unsupported platform
#endif
    }

    if (col_state == cs_stopped)
    {
        PYSAMPROF_LOG(PL_INFO, "Caught new library loaded, map unreported, handle: %p", handle);
        // collection not started, just update the map
        if (module_name != NULL)
        {
            PYSAMPROF_LOG(PL_INFO, "lib name: %s", module_name);
        }

        // FIXME: add a lock so parse_memory_regions() cannot be called concurrently
        res = parse_memory_regions(&new_regions, 1);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(res, "Cannot parse memory regions",);
        free_memory_regions(s_memory_regions);
        s_memory_regions = new_regions;
    }
    else
    {
        int64_t load_time;
        memory_region_info_t* current;
        int i;
        thread_handle_t* myself;

        // collection already started, grab new map but report only current library
        PYSAMPROF_LOG(PL_INFO, "Caught new library loaded, map update, handle: %p", handle);
        if (module_name == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot update memory map: module name not found");
            return;
        }

        res = get_mono_time_nanosec(&load_time);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(res, "Cannot get mono time for reporting new module",);
        // FIXME: add a lock so parse_memory_regions() cannot be called concurrently
        res = parse_memory_regions(&new_regions, 1);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(res, "Cannot parse memory regions",);

        res = grab_collector_handles(&myself, NULL);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(res, "Cannot grab handles from collector",);

        // XXX extremely inefficient way to parse... think about something better
        // FIXME: report ALL unreported regions, even those belonging NOT to current library;
        //        this might be the case for e.g. dependencies of current library
        current = new_regions.regions;
        for (i = 0; i < new_regions.count; i++, current++)
        {
            if (current->filename == NULL) continue;
            if (strcmp(current->filename, module_name) == 0)
            {
                PYSAMPROF_LOG(PL_INFO, "Found region for %s at %p", current->filename,
                        current->base);
                res = write_mapping_info(myself, (uint64_t)current->base,
                        (uint64_t)current->base + current->size, (uint64_t)current->file_offset,
                        load_time, current->filename);
                if (res != or_okay)
                {
                    PYSAMPROF_LOG(PL_ERROR, "Cannot report new region at %p: %s",
                            (void* )current->base, get_operation_result_str(res));
                }
            }
        }
        res = release_collector_handles();
        free_memory_regions(new_regions);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(res, "Cannot release collector handles",);
    }
    mark_thread_sampling_safe();
}

typedef void (*PyImport_Cleanup_t)(void);
static PyImport_Cleanup_t s_PyImport_Cleanup_original = NULL;
void PyImport_Cleanup_probe(void)
{
    mark_thread_sampling_unsafe();
    pysamprof_stop_collection(1, cs_stopped);
    mark_thread_sampling_safe();
    if (s_PyImport_Cleanup_original != NULL) s_PyImport_Cleanup_original();
}

#ifdef __linux__
static operation_result_t report_vdso_function(thread_handle_t* myself,
        vdso_entry_t* entry, int64_t load_time)
{
    PYSAMPROF_LOG(PL_INFO, "vDSO function: %s at %p (+%d)", entry->name, entry->start,
            entry->length);
    Perftools__Symbols__FunctionInfo* info = NULL;
    operation_result_t res = make_function_info(&info);
    CHECK_AND_REPORT_ERROR(res, "Cannot create storage for vDSO info proto", res);

    res = add_code_region_function_info(info, (uint64_t)entry->start, (uint8_t*)entry->start,
            (uint32_t)entry->length);
    CHECK_CLEANUP_AND_REPORT(res, "Cannot add vDSO code region", info, res);

    res = add_function_name_function_info(info, entry->name);
    CHECK_CLEANUP_AND_REPORT(res, "Cannot add vDSO name", info, res);

    res = add_timing_function_info(info, load_time);
    CHECK_CLEANUP_AND_REPORT(res, "Cannot add vDSO load time", info, res);

    res = send_function_info(myself, info);
    CHECK_CLEANUP_AND_REPORT(res, "Cannot send function proto info via IPC", info, res);

    free_proto_function_info(info);
    return or_okay;
}
#endif

#ifdef _WIN32
static __inline int64_t getpid()
{
    return GetCurrentProcessId();
}
#endif

#define CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, msg, retval)   \
    do {                                                        \
        if (res != or_okay)                                     \
        {                                                       \
            operation_result_t release_status;                  \
            PYSAMPROF_LOG(PL_ERROR, "%s: %s",                   \
                    msg, get_operation_result_str(res));        \
            release_status = release_collector_handles();       \
            if (release_status != or_okay)                      \
            {                                                   \
                PYSAMPROF_LOG(PL_ERROR,                         \
                    "Cannot release collector handles: %s",     \
                    get_operation_result_str(release_status));  \
            }                                                   \
            return retval;                                      \
        }                                                       \
    } while(0)

static operation_result_t validate_collection_params(const char* func, collection_state_t state,
        int period_msec, int signo, int64_t forked_parent_pid)
{
    VALIDATE_PARAMS(state == cs_stopped || state == cs_running || state == cs_paused,
        "%s got invalid 'state' parameter: %d", func, (int)state);
    VALIDATE_PARAMS(period_msec > 0,
        "%s got non-positive 'period_msec': %d", func, period_msec);
#ifdef _WIN32
    VALIDATE_PARAMS(signo == 0 && forked_parent_pid == 0,
        "%s got non-zero signo (%d) or forked_parent_pid (%d) on Windows", func, signo, forked_parent_pid);
#elif defined(__linux__)
    VALIDATE_PARAMS(forked_parent_pid >= 0,
        "%s got negative 'forked_parent_pid': %lld", func, forked_parent_pid);
    VALIDATE_PARAMS(signo >= 1 && signo <= SIGRTMAX,
        "%s got incorrect signo: %d", func, signo);
#else
#error Unsupported platform
#endif
    return or_okay;
}

// FIXME: probably should be protected by "mark sampling unsafe"
// for now all its callers are protected, but the function is now public, so to be safer...
operation_result_t pysamprof_enable_collection(collection_state_t state,
        const char* path, int period_msec, int signo, int64_t forked_parent_pid)
{
    int64_t start_time;
    operation_result_t res = or_okay;
    thread_handle_t* myself;
    master_handle_t* master;
    collection_state_t current_col_state;

    if (validate_collection_params(__FUNCTION__, state, period_msec, signo, forked_parent_pid) != or_okay) return or_invalid_parameter;

    if (state == cs_stopped)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot enable collection with 'stopped' state");
        return or_inconsistent_state;
    }

    res = grab_collection_state(&current_col_state);
    CHECK_AND_REPORT_ERROR(res, "Cannot grab collection state from collector", res);

    if (current_col_state == cs_running)
    {
        PYSAMPROF_LOG(PL_ERROR, "Collection already running");
        return or_cannot_change_collection_state;
    }

    if (path == NULL)
    {
        if (current_col_state == cs_stopped)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot collect into NULL target path");
            return or_fail;
        }
        if (s_collect_path == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot resume with NULL target path");
            return or_fail;
        }
        path = s_collect_path;
    } else if (s_collect_path != path)
    {
        if (s_collect_path != NULL) free(s_collect_path);
        s_collect_path = strdup(path);
        if (s_collect_path == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot store collection path");
            return or_insufficient_memory;
        }
    }

    res = get_mono_time_nanosec(&start_time);
    CHECK_AND_REPORT_ERROR(res, "Cannot get current time as 'collection start time'",
        or_time_utils_fail);
    res = grab_collector_handles(&myself, &master);
    CHECK_AND_REPORT_ERROR(res, "Cannot grab collector handles from collector", res);
    // from now on release handles upon return

    res = start_code_reporting();
    CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot start code reporting", res);

    PYSAMPROF_LOG(PL_INFO, "collecting into '%s'", path);
    if (current_col_state == cs_stopped)
    {
        if (g_server_info.pid == 0)
        {
            // no master server in current session, spawn it
#ifdef __linux__
            // on Linux spawn_master_server will fork, and atfork() may try to grab handles AGAIN thus deadlocks
            s_forking_tid = GETTID();
#endif
            res = spawn_master_server(s_memory_regions, &g_server_info);
            CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot spawn master server", res);
            PYSAMPROF_LOG(PL_INFO, "Spawned master server");

            res = init_master_handle_client(&master, g_server_info.pid);
            CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot init master handle", res);

            res = start_collection(master, start_time,
                period_msec * 1000000LL /* convert millis to nanos */, signo, path);
            CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot send start_collection", res);
            PYSAMPROF_LOG(PL_INFO, "Sent 'start collection' to '%s' with %d ms period",
                path, period_msec);
        }
        else
        {
            PYSAMPROF_LOG(PL_INFO, "Connecting to existing server at %lld", (long long)(g_server_info.pid));
            res = init_master_handle_client(&master, g_server_info.pid);
            CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot init master handle", res);
        }
        res = init_thread_handle_client(master, getpid(), &myself);
        CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot init my own ipc handle", res);
        res = register_process(master, myself, forked_parent_pid);
        CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot register myself at server", res);
        res = set_collector_handles(myself, master);
        CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot set collector handles", res);
        PYSAMPROF_LOG(PL_INFO, "Initialized master and own ipc handles");
    }

#ifdef __linux__
    if (s_vdso_table.entries != NULL)
    {
        vdso_entry_t* entry = s_vdso_table.entries;
        for (int i = 0; i < s_vdso_table.count; i++, entry++)
        {
            res = report_vdso_function(myself, entry, start_time);
            CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot report vDSO function", res);
        }
        PYSAMPROF_LOG(PL_INFO, "Reported vDSO table (%d entries)", (int )s_vdso_table.count);
    }
#endif
    {
        memory_region_info_t* current = s_memory_regions.regions;
        int i;

        for (i = 0; i < s_memory_regions.count; i++, current++)
        {
            if (current->filename == NULL) continue;
            res = write_mapping_info(myself, (uint64_t)current->base,
                    (uint64_t)current->base + current->size, (uint64_t)current->file_offset,
                    start_time, current->filename);
            CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot report memory mapping", res);
        }
        PYSAMPROF_LOG(PL_INFO, "Reported memory mappings (%d entries)",
                (int )s_memory_regions.count);
    }

#ifdef __linux__
    res = setup_signal_handler(handler, signo, 1);
    CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "cannot install handler", res);
    PYSAMPROF_LOG(PL_INFO, "Installed signal handler");
#elif defined(_WIN32)
    // nothing to do, sampling is done using threads which should be set up by "create_timers"
#else
#error Unsupported platform
#endif

    // FIXME: add no-lock API for setting collector state parameters, release handles at the very end
    res = release_collector_handles();
    CHECK_AND_REPORT_ERROR(res, "Cannot release collector handles", res);

    res = set_sampling_params(period_msec, signo);
    CHECK_AND_REPORT_ERROR(res, "Cannot set sampling params in collector", res);

    res = set_collection_state(state);
    CHECK_AND_REPORT_ERROR(res, "Cannot set collection state in collector", res);

    if (state == cs_running)
    {
        PYSAMPROF_LOG(PL_INFO, "iterating workspaces: creating timers");
        res = iterate_workspaces(create_timers, NULL);
        if (res != or_thread_not_found)
        {
            CHECK_AND_REPORT_ERROR(res, "cannot create timers", res);
        }
        PYSAMPROF_LOG(PL_INFO, "Created sampling timers");
    }
    else
    {
        PYSAMPROF_LOG(PL_INFO, "Not creating sampling timers: collection in not running state");
    }

    PYSAMPROF_LOG(PL_INFO, "Sampling successfully started");
    return or_okay;
}

#define CHECK_AND_REPORT_PYTHON_ERROR(res, msg)         \
    do {                                                \
        if (res != or_okay)                             \
        {                                               \
            PYSAMPROF_LOG(PL_ERROR, "%s: %s",           \
                    msg, get_operation_result_str(res));\
            PyErr_SetString(PyExc_RuntimeError, msg);   \
            mark_thread_sampling_safe();                \
            return NULL;                                \
        }                                               \
    } while(0)

#define VALIDATE_PARAMS_PYTHON_ERROR(condition, py_message, log_message, ...) \
    {                                                                         \
        if (!(condition))                                                     \
        {                                                                     \
            PYSAMPROF_LOG(PL_ERROR, log_message, __VA_ARGS__);                \
            PyErr_SetString(PyExc_RuntimeError, py_message);                  \
            mark_thread_sampling_safe();                                      \
            return NULL;                                                      \
        }                                                                     \
    }

static PyObject* pysamprof_start(PyObject* self, PyObject* args)
{
    const char* path;
    operation_result_t status = or_okay;
    collection_state_t current_state;
    int rate_msec, signo;

    mark_thread_sampling_unsafe();
    status = grab_collection_state(&current_state);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot grab collection state from collector");
    status = grab_sampling_params(&rate_msec, &signo);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot grab sampling params from collector");

    if (!PyArg_ParseTuple(args, "s|ii", &path, &rate_msec, &signo))
    {
        mark_thread_sampling_safe();
        return NULL;
    }

    VALIDATE_PARAMS_PYTHON_ERROR(rate_msec > 0,
        "pysamprof.start got non-positive sampling period",
        "pysamprof.start got non-positive sampling period: %d", rate_msec);
#ifdef _WIN32
    VALIDATE_PARAMS_PYTHON_ERROR(signo == 0,
        "pysamprof.start got non-zero profiling signal number",
        "pysamprof.start got incorrect signo: %d", signo);
#elif defined(__linux__)
    VALIDATE_PARAMS_PYTHON_ERROR(signo >= 1 && signo <= SIGRTMAX,
        "pysamprof.start got incorrect profiling signal number",
        "pysamprof.start got incorrect signo: %d", signo);
#else
#error Unsupported platform
#endif

    status = pysamprof_enable_collection(cs_running, path, rate_msec, signo, 0);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot start pysamprof_collection");

    mark_thread_sampling_safe();
    Py_RETURN_NONE;
}

static PyObject* pysamprof_pause_current(PyObject* self, PyObject* args)
{
    operation_result_t status;
    collection_state_t current_state;

    mark_thread_sampling_unsafe();

    status = grab_collection_state(&current_state);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot grab collection state from collector");

    if (current_state != cs_running)
    {
        PyErr_SetString(PyExc_RuntimeError, "Cannot pause non-running collection");
        mark_thread_sampling_safe();
        return NULL;
    }

    status = pysamprof_stop_collection(1, cs_paused);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot pause collection");

    PYSAMPROF_LOG(PL_INFO, "Collection successfully paused");

    mark_thread_sampling_safe();
    Py_RETURN_NONE;
}

static PyObject* pysamprof_resume_current(PyObject* self, PyObject* args)
{
    operation_result_t status;
    collection_state_t current_state;
    int rate_msec, signo;

    mark_thread_sampling_unsafe();

    status = grab_collection_state(&current_state);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot grab collection state from collector");

    if (current_state != cs_paused)
    {
        PyErr_SetString(PyExc_RuntimeError, "Cannot resume non-paused collection");
        mark_thread_sampling_safe();
        return NULL;
    }

    status = grab_sampling_params(&rate_msec, &signo);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot grab sampling params from collector");
    status = pysamprof_enable_collection(cs_running, NULL, rate_msec, signo, s_forked_parent_pid);
    CHECK_AND_REPORT_PYTHON_ERROR(status, "Cannot resume collection");

    PYSAMPROF_LOG(PL_INFO, "Collection successfully resumed");

    mark_thread_sampling_safe();
    Py_RETURN_NONE;
}

PYSAMPROF_API_FUNC(long long) pysamprof_api_request_server_pid(long long target_pid)
{
    operation_result_t status;
    long long result;
    ipc_client_data_t* client;
    char buf[256];

    VALIDATE_PARAMS3(target_pid > 0, API_INVALID_PARAMETER,
        "pysamprof_api_request_server_pid got non-positive target pid: %lld", target_pid);

    mark_thread_sampling_unsafe();
    status = get_master_socket_url(buf, sizeof(buf) - 1, target_pid);
    CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
        "Cannot compose URL to connect to supplied pid", API_IPC_ERROR);
    status = ipc_connect_to_stream_server(&buf[0], NULL, &client);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot connect to %lld: %s", (long long)target_pid,
            get_operation_result_str(status));
        mark_thread_sampling_safe();
        return API_CANNOT_CONNECT;
    }

    {
        ipc_message_command_with_pid_t msg;
        msg.head.version = IPC_NG_HEADER_VERSION;
        msg.head.type = ipc_message_command_with_pid_type;
        msg.head.size = sizeof(msg);
        msg.head.data_offset = offsetof(ipc_message_command_with_pid_t, body);
        msg.body.command = ck_get_server_pid;
        msg.body.pid = 0;

        status = ipc_send_message(client, &(msg.head));
        if (status != or_okay) ipc_disconnect_from_server(client);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
            "Cannot send 'get server' message", API_IPC_ERROR);
    }

    {
        ipc_message_header_t* response;
        ipc_message_command_with_pid_body_t* body;
        status = ipc_receive_message(client, &response);
        ipc_disconnect_from_server(client);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
            "Cannot read response to 'get server' message", API_IPC_ERROR);

        GET_MESSAGE_BODY(response, command_with_pid, body, status);

        if ((status == or_okay) && (body->command != ck_set_server_pid)) status = or_ipc_bad_message;
        if (status == or_okay) result = body->pid;
        free(response);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
            "Received wrong message", API_BAD_RESPONSE);
    }

    mark_thread_sampling_safe();
    return result;
}

PYSAMPROF_API_FUNC(int) pysamprof_api_start_collection(long long target_pid, const char* result_path, int sampling_period_msec, int signo)
{
    // TODO: think how to reduce copy-pasteness of connecting to target_pid
    operation_result_t status;
    ipc_client_data_t* client;
    char buf[256];

    if (validate_collection_params(__FUNCTION__, cs_stopped, sampling_period_msec, signo, 0) != or_okay) return API_INVALID_PARAMETER;

    mark_thread_sampling_unsafe();
    status = get_master_socket_url(buf, sizeof(buf) - 1, target_pid);
    CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
        "Cannot compose URL to connect to supplied pid", API_IPC_ERROR);
    status = ipc_connect_to_stream_server(&buf[0], NULL, &client);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot connect to %lld: %s", (long long)target_pid,
            get_operation_result_str(status));
        mark_thread_sampling_safe();
        return API_CANNOT_CONNECT;
    }

    {
        // FIXME: unify with trace_writer, copied from there
        ipc_message_start_command_t *start_msg;
        size_t start_msg_size = sizeof(ipc_message_start_command_t);

        if (result_path != NULL)
        {
            start_msg_size += strlen(result_path);
        }
        if ((uint32_t)start_msg_size != start_msg_size)
        {
            PYSAMPROF_LOG(PL_ERROR, "Too big 'start collection' message");
            ipc_disconnect_from_server(client);
            mark_thread_sampling_safe();
            return API_NO_MEMORY;
        }
        start_msg = (ipc_message_start_command_t*)malloc(start_msg_size);
        if (start_msg == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate 'start collection' message");
            ipc_disconnect_from_server(client);
            mark_thread_sampling_safe();
            return API_NO_MEMORY;
        }

        start_msg->head.version = IPC_NG_HEADER_VERSION;
        start_msg->head.type = ipc_message_start_command_type;
        start_msg->head.data_offset = offsetof(ipc_message_start_command_t, body);
        start_msg->head.size = start_msg_size;

        start_msg->body.period = sampling_period_msec * 1000000LL /* convert to nanosec */;
        status = get_mono_time_nanosec(&(start_msg->body.start_time));
        if (status != or_okay)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot get mono time: %s", get_operation_result_str(status));
            ipc_disconnect_from_server(client);
            free(start_msg);
            mark_thread_sampling_safe();
            return API_INTERNAL_ERROR;
        }
        start_msg->body.signo = signo;
        if (result_path != NULL)
        {
            strcpy_s(&(start_msg->body.result_path[0]),
                start_msg_size - sizeof(ipc_message_start_command_t) + 1,
                result_path);
        }

        status = ipc_send_message(client, &(start_msg->head));
        ipc_disconnect_from_server(client);
        free(start_msg);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
            "Cannot send 'start collection' message", API_IPC_ERROR);
    }
    mark_thread_sampling_safe();
    return API_OKAY;
}

static int api_send_command_to_target(long long target_pid, command_kind_t command)
{
    operation_result_t status;
    ipc_client_data_t* client;
    char buf[256];

    mark_thread_sampling_unsafe();
    status = get_master_socket_url(buf, sizeof(buf) - 1, target_pid);
    CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
        "Cannot compose URL to connect to supplied pid", API_IPC_ERROR);
    status = ipc_connect_to_stream_server(&buf[0], NULL, &client);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot connect to %lld: %s", (long long)target_pid,
            get_operation_result_str(status));
        mark_thread_sampling_safe();
        return API_CANNOT_CONNECT;
    }

    {
        ipc_message_command_with_pid_t msg;
        msg.head.version = IPC_NG_HEADER_VERSION;
        msg.head.type = ipc_message_command_with_pid_type;
        msg.head.size = sizeof(msg);
        msg.head.data_offset = offsetof(ipc_message_command_with_pid_t, body);
        msg.body.command = command;
        msg.body.pid = 0;

        status = ipc_send_message(client, &(msg.head));
        ipc_disconnect_from_server(client);
        CHECK_AND_REPORT_ERROR_MARK_SAMPLING_SAFETY(status,
            "Cannot send command message", API_IPC_ERROR);
    }
    return API_OKAY;
}

PYSAMPROF_API_FUNC(int) pysamprof_api_pause_collection(long long target_pid)
{
    VALIDATE_PARAMS3(target_pid > 0, API_INVALID_PARAMETER,
        "%s got incorrect target pid: %lld", __FUNCTION__, target_pid);
    return api_send_command_to_target(target_pid, ck_pause_collection);
}

PYSAMPROF_API_FUNC(int) pysamprof_api_resume_collection(long long target_pid)
{
    VALIDATE_PARAMS3(target_pid > 0, API_INVALID_PARAMETER,
        "%s got incorrect target pid: %lld", __FUNCTION__, target_pid);
    return api_send_command_to_target(target_pid, ck_resume_collection);
}

PYSAMPROF_API_FUNC(int) pysamprof_api_stop_collection(long long target_pid)
{
    VALIDATE_PARAMS3(target_pid > 0, API_INVALID_PARAMETER,
        "%s got incorrect target pid: %lld", __FUNCTION__, target_pid);
    return api_send_command_to_target(target_pid, ck_stop_collection);
}

static PyObject* pysamprof_request_server_pid(PyObject* self, PyObject* args)
{
    long long target_pid, result;

    if (!PyArg_ParseTuple(args, "L", &target_pid)) return NULL;

    if (target_pid <= 0)
    {
        PyErr_SetString(PyExc_ValueError, "Bad pid supplied, must be positive");
        return NULL;
    }

    result = pysamprof_api_request_server_pid(target_pid);
    switch (result)
    {
    case API_IPC_ERROR:
        PyErr_SetString(PyExc_RuntimeError, "Cannot connect to supplied pid");
        return NULL;
    case API_CANNOT_CONNECT:
        // not a pysamprof-enabled process
        Py_RETURN_NONE;
    case API_BAD_RESPONSE:
        PyErr_SetString(PyExc_RuntimeError, "Bad response to 'get server' request");
        return NULL;
    default:
        return PyLong_FromLongLong(result);
    }
}

static PyMethodDef module_methods[] = {
        {"start", pysamprof_start, METH_VARARGS, start_docstring },
        {"pause_current", pysamprof_pause_current, METH_NOARGS, pause_current_docstring},
        {"resume_current", pysamprof_resume_current, METH_NOARGS, resume_current_docstring},
        {"request_server_pid", pysamprof_request_server_pid, METH_VARARGS, request_server_pid_docstring},
        {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "pysamprof",
    module_docstring,
    0,
    module_methods,
    NULL, // m_slots
    NULL, // m_traverse
    NULL, // m_clear
    NULL  // m_free
};
#define INIT_ERROR NULL
#else
#define INIT_ERROR
#endif

#ifdef __linux__
static void before_fork_mark_sampling_unsafe()
{
    mark_thread_sampling_unsafe();
}

static void after_fork_mark_sampling_safe()
{
    mark_thread_sampling_safe();
}

static void before_fork()
{
    PYSAMPROF_LOG(PL_INFO, "_pysamprof.c:before_fork begin");
    code_reporting_state_t* code_reporting;
    operation_result_t status = get_code_reporting(&code_reporting);
    CHECK_AND_REPORT_ERROR(status, "Cannot get code reporting from collector",);
    if (s_forking_tid != GETTID())
    {
        status = grab_collector_handles(NULL, NULL);
        CHECK_AND_REPORT_ERROR(status, "Cannot grab collector handles lock before fork",);
    }
    else
    {
        PYSAMPROF_LOG(PL_INFO, "Not grabbing collector handles - should already be owned by current thread");
    }

    int res = LOCK_CODE_RING(code_reporting);
    if (res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot lock symbol ring mutex before fork, error: %d", res);
    }
    PYSAMPROF_LOG(PL_INFO, "_pysamprof.c:before_fork end");
}

static void after_fork_in_parent()
{
    PYSAMPROF_LOG(PL_INFO, "_pysamprof.c:after_fork_in_parent begin");
    operation_result_t status;
    if (s_forking_tid != GETTID())
    {
        status = release_collector_handles();
        CHECK_AND_REPORT_ERROR(status, "Cannot release collector handles lock after fork in parent",);
    }
    else
    {
        s_forking_tid = 0;
    }

    code_reporting_state_t* code_reporting;
    status = get_code_reporting(&code_reporting);
    CHECK_AND_REPORT_ERROR(status, "Cannot get code reporting from collector",);

    int res = UNLOCK_CODE_RING(code_reporting);
    if (res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Cannot unlock symbol ring mutex after fork in parent, error: %d", res);
    }
    PYSAMPROF_LOG(PL_INFO, "_pysamprof.c:after_fork_in_parent end");
}

static void after_fork_in_child()
{
    PYSAMPROF_LOG(PL_INFO, "_pysamprof.c:after_fork_in_child begin");
    s_forking_tid = 0;
    operation_result_t status = release_collector_handles();
    CHECK_AND_REPORT_ERROR(status, "Cannot release collector handles lock after fork in child",);
    s_forked_parent_pid = getppid();

    code_reporting_state_t* code_reporting;
    status = get_code_reporting(&code_reporting);
    CHECK_AND_REPORT_ERROR(status, "Cannot get code reporting from collector",);

    code_reporting->pystate_ready = 0;
    FULL_MEMORY_BARRIER();

    int res = UNLOCK_CODE_RING(code_reporting);
    if (res != 0)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Cannot unlock symbol ring mutex after fork in child, error: %d", res);
        return;
    }

    thread_handle_t* myself;
    master_handle_t* master;
    collection_state_t col_state;
    int rate_msec, signo;
    status = grab_collection_state(&col_state);
    CHECK_AND_REPORT_ERROR(status,
        "Cannot grab collection state from collector after fork in child",);
    status = set_collection_state(cs_stopped);
    CHECK_AND_REPORT_ERROR(status,
        "Cannot reset collection state to stopped after fork in child",);
    status = grab_sampling_params(&rate_msec, &signo);
    CHECK_AND_REPORT_ERROR(status,
        "Cannot grab sampling params from collector after fork in child",);
    status = grab_collector_handles(&myself, &master);
    CHECK_AND_REPORT_ERROR(status, "Cannot grab collector handles after fork in child",);
    int handles_grabbed = 1;

    if (col_state != cs_stopped)
    {
        if (master != NULL) free_master_handle_client(master);
        if (myself != NULL) free_thread_handle_client(myself);
        res = set_collector_handles(NULL, NULL);
        CHECK_AND_REPORT_ERROR_FREE_HANDLES(res,
            "Cannot set NULL collector handles after fork in child",);
        master = NULL;
        myself = NULL;

        if (g_server_info.pid != 0)
        {
            operation_result_t res = init_master_handle_client(&master, g_server_info.pid);
            if (res != or_okay)
            {
                PYSAMPROF_LOG(PL_ERROR,
                        "Cannot reconnect to master server after fork at %lld pid: %s",
                        (long long )g_server_info.pid, get_operation_result_str(res));
                release_collector_handles();
                handles_grabbed = 0;
                return;
            }
            release_collector_handles();
            handles_grabbed = 0;
            PYSAMPROF_LOG(PL_INFO, "Restarting collection after fork");
            // FIXME: use global state to store current collection state;
            //        hardcoded as running for now
            res = pysamprof_enable_collection(col_state, s_collect_path,
                    rate_msec, signo, getppid());
            CHECK_AND_REPORT_ERROR(res, "Cannot restart collection after fork",);
            PYSAMPROF_LOG(PL_INFO, "Restarted collection as %lld pid after fork",
                    (long long )getpid());
        }
    }
    if (handles_grabbed)
    {
        release_collector_handles();
        handles_grabbed = 0;
    }
    PYSAMPROF_LOG(PL_INFO, "_pysamprof.c:after_fork_in_child end");
}

void on_pyready()
{
    PYSAMPROF_LOG(PL_INFO, "Marking Python thread state machine as 'ready'");
    PyEval_InitThreads();
    code_reporting_state_t* code_reporting;
    operation_result_t status = get_code_reporting(&code_reporting);
    CHECK_AND_REPORT_ERROR(status, "Cannot get code reporting from collector on PyReady",);
    code_reporting->pystate_ready = 1;
    FULL_MEMORY_BARRIER();
}

void before_exec()
{
    PYSAMPROF_LOG(PL_INFO, "Before exec: calling pysamprof_stop_collection()");

    /* Either current thread has GIL (in that case its state would be stored as "current"
       and no one would touch it) or this thread does not have GIL. In any case comparing
       global value to thread state in wsp should be safe enough. */

    int has_gil = 0;
    workspace_t* wsp = get_thread_wsp();
    if (wsp != NULL && wsp->tstate != NULL && wsp->tstate == GET_CURRENT_PYSTATE) has_gil = 1;

    pysamprof_stop_collection(has_gil, cs_stopped);
    PYSAMPROF_LOG(PL_INFO, "Before exec: pysamprof_stop_collection() finished");
}
#elif defined(_WIN32)
// nothing special needed, neither forks nor execs on Windows
#else
#error Unsupported platform
#endif

void atexit_mark_sampling_unsafe(void)
{
    mark_thread_sampling_unsafe();
}

PyMODINIT_FUNC initpysamprof(void)
{
    operation_result_t res = or_okay;
    // TODO: call finalize_logging() somewhere
    res = init_logging();
    if (res != or_okay)
    {
        fprintf(stderr, "Cannot init logging :(\n");
    }

#ifdef __linux__
    int err = pthread_atfork(before_fork_mark_sampling_unsafe, after_fork_mark_sampling_safe, after_fork_mark_sampling_safe);
    if (err != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot register atfork() in main pysamprof routine, error: %d",
                err);
        return INIT_ERROR;
    }
#endif

    res = init_ipc_innards();
    CHECK_AND_REPORT_ERROR(res, "Cannot init IPC innards", INIT_ERROR);

#ifdef _WIN32
    if (!SymInitialize(GetCurrentProcess(), NULL, TRUE))
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot do SymInitialize, error: %ld", GetLastError());
        return INIT_ERROR;
    }
#endif

    res = init_collector_state();
    CHECK_AND_REPORT_ERROR(res, "Cannot init collector state", INIT_ERROR);
    res = parse_memory_regions(&s_memory_regions, 0);
    CHECK_AND_REPORT_ERROR(res, "Cannot parse memory regions", INIT_ERROR);

    xed_initialize();

    res = init_hang_protection(s_memory_regions);
    CHECK_AND_REPORT_ERROR(res, "Cannot init hang protection", INIT_ERROR);

    res = init_workspace_machinery();
    CHECK_AND_REPORT_ERROR(res, "Cannot init workspace machinery", INIT_ERROR);

#ifdef __linux__
    err = pthread_atfork(before_fork, after_fork_in_parent, after_fork_in_child);
    if (err != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot register atfork() in main pysamprof routine, error: %d",
                err);
        return INIT_ERROR;
    }
#endif

    res = start_following_threads(s_memory_regions, on_new_thread, NULL);
#ifdef __linux__
    register_forkexec_callbacks(NULL, NULL, NULL, on_pyready, before_exec);
#elif defined(_WIN32)
    // no callbacks as no forks
#else
#error Unsupported platform
#endif
    CHECK_AND_REPORT_ERROR(res, "Cannot start following threads", INIT_ERROR);
    res = init_callstack_helper(s_memory_regions);
    CHECK_AND_REPORT_ERROR(res, "Cannot init callstack helper", INIT_ERROR);

    res = setup_server_pointer_thread();
    CHECK_AND_REPORT_ERROR(res, "Cannot setup pointer thread", INIT_ERROR);

    res = get_server_info(&g_server_info);
    CHECK_AND_REPORT_ERROR(res, "Cannot get server whereabouts", INIT_ERROR);
    if (g_server_info.pid == 0)
    {
        PYSAMPROF_LOG(PL_INFO, "No server in current session, will spawn one on collection start");
    }
    else
    {
        PYSAMPROF_LOG(PL_INFO, "Found server %lld in current session", (long long)(g_server_info.pid));
    }

    if (atexit(pysamprof_stop_collection_atextit) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot register atexit() handler, errno: %d", errno);
        return INIT_ERROR;
    }

    res = probe_function(PyImport_Cleanup, PyImport_Cleanup_probe, s_memory_regions,
            (void**)&s_PyImport_Cleanup_original);
    CHECK_AND_REPORT_ERROR(res, "Cannot probe PyImport_Cleanup", INIT_ERROR);

    res = init_module_following(s_memory_regions, on_new_lib);
    CHECK_AND_REPORT_ERROR(res, "Cannot init module following", INIT_ERROR);

#ifdef __linux__
    res = parse_vdso_table(s_memory_regions, &s_vdso_table);
    if (res != or_cannot_find_image)
    {
        CHECK_AND_REPORT_ERROR(res, "Cannot parse vDSO table", INIT_ERROR);
    }

#endif

    if (g_server_info.pid != 0)
    {
        collection_state_t state;
        int64_t period_nano;
        int signo;
        char* result_path = NULL;
        master_handle_t* master;

        res = grab_collector_handles(NULL, NULL);

        res = init_master_handle_client(&master, g_server_info.pid);
        CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot init master handle", INIT_ERROR);
        res = set_collector_handles(NULL, master);
        CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot set collector handles in init", INIT_ERROR);

        res = get_collection_state(master, &state, &period_nano, &signo, &result_path);
        CHECK_AND_REPORT_ERROR_FREE_HANDLES(res, "Cannot get collection state", INIT_ERROR);
        PYSAMPROF_LOG(PL_INFO, "Got collection status: state=%d, period=%lld ns, signo=%d, result='%s'",
                (int )state, (long long )period_nano, signo, result_path);
        res = release_collector_handles();
        CHECK_AND_REPORT_ERROR(res, "Cannot release collector handles", INIT_ERROR);
        if (state == cs_running || state == cs_paused)
        {
            res = pysamprof_enable_collection(state, result_path,
                period_nano / 1000000LL /* convert nano to milli */, signo, 0);
            free(result_path);
            CHECK_AND_REPORT_ERROR(res, "Cannot start collection", INIT_ERROR);
            PYSAMPROF_LOG(PL_INFO, "Started collection as non-first process");
        }
    }

    if (atexit(atexit_mark_sampling_unsafe) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot register atexit() handler, errno: %d", errno);
        return INIT_ERROR;
    }

    {
#if PY_MAJOR_VERSION >= 3
        PyObject* m = PyModule_Create(&module_def);
#else
        PyObject* m = Py_InitModule3("pysamprof", module_methods, module_docstring);
#endif
        if (m == NULL) INIT_ERROR;
        PyEval_InitThreads();
        PYSAMPROF_LOG(PL_INFO, "pysamprof initialized");
#if PY_MAJOR_VERSION >= 3
        return m;
#endif
    }
}
