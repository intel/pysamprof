#include "code_reporting.h"

#include <Python.h>

#ifdef __linux__
#include <safe_mem_lib.h>
#elif defined(_WIN32)
#include <Windows.h>
#else
#error Unsupported platform
#endif

#include <utilities/utilities.h>

#include "../trace_writer/include/trace_writer_api.h"

#include "time_utils.h"
#include "threading_follow.h"
#include "ringbuffer.h"
#include "collector_state.h"

#ifdef __linux__
#define IS_SYMBOL_THREAD_STARTED(state) ((state)->symbol_thread_started != 0)
#define MARK_THREAD_STOPPED(state) {(state)->symbol_thread_started = 0;}
#elif defined(_WIN32)
#define IS_SYMBOL_THREAD_STARTED(state) ((state)->symbol_thread != NULL)
#define MARK_THREAD_STOPPED(state) {(state)->symbol_thread = NULL;}
#else
#error Unsupported platform
#endif

#if PY_MAJOR_VERSION >= 3
#define GET_PYSTR_AS_PCHAR(pystr) PyUnicode_AsUTF8(pystr)
#else
#define GET_PYSTR_AS_PCHAR(pystr) PyString_AsString(pystr)
#endif


static volatile uint64_t s_function_id = 1;
operation_result_t make_function_info(Perftools__Symbols__FunctionInfo** info)
{
#ifdef __linux__
    uint64_t function_id = __sync_fetch_and_add(&s_function_id, 1);
#elif defined(_WIN32)
    uint64_t function_id = InterlockedIncrement64(&s_function_id);
#else
#error Unsupported platform
#endif

    operation_result_t res = or_okay;
    if (info == NULL) return or_fail;

    *info = NULL;
    res = create_proto_function_info(info);
    CHECK_AND_REPORT_ERROR(res, "Cannot create storage for function info proto", res);

    res = add_functionid_function_info(*info, function_id);
    CHECK_AND_REPORT_ERROR(res, "Cannot add function id in proto", res);

    return or_okay;
}

operation_result_t send_function_info(thread_handle_t* myself,
        Perftools__Symbols__FunctionInfo* info)
{
    void* buf = NULL;
    uint32_t len = 0;
    ipc_message_function_info_t* message;

    // TODO: split serialize_function_info() into two to avoid memcpy() and double malloc
    operation_result_t res = serialize_function_info(info, &buf, &len);
    if (res != or_okay && res != or_insufficient_memory)
    {
        free(buf);
    }
    CHECK_AND_REPORT_ERROR(res, "Cannot serialize function info to proto", res);

    message = (ipc_message_function_info_t*)malloc(
            sizeof(ipc_message_function_info_t) + len);
    if (message == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate function_info message");
        free(buf);
        return or_insufficient_memory;
    }
    
    memcpy_s(message->body.protobuf_data, len, buf, len);
    
    message->body.protobuf_size = len;
    free(buf);
    message->head.data_offset = offsetof(ipc_message_function_info_t, body);
    message->head.size = sizeof(ipc_message_function_info_t) + len;
    message->head.type = ipc_message_function_info_type;
    message->head.version = IPC_NG_HEADER_VERSION;

    {
        int grabbed = 0;
        if (myself == NULL)
        {
            res = grab_collector_handles(&myself, NULL);
            if (res != or_okay)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot grab handle from collector: %s",
                    get_operation_result_str(res));
            }
            else
            {
                grabbed = 1;
            }
        }
        if (myself != NULL)
        {
            res = write_function_info(myself, message);
        }
        else
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot send functino info: got NULL own handle");
            res = or_fail;
        }
        if (grabbed) release_collector_handles();
    }
    free(message);
    CHECK_AND_REPORT_ERROR(res, "Cannot send function info", res);

    return or_okay;
}

#define GET_CODE_REPORTING(code_reporting, res, retval) \
{                                                       \
    res = get_code_reporting(&code_reporting);          \
    CHECK_AND_REPORT_ERROR(res, "Cannot get code reporting from collector", retval);	\
}

static operation_result_t add_code_object_to_reported(PyCodeObject* code)
{
    code_object_list_t* list = NULL;
    PyCodeObject** obj_ptr;
    int i;
    code_reporting_state_t* code_reporting;
    operation_result_t res;

    GET_CODE_REPORTING(code_reporting, res, res);

    if (code_reporting->reported == NULL)
    {
        code_reporting->reported = (code_object_list_t*)malloc(sizeof(code_object_list_t));
        if (code_reporting->reported == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate reported objects list");
            return or_insufficient_memory;
        }
        memset(code_reporting->reported, 0, sizeof(code_object_list_t));
    }
    list = code_reporting->reported;
    while (list->next != NULL) list = list->next;
    for (i = 0, obj_ptr = list->objects;
        i < CO_LIST_ENTRY_SIZE && *obj_ptr != NULL;
        i++, obj_ptr++);
    if (i >= CO_LIST_ENTRY_SIZE)
    {
        // not enough space in current list entry, add another one
        list->next = (code_object_list_t*)malloc(sizeof(code_object_list_t));
        if (list->next == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate reported objects list");
            return or_insufficient_memory;
        }
        memset(list->next, 0, sizeof(code_object_list_t));
        obj_ptr = list->next->objects;
    }

    // now obj_ptr points to first empty cell, store "code" there
    *obj_ptr = code;
    return or_okay;
}

static operation_result_t cleanup_reported_objects(code_reporting_state_t* state)
{
    code_object_list_t* list = NULL;

    if (state == NULL) return or_fail;

    list = state->reported;
    state->reported = NULL;
    while(list != NULL)
    {
        code_object_list_t* next = list->next;
        PyCodeObject** obj_ptr;
        int i;
        for (i = 0, obj_ptr = list->objects;
            i < CO_LIST_ENTRY_SIZE && *obj_ptr != NULL;
            i++, obj_ptr++)
        {
            // FIXME: would crash if code object gets destroyed
            //        probably should not decref when popping from buffer,
            //        but rather decref here (if owning GIL)
            (*obj_ptr)->co_flags &= (~CO_CODEOBJECT_REPORTED);
        }

        free(list);
        list = next;
    }
    return or_okay;
}

static void report_code_object(ring_buffer_element_t element)
{
    Perftools__Symbols__FunctionInfo* info = NULL;
    operation_result_t res;
    PyCodeObject* code = (PyCodeObject*)(element.data);

    if (code == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "report_code_object() got NULL code to report");
        return;
    }
    res = add_code_object_to_reported(code);
    if (res != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot store code object for later cleanup");
    }
    res = make_function_info(&info);

    CHECK_AND_REPORT_ERROR(res, "Cannot create storage for function info proto",);

    if (code->co_code != NULL)
    {
#if PY_MAJOR_VERSION >= 3
        Py_ssize_t size = PyBytes_Size(code->co_code);
#else
        Py_ssize_t size = PyString_Size(code->co_code);
#endif
        if (size >= 0 && size <= ((uint32_t)-1))
        {
            res = add_code_region_function_info(info, (uint64_t)(code->co_code),
                    (uint8_t*)(code->co_code), (uint32_t)size);
            CHECK_CLEANUP_AND_REPORT(res, "Cannot copy code region", info,);
        }
    }

    if (code->co_filename != NULL)
    {
        const char* filename = GET_PYSTR_AS_PCHAR(code->co_filename);
        if (filename != NULL)
        {
            res = add_source_file_name_function_info(info, filename);
            CHECK_CLEANUP_AND_REPORT(res, "Cannot add source file name to proto", info,);

            res = add_module_name_function_info(info, filename);
            CHECK_CLEANUP_AND_REPORT(res, "Cannot add module file name to proto", info,);
        }
    }

    if (code->co_name != NULL)
    {
#if PY_MAJOR_VERSION >= 3
        const char* name = PyUnicode_AsUTF8(code->co_name);
#else
        const char* name = PyString_AsString(code->co_name);
#endif
        if (name != NULL)
        {
            res = add_function_name_function_info(info, name);
            CHECK_CLEANUP_AND_REPORT(res, "Cannot add function name to proto", info,);
        }
    }
    // TODO: add reading co_lnotab here to compose line-level information

    res = add_timing_function_info(info, element.timestamp);
    CHECK_CLEANUP_AND_REPORT(res, "Cannot add load time to proto", info,);

    res = send_function_info(NULL, info);
    CHECK_CLEANUP_AND_REPORT(res, "Cannot send function proto info via IPC", info,);    
    free_proto_function_info(info);
}

#ifdef __linux__
#define THREAD_VALUE NULL
static void* symbol_gather_routine(void* data)
#elif defined(_WIN32)
#define THREAD_VALUE 0
static DWORD WINAPI symbol_gather_routine(void* data)
#else
#error Unsupported platform
#endif
{
    PyThreadState* tstate;
    operation_result_t status;
    code_reporting_state_t* state = NULL;
    PyInterpreterState* interpreter = NULL;

    GET_CODE_REPORTING(state, status, THREAD_VALUE);

#ifdef __linux__
    {
        // block all signals except a few key ones
        sigset_t mask;
        sigfillset(&mask);
        sigdelset(&mask, SIGSEGV);
        sigdelset(&mask, SIGBUS);
        sigdelset(&mask, SIGFPE);
        sigdelset(&mask, SIGILL);
        pthread_sigmask(SIG_SETMASK, &mask, NULL);
    }
#elif !defined(_WIN32)
#error Unsupported platform
#endif
    state->state = crts_running;
    FULL_MEMORY_BARRIER();

#ifdef __linux__
    if (state->pystate_ready != 1)
    {
        PYSAMPROF_LOG(PL_INFO, "Python thread state not ready, waiting");
        while (state->pystate_ready != 1)
        {
            msleep(1);
            FULL_MEMORY_BARRIER();
        }
    }
#endif

    interpreter = PyInterpreterState_Head();
    if (interpreter == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "PyInterpreterState_Head() == NULL, cannot gather Python symbols");
        return THREAD_VALUE;
    }
    tstate = PyThreadState_New(interpreter);
    if (tstate == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create PyThreadState for symbol gathering");
        return THREAD_VALUE;
    }

    while (1)
    {
        ring_buffer_element_t element;
        FULL_MEMORY_BARRIER();
        if (state->state == crts_stop_requested) break;

        // TODO: change to condition variable
        msleep(10);

        LOCK_MUTEX(&(state->symbol_ring_mutex));
        status = ring_buffer_pop(&(state->symbol_ring), &element);
        UNLOCK_MUTEX(&(state->symbol_ring_mutex));
        switch (status)
        {
        case or_okay:
            break;
        case or_ring_buffer_empty:
            continue;
        default:
            PYSAMPROF_LOG(PL_ERROR, "Got unexpected result from ring_buffer_pop: %s",
                get_operation_result_str(status));
            continue;
        }

        // now we have at least one object to report, get the GIL
        PyEval_AcquireThread(tstate);

        while (status == or_okay)
        {
            PyCodeObject* code = (PyCodeObject*)(element.data);
            FULL_MEMORY_BARRIER();
            if (state->state == crts_stop_requested) break;

			PYSAMPROF_LOG(PL_INFO, "Got code object %p: '%s'", code,
					GET_PYSTR_AS_PCHAR(code->co_name));
            report_code_object(element);

            Py_DECREF((PyObject* )(element.data));

            // check if there's more
            LOCK_MUTEX(&(state->symbol_ring_mutex));
            status = ring_buffer_pop(&(state->symbol_ring), &element);
            UNLOCK_MUTEX(&(state->symbol_ring_mutex));
        }
        if (state->state == crts_stop_requested && status == or_okay)
        {
            PYSAMPROF_LOG(PL_INFO, "Symbol gather requested to stop, but buffer is not empty yet, emptying");
            LOCK_MUTEX(&(state->symbol_ring_mutex));
            while (status == or_okay)
            {
                // reset "code object reported" flag
                ((PyCodeObject*)(element.data))->co_flags &= (~CO_CODEOBJECT_REPORTED);
                Py_DECREF((PyObject*)(element.data));
                status = ring_buffer_pop(&(state->symbol_ring), &element);
            }
            UNLOCK_MUTEX(&(state->symbol_ring_mutex));
        }
        if (status != or_ring_buffer_empty)
        {
            PYSAMPROF_LOG(PL_ERROR, "Got unexpected result from ring_buffer_pop: %s",
                get_operation_result_str(status));
        }

        // release GIL back
        PyEval_ReleaseThread(tstate);
    }

    PyThreadState_Delete(tstate);

    return THREAD_VALUE;
}

operation_result_t init_code_reporting()
{
    code_reporting_state_t* state = NULL;
    operation_result_t res;

    GET_CODE_REPORTING(state, res, res);

    memset(state, 0, sizeof(code_reporting_state_t));
#ifdef __linux__
    state->pystate_ready = 1;
    int status = pthread_mutex_init(&(state->symbol_ring_mutex), NULL);
    if (status != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot init ring buffer mutex: %d", status);
        return or_mutex_error;
    }
#elif defined(_WIN32)
    InitializeCriticalSectionAndSpinCount(&(state->dbghelp_lock), 4000);
    InitializeCriticalSectionAndSpinCount(&(state->symbol_ring_mutex), 4000);
#else
#error Unsupported platform
#endif
    FULL_MEMORY_BARRIER();
    return or_okay;
}

operation_result_t start_code_reporting()
{
    int thread_started = 1;
    code_reporting_state_t* state = NULL;
    operation_result_t res;

    GET_CODE_REPORTING(state, res, res);

    ring_buffer_init(&(state->symbol_ring));

    state->state = crts_not_stared;
    FULL_MEMORY_BARRIER();
#ifdef __linux__
    state->symbol_thread_started = 0;
    if (pthread_create_nofollow(&(state->symbol_thread), NULL,
        symbol_gather_routine, (void*)state) == 0)
    {
        state->symbol_thread_started = 1;
    } else
    {
        thread_started = 0;
    }
#elif defined(_WIN32)
    state->symbol_thread = CreateThread_nofollow(NULL, 0, symbol_gather_routine, (void*)state, 0, NULL);
    if (state->symbol_thread == NULL) thread_started = 0;
#else
#error Unsupported platform
#endif

    if (!thread_started)
    {
        long long err = GET_ERROR_AS_LL();
        PYSAMPROF_LOG(PL_ERROR, "Cannot spawn symbol gather thread, error: %ld", err);
        return or_cannot_start_thread;
    }

    FULL_MEMORY_BARRIER();
    while (state->state == crts_not_stared) msleep(1);
    PYSAMPROF_LOG(PL_INFO, "Initialized symbol gather thread");

    return or_okay;
}

operation_result_t stop_code_reporting()
{
    operation_result_t status;
    code_reporting_state_t* code_reporting;

    GET_CODE_REPORTING(code_reporting, status, status);

    code_reporting->state = crts_stop_requested;
    FULL_MEMORY_BARRIER();
    if (IS_SYMBOL_THREAD_STARTED(code_reporting))
    {
        JOIN_THREAD(code_reporting->symbol_thread);
        MARK_THREAD_STOPPED(code_reporting);
    }
    status = cleanup_reported_objects(code_reporting);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot cleanup reported code objects: %s",
            get_operation_result_str(status));
        return status;
    }
        
    return or_okay;
}
