#ifndef __PYSAMPROF_CALLSTACK_HELPER_H__
#define __PYSAMPROF_CALLSTACK_HELPER_H__

#include <Python.h>
#include <frameobject.h>

#include <status/status.h>
#include <probengine/memory_regions.h>

PyObject* PyEval_EvalFrameEx_probe(PyFrameObject* f, int throwflag);

extern size_t g_PyEval_EvalFrameEx_probe_start;

// to get PYEVAL_PROBE_SIZE do #include "callstack_helper_gen.h"
#define IS_PYEVAL_PROBE(ip)                                           \
    ((ip) >= g_PyEval_EvalFrameEx_probe_start &&                      \
     (ip) <= g_PyEval_EvalFrameEx_probe_start + PYEVAL_PROBE_SIZE)

operation_result_t init_callstack_helper(const all_memory_regions_t regions);

#endif
