#include "callstack_helper.h"

#include <common/logging/logging.h>
#include <probengine/prober.h>
#include <probengine/function_methods.h>

size_t g_PyEval_EvalFrameEx_probe_start = 0;

typedef PyObject* (*pyeval_t)(PyFrameObject* f, int throwflag);
static pyeval_t s_original_pyeval = NULL;
PyObject* PyEval_EvalFrameEx_probe(PyFrameObject* f, int throwflag)
{
    if (s_original_pyeval != NULL) return s_original_pyeval(f, throwflag);
    return NULL;
}

operation_result_t init_callstack_helper(const all_memory_regions_t regions)
{   
	operation_result_t res = get_real_function_start(PyEval_EvalFrameEx_probe,
		&g_PyEval_EvalFrameEx_probe_start);
	if (res != or_okay)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get real start of PyEval_EvalFrameEx_probe: %s", get_operation_result_str(res));
		return res;
	}

    if (s_original_pyeval == NULL)
    {
        res = probe_function(PyEval_EvalFrameEx,
                (void*)PyEval_EvalFrameEx_probe,
                regions, (void**)&s_original_pyeval);
        if (res != or_okay) return res;
    }
    return or_okay;
}
