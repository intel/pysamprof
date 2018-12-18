#ifndef __PYSAMPROF_PROBER_H__
#define __PYSAMPROF_PROBER_H__

#include <status/status.h>
#include "memory_regions.h"

operation_result_t probe_function(void* target, void* replacement,
        all_memory_regions_t regions, void** trampoline);
void xed_initialize(void);

#endif
