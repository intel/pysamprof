#ifndef __PYSAMPROF_TRAMPOLINE_MGR_H__
#define __PYSAMPROF_TRAMPOLINE_MGR_H__

#include <common/status/status.h>
#include "memory_regions.h"

#define TRAMPOLINE_ENTRY_SIZE 64

operation_result_t allocate_nearest_trampoline(void* target,
        int bitdiff, all_memory_regions_t regions, void** result);
operation_result_t mark_trampoline_free(void* trampoline);
void free_all_trampolines(void);

#endif
