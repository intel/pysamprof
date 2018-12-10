#ifndef __PYSAMPROF_HANG_PROTECTION_H__
#define __PYSAMPROF_HANG_PROTECTION_H__

#include <common/status/status.h>
#include <probengine/memory_regions.h>

operation_result_t init_hang_protection(all_memory_regions_t regions);

#endif