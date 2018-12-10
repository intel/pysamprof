#ifndef __PYSAMPROF_MODULE_FOLLOWING_H
#define __PYSAMPROF_MODULE_FOLLOWING_H

#include <common/status/status.h>
#include <probengine/memory_regions.h>

#include "os_abstract.h"

typedef void (*on_new_lib_callback_t)(module_handle_t handle);

operation_result_t init_module_following(all_memory_regions_t regions,
		on_new_lib_callback_t on_new_lib);

#endif