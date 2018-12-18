#ifndef __PYSAMPROF_IMAGE_DATA_H__
#define __PYSAMPROF_IMAGE_DATA_H__

#include <stdlib.h>

#include <utilities/inttype_helper.h>
#include <status/status.h>

#include "memory_regions.h"

typedef struct
{
    void* start;
    size_t length;
    /* CAUTION: check with end of respective memory region,
       start + length might end after that */
} function_size_t;

typedef struct _image_data_t
{
    char* filename;
    uint64_t relocation;
    int function_count;
    function_size_t* function_entries;
} image_data_t;

#define INVALID_RELOCATION ((uint64_t)-1)

/* "region size" is determined by parsing public functions of a binary
 * and taking the difference between target function and next public function.
 * This might be inaccurate if there are any private (e.g. static) functions
 * following the target, so this function's result should be used to only determine
 * the memory region where it's safe to read function data. */
operation_result_t get_function_region_size(void* addr, all_memory_regions_t regions,
        size_t* result);
void free_all_image_data(void);

#endif
