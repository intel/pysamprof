#ifndef __PYSAMPROF_VDSO_PARSER_H__
#define __PYSAMPROF_VDSO_PARSER_H__

#ifndef __linux__
#error vDSO parsing is Linux specific
#endif

#include "../common/status/status.h"
#include <probengine/memory_regions.h>

typedef struct
{
    void* start;
    size_t length;
    const char* name;
} vdso_entry_t;
typedef struct
{
    int count;
    vdso_entry_t* entries;
} vdso_table_t;

operation_result_t parse_vdso_table(all_memory_regions_t regions, vdso_table_t* result);

#endif
