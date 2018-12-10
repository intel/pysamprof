#ifndef __PYSAMPROF_MEMORY_REGIONS_H__
#define __PYSAMPROF_MEMORY_REGIONS_H__

#include <stdlib.h>

#include <common/status/status.h>

#define PERMISSIONS_NONE    0
#define PERMISSIONS_READ    1
#define PERMISSIONS_WRITE   2
#define PERMISSIONS_EXECUTE 4
#define PERMISSIONS_PRIVATE 8

struct _image_data_t;

typedef struct
{
    char* filename;
    void* base;
    size_t size;
    size_t file_offset;
    int permissions;

    struct _image_data_t* image_data;
} memory_region_info_t;

typedef struct
{
    int count;
    memory_region_info_t* regions;
} all_memory_regions_t;

operation_result_t parse_memory_regions(all_memory_regions_t* regions,
		int ignore_extra_regions);
void free_memory_regions(all_memory_regions_t regions);

operation_result_t find_memory_region(void* target,
        all_memory_regions_t regions, int* index);

#endif
