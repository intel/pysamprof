#ifndef __PYSAMPROF_BINARY_SEARCH_H__
#define __PYSAMPROF_BINARY_SEARCH_H__

#include <stddef.h>

/* Performs a binary search over sorted array of elements each being
   "element_size" big with search criteria a "size_t"-sized search criteria
   defined by a callback. Returns index of element. */
typedef size_t (*binary_search_criteria_t)(void* element);
int perform_binary_search(void* array, int count,
        size_t target, size_t element_size,
        binary_search_criteria_t criteria);

#endif
