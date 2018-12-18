#ifndef __PYSAMPROF_FUNCTION_METHODS_H__
#define __PYSAMPROF_FUNCTION_METHODS_H__

#include <status/status.h>
#include <stddef.h>

/* Gets "real" function start (that is, if a binary is compiled in e.g. Incremental Link mode
   all functions are actually a one-instruction "jmp <real_address>" things.
   get_real_function_start() function computes this <real_address> value.
   addr must point to a valid function. */
operation_result_t get_real_function_start(void* addr, size_t* result);

#endif
