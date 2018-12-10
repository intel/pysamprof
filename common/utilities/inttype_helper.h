#ifndef __PYSAMPROF_INTTYPE_HELPER_H__
#define __PYSAMPROF_INTTYPE_HELPER_H__

#ifdef __linux__
#include <stdint.h>
#include <inttypes.h>
#elif defined(_WIN32)
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;

typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;

#define PRIu64 "I64u"
#define PRId64 "I64d"
#define PRIu32 "u"
#define PRId32 "d"

#else
#error Unsupported platform
#endif

#endif
