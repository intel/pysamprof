#ifndef __PYSAMPROF_LOGGING_H__
#define __PYSAMPROF_LOGGING_H__

#include "../status/status.h"

#include <stdio.h>

typedef enum
{
    PL_NO_LOGGING = 0,
    PL_ERROR = 1,
    PL_WARNING = 2,
    PL_INFO = 3
} pysamprof_loglevel_t;

extern FILE* g_pysamprof_logfile;
extern pysamprof_loglevel_t g_pysamprof_loglevel;

#define PYSAMPROF_LOG(level, fmt, ...)                                      \
    do {                                                                    \
        if (g_pysamprof_logfile != NULL && level <= g_pysamprof_loglevel)   \
        {                                                                   \
            pysamprof_log(g_pysamprof_logfile, level, fmt, ##__VA_ARGS__);  \
        }                                                                   \
    } while(0)

#define PYSAMPROF_LOGGING_ENV "PYSAMPROF_LOGGING"

operation_result_t init_logging(void);
operation_result_t finish_logging(void);
void pysamprof_log(FILE* f, pysamprof_loglevel_t level, const char* fmt, ...);

#endif
