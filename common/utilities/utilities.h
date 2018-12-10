#ifndef __PYSAMPROF_UTILITIES_H__
#define __PYSAMPROF_UTILITIES_H__

#ifdef _WIN32
#include <windows.h>
#endif

#include "../status/status.h"

operation_result_t mkdir_recoursive(const char *dir);

void msleep(int msec); // sleeps for msec milliseconds

#ifdef _WIN32

typedef struct
{
	SECURITY_ATTRIBUTES attrs;
	PACL acl;
	PSID admin_sid;
	PTOKEN_USER user_token;
} pysamprof_security_attrs_t;

operation_result_t create_tight_security_attrs(pysamprof_security_attrs_t* result);
operation_result_t free_security_attrs(pysamprof_security_attrs_t* attrs);
#endif

#endif
