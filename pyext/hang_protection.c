#include "hang_protection.h"

#include <logging/logging.h>
#include <probengine/prober.h>

#include "workspace.h"
#include "threading_follow.h"

#ifdef _WIN32
#include <Windows.h>

static PVOID s_ProcessHeap = NULL;

/* StackWalk64 can allocate/free memory on ProcessHeap using RtlAllocateHeap / RtlFreeHeap.
   At the same time sampled thread might call alloc/free over ProcessHeap for e.g. converting
   ASCII to Unicode when loading a module. This could lead to a deadlock when sampling.
   So we need to disable sampling when target thread is inside alloc/free in ProcessHeap. */

#define MAKE_GUARDING_PROBE(function, rettype, typed_args, name_args, heap_handle_arg, err_value)		\
	typedef rettype (*function##_t) typed_args;											\
	static function##_t s_##function##_original = NULL;									\
																						\
	rettype function##_probe typed_args													\
	{																					\
		if (heap_handle_arg == s_ProcessHeap)											\
		{																				\
			rettype result;																\
			workspace_t* wsp = get_thread_wsp();										\
			MARK_WSP_SAMPLING_UNSAFE(wsp);												\
			result = (s_##function##_original != NULL) ? s_##function##_original name_args : err_value;	\
			MARK_WSP_SAMPLING_SAFE(wsp);												\
			return result;																\
		}																				\
		return (s_##function##_original != NULL) ? s_##function##_original name_args : err_value;		\
	}

MAKE_GUARDING_PROBE(RtlAllocateHeap, PVOID, (PVOID handle, ULONG flags, SIZE_T size), (handle, flags, size), handle, NULL);
MAKE_GUARDING_PROBE(RtlFreeHeap, BOOLEAN, (PVOID handle, ULONG flags, PVOID ptr), (handle, flags, ptr), handle, FALSE);

#define INSTALL_GUARDING_PROBE(function, module_name, regions)		\
{																	\
	function##_t func;												\
	HANDLE hModule = LoadLibrary(module_name);						\
	operation_result_t result = or_okay;							\
	if (hModule == NULL)											\
	{																\
		PYSAMPROF_LOG(PL_ERROR, "Cannot open '" module_name "': %ld", GetLastError());					\
		return or_cannot_open_file;									\
	}																\
	func = (function##_t)GetProcAddress(hModule, #function);		\
	if (func == NULL)												\
	{																\
		PYSAMPROF_LOG(PL_ERROR, "Cannot get address of '" #function "': %ld", GetLastError());			\
		FreeLibrary(hModule);										\
		return or_invalid_function;									\
	}																\
	else															\
	{																\
		FreeLibrary(hModule);										\
		result = probe_function(func, function##_probe, regions, (void**)(&s_##function##_original));	\
		CHECK_AND_REPORT_ERROR(result, "Cannot probe " #function, result);								\
	}																\
}

#endif

operation_result_t init_hang_protection(all_memory_regions_t regions)
{
	operation_result_t res = or_okay;
#ifdef _WIN32
	s_ProcessHeap = GetProcessHeap();
	if (s_ProcessHeap == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get process heap: got NULL");
		return or_invalid_function;
	}
	INSTALL_GUARDING_PROBE(RtlAllocateHeap, "ntdll.dll", regions);
	INSTALL_GUARDING_PROBE(RtlFreeHeap, "ntdll.dll", regions);
#endif
	return res;
}

