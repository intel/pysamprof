#ifndef __PYSAMPROF_FUNCTION_INFO_H__
#define __PYSAMPROF_FUNCTION_INFO_H__

#include <string.h>

#include "../../common/logging/logging.h"

#include "../include/ipc_message.h"
#include "../../common/status/status.h"

#include "../proto/functionInfo.pb-c.h"

operation_result_t create_proto_function_info(Perftools__Symbols__FunctionInfo **function_info);

operation_result_t add_code_region_function_info(
        Perftools__Symbols__FunctionInfo *function_info, uint64_t startaddr, uint8_t *data,
        uint32_t length);

operation_result_t add_functionid_function_info(Perftools__Symbols__FunctionInfo *function_info,
        uint64_t function_id);

operation_result_t add_function_name_function_info(
        Perftools__Symbols__FunctionInfo *function_info, const char *functionname);

operation_result_t add_source_file_name_function_info(
        Perftools__Symbols__FunctionInfo *function_info, const char *sourcefilename);

operation_result_t add_module_name_function_info(
        Perftools__Symbols__FunctionInfo *function_info, const char *modulename);

operation_result_t add_timing_function_info(Perftools__Symbols__FunctionInfo *function_info,
        uint64_t loadtime);

operation_result_t add_line_number_mappings_function_info(
        Perftools__Symbols__FunctionInfo *function_info, uint32_t startoffset,
        uint32_t endoffset, uint32_t linenumber);

operation_result_t serialize_function_info(Perftools__Symbols__FunctionInfo *function_info,
        void **buf, uint32_t *length);

operation_result_t free_proto_function_info(Perftools__Symbols__FunctionInfo *function_info);

#define CHECK_CLEANUP_AND_REPORT(res, msg, info, retval)     \
{                                                            \
    if (res != or_okay) free_proto_function_info(info);      \
    CHECK_AND_REPORT_ERROR(res, msg, retval);                \
}
#endif
