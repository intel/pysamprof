#include "status.h"

const char* get_operation_result_str(operation_result_t res)
{
#define MAKE_ENTRY(name) #name
    static const char* const strs[] = {
        MAKE_OPERATION_RESULT_LIST("")
    };
#undef MAKE_ENTRY
    if (res < or_okay || (int)res >= (sizeof(strs) / sizeof(strs[0]))) return "unknown";
    return strs[(int)res];
}
