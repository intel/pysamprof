#include "../include/function_info.h"


#ifdef __linux__
#include <safe_mem_lib.h>
#elif defined(_WIN32)
#define strdup(x) _strdup(x)
#else
#error Unsupported platform
#endif


operation_result_t create_proto_function_info(Perftools__Symbols__FunctionInfo **function_info)
{
    Perftools__Symbols__FunctionInfo *info = (Perftools__Symbols__FunctionInfo*)malloc(
            sizeof(Perftools__Symbols__FunctionInfo));
    if (info == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate proto function info struct");
        return or_insufficient_memory;
    }
    perftools__symbols__function_info__init(info);
    *function_info = info;
    return or_okay;
}

operation_result_t free_proto_function_info(Perftools__Symbols__FunctionInfo *function_info)
{
    if (function_info == NULL)
    {
        PYSAMPROF_LOG(PL_WARNING, "Tried to free NULL function info");
        return or_okay;
    }
    perftools__symbols__function_info__free_unpacked(function_info, NULL);
    return or_okay;
}

operation_result_t add_code_region_function_info(
        Perftools__Symbols__FunctionInfo *function_info, uint64_t startaddr, uint8_t *data,
        uint32_t length)
{
    Perftools__Symbols__CodeRegion *coderegion;
    Perftools__Symbols__CodeRegion **coderegions;
    uint8_t *buffer;

    if (!function_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Tried to add code region to NULL function info");
        return or_fail;
    }
    if (!function_info->codeinfo)
    {
        Perftools__Symbols__CodeInfo *codeinfo = (Perftools__Symbols__CodeInfo *)malloc(
                sizeof(Perftools__Symbols__CodeInfo));
        if (!codeinfo)
        {
            PYSAMPROF_LOG(PL_ERROR,
                    "Not enough memory: failed to allocate code info for proto function info");
            return or_insufficient_memory;
        }
        perftools__symbols__code_info__init(codeinfo);
        function_info->codeinfo = codeinfo;
    }
    coderegion = (Perftools__Symbols__CodeRegion *)malloc(sizeof(Perftools__Symbols__CodeRegion));
    if (!coderegion)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate code region for proto function info struct");
        return or_insufficient_memory;
    }
    perftools__symbols__code_region__init(coderegion);
    coderegion->has_startaddr = 1;
    coderegion->startaddr = startaddr;
    buffer = (uint8_t *)malloc(sizeof(uint8_t) * length);
    if (!buffer)
    {
        free(coderegion);
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate buffer for code region inproto function info struct");
        return or_insufficient_memory;
    }
    coderegion->buffer.data = buffer;
    coderegion->buffer.len = length;
    coderegion->has_buffer = 1;

    memcpy_s(coderegion->buffer.data, length, data, length);
    
    (function_info->codeinfo->n_coderegions)++;
    coderegions = (Perftools__Symbols__CodeRegion **)realloc(function_info->codeinfo->coderegions,
            (function_info->codeinfo->n_coderegions) * sizeof(Perftools__Symbols__CodeRegion *));
    if (!coderegions)
    {
        free(buffer);
        free(coderegion);
        (function_info->codeinfo->n_coderegions)--;
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate coderegions array for proto function info struct");
        return or_insufficient_memory;
    }

    coderegions[(function_info->codeinfo->n_coderegions) - 1] = coderegion;
    function_info->codeinfo->coderegions = coderegions;
    return or_okay;
}

operation_result_t add_functionid_function_info(Perftools__Symbols__FunctionInfo *function_info,
        uint64_t function_id)
{
    if (!function_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Tried to add function id to NULL function info");
        return or_fail;
    }
    function_info->has_functionid = 1;
    function_info->functionid = function_id;
    return or_okay;
}

operation_result_t add_function_name_function_info(
        Perftools__Symbols__FunctionInfo *function_info, const char *functionname)
{
    if (!function_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Tried to add function name to NULL function info");
        return or_fail;
    }
    function_info->functionname = strdup(functionname);
    if (!function_info->functionname)
    {
        PYSAMPROF_LOG(PL_ERROR, "Failed to strdup function name for function info");
        return or_insufficient_memory;
    }
    return or_okay;
}

operation_result_t add_source_file_name_function_info(
        Perftools__Symbols__FunctionInfo *function_info, const char *sourcefilename)
{
    int should_free = 0;

    if (!function_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Tried to add source file name to NULL function info");
        return or_fail;
    }
    if (!function_info->sourcefileinfo)
    {
        Perftools__Symbols__SourceFileInfo *source_file_info =
                (Perftools__Symbols__SourceFileInfo *)malloc(
                        sizeof(Perftools__Symbols__SourceFileInfo));
        if (!source_file_info)
        {
            PYSAMPROF_LOG(PL_ERROR,
                    "Not enough memory: failed to allocate source file info in proto function info struct");
            return or_insufficient_memory;
        }
        should_free = 1;
        perftools__symbols__source_file_info__init(source_file_info);
        function_info->sourcefileinfo = source_file_info;
    }
    function_info->sourcefileinfo->sourcefilename = strdup(sourcefilename);
    if (!function_info->sourcefileinfo->sourcefilename)
    {
        if (should_free != 0)
        {
            perftools__symbols__source_file_info__free_unpacked(function_info->sourcefileinfo,NULL);
            function_info->sourcefileinfo = NULL;
        }
        PYSAMPROF_LOG(PL_ERROR, "Failed to strdup source file name for function info");
        return or_insufficient_memory;
    }
    return or_okay;
}

operation_result_t add_module_name_function_info(
        Perftools__Symbols__FunctionInfo *function_info, const char *modulename)
{
    int should_free = 0;

    if (!function_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Tried to add module name to NULL function info");
        return or_fail;
    }
    if (!function_info->moduleinfo)
    {
        Perftools__Symbols__ModuleInfo *module_file_info =
                (Perftools__Symbols__ModuleInfo *)malloc(
                        sizeof(Perftools__Symbols__ModuleInfo));
        if (!module_file_info)
        {
            PYSAMPROF_LOG(PL_ERROR,
                    "Not enough memory: failed to allocate module info in proto function info struct");
            return or_insufficient_memory;
        }
        should_free = 1;
        perftools__symbols__module_info__init(module_file_info);
        function_info->moduleinfo = module_file_info;
    }
    function_info->moduleinfo->modulename = strdup(modulename);
    if (!function_info->moduleinfo->modulename)
    {
        if (should_free != 0)
        {
            perftools__symbols__module_info__free_unpacked(function_info->moduleinfo, NULL);
            function_info->moduleinfo = NULL;
        }
        PYSAMPROF_LOG(PL_ERROR, "Failed to strdup module file name for function info");
        return or_insufficient_memory;
    }
    return or_okay;
}

operation_result_t add_timing_function_info(Perftools__Symbols__FunctionInfo *function_info,
        uint64_t loadtime)
{
    if (!function_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Tried to add load time to NULL function info");
        return or_fail;
    }
    if (!function_info->timing)
    {
        Perftools__Symbols__Timing *timing = (Perftools__Symbols__Timing *)malloc(
                sizeof(Perftools__Symbols__Timing));
        if (!timing)
        {
            PYSAMPROF_LOG(PL_ERROR,
                    "Not enough memory: failed to allocate timing in proto function info struct");
            return or_insufficient_memory;
        }
        perftools__symbols__timing__init(timing);
        function_info->timing = timing;
    }
    function_info->timing->has_loadtime = 1;
    function_info->timing->loadtime = loadtime;
    return or_okay;
}

operation_result_t add_line_number_mappings_function_info(
        Perftools__Symbols__FunctionInfo *function_info, uint32_t startoffset,
        uint32_t endoffset, uint32_t linenumber)
{
    Perftools__Symbols__LineNumberMapEntry **nativetosourcemap;
    Perftools__Symbols__LineNumberMapEntry *nativetosourcemap_entry;

    if (!function_info)
    {
        PYSAMPROF_LOG(PL_ERROR, "Tried to add line number mapping to NULL function info");
        return or_fail;
    }
    if (!function_info->linenumbermappings)
    {
        Perftools__Symbols__LineNumberMappings *line_number_mappings =
                (Perftools__Symbols__LineNumberMappings *)malloc(
                        sizeof(Perftools__Symbols__LineNumberMappings));
        if (!line_number_mappings)
        {
            PYSAMPROF_LOG(PL_ERROR,
                    "Not enough memory: failed to allocate line number mappings in proto function info struct");
            return or_insufficient_memory;
        }
        perftools__symbols__line_number_mappings__init(line_number_mappings);
        function_info->linenumbermappings = line_number_mappings;
    }
    (function_info->linenumbermappings->n_nativetosourcemap)++;
    nativetosourcemap = (Perftools__Symbols__LineNumberMapEntry **)realloc(
                    function_info->linenumbermappings->nativetosourcemap,
                    sizeof(Perftools__Symbols__LineNumberMapEntry*)
                            * (function_info->linenumbermappings->n_nativetosourcemap));
    if (!nativetosourcemap)
    {
        (function_info->linenumbermappings->n_nativetosourcemap)--;
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate line number mappings in proto function info struct");
        return or_insufficient_memory;
    }
    function_info->linenumbermappings->nativetosourcemap = nativetosourcemap;
    nativetosourcemap_entry = (Perftools__Symbols__LineNumberMapEntry *)malloc(
                    sizeof(Perftools__Symbols__LineNumberMapEntry));
    if (!nativetosourcemap_entry)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Not enough memory: failed to allocate line number mapping entry in proto function info struct");
        return or_insufficient_memory;
    }
    perftools__symbols__line_number_map_entry__init(nativetosourcemap_entry);
    nativetosourcemap_entry->startoffset = startoffset;
    nativetosourcemap_entry->endoffset = endoffset;
    nativetosourcemap_entry->linenumber = linenumber;
    nativetosourcemap_entry->has_startoffset = 1;
    nativetosourcemap_entry->has_endoffset = 1;
    nativetosourcemap_entry->has_linenumber = 1;
    function_info->linenumbermappings->nativetosourcemap[(function_info->linenumbermappings->n_nativetosourcemap)
            - 1] = nativetosourcemap_entry;
    return or_okay;
}

operation_result_t serialize_function_info(Perftools__Symbols__FunctionInfo *function_info,
        void **buf, uint32_t *length)
{
    operation_result_t status = or_okay;
    void *buf_tmp;
    uint32_t packed, required;

    if (!function_info || !buf || !length)
    {
        PYSAMPROF_LOG(PL_ERROR,
                "Serialization of function info unexpectedly received NULL pointer in arguments");
        return or_fail;
    }
    required = perftools__symbols__function_info__get_packed_size(function_info);
    buf_tmp = malloc(required);
    if (!buf_tmp)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: failed to allocate buffer");
        return or_insufficient_memory;
    }

    packed = perftools__symbols__function_info__pack(function_info, buf_tmp);
    if (packed != required)
    {
        free(buf_tmp);
        PYSAMPROF_LOG(PL_ERROR, "Serialization of function info failed, packed size mismatch");
        return or_protobuf_fail;
    }
    *buf = buf_tmp;
    *length = required;
    return status;
}
