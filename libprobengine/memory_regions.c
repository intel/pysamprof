#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "include/probengine/memory_regions.h"
#include "include/probengine/binary_search.h"

#include "../common/logging/logging.h"

#ifdef _WIN32
#include <windows.h>
#endif

#define BUFSIZE_INCREMENT 256

typedef struct
{
    char read;
    char write;
    char execute;
    char private;
} permissions_chars_t;

typedef struct
{
    union
    {
        permissions_chars_t chars;
        char elems[4];
    };
} permissions_str_t;

#ifdef __linux__
static operation_result_t parse_memory_regions_internal(memory_region_info_t* regions,
        int* count, int buffer_size, int ignore_extra_regions)
{
    if (count == NULL) return or_fail;

    FILE* mapfile = fopen("/proc/self/maps", "r");
    if (!mapfile)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot open '/proc/self/maps', errno: %d", errno);
        return or_cannot_open_file;
    }

    size_t bufsize = BUFSIZE_INCREMENT;
    char* buf = (char*)malloc(bufsize);
    if (buf == NULL)
    {
        fclose(mapfile);
        return or_insufficient_memory;
    }

    operation_result_t result = or_okay;
    size_t num_regions_read = 0;

    while (1)
    {
        buf[0] = fgetc(mapfile);
        if (buf[0] == EOF) break;
        char* read = fgets(&buf[1], bufsize - 1, mapfile);
        if (read == NULL)
        {
            if (feof(mapfile)) break;
            PYSAMPROF_LOG(PL_ERROR, "Cannot read from '/proc/self/maps'");
            fclose(mapfile);
            free(buf);
            return or_cannot_read_file;
        }
        char* symbol = buf;
        while (1)
        {
            while (*symbol != '\0' && *symbol != '\n' && (symbol - buf <= bufsize)) symbol++;
            if (*symbol != '\n')
            {
                char next = fgetc(mapfile);
                if (next == EOF) break;
                *symbol = next;
                symbol++;

                // did not read whole line, read further
                bufsize += BUFSIZE_INCREMENT;
                char* newbuf = (char*)realloc(buf, bufsize);
                if (newbuf == NULL)
                {
                    fclose(mapfile);
                    free(buf);
                    return or_insufficient_memory;
                }
                symbol = symbol - buf + newbuf;
                buf = newbuf;
                read = fgets(symbol, bufsize - (symbol - buf), mapfile);
                if (read == NULL)
                {
                    if (feof(mapfile)) break;
                    PYSAMPROF_LOG(PL_ERROR, "Cannot read from '/proc/self/maps'");
                    fclose(mapfile);
                    free(buf);
                    return or_cannot_read_file;
                }
            }
            else
            {
                break;
            }
        }
        // now buf contains the whole line

        unsigned long long region_start, region_stop, file_offset, ignored;
        //char is_read, is_write, is_exec, is_private;
        permissions_str_t perm_str;
        char* path = NULL;
        int read_count = sscanf(buf, "%llx-%llx %4c %llx %llx:%llx %llu %ms",
                &region_start, &region_stop, &perm_str.elems[0],
                &file_offset,
                &ignored /* device1 */, &ignored /* device2 */,
                &ignored /* inode */,
                &path);
        if (!(read_count == 8 || (read_count == 7 && path == NULL)))
        {
            result = or_fail;
            if (path != NULL) free(path);
            PYSAMPROF_LOG(PL_ERROR, "failed to parse a line from /proc/self/maps, " \
                    "got only %d elements (line: %s)", read_count, buf);
            break;
        }

        // read the region line just fine
        num_regions_read++;
        if (regions == NULL)
        {
            // just count the regions we need to read
            free(path); // allocated by %ms in sscanf()
            continue;
        }

        if (num_regions_read > buffer_size)
        {
            // not enough memory passed in :(
            free(path);
            if (!ignore_extra_regions)
            {
                result = or_insufficient_memory;
                PYSAMPROF_LOG(PL_ERROR, "Not enough memory to parse /proc/self/maps");
            }
            else
            {
                PYSAMPROF_LOG(PL_WARNING,
                    "Encountered extra region while parsing memory maps, ignoring");
            }
            num_regions_read--;
            break;
        }

        int permissions = PERMISSIONS_NONE;
#define PARSE_PERMISSION_CHAR(ch, truth, flag) \
        if (perm_str.chars.ch == truth) permissions |= flag;
        PARSE_PERMISSION_CHAR(read, 'r', PERMISSIONS_READ);
        PARSE_PERMISSION_CHAR(write, 'w', PERMISSIONS_WRITE);
        PARSE_PERMISSION_CHAR(execute, 'x', PERMISSIONS_EXECUTE);
        PARSE_PERMISSION_CHAR(private, 'p', PERMISSIONS_PRIVATE);
#undef PARSE_PERMISSION_CHAR

        memory_region_info_t* current = &regions[num_regions_read - 1];
        current->filename = path;
        current->base = (void*)region_start;
        current->size = region_stop - region_start;
        current->file_offset = file_offset;
        current->permissions = permissions;
    }

    fclose(mapfile);
    free(buf);
    *count = num_regions_read;

    // TODO: sort memory regions... should be sorted, but to be safe

    return result;
}
#elif defined(_WIN32)
static operation_result_t parse_memory_regions_internal(memory_region_info_t* regions,
        int* count, int buffer_size, int ignore_extra_regions)
{
    SYSTEM_INFO si;
    MEMORY_BASIC_INFORMATION mbi;
    void* current = 0;
    int regions_read = 0;
    operation_result_t result = or_okay;

    GetSystemInfo(&si);
    while (result == or_okay && current < si.lpMaximumApplicationAddress)
    {
        if (!VirtualQuery(current, &mbi, sizeof(mbi)))
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot get information about region at %p, error: %ld", current, GetLastError());
            return or_fail;
        }
        current = (void*)((size_t)mbi.BaseAddress + mbi.RegionSize);
        if (mbi.State == MEM_FREE) continue;
        
        regions_read++;
        if (regions != NULL)
        {
            memory_region_info_t* region;
            HMODULE hModule;

            if (regions_read > buffer_size)
            {
                if (!ignore_extra_regions)
                {
                    result = or_insufficient_memory;
                    PYSAMPROF_LOG(PL_ERROR, "Not enough memory to parse memory regions");
                }
                else
                {
                    PYSAMPROF_LOG(PL_WARNING,
                        "Encountered extra region while parsing memory modules, ignoring");
                }
                regions_read--;
                break;
            }

            region = &regions[regions_read - 1];
            region->base = mbi.BaseAddress;
            region->file_offset = 0;
            
            region->filename = NULL;
            if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                (LPCSTR)mbi.BaseAddress, &hModule))
            {
                char buffer[1024];
                DWORD pathlen = GetModuleFileName(hModule, &buffer[0], sizeof(buffer) - 1);
                if (pathlen != 0)
                {
                    buffer[pathlen] = '\0'; // manually NULL-terminate if path was exactly sizeof(buffer)-1
                    region->filename = _strdup(buffer);
                    if (region->filename == NULL)
                    {
                        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot copy path to module at address %p", mbi.BaseAddress);
                        result = or_insufficient_memory;
                        break;
                    }
                }
            }
            region->image_data = NULL;

#define CONVERT_PERMISSION(check_perm, value)           \
    if ((mbi.Protect & (check_perm)) == (check_perm))   \
    {                                                   \
        region->permissions = value;                    \
    }                                                   \
    else
            region->permissions = PERMISSIONS_NONE;

            // CONVERT_PERMISSION if-else chain follows
            CONVERT_PERMISSION(PAGE_EXECUTE_WRITECOPY,
                PERMISSIONS_READ | PERMISSIONS_WRITE | PERMISSIONS_EXECUTE)
            CONVERT_PERMISSION(PAGE_EXECUTE_READWRITE,
                PERMISSIONS_READ | PERMISSIONS_WRITE | PERMISSIONS_EXECUTE)
            CONVERT_PERMISSION(PAGE_EXECUTE_READ,
                PERMISSIONS_READ | PERMISSIONS_EXECUTE)
            CONVERT_PERMISSION(PAGE_EXECUTE,
                PERMISSIONS_EXECUTE)

            CONVERT_PERMISSION(PAGE_WRITECOPY,
                PERMISSIONS_READ | PERMISSIONS_WRITE)
            CONVERT_PERMISSION(PAGE_READWRITE,
                PERMISSIONS_READ | PERMISSIONS_WRITE)
            CONVERT_PERMISSION(PAGE_READONLY,
                PERMISSIONS_READ)
            {
                // we're here if none of the above matched
                PYSAMPROF_LOG(PL_INFO, "Found a region having unknown permissions %llx", (long long)mbi.Protect);
            }
#undef CONVERT_PERMISSION

            if ((mbi.Type & MEM_PRIVATE) == MEM_PRIVATE) region->permissions |= PERMISSIONS_PRIVATE;

            region->size = mbi.RegionSize;
        }
    }

    *count = regions_read;

    return result;
}
#else
#error Unsupported platform
#endif

operation_result_t parse_memory_regions(all_memory_regions_t* regions,
        int ignore_extra_regions)
{
    int required_count;
    operation_result_t intermediate;

    if (regions == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "parse_memory_regions got NULL argument");
        return or_fail;
    }
    intermediate = parse_memory_regions_internal(NULL,
            &required_count, 0, 0);
    if (intermediate != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot count memory regions: %s",
                get_operation_result_str(intermediate));
        return intermediate;
    }

    regions->regions = (memory_region_info_t*)malloc(sizeof(memory_region_info_t) * \
            required_count);
    if (regions->regions == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate regions");
        return or_insufficient_memory;
    }
    memset(regions->regions, 0, sizeof(memory_region_info_t) * required_count);
    intermediate = parse_memory_regions_internal(regions->regions, &(regions->count),
            required_count, ignore_extra_regions);
    if (intermediate != or_okay || regions->count > required_count)
    {
        // reset the counter to not walk over allocated buffer size
        if (regions->count > required_count) regions->count = required_count;
        free_memory_regions(*regions);
        PYSAMPROF_LOG(PL_ERROR, "Cannot parse memory regions: %s",
                get_operation_result_str(intermediate));
        return (intermediate != or_okay) ? intermediate : or_fail;
    }
    return or_okay;
}

void free_memory_regions(all_memory_regions_t regions)
{
    int i;
    memory_region_info_t* current = regions.regions;
    for (i = 0; i < regions.count; i++, current++)
    {
        if (current->filename != NULL) free(current->filename);
    }
    free(regions.regions);
}

static size_t get_memory_region_base(void* region)
{
    return (size_t)(((memory_region_info_t*)region)->base);
}

operation_result_t find_memory_region(void* target,
        all_memory_regions_t regions, int* index)
{
    int probable_index;

    if (index == NULL || regions.count < 1)
    {
        PYSAMPROF_LOG(PL_ERROR, "find_memory_region got bad params: index (%p) " \
                "or regions.count (%d)", index, regions.count);
        return or_fail;
    }

    if ((size_t)target < (size_t)(regions.regions[0].base) ||
        (size_t)target >= (size_t)(regions.regions[regions.count - 1].base) + \
                                   regions.regions[regions.count - 1].size)
    {
        // target outside of any known region for sure
        return or_unknown_region;
    }
    probable_index = perform_binary_search(regions.regions, regions.count,
            (size_t)target, sizeof(memory_region_info_t), get_memory_region_base);
    if ((size_t)target >= (size_t)(regions.regions[probable_index].base) +
                                   regions.regions[probable_index].size)
    {
        return or_unknown_region;
    }

    *index = probable_index;
    return or_okay;
}
