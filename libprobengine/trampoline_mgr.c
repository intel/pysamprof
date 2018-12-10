#include "include/probengine/trampoline_mgr.h"

#ifdef __linux__
#include <unistd.h>
#include <sys/mman.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include <string.h>
#include <errno.h>

#include "../common/logging/logging.h"

#define TRAMPOLINE_CACHE_INCREMENT 4
#define MINIMAL_TRAMPOLINES_IN_PAGE 100

typedef struct
{
    void* addr;
    int taken;
} trampoline_page_t;

static long s_pagesize = 0;
static long s_allocsize = 0;
static int s_trampoline_page_size = 0;
static int s_trampoline_pages_count = 0;
static int s_trampoline_max_entries = 0;
static trampoline_page_t* s_trampoline_pages = NULL;

#ifdef _MSC_VER
#define INLINE __inline
#else
#define INLINE inline
#endif

// TODO: extract to some separate file to manage determining page size
static INLINE void ensure_page_size(void)
{
    if (s_pagesize == 0)
    {
#ifdef __linux__
        s_pagesize = sysconf(_SC_PAGESIZE);
		s_allocsize = s_pagesize;
#elif defined(_WIN32)
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		s_pagesize = info.dwPageSize;
		s_allocsize = info.dwAllocationGranularity;
#else
#error Unsupported platform
#endif
        if (s_pagesize <= 0)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot determine page size");
            return;
        }
        while (s_trampoline_page_size < MINIMAL_TRAMPOLINES_IN_PAGE * TRAMPOLINE_ENTRY_SIZE)
        {
            s_trampoline_page_size += s_pagesize;
        }
        s_trampoline_max_entries = s_trampoline_page_size / TRAMPOLINE_ENTRY_SIZE;
    }
}

static operation_result_t check_pages_are_free(size_t start, size_t length, all_memory_regions_t regions)
{
	char* page = (char*)start;
	size_t i, count;
	int index;
	operation_result_t intermediate;

	ensure_page_size();
	count = length / s_pagesize;
	if (length % s_pagesize != 0) count++;

	for (i = 0; i < count; i++, page += s_pagesize)
	{
		intermediate = find_memory_region((void*)page, regions, &index);
		switch (intermediate)
		{
		case or_okay:
			// page taken by the application
			return or_region_taken;
		case or_unknown_region:
			// page is free, continue checking
			continue;
		default:
			// something wrong happened
			PYSAMPROF_LOG(PL_WARNING, "Cannot check if memory region containing %p is free: %s", page, get_operation_result_str(intermediate));
			return intermediate;
		}
	}

	// if we get here all the pages are free
	return or_okay;
}

static operation_result_t find_free_page(size_t start, int increment,
        all_memory_regions_t regions, size_t target, size_t maxdiff, size_t* result)
{
    ensure_page_size();
	if (start % s_allocsize != 0)
	{
		if (increment > 0)
		{
			start += s_allocsize - start % s_allocsize;
		}
		else
		{
			start -= start % s_allocsize;
		}
	}
    while (1)
    {
#define CALC_DIFF(from) ((from) > target ? (from) - target : target - (from))
        if (CALC_DIFF(start) <= maxdiff)
#undef CALC_DIFF
        {
            // check if "start"-"start + s_trampoline_page_size" are free pages
			if (check_pages_are_free(start, s_trampoline_page_size, regions) == or_okay)
            {
                // now check if any trampoline page takes that
                // TODO: add assert that (current != NULL)
                trampoline_page_t* current = s_trampoline_pages;
                int taken_by_page = 0, i;
                for (i = 0; i < s_trampoline_pages_count; i++, current++)
                {
                    if (current->addr == NULL) continue; //empty page
                    if (((size_t)(current->addr) <= start) &&
                        ((size_t)(current->addr) + s_trampoline_page_size >= start))
                    {
                        // "start" is taken by trampoline page
                        taken_by_page = 1;
                        break;
                    }
                }
                if (taken_by_page == 0)
                {
                    // YAY, found free page!!
                    *result = start;
                    return or_okay;
                }
            }
        }

        // "start" is either taken by region or by trampoline pool, go further
        if ((increment >= 0 && start <= ((size_t)-1) - increment) ||
            (increment <= 0 && start >= -increment))
        {
            start += increment;
            continue;
        }
        else
        {
            // adress space ended :(
            PYSAMPROF_LOG(PL_WARNING, "Cannot find a free page adjacent to %p " \
                    "with %d increment", (void*)start, increment);
            return or_fail;
        }
    }
}

static operation_result_t allocate_trampoline_page(size_t target,
        size_t maxdiff, all_memory_regions_t regions, trampoline_page_t* page)
{
    int containing, use_left, use_right;
    size_t left, right;
	size_t difference = (size_t)-1, result = (size_t)-1;
	operation_result_t intermediate;

	ensure_page_size();
    if (page == NULL) return or_fail;

	// find containing free memory region
    intermediate = find_memory_region((void*)target,
            regions, &containing);
    if (intermediate != or_okay) return intermediate;

    use_left = (find_free_page((size_t)(regions.regions[containing].base),
                -s_allocsize, regions,
                target, maxdiff, &left) == or_okay) ? 1 : 0;
    use_right = (find_free_page((size_t)(regions.regions[containing].base) + \
                                             regions.regions[containing].size,
                s_allocsize, regions,
                target, maxdiff, &right) == or_okay) ? 1 : 0;

#define CALC_DIFF(from) ((from) > target ? (from) - target : target - (from))
    if (use_left)
    {
        size_t curdiff = CALC_DIFF(left);
        if (curdiff < difference && curdiff < maxdiff)
        {
            difference = curdiff;
            result = left;
        }
    }
    if (use_right)
    {
        size_t curdiff = CALC_DIFF(right);
        if (curdiff < difference && curdiff < maxdiff)
        {
            difference = curdiff;
            result = right;
        }
    }
#undef CALC_DIFF
    if (difference >= maxdiff)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot find suitable trampoline page that is " \
                "near enough to %p", (void*)target);
        return or_fail;
    }

#ifdef __linux__
    page->addr = mmap((void*)result, s_trampoline_page_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
#elif defined(_WIN32)
	page->addr = VirtualAlloc((void*)result, s_trampoline_page_size,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
#error Unsupported platform
#endif
    if (page->addr != (void*)result)
    {
#ifdef _WIN32
		PYSAMPROF_LOG(PL_ERROR, "Cannot allocate page for trampolines, alloc result: %p, error: %ld", page->addr, GetLastError());
		if (page->addr != NULL)
		{
			if (VirtualFree(page->addr, s_trampoline_page_size, MEM_DECOMMIT) == 0)
			{
				PYSAMPROF_LOG(PL_ERROR, "Cannot free the page that was allocated somehow incorrectly, error: %ld", GetLastError());
			}
		}
#else
		PYSAMPROF_LOG(PL_ERROR, "Cannot allocate page for trampolines, alloc result: %p, errno: %d", page->addr, errno);
#endif
        page->addr = NULL;
        return or_insufficient_memory;
    }
	memset(page->addr, 0xCC, s_trampoline_page_size); // fill trampoline page with "int 3" instructions just in case

    return or_okay;
}

static operation_result_t get_trampoline_page(size_t target,
        size_t maxdiff, all_memory_regions_t regions, trampoline_page_t** result)
{
	trampoline_page_t* current;
    trampoline_page_t* found = NULL;
    trampoline_page_t* first_empty = NULL;
    size_t difference = (size_t)-1;
	int i;

    if (result == NULL) return or_fail;
    ensure_page_size();

    if (s_trampoline_pages_count == 0 || s_trampoline_pages == NULL)
    {
        if (s_trampoline_pages != NULL) free(s_trampoline_pages);
        s_trampoline_pages_count = TRAMPOLINE_CACHE_INCREMENT;
        s_trampoline_pages = (trampoline_page_t*)malloc(
                sizeof(trampoline_page_t) * s_trampoline_pages_count);
        if (s_trampoline_pages == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for trampoline pages");
            return or_insufficient_memory;
        }
        memset(s_trampoline_pages, 0,
                sizeof(trampoline_page_t) * s_trampoline_pages_count);
    }

	current = s_trampoline_pages;
    for (i = 0; i < s_trampoline_pages_count; i++, current++)
    {
		size_t curdiff;
        if (current->addr == NULL)
        {
            // non-allocated page
            if (first_empty == NULL) first_empty = current;
            continue;
        }
        if (current->taken + 1 >= s_trampoline_max_entries)
        {
            // page is full
            continue;
        }
#define CALC_DIFF(from) (((size_t)(from) > target) ? (size_t)(from) - target : target - (size_t)(from))
        curdiff = CALC_DIFF((size_t)(current->addr) + \
                (current->taken + 1) * TRAMPOLINE_ENTRY_SIZE);
#undef CALC_DIFF
        if ((found == NULL || curdiff < difference) && curdiff < maxdiff)
        {
            found = current;
            difference = curdiff;
        }
    }
    if (found != NULL)
    {
        *result = found;
        return or_okay;
    }

    // no suitable page found, allocate one
    if (first_empty == NULL)
    {
        // no free space left, enlarge the storage
        trampoline_page_t* new_pages = (trampoline_page_t*)realloc(s_trampoline_pages,
                sizeof(trampoline_page_t) * (s_trampoline_pages_count + \
                                             TRAMPOLINE_CACHE_INCREMENT));
        if (new_pages == NULL) return or_insufficient_memory;
        first_empty = new_pages + s_trampoline_pages_count;
        memset(first_empty, 0,
                sizeof(trampoline_page_t) * TRAMPOLINE_CACHE_INCREMENT);
        s_trampoline_pages_count += TRAMPOLINE_CACHE_INCREMENT;
        s_trampoline_pages = new_pages;
    }

	{
		operation_result_t intermediate = allocate_trampoline_page(target,
				maxdiff, regions, first_empty);
		if (intermediate == or_okay)
		{
			*result = first_empty;
		}
		return intermediate;
	}
}

operation_result_t allocate_nearest_trampoline(void* target,
        int bitdiff, all_memory_regions_t regions, void** result)
{
	size_t maxdiff;
    trampoline_page_t *page;
	operation_result_t intermediate;

    if (result == NULL || regions.regions == NULL ||
        regions.count == 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "allocate_trampoline_page got bad arguments: " \
                "result(%p), regions.regions(%p) or regions.count(%d)",
                result, regions.regions, regions.count);
        return or_fail;
    }

    ensure_page_size();
    if (bitdiff == 0) bitdiff = sizeof(size_t) * 8;
    maxdiff = (size_t)(1ULL << bitdiff) - s_trampoline_page_size;

    intermediate = get_trampoline_page((size_t)target,
            maxdiff, regions, &page);
    if (intermediate != or_okay) return intermediate;

    *result = (void*)((char*)(page->addr) + page->taken * TRAMPOLINE_ENTRY_SIZE);
    page->taken++;

    return or_okay;
}

operation_result_t mark_trampoline_free(void* trampoline)
{
    trampoline_page_t* page = s_trampoline_pages;
	int i;

    for (i = 0; page != NULL && i < s_trampoline_pages_count; page++, i++)
    {
        if (page->addr != NULL && page->taken > 0)
        {
            void* last = (void*)((char*)(page->addr) + (page->taken - 1) * TRAMPOLINE_ENTRY_SIZE);
            if (last == trampoline)
            {
				memset(last, 0xCC, TRAMPOLINE_ENTRY_SIZE); // fill the freed entry with "int 3"
                page->taken--;
                return or_okay;
            }
        }
    }
    PYSAMPROF_LOG(PL_WARNING, "Cannot find a trampoline to mark it as free");
    return or_fail;
}

void free_all_trampolines()
{
    trampoline_page_t* current;
	int i;

    ensure_page_size();
    if (s_trampoline_pages == NULL) return;

    current = s_trampoline_pages;
    for (i = 0; i < s_trampoline_pages_count; i++, current++)
    {
        if (current->addr != NULL)
		{
#ifdef __linux__
			// TODO: add logging if munmap failed
			munmap(current->addr, s_trampoline_page_size);
#elif defined(_WIN32)
			if (!VirtualFree(current->addr, 0, MEM_RELEASE))
			{
				PYSAMPROF_LOG(PL_WARNING, "Cannot free trampoline at %p, error: %lld", current->addr, GetLastError());
			}
#else
#error Unsupported platform
#endif
		}
    }
    free(s_trampoline_pages);
}

