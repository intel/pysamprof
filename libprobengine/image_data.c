#ifdef __linux__
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported plaform
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "include/probengine/image_data.h"
#include "include/probengine/binary_search.h"
#include "../common/logging/logging.h"

static int s_image_data_cache_size = 0;
static image_data_t* s_image_data_cache = NULL;
#define IMAGE_CACHE_INCREMENT 4

#ifdef __linux__

#ifdef __amd64__
#define CORRECT_ELF_CLASS ELFCLASS64
#define ELF_ST_TYPE ELF64_ST_TYPE
#else
#define CORRECT_ELF_CLASS ELFCLASS32
#define ELF_ST_TYPE ELF32_ST_TYPE
#endif

typedef struct
{
    image_data_t* img_data;
    char* region_start;
} phdr_callback_data_t;

static int phdr_callback(struct dl_phdr_info* info, size_t size, void* data)
{
    if (!info || !data) return 0;
    char* region_start = ((phdr_callback_data_t*)data)->region_start;

    const ElfW(Phdr)* pheader = info->dlpi_phdr;
    for(int j = 0; j < info->dlpi_phnum; j++, pheader++)
    {
        if (pheader->p_type == PT_LOAD)
        {
            char* load_address = (char*)(info->dlpi_addr + pheader->p_vaddr);
            if (region_start >= load_address &&
                region_start <= load_address + pheader->p_memsz)
            {
                // this is the region we were looking for
                ((phdr_callback_data_t*)data)->img_data->relocation = info->dlpi_addr;
                return 1;
            }
        }
    }

    return 0;
}
#endif

static int function_size_cmp(const void* a, const void* b)
{
    void* pa = ((function_size_t*)a)->start;
    void* pb = ((function_size_t*)b)->start;
    return (pa < pb) ? -1 : ((pa > pb) ? 1 : 0 );
}

#ifdef __linux__
static operation_result_t fill_image_data_no_cache(image_data_t* data, void* region_start)
{
    if (data == NULL || region_start == NULL) return or_fail;
    data->relocation = INVALID_RELOCATION;
    phdr_callback_data_t phdr_data;
    phdr_data.img_data = data;
    phdr_data.region_start = (char*)region_start;
    struct stat image_stat;
    if (stat(data->filename, &image_stat) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot find '%s' on disk", data->filename);
        return or_cannot_find_image;
    }

    dl_iterate_phdr(phdr_callback, (void*)&phdr_data);
    if (data->relocation == INVALID_RELOCATION)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot find '%s' in loaded modules", data->filename);
        return or_cannot_find_image;
    }

    FILE* binfile = fopen(data->filename, "r");
    if (binfile == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot open '%s' for reading", data->filename);
        return or_cannot_open_file;
    }
    ElfW(Ehdr)* header = (ElfW(Ehdr)*)mmap(0, image_stat.st_size,
            PROT_READ, MAP_PRIVATE, fileno(binfile), 0);
    fclose(binfile);
    if (header == MAP_FAILED)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot mmap('%s') for reading", data->filename);
        return or_cannot_open_file;
    }
    if (header->e_ident[EI_CLASS] != CORRECT_ELF_CLASS)
    {
        if (munmap(header, image_stat.st_size) == -1)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot munmap() elf file '%s', errno: %d",
                    data->filename, errno);
        }
        PYSAMPROF_LOG(PL_ERROR, "Bad ELF header in '%s'", data->filename);
        return or_bad_image_file;
    }

    int function_count = 0;
    for (int i = 0; i < header->e_shnum; i++)
    {
        ElfW(Shdr)* section_header = (ElfW(Shdr)*)((char*)header + \
                header->e_shoff + i * header->e_shentsize);
        if (section_header->sh_type == SHT_DYNSYM)
        {
            for (int j = 0;
                 j * section_header->sh_entsize <= section_header->sh_size; j++)
            {
                ElfW(Sym)* symbol = (ElfW(Sym)*)((char*)header + \
                        section_header->sh_offset + j * section_header->sh_entsize);
                if (ELF_ST_TYPE(symbol->st_info) == STT_FUNC && symbol->st_value != 0)
                {
                    function_count++;
                }
            }
        }
    }
    if (function_count > 0)
    {
        data->function_count = function_count;
        data->function_entries = (function_size_t*)malloc(sizeof(function_size_t) * function_count);
        if (data->function_entries == NULL)
        {
            if (munmap(header, image_stat.st_size) == -1)
            {
                PYSAMPROF_LOG(PL_WARNING, "Cannot munmap() elf file '%s', errno: %d",
                        data->filename, errno);
            }
            PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for function entries");
            return or_insufficient_memory;
        }

        function_size_t* function_entry = data->function_entries;
        for (int i = 0; i < header->e_shnum; i++)
        {
            ElfW(Shdr)* section_header = (ElfW(Shdr)*)((char*)header + \
                    header->e_shoff + i * header->e_shentsize);
            if (section_header->sh_type == SHT_DYNSYM)
            {
                for (int j = 0;
                     j * section_header->sh_entsize <= section_header->sh_size; j++)
                {
                    ElfW(Sym)* symbol = (ElfW(Sym)*)((char*)header + \
                            section_header->sh_offset + j * section_header->sh_entsize);
                    if (ELF_ST_TYPE(symbol->st_info) == STT_FUNC && symbol->st_value != 0)
                    {
                        /* TODO: use target section to determine maximum symbol size
                           ElfW(Shdr)* target_header = (ElfW(Shdr)*)((char*) header + \
                                 header->e_shoff + symbol->st_shndx * header->e_shentsize); */
                        function_entry->start = (void*)(symbol->st_value + data->relocation);
                        function_entry->length = 0; // will be determined later
                        function_entry++;
                    }
                }
            }
        }
        qsort(data->function_entries, function_count, sizeof(function_size_t), function_size_cmp);
        function_entry = data->function_entries;
        for (int i = 0; i < function_count - 1; i++, function_entry++)
        {
            // TODO: when function_entry->length is filled within loop above
            //       use it as max.possible value here
            function_entry->length = (size_t)((function_entry + 1)->start) - \
                    (size_t)(function_entry->start);
        }
        // function_entry now points to last element
        // TODO: this should not be needed when loop above correctly fills maximum
        function_entry->length = ((size_t)-1) - (size_t)function_entry->start;
    }

    if (munmap(header, image_stat.st_size) == -1)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot munmap() elf file '%s', errno: %d",
                data->filename, errno);
    }
    return or_okay;
}
#elif defined(_WIN32)
typedef struct
{
	void* start;
	void* stop;
} section_size_t;

static operation_result_t fill_image_data_no_cache(image_data_t* data, void* region_start)
{
	HMODULE hModule;
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* NTHeader;
	IMAGE_EXPORT_DIRECTORY* pExportSection;
	section_size_t* sectionSizes;
	int sectionCount;

	if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)region_start, &hModule))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot find a module for %p address, error: %ld", region_start, GetLastError());
		return or_cannot_find_image;
	}

	dosHeader = (IMAGE_DOS_HEADER*)hModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot parse module %p symbols: bad DOS signature", (void*)hModule);
		return or_bad_image_file;
	}
	if (dosHeader->e_lfanew == 0)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot parse module %p symbols: bad NT header offset", (void*)hModule);
		return or_bad_image_file;
	}
	NTHeader = (IMAGE_NT_HEADERS*)((char*)hModule + dosHeader->e_lfanew);
	if (NTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot parse module %p symbols: bad NT header signature", (void*)hModule);
		return or_bad_image_file;
	}

	sectionCount = NTHeader->FileHeader.NumberOfSections;
	sectionSizes = (section_size_t*)malloc(sizeof(section_size_t) * sectionCount);
	if (sectionSizes == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate memory for section sizes");
		data->function_count = 0;
		return or_insufficient_memory;
	}
	else
	{
		section_size_t* pSize = sectionSizes;
		IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)((char*)NTHeader + sizeof(*NTHeader));
		int j;
		for (j = 0; j < sectionCount; j++, pSize++, header++)
		{
			pSize->start = (void*)((char*)hModule + header->VirtualAddress);
			pSize->stop = (void*)((char*)pSize->start + header->SizeOfRawData - 1);
		}
	}

	pExportSection = (IMAGE_EXPORT_DIRECTORY*)((char*)hModule + NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

#define OWN_MIN(a, b) (((a) < (b)) ? (a) : (b))
	{
		DWORD function_count = OWN_MIN(pExportSection->NumberOfFunctions, pExportSection->NumberOfNames);
		data->function_count = (int)(OWN_MIN((DWORD)INT_MAX, function_count));
	}

	data->relocation = 0; // TODO: check if this is always true or even if it is needed on Windows
	data->function_entries = (function_size_t*)malloc(sizeof(function_size_t) * data->function_count);
	if (data->function_entries == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate memory for function entries");
		free(sectionSizes);
		data->function_count = 0;
		return or_insufficient_memory;
	}

	{
		DWORD* nameOffset = (DWORD*)((char*)hModule + pExportSection->AddressOfNames);
		DWORD* functionOffset = (DWORD*)((char*)hModule + pExportSection->AddressOfFunctions);
		function_size_t* current = data->function_entries;
		int i;

		for (i = 0; i < data->function_count; i++, current++, nameOffset++, functionOffset++)
		{
			section_size_t* pSection = sectionSizes;
			int j;

			current->start = (void*)((char*)hModule + *functionOffset);
			current->length = 0;
			for (j = 0; j < sectionCount; j++, pSection++)
			{
				if (current->start >= pSection->start && current->start <= pSection->stop)
				{
					current->length = (size_t)pSection->stop - (size_t)current->start + 1;
					//PYSAMPROF_LOG(PL_INFO, "Found section (%p-%p) for function %s", pSection->start, pSection->stop, (char*)hModule + *nameOffset);
					break;
				}
			}
			if (current->length == 0)
			{
				PYSAMPROF_LOG(PL_WARNING, "Cannot find a section containing function %s in module %s", (char*)hModule + *nameOffset, data->filename);
				current->length = (size_t)-1;
			}
		}
	}
	
	free(sectionSizes);

	{
        function_size_t* function_entry = data->function_entries;
		int i;

		qsort(data->function_entries, data->function_count, sizeof(function_size_t), function_size_cmp);
        for (i = 0; i < data->function_count - 1; i++, function_entry++)
        {
            function_entry->length = OWN_MIN(function_entry->length,
				(size_t)((function_entry + 1)->start) - (size_t)(function_entry->start));
        }
        // function_entry now points to last element
		function_entry->length = OWN_MIN(function_entry->length,
			((size_t)-1) - (size_t)function_entry->start);
	}

	return or_okay;
#undef OWN_MIN
}
#else
#error Unsupported platform
#endif

static operation_result_t fill_image_data(memory_region_info_t* region)
{
	image_data_t *cached, *first_empty;
	int i;

    if (region == NULL) return or_fail;
    if (s_image_data_cache_size == 0 || s_image_data_cache == NULL)
    {
        if (s_image_data_cache != NULL) free(s_image_data_cache);
        s_image_data_cache_size = IMAGE_CACHE_INCREMENT;
        s_image_data_cache = (image_data_t*)malloc(sizeof(image_data_t) * s_image_data_cache_size);
        if (s_image_data_cache == NULL)
        {
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate image_data cache");
            return or_insufficient_memory;
        }
        memset(s_image_data_cache, 0, sizeof(image_data_t) * s_image_data_cache_size);
    }

    cached = s_image_data_cache;
    first_empty = NULL;
    for (i = 0; i < s_image_data_cache_size; i++, cached++)
    {
        if (cached->filename == NULL)
        {
            // empty cache entry
            if (first_empty == NULL) first_empty = cached;
            continue;
        }
        if (strcmp(cached->filename, region->filename) == 0)
        {
            // we're lucky, it's cache hit!
            region->image_data = cached;
            return or_okay;
        }
    }

    if (first_empty == NULL)
    {
		image_data_t* new_cache;
        // cache is full, but we need to insert more there
        s_image_data_cache_size += IMAGE_CACHE_INCREMENT;
        new_cache = realloc(s_image_data_cache,
                sizeof(image_data_t) * s_image_data_cache_size);
        if (new_cache == NULL)
        {
            s_image_data_cache_size -= IMAGE_CACHE_INCREMENT;
            PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot grow image_data cache");
            return or_insufficient_memory;
        }
        s_image_data_cache = new_cache;
        first_empty = &s_image_data_cache[s_image_data_cache_size - IMAGE_CACHE_INCREMENT];
        memset(first_empty, 0, sizeof(image_data_t) * IMAGE_CACHE_INCREMENT);
    }

#ifdef _WIN32
#define strdup _strdup
#endif
    first_empty->filename = strdup(region->filename);
    if (first_empty->filename == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot copy filename");
        return or_insufficient_memory;
    }
	{
		operation_result_t result = fill_image_data_no_cache(first_empty, region->base);
		if (result == or_okay)
		{
			region->image_data = first_empty;
		}
		else
		{
			free(first_empty->filename);
			first_empty->filename = NULL;
		}

		return result;
	}
}

static size_t get_memory_region_base(void* region)
{
    return (size_t)(((memory_region_info_t*)region)->base);
}

static operation_result_t get_image_data_by_addr(void* addr, memory_region_info_t* regions,
        int region_count, memory_region_info_t* result)
{
	int index;
    if (result == NULL || regions == NULL || region_count <= 0) return or_fail;

    index = perform_binary_search(regions, region_count, (size_t)addr,
            sizeof(memory_region_info_t), get_memory_region_base);

    if ((size_t)addr >= (size_t)(regions[index].base) + regions[index].size)
    {
        return or_unknown_region;
    }
    if (regions[index].filename == NULL) return or_unknown_region;

    if (regions[index].image_data == NULL)
    {
        operation_result_t intermediate = fill_image_data(&regions[index]);
        if (intermediate != or_okay) return intermediate;
    }

    *result = regions[index];

    return or_okay;
}

static size_t get_function_start(void* function)
{
    return (size_t)(((function_size_t*)function)->start);
}

operation_result_t get_function_region_size(void* addr, all_memory_regions_t regions,
        size_t* result)
{
    memory_region_info_t region;
	function_size_t* function_entries;
	int index;

    operation_result_t res = get_image_data_by_addr(addr,
            regions.regions, regions.count, &region);
    if (res != or_okay) return res;
    if (region.image_data->function_count <= 0)
    {
        return or_unknown_region;
    }
    function_entries = region.image_data->function_entries;
    if ((size_t)addr < (size_t)(function_entries[0].start))
    {
        return or_unknown_region;
    }

    index = perform_binary_search(function_entries, region.image_data->function_count,
            (size_t)addr, sizeof(function_size_t), get_function_start);

    if (function_entries[index].start != addr)
    {
        PYSAMPROF_LOG(PL_ERROR, "Requested function size of " \
                "unknown function at address: %p", addr);
        return or_invalid_function;
    }
    while(index < region.image_data->function_count - 1 && \
          function_entries[index].length == 0 && \
          function_entries[index + 1].start == addr)
    {
        index++;
    }
    if (function_entries[index].length == 0)
	{
		PYSAMPROF_LOG(PL_ERROR, "All entries for function at %p have zero length", function_entries[index].start);
		return or_bad_image_file;
	}

	{
		size_t function_end = (size_t)addr + function_entries[index].length - 1;
		size_t module_end = (size_t)region.base + region.size - 1;
		if (function_end > module_end) function_end = module_end;

		*result = function_end - (size_t)addr + 1;
	}
    return or_okay;
}

void free_all_image_data(void)
{
	image_data_t* data;
	int i;

    if (s_image_data_cache_size <= 0 || s_image_data_cache == NULL) return;

	data = s_image_data_cache;
    for (i = 0; i < s_image_data_cache_size; i++, data++)
    {
        if (data->filename == NULL) continue; // empty cache entry
        free(data->filename);
        if (data->function_entries) free(data->function_entries);
    }

    free(s_image_data_cache);
    s_image_data_cache = NULL;
    s_image_data_cache_size = 0;
}
