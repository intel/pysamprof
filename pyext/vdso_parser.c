#include "vdso_parser.h"

#include <stdio.h>
#include <link.h>
#include <string.h>
#include <stdlib.h>

#include <logging/logging.h>

static const char s_vdso_name[] = "[vdso]";

#ifdef __amd64__
#define CORRECT_ELF_CLASS ELFCLASS64
#define ELF_ST_TYPE ELF64_ST_TYPE
#else
#define CORRECT_ELF_CLASS ELFCLASS32
#define ELF_ST_TYPE ELF32_ST_TYPE
#endif

/* This source is almost copy-paste from some functionality from image_data.c.
 * Refactor this somehow in one interface. */

typedef operation_result_t (*section_loop_t)(ElfW(Ehdr)* header,
        ElfW(Shdr)* section, void* data);

static operation_result_t loop_over_sections(ElfW(Ehdr)* header,
        section_loop_t callback, void* data)
{
    if (header == NULL || callback == NULL) return or_fail;
    for (int i = 0; i < header->e_shnum; i++)
    {
        ElfW(Shdr)* section_header = (ElfW(Shdr)*)((char*)header + \
                header->e_shoff + i * header->e_shentsize);
        operation_result_t res = callback(header, section_header, data);
        if (res != or_continue_iterating) return res;
    }
    return or_fail;
}

typedef struct
{
    uint32_t sh_type;
    ElfW(Shdr)* section;
} find_section_operand_t;

static operation_result_t find_section(ElfW(Ehdr)* header,
        ElfW(Shdr)* section, void* data)
{
    if (header == NULL || section == NULL || data == NULL) return or_fail;
    find_section_operand_t* operand = (find_section_operand_t*)data;
    if (section->sh_type == operand->sh_type)
    {
        operand->section = section;
        return or_okay;
    }
    return or_continue_iterating;
}

static int vdso_entry_cmp(const void* a, const void* b)
{
    void* pa = ((vdso_entry_t*)a)->start;
    void* pb = ((vdso_entry_t*)b)->start;
    return (pa < pb) ? -1 : ((pa > pb) ? 1 : 0);
}

static operation_result_t find_symbol_phdr(ElfW(Ehdr)* header, ElfW(Sym)* symbol,
        ElfW(Phdr)** result)
{
    /* Find maximal program header containing the symbol */
    if (header == NULL || symbol == NULL || result == NULL) return or_fail;

    size_t start = (size_t)symbol->st_value;
    size_t stop = (size_t)symbol->st_value + symbol->st_size;
    size_t max_end = stop;
    operation_result_t status = or_fail;

    for (int i = 0; i < header->e_phnum; i++)
    {
        ElfW(Phdr)* program_header = (ElfW(Phdr)*)((char*)header + header->e_phoff +
                i * header->e_phentsize);
        size_t phdr_end = (size_t)program_header->p_paddr + program_header->p_memsz;
        if (start >= (size_t)program_header->p_paddr &&
            start <= phdr_end &&
            stop <= phdr_end)
        {
            // this is a program header that fully contains the symbol
            if (phdr_end >= max_end)
            {
                *result = program_header;
                max_end = phdr_end;
                status = or_okay;
            }
        }
    }
    return status;
}

operation_result_t parse_vdso_table(all_memory_regions_t regions,
        vdso_table_t* result)
{
    if (result == NULL) return or_fail;
    memory_region_info_t* vdso = NULL;
    {
        size_t i;
        memory_region_info_t* current = regions.regions;
        for (i = 0; i < regions.count; i++, current++)
        {
            if (current->filename != NULL &&
                strncmp(current->filename, s_vdso_name, sizeof(s_vdso_name)) == 0)
            {
                vdso = current;
                break;
            }
        }
        if (vdso == NULL)
        {
            PYSAMPROF_LOG(PL_WARNING, "Cannot find vDSO image");
            return or_cannot_find_image;
        }
    }

    ElfW(Ehdr)* header = (ElfW(Ehdr)*)(vdso->base);
    // TODO: a lot of copy-paste between this file and libprobengine/image_data; fix it
    if (header->e_ident[4] != CORRECT_ELF_CLASS)
    {
        PYSAMPROF_LOG(PL_ERROR, "Bad ELF header for vDSO image");
        return or_bad_image_file;
    }

    // first find SHT_STRTAB section
    find_section_operand_t find_operand;
    find_operand.sh_type = SHT_STRTAB;
    operation_result_t status = loop_over_sections(header, find_section, &find_operand);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot find SHT_STRTAB for vDSO");
        return or_bad_image_file;
    }
    char* strtab = (char*)header + find_operand.section->sh_offset;

    // now find SHT_DYNSYM section
    find_operand.sh_type = SHT_DYNSYM;
    status = loop_over_sections(header, find_section, &find_operand);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot find SHT_DYNSYM for vDSO");
        return or_bad_image_file;
    }

    result->entries = NULL;
    for (int i = 0; i < 2; i++)
    {
        int function_count = 0;
        // two iterations; first one counts functions, second one fills them in
        for (int j = 0;
             j * find_operand.section->sh_entsize <= find_operand.section->sh_size; j++)
        {
            ElfW(Sym)* symbol = (ElfW(Sym)*)((char*)header + \
                    find_operand.section->sh_offset + j * find_operand.section->sh_entsize);
            if (ELF_ST_TYPE(symbol->st_info) == STT_FUNC && symbol->st_value != 0)
            {
                char* name = strtab + symbol->st_name;
                if (result->entries != NULL)
                {
                    ElfW(Phdr)* phdr = NULL;
                    status = find_symbol_phdr(header, symbol, &phdr);
                    if (status != or_okay)
                    {
                        PYSAMPROF_LOG(PL_ERROR, "Cannot find program header for '%s'", name);
                        free(result->entries);
                        result->entries = NULL;
                        return status;
                    }
                    // compute "relocated" symbol address basing onto assumption that
                    // "phdr->p_ppaddr - phdr->p_offset" == "-(dynamic object relocation)",
                    // thus "load address" == "header + relocation"
                    result->entries[function_count].start = (void*)((char*)header +
                            (size_t)symbol->st_value -
                            ((size_t)phdr->p_paddr - (size_t)phdr->p_offset));
                    size_t max_size = (size_t)phdr->p_paddr + phdr->p_memsz -
                        (size_t)symbol->st_value;
                    result->entries[function_count].length = \
                        (max_size < symbol->st_size) ? max_size : symbol->st_size;
                    result->entries[function_count].name = name;
                }
                function_count++;
            }
        }
        if (result->entries == NULL)
        {
            result->entries = (vdso_entry_t*)malloc(sizeof(vdso_entry_t) * function_count);
            if (result->entries == NULL)
            {
                PYSAMPROF_LOG(PL_ERROR, "Not enough memory: cannot allocate vdso function list");
                return or_insufficient_memory;
            }
            result->count = function_count;
        }
    }
    qsort(result->entries, result->count, sizeof(vdso_entry_t), vdso_entry_cmp);

    vdso_entry_t* entry = result->entries;
    for (int i = 0; i < result->count - 1; i++, entry++)
    {
        size_t max_length = (size_t)((entry + 1)->start) - (size_t)entry->start;
        if (entry->length > max_length) entry->length = max_length;
    }

    return or_okay;
}
