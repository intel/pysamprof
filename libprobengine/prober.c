#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/mman.h>
#include <safe_mem_lib.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error Unsupported platform
#endif

#include <xed/xed-interface.h>

#include "include/probengine/prober.h"
#include "include/probengine/image_data.h"
#include "include/probengine/trampoline_mgr.h"
#include <common/logging/logging.h>

#define GET_ABS_DIFF(x, y) (((x) >= (y)) ? ((x) - (y)) : ((y) - (x)))
#define GET_SIZE_DIFF(x, y) GET_ABS_DIFF((size_t)(x), (size_t)(y))

#define MAX_RELATIVE_BRANCH_BITS 31
#define MAX_RELATIVE_DIFF (1ULL << MAX_RELATIVE_BRANCH_BITS)

static int s_xed_initialized = 0;
static xed_state_t s_xed_state;
static xed_chip_enum_t s_xed_chip = XED_CHIP_INVALID;

static long s_pagesize = 0;

#ifdef __linux__
typedef int protection_flags_t;
#elif defined(_WIN32)
typedef DWORD protection_flags_t;
#else
#error Unsupported platform
#endif

static operation_result_t ensure_page_size(void)
{
    if (s_pagesize <= 0)
    {
#ifdef __linux__
        s_pagesize = sysconf(_SC_PAGESIZE);
#elif defined(_WIN32)
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		s_pagesize = info.dwPageSize;
#else
#error Unsupported platform
#endif
        if (s_pagesize == -1)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot determine page size");
            return or_fail;
        }
    }
    return or_okay;
}

#define RELATIVE_BRANCH_SIZE 5
#if defined(_WIN64) || defined(__amd64__)
#define ABSOLUTE_BRANCH_SIZE 14
#else
#define ABSOLUTE_BRANCH_SIZE RELATIVE_BRANCH_SIZE
#endif

void xed_initialize()
{
    if (s_xed_initialized != 0) return;

    xed_tables_init();
    xed_state_zero(&s_xed_state);
#if defined(_WIN64) || defined(__amd64__)
    s_xed_state.mmode = XED_MACHINE_MODE_LONG_64;
    s_xed_state.stack_addr_width = XED_ADDRESS_WIDTH_64b;
#else
    s_xed_state.mmode = XED_MACHINE_MODE_LEGACY_32;
    s_xed_state.stack_addr_width = XED_ADDRESS_WIDTH_32b;
#endif

    s_xed_initialized = 1;
}

static operation_result_t get_region_protection(void* target,
        all_memory_regions_t regions, protection_flags_t* result)
{
    int index = 0, permissions = 0;
	operation_result_t status;

    if (target == NULL || result == NULL) return or_fail;

    status = find_memory_region(target, regions, &index);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot find memory region for %p to get permissions",
                target);
        return status;
    }

    permissions = regions.regions[index].permissions;
#ifdef __linux__
    *result = PROT_NONE;
#define TRANSLATE_PERMISSION(from, to) \
    if ((permissions & (from)) == (from)) *result |= (to);
    TRANSLATE_PERMISSION(PERMISSIONS_READ, PROT_READ);
    TRANSLATE_PERMISSION(PERMISSIONS_WRITE, PROT_WRITE);
    TRANSLATE_PERMISSION(PERMISSIONS_EXECUTE, PROT_EXEC);
#undef TRANSLATE_PERMISSION
#elif defined(_WIN32)
#define CHECK_PERMISSION(perm)	((permissions & (perm)) == (perm))
	if (CHECK_PERMISSION(PERMISSIONS_EXECUTE))
	{
		if (CHECK_PERMISSION(PERMISSIONS_WRITE))
		{
			if (CHECK_PERMISSION(PERMISSIONS_READ))
			{
				*result = PAGE_EXECUTE_READWRITE;
			}
			else
			{
				PYSAMPROF_LOG(PL_ERROR, "Bad region permissions: %p has exec and write but no read", target);
				return or_bad_permissions;
			}
		}
		else
		{ // don't have WRITE permission
			if (CHECK_PERMISSION(PERMISSIONS_READ))
			{
				*result = PAGE_EXECUTE_READ;
			}
			else
			{
				*result = PAGE_EXECUTE;
			}
		}
	}
	else
	{ // don't have EXECUTE permission
		if (CHECK_PERMISSION(PERMISSIONS_WRITE))
		{
			if (CHECK_PERMISSION(PERMISSIONS_READ))
			{
				*result = PAGE_READWRITE;
			}
			else
			{
				PYSAMPROF_LOG(PL_ERROR, "Bad region permissions: %p has write but no read", target);
				return or_bad_permissions;
			}
		}
		else
		{ // don't have WRITE permission
			if (CHECK_PERMISSION(PERMISSIONS_READ))
			{
				*result = PAGE_READONLY;
			}
			else
			{
				*result = PAGE_NOACCESS;
			}
		}
	}
#else
#error Unsupported platform
#endif
    return or_okay;
}

static operation_result_t unprotect_target(void* target, size_t size,
        all_memory_regions_t regions, protection_flags_t* old_protection)
{
	operation_result_t status;
	size_t start, stop, current;
	protection_flags_t protection = (protection_flags_t)-1;

    if (target == NULL || old_protection == NULL) return or_fail;

    status = ensure_page_size();
    if (status != or_okay) return status;

    start = (size_t)target - ((size_t)target) % s_pagesize;
    stop = (size_t)target + size;

    for (current = start; current < stop; current += s_pagesize)
    {
        protection_flags_t current_prot = 0;
        status = get_region_protection((void*)current,
                regions, &current_prot);
        if (status != or_okay) return status;
        if (protection == (protection_flags_t)-1)
        {
            protection = current_prot;
        }
        else
        {
            if (protection != current_prot)
            {
                PYSAMPROF_LOG(PL_ERROR, "Cannot unprotect regions with different protections");
				return or_bad_permissions;
            }
        }
    }
    if (protection == (protection_flags_t)-1)
	{
		PYSAMPROF_LOG(PL_ERROR, "No region found covering range from %p to %p", (void*)start, (void*)stop);
		return or_fail;
	}

#ifdef __linux__
    if (mprotect((void*)start, stop - start,
                PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
#elif defined(_WIN32)
	if (!VirtualProtect((void*)start, stop - start, PAGE_EXECUTE_READWRITE, old_protection))
#else
#error Unsupported platform
#endif
    {
        // something bad happened :(
#ifdef __linux__
		PYSAMPROF_LOG(PL_ERROR, "Cannot unprotect region, errno: %d", errno);
#elif defined(_WIN32)
		PYSAMPROF_LOG(PL_ERROR, "Cannot unprotect region, error: %ld", GetLastError());
#else
#error Unsupported platform
#endif
        return or_fail;
    }
#ifndef _WIN32
	// not needed on Windows as VirtualProtect does this for us
    *old_protection = protection;
#endif
    return or_okay;
}

static int unaligned_mprotect(void* addr, size_t length, protection_flags_t flags)
{
	size_t start;
    operation_result_t status = ensure_page_size();
    if (status != or_okay) return -1;

    start = (size_t)addr - ((size_t)addr) % s_pagesize;
#ifdef __linux__
    return mprotect((void*)start, (size_t)addr - start + length, flags);
#elif defined(_WIN32)
	{
		DWORD old_protect;
		BOOL okay = VirtualProtect((void*)start, (size_t)addr - start + length, flags, &old_protect);
		return okay ? 0 : 1;
	}
#else
#error Unsupported platform
#endif
}

static operation_result_t analyze_function(void* target, size_t length, int jmp_size,
        size_t* first_branch, int* jmp_rip_safe, int* bytes_to_take)
{
    xed_error_enum_t err;
    xed_decoded_inst_t xedd;
    size_t diff = 0;
	int ret_count = 0;

	if (target == NULL || first_branch == NULL ||
            jmp_rip_safe == NULL || bytes_to_take == NULL) return or_fail;

    *first_branch = (size_t)target + length;
    *jmp_rip_safe = 1;
    *bytes_to_take = 0;
    while (diff < length)
    {
		const xed_inst_t* decoded;
        int is_jmp_probed = (diff <= jmp_size) ? 1 : 0;
        void* itext = (void*)((char*)target + diff);

        unsigned int bytes = XED_MAX_INSTRUCTION_BYTES;
        if (bytes > length - diff)
        {
            bytes = (unsigned int)(length - diff);
        }

        xed_decoded_inst_zero_set_mode(&xedd, &s_xed_state);
        xed_decoded_inst_set_input_chip(&xedd, s_xed_chip);
        err = xed_decode(&xedd, itext, bytes);
        if (err != XED_ERROR_NONE)
        {
			PYSAMPROF_LOG((ret_count > 0) ? PL_WARNING : PL_ERROR,
				"Cannot decode instruction at %p, xed error: %s",
				itext, xed_error_enum_t2str(err));
			return (ret_count > 0) ? or_okay : or_xed_error;
        }

		if (xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_RET ||
			xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_SYSRET)
		{
			ret_count++;
		}

        diff += xed_decoded_inst_get_length(&xedd);
        if (is_jmp_probed) *bytes_to_take = (int)diff;

        decoded = xed_decoded_inst_inst(&xedd);
        if (xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_COND_BR ||
            xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_UNCOND_BR ||
            xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_CALL)
        {
            size_t branch_target = (size_t)target + diff + \
                                  xed_decoded_inst_get_branch_displacement(&xedd);
            if (branch_target < *first_branch && branch_target > (size_t)target)
            {
                *first_branch = branch_target;
            }
        }

        if (is_jmp_probed)
        {
            // we only need to analyze for RIP-safety the instructions
            // we're expecting to be relocated
			unsigned int op;
            for (op = 0; op < xed_inst_noperands(decoded); op++)
            {
                const xed_operand_t* operand = xed_inst_operand(decoded, op);
                xed_operand_enum_t opname = xed_operand_name(operand);

                if (xed_operand_is_register(opname))
                {
                    xed_reg_enum_t opreg = xed_decoded_inst_get_reg(&xedd, opname);
                    if (opreg == XED_REG_RIP)
                    {
                        xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
                        if (category != XED_CATEGORY_CALL &&
                            category != XED_CATEGORY_RET &&
                            category != XED_CATEGORY_COND_BR &&
                            category != XED_CATEGORY_UNCOND_BR &&
                            category != XED_CATEGORY_SYSCALL)
                        {
                            *jmp_rip_safe = 0;
                        }
                    }
                }
            }
        }
    }

    return or_okay;
}

// FIXME: pass max length as well (should be known from function analysis)
static operation_result_t get_instructions_length(void* target, int min_len, int* result)
{
	xed_error_enum_t err;
    xed_decoded_inst_t xedd;
	int total_size = 0;

	if (target == NULL || min_len < 1 || result == NULL) return or_fail;

	while (total_size < min_len)
	{
		xed_decoded_inst_zero_set_mode(&xedd, &s_xed_state);
		xed_decoded_inst_set_input_chip(&xedd, s_xed_chip);
		err = xed_decode(&xedd, (const xed_uint8_t*)target + total_size, XED_MAX_INSTRUCTION_BYTES);
		if (err != XED_ERROR_NONE)
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot decode instruction at %p, xed error: %s",
				(char*)target + total_size, xed_error_enum_t2str(err));
			return or_xed_error;
		}
		total_size += xed_decoded_inst_get_length(&xedd);
	}

    *result = total_size;
	return or_okay;
}

static operation_result_t generate_relative_jmp(void* where, void* target,
        all_memory_regions_t regions)
{
	long long displacement = (long long)target - (long long)where - RELATIVE_BRANCH_SIZE;
    xed_encoder_request_t req;
    unsigned int encoded;
    xed_uint8_t buf[2 * XED_MAX_INSTRUCTION_BYTES - 1];
    xed_error_enum_t err;

	if ((int)displacement != displacement)
	{
		PYSAMPROF_LOG(PL_ERROR, "Got too big displacement in %s, does not fit in int", __FUNCTION__);
		return or_fail;
	}

    xed_encoder_request_zero_set_mode(&req, &s_xed_state);
    xed_encoder_request_set_iclass(&req, XED_ICLASS_JMP);
    xed_encoder_request_set_operand_order(&req, 0, XED_OPERAND_RELBR);
    xed_encoder_request_set_relbr(&req);
    xed_encoder_request_set_branch_displacement(&req, (int)displacement, sizeof(xed_int32_t));
    err = xed_encode(&req, buf, sizeof(buf), &encoded);
    if (err != XED_ERROR_NONE || encoded > RELATIVE_BRANCH_SIZE)
    {
        if (err != XED_ERROR_NONE)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot generate relative jmp, xed error: %s",
                    xed_error_enum_t2str(err));
        }
        else
        {
            PYSAMPROF_LOG(PL_ERROR, "Generated relative jump of %d bytes, " \
                    "expected to be no more than %d", (int)encoded,
                    (int)RELATIVE_BRANCH_SIZE);
        }
        return or_cannot_probe;
    }

	{
		int replaced_length;
		operation_result_t status = get_instructions_length(where,
			encoded, &replaced_length);
		if (status != or_okay)
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot get replaced length at %p: %s",
				where, get_operation_result_str(status));
			return status;
		}
		if (replaced_length > sizeof(buf))
		{
			PYSAMPROF_LOG(PL_WARNING, "Got too big replacement length at %p: %d",
				where, replaced_length);
		}
		else if ((unsigned int)replaced_length > encoded)
		{
			memset(&(buf[encoded]), 0xCC, replaced_length - encoded);
			encoded = replaced_length;
		}
	}

	{
		protection_flags_t protection_flags;
		operation_result_t status = unprotect_target(where,
				encoded, regions, &protection_flags);
		if (status != or_okay) return status;

		memcpy_s(where, encoded, buf, encoded);

		// protect region back
		if (unaligned_mprotect(where, encoded, protection_flags) != 0)
		{
			PYSAMPROF_LOG(PL_ERROR, "Cannot protect region back");
			return or_fail;
		}
	}
#ifdef _WIN32
	if (!FlushInstructionCache(GetCurrentProcess(), where, encoded))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot flush instruction cache, error: %ld", GetLastError());
		return or_fail;
	}
#endif

	return or_okay;
}
#if defined(_WIN64) || defined(__amd64__)
static operation_result_t generate_absolute_jmp(void* where, void* target)
{
    /* There are no absolute jmp instructions on x86_64.
     * To make an absolute jmp we do a "jmp QWORD PTR [rip + 0x0]" followed
     * by target address. */
    xed_encoder_request_t req;
    unsigned int length;
	xed_error_enum_t err;

	xed_encoder_request_zero_set_mode(&req, &s_xed_state);
    xed_encoder_request_set_iclass(&req, XED_ICLASS_JMP);
    xed_encoder_request_set_branch_displacement(&req, 0, sizeof(xed_int32_t));
    xed_encoder_request_set_mem0(&req);
    xed_encoder_request_set_operand_order(&req, 0, XED_OPERAND_MEM0);
    xed_encoder_request_set_base0(&req, XED_REG_RIP);
    xed_encoder_request_set_index(&req, XED_REG_INVALID);
    xed_encoder_request_set_scale(&req, 0);
    xed_encoder_request_set_seg0(&req, XED_REG_INVALID);
    xed_encoder_request_set_effective_operand_width(&req, 64 /* in bits */);
    xed_encoder_request_set_memory_operand_length(&req, 8);

    err = xed_encode(&req, (xed_uint8_t*)where, ABSOLUTE_BRANCH_SIZE, &length);
    if (err != XED_ERROR_NONE || length > ABSOLUTE_BRANCH_SIZE - sizeof(size_t))
    {
        if (err != XED_ERROR_NONE)
        {
            PYSAMPROF_LOG(PL_ERROR, "Cannot generate absolute jmp, xed error: %s",
                    xed_error_enum_t2str(err));
        }
        else
        {
            PYSAMPROF_LOG(PL_ERROR, "Generated absolute jmp of %d bytes, " \
                    "expected to be no more than %d", (int)length,
                    (int)(ABSOLUTE_BRANCH_SIZE - sizeof(size_t)));
        }
        return or_cannot_probe;
    }
    *(size_t*)((xed_uint8_t*)where + length) = (size_t)target;

#ifdef _WIN32
	if (!FlushInstructionCache(GetCurrentProcess(), where, length + sizeof(size_t)))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot flush instruction cache, error: %ld", GetLastError());
		return or_fail;
	}
#endif

    return or_okay;
}
#else
#error Unsupported generating 32-bit absolute jmp, re-use generate_relative_jmp
#endif

static int does_value_fit(long long value, int nbytes)
{
    unsigned long long uvalue;
    if (nbytes >= 8) return 1;
    uvalue = (unsigned long long)value;
    if (value >= 0)
    {
        unsigned long long mask = (1ULL << (nbytes * 8)) - 1; // nbytes each equals to 0xFF
        // check that clearing all bits that don't fit in "nbytes" does not change the value
        return ((uvalue & mask) == uvalue) ? 1 : 0;
    }
    else
    {
        // set all bits except lowest 8 * nbytes
        unsigned long long mask = ((unsigned long long)-1) - (1ULL << (nbytes * 8)) + 1;
        // check that setting all bits that don't fit in "nbytes" does not change the value
        return ((uvalue | mask) == uvalue) ? 1 : 0;
    }
}

// Checks if xedd points to instruction that addresses memory
// relative to Instruction Pointer register
static operation_result_t is_instruction_ip_related(xed_decoded_inst_t* xedd, int* result)
{
    const xed_inst_t* decoded;
	unsigned int op;

	if (xedd == NULL || result == NULL) return or_fail;

    decoded = xed_decoded_inst_inst(xedd);
    for (op = 0; op < xed_inst_noperands(decoded); op++)
    {
        const xed_operand_t* operand = xed_inst_operand(decoded, op);
        xed_operand_enum_t opname = xed_operand_name(operand);
        int memindex = -1;
        switch (opname)
        {
            case XED_OPERAND_AGEN:
            case XED_OPERAND_MEM0:
                memindex = 0;
                break;
            case XED_OPERAND_MEM1:
                memindex = 1;
                break;
            default:
                break;
        }
        if (memindex != -1)
        {
            xed_reg_enum_t basereg = xed_decoded_inst_get_base_reg(xedd, memindex);
            xed_reg_enum_t indexreg = xed_decoded_inst_get_index_reg(xedd, memindex);
            if (basereg == XED_REG_RIP || indexreg == XED_REG_RIP)
			{
				*result = 1;
				return or_okay;
			}
		}
	}

	*result = 0;
	return or_okay;
}

static operation_result_t make_calling_trampoline(void* target, all_memory_regions_t regions,
        int bytes_to_take, int bitdiff, void** result)
{
    char* trampoline;
    xed_error_enum_t err;
    xed_decoded_inst_t xedd;
    size_t diff = 0, tram_diff = 0;
	operation_result_t status;

	if (target == NULL || bytes_to_take + ABSOLUTE_BRANCH_SIZE > TRAMPOLINE_ENTRY_SIZE)
    {
        return or_cannot_probe;
    }

    status = allocate_nearest_trampoline(target,
            bitdiff, regions, (void**)&trampoline);
    if (status != or_okay) return status;

    // rewrite arguments if needed
    while (diff < bytes_to_take)
    {
        unsigned int old_length, new_length = 0;
		xed_encoder_request_t* rewrite_req;
		int is_ip_related;

        unsigned int bytes = XED_MAX_INSTRUCTION_BYTES;
        void* original = (void*)((char*)target + diff);
        if (bytes > bytes_to_take - diff)
        {
            bytes = (unsigned int)(bytes_to_take - diff);
        }

        xed_decoded_inst_zero_set_mode(&xedd, &s_xed_state);
        xed_decoded_inst_set_input_chip(&xedd, s_xed_chip);
        err = xed_decode(&xedd, original, bytes);
        if (err != XED_ERROR_NONE)
        {
            mark_trampoline_free((void*)trampoline);
            PYSAMPROF_LOG(PL_ERROR, "Cannot decode instruction at %p " \
                    "during making trampoline to original, xed error: %s",
                    original, xed_error_enum_t2str(err));
            return or_cannot_probe;
        }
		status = is_instruction_ip_related(&xedd, &is_ip_related);
		if (status != or_okay)
        {
            mark_trampoline_free((void*)trampoline);
            PYSAMPROF_LOG(PL_ERROR, "Cannot determine if instruction at %p is IP-relative", original);
            return or_cannot_probe;
        }

        old_length = xed_decoded_inst_get_length(&xedd);
        xed_encoder_request_init_from_decode(&xedd);
        rewrite_req = (xed_encoder_request_t*)&xedd;

        if ((!is_ip_related) && (xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_COND_BR ||
            xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_UNCOND_BR ||
            xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_CALL))
        {
            long long branch_target = (long long)target + diff + old_length + \
                                   xed_decoded_inst_get_branch_displacement(&xedd);
            int encoded = 0, argsize;
            /* We loop over all possible sizes of a relative branch argument:
             * 1 byte, 2 bytes, 4 bytes. Smallest one that XED could encode
             * that is enough to generate a jmp we need is taken. */
            for (argsize = 1; argsize <= 4; argsize *= 2)
            {
                // we need a copy of encoder request - xed cannot encode a request more than once
                xed_encoder_request_t temp_req = *rewrite_req;
                xed_uint8_t temp_buf[XED_MAX_INSTRUCTION_BYTES];
				long long new_displacement;

				xed_encoder_request_set_branch_displacement(&temp_req, 0, argsize);
                err = xed_encode(&temp_req, temp_buf, sizeof(temp_buf), &new_length);
                if (err != XED_ERROR_NONE)
                {
                    // cannot encode instruction with "argsize"-sized operand
                    continue;
                }

                new_displacement = branch_target - (long long)trampoline - tram_diff - new_length;
                if (!does_value_fit(new_displacement, argsize))
                {
                    continue;
                }

                xed_encoder_request_set_branch_displacement(rewrite_req,
                        (xed_int32_t)new_displacement, argsize);
                // yee-eha! we can encode this branch in "argsize" bytes
                encoded = 1;
                break;
            }

            if (encoded != 1)
            {
                mark_trampoline_free((void*)trampoline);
                PYSAMPROF_LOG(PL_WARNING, "Cannot rewrite branch or call " \
                        "instruction, try nearer trampoline");
                return or_cannot_probe;
            }
        }
        else if (is_ip_related)
        {
            const xed_inst_t* decoded = xed_decoded_inst_inst(&xedd);
			unsigned int op;
            for (op = 0; op < xed_inst_noperands(decoded); op++)
            {
                const xed_operand_t* operand = xed_inst_operand(decoded, op);
                xed_operand_enum_t opname = xed_operand_name(operand);
                int memindex = -1;
                switch (opname)
                {
                    case XED_OPERAND_AGEN:
                    case XED_OPERAND_MEM0:
                        memindex = 0;
                        break;
                    case XED_OPERAND_MEM1:
                        memindex = 1;
                        break;
                    default:
                        break;
                }
                if (memindex != -1)
                {
                    xed_reg_enum_t basereg = xed_decoded_inst_get_base_reg(&xedd,
                            memindex);
                    xed_reg_enum_t indexreg = xed_decoded_inst_get_index_reg(&xedd,
                            memindex);
                    if (basereg == XED_REG_RIP || indexreg == XED_REG_RIP)
                    {

                        size_t next_rip_orig = (size_t)original + old_length;
                        size_t basevalue = (basereg == XED_REG_RIP) ? next_rip_orig : 0;
                        size_t indexvalue = (indexreg == XED_REG_RIP) ? next_rip_orig : 0;
                        size_t effective_orig = basevalue + \
                            indexvalue * xed_decoded_inst_get_scale(&xedd, memindex) + \
                            xed_decoded_inst_get_memory_displacement(&xedd, memindex);

                        int encoded = 0, argsize;
                        // See upper comment explaining similar loop for relative branches.
                        // Note that memory args could be 1-, 2-, 4- and 8-byte big.
                        for (argsize = 1; argsize <= 8; argsize *= 2)
                        {
                            xed_encoder_request_t temp_req = *rewrite_req;
                            xed_uint8_t temp_buf[XED_MAX_INSTRUCTION_BYTES];
							size_t next_rip_tram, effective_tram;
							long long new_displacement;

                            xed_encoder_request_set_memory_displacement(&temp_req, 0, argsize);
                            err = xed_encode(&temp_req, temp_buf, sizeof(temp_buf), &new_length);
                            if (err != XED_ERROR_NONE)
                            {
                                // cannot encode instruction with "argsize"-sized operand
                                continue;
                            }

                            next_rip_tram = (size_t)trampoline + tram_diff + new_length;
                            basevalue = (basereg == XED_REG_RIP) ? next_rip_tram : 0;
                            indexvalue = (indexreg == XED_REG_RIP) ? next_rip_tram : 0;
                            effective_tram = basevalue + \
                                indexvalue * xed_decoded_inst_get_scale(&xedd, memindex);
                            new_displacement = (long long)effective_orig - (long long)effective_tram;
                            if (!does_value_fit(new_displacement, argsize))
                            {
                                continue;
                            }

                            xed_encoder_request_set_memory_displacement(rewrite_req,
                                    (xed_int32_t)new_displacement, argsize);
                            encoded = 1;
                            break;
                        }

                        if (encoded != 1)
                        {
                            mark_trampoline_free((void*)trampoline);
                            PYSAMPROF_LOG(PL_WARNING, "Cannot rewrite memory accessing " \
                                    "instruction, try nearer trampoline");
                            return or_cannot_probe;
                        }
                    }
                }
            }
        }

		{
			size_t remaining = TRAMPOLINE_ENTRY_SIZE - diff - old_length;
			if ((unsigned int)remaining != remaining)
			{
				mark_trampoline_free((void*)trampoline);
				PYSAMPROF_LOG(PL_ERROR, "Cannot encode instruction for trampoline, unexpected remaining buffer size");
				return or_fail;
			}
			err = xed_encode(rewrite_req, (xed_uint8_t*)(trampoline + tram_diff),
					(unsigned int)remaining, &new_length);
		}
        if (err != XED_ERROR_NONE)
        {
            mark_trampoline_free((void*)trampoline);
            PYSAMPROF_LOG(PL_ERROR, "Cannot encode instruction for trampoline, " \
                    "xed error: %s", xed_error_enum_t2str(err));
            return or_fail;
        }
        diff += old_length;
        tram_diff += new_length;
    }

#ifdef _WIN32
	if (!FlushInstructionCache(GetCurrentProcess(), (void*)trampoline, tram_diff))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot flush instruction cache, error: %ld", GetLastError());
		return or_fail;
	}
#endif

    *result = (void*)trampoline;
    trampoline += tram_diff;

    // now insert absolute jmp
    return generate_absolute_jmp((void*)trampoline,
            (void*)((size_t)target + bytes_to_take));
}


static operation_result_t make_entry_trampoline(void* target, void* replacement,
       all_memory_regions_t regions, void** result)
{
    void* trampoline;
	operation_result_t status;

    if (target == NULL || replacement == NULL || result == NULL) return or_fail;

    status = allocate_nearest_trampoline(target,
            MAX_RELATIVE_BRANCH_BITS, regions, &trampoline);
    if (status != or_okay) return status;

    status = generate_absolute_jmp(trampoline, replacement);
    if (status != or_okay) return status;
    *result = trampoline;

    return generate_relative_jmp(target, trampoline, regions);
}

operation_result_t probe_function(void* target, void* replacement,
       all_memory_regions_t regions, void** trampoline)
{
    int jmp_size = 0, need_entry_trampoline = 0;
    int jmp_rip_safe = 0, bytes_to_take = 0;
	size_t branch_diff, length = 0, first_branch = (size_t)target;
	operation_result_t status;
    void* calling_trampoline = NULL;

	if (target == NULL || replacement == NULL || trampoline == NULL) return or_fail;

    // first check if we can use short jump
    branch_diff = GET_SIZE_DIFF(target, replacement);
    if (branch_diff <= MAX_RELATIVE_DIFF)
    {
        jmp_size = RELATIVE_BRANCH_SIZE;
    }
    else
    {
        jmp_size = ABSOLUTE_BRANCH_SIZE;
    }

    // now analyze the function
    status = get_function_region_size(target, regions, &length);
    if (status != or_okay) return status;

    status = analyze_function(target, length, jmp_size, &first_branch,
            &jmp_rip_safe, &bytes_to_take);
    if (status != or_okay) return status;

    PYSAMPROF_LOG(PL_INFO, "jmp size: %d, first branch offset: %d, bytes to take: %d, is jmp rip safe: %s",
            jmp_size, (int)(first_branch - (size_t)target), bytes_to_take,
            jmp_rip_safe ? "yes" : "no");

    /* We may need an entry trampoline [== short branch] if (any of):
       a) function is shorter than ABSOLUTE_BRANCH_SIZE bytes;
       b) instructions we want to relocate are RIP-unsafe
          (they work with RIP in unexpected way - neither branch/call/return
           nor addressing using RIP as argument);
       c) there's a branch target within the function that is
          within relocated bytes.

       Note that we always need an "exit" trampoline (the way to call the original).
    */
    if (jmp_size > RELATIVE_BRANCH_SIZE &&
            (first_branch - (size_t)target <= jmp_size ||
             !jmp_rip_safe ||
             length < jmp_size))
    {
        // check to see if relative branch helps in making function "probe safe"
        jmp_size = RELATIVE_BRANCH_SIZE;
        status = analyze_function(target, length, jmp_size,
                &first_branch, &jmp_rip_safe, &bytes_to_take);
        if (status != or_okay) return status;
        if (first_branch - (size_t)target <= jmp_size ||
             !jmp_rip_safe || length < jmp_size) return or_cannot_probe;
        need_entry_trampoline = 1;
    }

    status = make_calling_trampoline(target, regions, bytes_to_take,
            0 /* allow far-located trampoline */, &calling_trampoline);
    switch (status)
    {
        case or_okay:
            break;
        case or_cannot_probe:
            // typically this is caused by inability to relocate some stuff
            // try again with near-located trampoline
            status = make_calling_trampoline(target, regions,
                    bytes_to_take, MAX_RELATIVE_BRANCH_BITS, &calling_trampoline);
            if (status == or_okay) break;
            // fallthrough to default
        default:
            PYSAMPROF_LOG(PL_ERROR, "Cannot probe %p: %s", target,
                    get_operation_result_str(status));
            return status;
    }
    *trampoline = calling_trampoline;

    if (need_entry_trampoline != 0)
    {
        void* entry_point;
        return make_entry_trampoline(target, replacement, regions, &entry_point);
    }
    else
    {
        if (bytes_to_take >= ABSOLUTE_BRANCH_SIZE)
        {
            protection_flags_t protection_flags;
            status = unprotect_target(target, bytes_to_take,
                    regions, &protection_flags);
            if (status != or_okay) return status;
            status = generate_absolute_jmp(target, replacement);
            if (unaligned_mprotect(target, bytes_to_take,
                        protection_flags) != 0) return or_fail;
        }
        else
        {
            status = generate_relative_jmp(target, replacement, regions);
        }
        return status;
    }
}
