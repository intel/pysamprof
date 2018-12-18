#include "include/probengine/function_methods.h"

#include <logging/logging.h>
#include <xed/xed-interface.h>

operation_result_t get_real_function_start(void* addr, size_t* result)
{
	xed_state_t xed_state;
	xed_chip_enum_t xed_chip = XED_CHIP_INVALID;
	xed_error_enum_t err;
    xed_decoded_inst_t xedd;

	if (addr == (void*)0 || result == (size_t*)0) return or_fail;

	xed_state_zero(&xed_state);
#if defined(_WIN64) || defined(__amd64__)
    xed_state.mmode = XED_MACHINE_MODE_LONG_64;
    xed_state.stack_addr_width = XED_ADDRESS_WIDTH_64b;
#else
    xed_state.mmode = XED_MACHINE_MODE_LEGACY_32;
    xed_state.stack_addr_width = XED_ADDRESS_WIDTH_32b;
#endif

    xed_decoded_inst_zero_set_mode(&xedd, &xed_state);
    xed_decoded_inst_set_input_chip(&xedd, xed_chip);
	err = xed_decode(&xedd, addr, XED_MAX_INSTRUCTION_BYTES);

	if (err != XED_ERROR_NONE)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot decode instruction at %p: %s", addr, xed_error_enum_t2str(err));
		return or_xed_error;
	}

	if (xed_decoded_inst_get_category(&xedd) != XED_CATEGORY_UNCOND_BR)
	{
		// this is not a "jmp-to" instruction
		*result = (size_t)addr;
		return or_okay;
	}

	*result =  (size_t)addr + xed_decoded_inst_get_length(&xedd) + \
		xed_decoded_inst_get_branch_displacement(&xedd);
	return or_okay;
}
