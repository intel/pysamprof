#ifndef __PYSAMPROF_PROTO_MESSAGE_TYPES_H__
#define __PYSAMPROF_PROTO_MESSAGE_TYPES_H__

#include "../proto/sample_t.pb-c.h"

typedef enum
{
    type_undefined = 'UNDF',
    type_sample = 'SMPL',
    type_function_info = 'FNCI',
    type_mapping = 'MAPP'
} message_type_t;

typedef Perftools__Samples__SampleT__StackTypeT stack_type_t;
#define native PERFTOOLS__SAMPLES__SAMPLE_T__STACK_TYPE_T__native
#define python PERFTOOLS__SAMPLES__SAMPLE_T__STACK_TYPE_T__python
#define mixed  PERFTOOLS__SAMPLES__SAMPLE_T__STACK_TYPE_T__mixed

#endif
