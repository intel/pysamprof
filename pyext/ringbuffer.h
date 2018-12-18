#ifndef __PYSAMPROF_RINGBUFFER_H__
#define __PYSAMPROF_RINGBUFFER_H__

// Inspired by https://github.com/AndersKaloer/Ring-Buffer
// original is MIT-licensed.

#include <utilities/inttype_helper.h>
#include <status/status.h>

/* The size of a ring buffer. Only RING_BUFFER_SIZE-1 items
   can be contained in the buffer. Must be a power of two.
*/
#define RING_BUFFER_SIZE 512

#if (RING_BUFFER_SIZE & (RING_BUFFER_SIZE - 1)) != 0
#error "RING_BUFFER_SIZE must be a power of two"
#endif

typedef uint16_t ring_buffer_index_t;
typedef struct
{
	void* data;
	int64_t timestamp;
} ring_buffer_element_t;

/* Modulo operator:
   a % b = (a & (b − 1)),
   where a is a positive index and b is the size of the buffer.
 */
#define RING_BUFFER_MASK (RING_BUFFER_SIZE-1)

typedef struct {
  ring_buffer_element_t buffer[RING_BUFFER_SIZE];
  ring_buffer_index_t tail_index;
  ring_buffer_index_t head_index;
} ring_buffer_t ;


void ring_buffer_init(ring_buffer_t *buffer);
operation_result_t ring_buffer_push(ring_buffer_t *buffer, ring_buffer_element_t data);
operation_result_t ring_buffer_pop(ring_buffer_t *buffer, ring_buffer_element_t *data);
int ring_buffer_is_empty(ring_buffer_t *buffer);
int ring_buffer_is_full(ring_buffer_t *buffer);

#endif /* __PYSAMPROF_RINGBUFFER_H__ */
