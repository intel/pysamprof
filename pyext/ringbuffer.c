#include "ringbuffer.h"

int ring_buffer_is_empty(ring_buffer_t *buffer)
{
	return (buffer->head_index == buffer->tail_index);
}

int ring_buffer_is_full(ring_buffer_t *buffer)
{
	return ((buffer->head_index - buffer->tail_index) & RING_BUFFER_MASK) == RING_BUFFER_MASK;
}

void ring_buffer_init(ring_buffer_t *buffer)
{
	buffer->tail_index = 0;
	buffer->head_index = 0;
}

operation_result_t ring_buffer_push(ring_buffer_t *buffer, ring_buffer_element_t data)
{
	if (ring_buffer_is_full(buffer)) return or_ring_buffer_full;

	buffer->buffer[buffer->head_index] = data;
	buffer->head_index = ((buffer->head_index + 1) & RING_BUFFER_MASK);

	return or_okay;
}

operation_result_t ring_buffer_pop(ring_buffer_t *buffer, ring_buffer_element_t *data)
{
    if (ring_buffer_is_empty(buffer)) return or_ring_buffer_empty;

    *data = buffer->buffer[buffer->tail_index];
    buffer->tail_index = ((buffer->tail_index + 1) & RING_BUFFER_MASK);
    return or_okay;
}
