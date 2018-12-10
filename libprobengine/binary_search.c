#include "include/probengine/binary_search.h"

int perform_binary_search(void* array, int count,
        size_t target, size_t element_size,
        binary_search_criteria_t criteria)
{
#define GET_CRITERIA(index) \
        (criteria((void*)((char*)array + (index) * element_size)))
    int left = 0, right = count - 1;
    while (right - left > 1)
    {
        int middle = (left + right) / 2;
        size_t value = GET_CRITERIA(middle);
        if (target >= value)
        {
            left = middle;
        }
        else
        {
            right = middle;
        }
    }
    if (left != right)
    {
        size_t value = GET_CRITERIA(right);
        if (target >= value) left = right;
    }

    return left;
#undef GET_CRITERIA
}
