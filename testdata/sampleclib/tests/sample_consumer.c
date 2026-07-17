#include "sample.h"

#include <stdio.h>

int main(void)
{
    sample_context *context = sample_context_create();
    char *serialized;

    if (context == NULL || !sample_context_parse(context, "1,2,3")) {
        sample_context_destroy(context);
        return 1;
    }
    if (!sample_context_parse(context, "123456789#CBF43926") ||
        sample_context_sum(context) != 123456789L) {
        sample_context_destroy(context);
        return 2;
    }
    if (sample_context_parse(context, "123456789#00000000") ||
        sample_context_sum(context) != 123456789L) {
        sample_context_destroy(context);
        return 3;
    }
    if (sample_context_parse(context, "123456789#0") ||
        sample_context_sum(context) != 123456789L) {
        sample_context_destroy(context);
        return 4;
    }
    printf("sum=%ld\n", sample_context_sum(context));
    serialized = sample_context_serialize(context);
    sample_buffer_free(serialized);
    sample_context_destroy(context);
    return 0;
}
