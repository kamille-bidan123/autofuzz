#ifndef SAMPLECLIB_SAMPLE_H
#define SAMPLECLIB_SAMPLE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sample_context sample_context;

sample_context *sample_context_create(void);
int sample_context_set(sample_context *context, const int *values, size_t count);
size_t sample_context_get(const sample_context *context, int *output, size_t capacity);
int sample_context_parse(sample_context *context, const char *text);
long sample_context_sum(const sample_context *context);
char *sample_context_serialize(const sample_context *context);
void sample_buffer_free(void *buffer);
void sample_context_destroy(sample_context *context);

#ifdef __cplusplus
}
#endif

#endif
