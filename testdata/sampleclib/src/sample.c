#include "sample.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SAMPLE_CAPACITY 16

struct sample_context {
    int values[SAMPLE_CAPACITY];
    size_t count;
};

static uint32_t sample_crc32(const unsigned char *data, size_t size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t index;

    for (index = 0; index < size; index++) {
        unsigned int bit;

        crc ^= data[index];
        for (bit = 0; bit < 8; bit++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & UINT32_C(1));
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return ~crc;
}

static int sample_parse_crc32(const char *text, uint32_t *result)
{
    uint32_t value = 0;
    size_t index;

    if (strlen(text) != 8) {
        return 0;
    }
    for (index = 0; index < 8; index++) {
        unsigned char character = (unsigned char)text[index];
        uint32_t digit;

        if (character >= '0' && character <= '9') {
            digit = (uint32_t)(character - '0');
        } else if (character >= 'a' && character <= 'f') {
            digit = (uint32_t)(character - 'a' + 10);
        } else if (character >= 'A' && character <= 'F') {
            digit = (uint32_t)(character - 'A' + 10);
        } else {
            return 0;
        }
        value = (value << 4) | digit;
    }
    *result = value;
    return 1;
}

sample_context *sample_context_create(void)
{
    return calloc(1, sizeof(sample_context));
}

int sample_context_set(sample_context *context, const int *values, size_t count)
{
    if (context == NULL || (values == NULL && count != 0) || count > SAMPLE_CAPACITY) {
        return 0;
    }
    if (count != 0) {
        memcpy(context->values, values, count * sizeof(*values));
    }
    context->count = count;
    return 1;
}

size_t sample_context_get(const sample_context *context, int *output, size_t capacity)
{
    size_t copied;
    if (context == NULL || (output == NULL && capacity != 0)) {
        return 0;
    }
    copied = context->count < capacity ? context->count : capacity;
    if (copied != 0) {
        memcpy(output, context->values, copied * sizeof(*output));
    }
    return copied;
}

int sample_context_parse(sample_context *context, const char *text)
{
    int values[SAMPLE_CAPACITY];
    size_t count = 0;
    const char *cursor = text;
    const char *payload_end;
    const char *crc_separator;

    if (context == NULL || text == NULL) {
        return 0;
    }

    payload_end = text + strlen(text);
    crc_separator = strchr(text, '#');
    if (crc_separator != NULL) {
        uint32_t expected_crc;
        uint32_t actual_crc;

        if (!sample_parse_crc32(crc_separator + 1, &expected_crc)) {
            return 0;
        }
        actual_crc = sample_crc32((const unsigned char *)text,
                                  (size_t)(crc_separator - text));
        if (actual_crc != expected_crc) {
            return 0;
        }
        payload_end = crc_separator;
    }

    while (cursor < payload_end && count <= SAMPLE_CAPACITY) {
        char *end = NULL;
        long value;

        errno = 0;
        value = strtol(cursor, &end, 10);
        if (end == cursor || end > payload_end || errno == ERANGE ||
            value < INT_MIN || value > INT_MAX) {
            return 0;
        }
        values[count++] = (int)value;
        cursor = end;
        while (cursor < payload_end && (*cursor == ' ' || *cursor == ',')) {
            cursor++;
        }
    }
    if (cursor != payload_end) {
        return 0;
    }
    return sample_context_set(context, values, count);
}

long sample_context_sum(const sample_context *context)
{
    long result = 0;
    size_t index;
    if (context == NULL) {
        return 0;
    }
    for (index = 0; index < context->count; index++) {
        result += context->values[index];
    }
    return result;
}

char *sample_context_serialize(const sample_context *context)
{
    size_t capacity;
    size_t offset = 0;
    size_t index;
    char *result;
    if (context == NULL) {
        return NULL;
    }
    capacity = context->count * 16 + 1;
    result = malloc(capacity);
    if (result == NULL) {
        return NULL;
    }
    result[0] = '\0';
    for (index = 0; index < context->count; index++) {
        int written = snprintf(result + offset, capacity - offset, "%s%d",
                               index == 0 ? "" : ",", context->values[index]);
        if (written < 0 || (size_t)written >= capacity - offset) {
            free(result);
            return NULL;
        }
        offset += (size_t)written;
    }
    return result;
}

void sample_buffer_free(void *buffer)
{
    free(buffer);
}

void sample_context_destroy(sample_context *context)
{
    free(context);
}
