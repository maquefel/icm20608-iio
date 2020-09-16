#ifndef __IIO_GRAB_H__
#define __IIO_GRAB_H__

#include <stdint.h>
#include <inttypes.h>

#include "c_bitops.h"

#define IIO_BYTE_TO_FLOAT(value, input, is_be, is_signed, shift, bits) \
    input = is_be ? betoh(input) : letoh(input); \
    input >>= shift; \
    input &= BIT_MASK(bits); \
    value = is_signed ? (float)sext(input, bits) : (float)input;

static inline float b8tof(uint8_t input, bool is_be, bool is_signed, unsigned shift, unsigned bits)
{
    float value = 0.0;

    IIO_BYTE_TO_FLOAT(value, input, is_be, is_signed, shift, bits);

    return value;
}

static inline float b16tof(uint16_t input, bool is_be, bool is_signed, unsigned shift, unsigned bits)
{
    float value = 0.0;

    // IIO_BYTE_TO_FLOAT(value, input, is_be, is_signed, shift, bits);
    input = is_be ? betoh(input) : letoh(input);
    input >>= shift;
    input &= BIT_MASK(bits);
    value = is_signed ? (float)sext(input, bits) : (float)input;

    return value;
}

static inline float b32tof(uint32_t input, bool is_be, bool is_signed, unsigned shift, unsigned bits)
{
    float value = 0.0;

    IIO_BYTE_TO_FLOAT(value, input, is_be, is_signed, shift, bits);

    return value;
}

static inline float b64tof(uint64_t input, bool is_be, bool is_signed, unsigned shift, unsigned bits)
{
    float value = 0.0;

    IIO_BYTE_TO_FLOAT(value, input, is_be, is_signed, shift, bits);

    return value;
}

static inline int64_t get_timestamp(uint64_t input, bool is_be, unsigned shift, unsigned bits)
{
    /* First swap if incorrect endian */
    if (is_be)
        input = betoh(input);
    else
        input = letoh(input);

    input >>= shift;
    input &= BIT_MASK(bits);

    int64_t value = (int64_t)input;

    return value;
}

#endif
