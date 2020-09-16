#ifndef __C_BITOPTS_H__
#define __C_BITOPTS_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <strings.h> // for ffs
#include <string.h>  // for ffsl and ffsll

#define _ffs(x) _Generic((x), \
                char: ffs, \
                int: ffs, \
                long int: ffsl, \
                long long int: ffsll, \
                default: ffsll)(x)

#define __ffs(x, size) (_ffs(x) == 0 ? size : _ffs(x) - 1)

#define __popcount(x) _Generic((x), \
                  char: __builtin_popcount, \
                  int: __builtin_popcount, \
                  unsigned int: __builtin_popcount, \
                  unsigned long: __builtin_popcountl, \
                  default: __builtin_popcountl)(x)

#define BITS_PER_BYTE 8
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_TO_BYTES(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE)

#define BIT_MASK(nr)    (nr == BITS_PER_TYPE(1ULL) ? ~0ULL : ((1ULL << nr) - 1))

#define first_set_bit_from(addr, bit, size) __ffs((addr) & BIT_MASK(bit), size)

#define for_each_set_bit(bit, addr, size)                       \
  for ((bit) = __ffs((addr), (size));                           \
       (bit) < (size);                                          \
       (bit) = first_set_bit_from((addr), (bit + 1), (size)))

#define for_each_set_bit_from(bit, addr, size)                  \
  for ((bit) = first_set_bit_from((addr), (bit), (size));       \
       (bit) < (size);                                          \
       (bit) = first_set_bit_from((addr), (bit), (size)))

#define popcount(x) __popcount(x)

#include <endian.h>

static inline uint8_t htobe8_(uint8_t val) { return val;}
static inline uint16_t htobe16_(uint16_t val) { return htobe16(val);}
static inline uint32_t htobe32_(uint32_t val) { return htobe32(val);}
static inline uint64_t htobe64_(uint64_t val) { return htobe64(val);}

static inline float fhtobe(float value) {
    union v {float d; uint64_t i;};
    ((union v*)&value)->i = htobe32((uint32_t)value);
    return ((union v*)&value)->d;
};

static inline double dhtobe(double value) {
    union v {double d; uint64_t i;};
    ((union v*)&value)->i = htobe64((uint64_t)value);
    return ((union v*)&value)->d;
};

static inline uint8_t htole8_(uint8_t val) { return val;}
static inline uint16_t htole16_(uint16_t val) { return htole16(val);}
static inline uint32_t htole32_(uint32_t val) { return htole32(val);}
static inline uint64_t htole64_(uint64_t val) { return htole64(val);}

static inline float fhtole(float value) {
    union v {float d; uint64_t i;};
    ((union v*)&value)->i = htole32((uint32_t)value);
    return ((union v*)&value)->d;
};

static inline double dhtole(double value) {
    union v {double d; uint64_t i;};
    ((union v*)&value)->i = htole64((uint64_t)value);
    return ((union v*)&value)->d;
};

static inline uint8_t be8toh_(uint8_t val) { return val;}
static inline uint16_t be16toh_(uint16_t val) { return be16toh(val);}
static inline uint32_t be32toh_(uint32_t val) { return be32toh(val);}
static inline uint64_t be64toh_(uint64_t val) { return be64toh(val);}

static inline float fbetoh(float value) {
    union v {float d; uint64_t i;};
    ((union v*)&value)->i = be32toh((uint32_t)value);
    return ((union v*)&value)->d;
};

static inline double dbetoh(double value) {
    union v {double d; uint64_t i;};
    ((union v*)&value)->i = be64toh((uint64_t)value);
    return ((union v*)&value)->d;
};

static inline uint8_t le8toh_(uint8_t val) { return val;}
static inline uint16_t le16toh_(uint16_t val) { return le16toh(val);}
static inline uint32_t le32toh_(uint32_t val) { return le32toh(val);}
static inline uint64_t le64toh_(uint64_t val) { return le64toh(val);}

static inline float fletoh(float value) {
    union v {float d; uint64_t i;};
    ((union v*)&value)->i = le32toh((uint32_t)value);
    return ((union v*)&value)->d;
};

static inline double dletoh(double value) {
    union v {double d; uint64_t i;};
    ((union v*)&value)->i = le64toh((uint64_t)value);
    return ((union v*)&value)->d;
};

#define htobe(x) _Generic((x), \
        uint8_t: htobe8_, \
        uint16_t: htobe16_, \
        uint32_t: htobe32_, \
        uint64_t: htobe64_, \
        float: fhtobe, \
        double: dhtobe)(x)

#define htole(x) _Generic((x), \
        uint8_t: htole8_, \
        uint16_t: htole16_, \
        uint32_t: htole32_, \
        uint64_t: htole64_, \
        float: fhtole, \
        double: dhtole)(x)

#define betoh(x) _Generic( (x), \
        uint8_t: be8toh_, \
        uint16_t: be16toh_, \
        uint32_t: be32toh_, \
        uint64_t: be64toh_, \
        float: fbetoh, \
        double: dbetoh)(x)

#define letoh(x) _Generic( (x), \
        uint8_t: le8toh_, \
        uint16_t: le16toh_, \
        uint32_t: le32toh_, \
        uint64_t: le64toh_, \
        float: fletoh, \
        double: dletoh)(x)

static inline int8_t sext8(uint8_t x, unsigned b)
{
    return (int8_t)(x << (8 - b)) >> (8 - b);
}

static inline int16_t sext16(uint16_t x, unsigned b)
{
    return (int16_t)(x << (16 - b)) >> (16 - b);
}

static inline int32_t sext32(uint32_t x, unsigned b)
{
    return (int32_t)(x << (32 - b)) >> (32 - b);
}

static inline int64_t sext64(uint64_t x, unsigned b)
{
    return (int64_t)(x << (64 - b)) >> (64 - b);
}

#define sext(x, b) _Generic((x), \
        uint8_t: sext8, \
        uint16_t: sext16, \
        uint32_t: sext32, \
        uint64_t: sext64)(x,b)

#endif // __C_BITOPTS_H__
