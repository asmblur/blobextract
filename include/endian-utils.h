#ifndef ENDIAN_UTILS_H
#define ENDIAN_UTILS_H

#include <stdint.h>

#if defined(_WIN32)
#warning "WIN32 has no headers or built-in macros for detecting architecture byte-order at compile-time!"
#elif defined( __FreeBSD__)
#include <sys/endian.h>
#elif defined(__GNUG__)
#include <endian.h>
#include <byteswap.h>
#else
#include <endian.h>
//#include <sys/param.h>
#endif

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
    defined(__BIG_ENDIAN__) || \
    defined(__ARMEB__) || \
    defined(__THUMBEB__) || \
    defined(__AARCH64EB__) || \
    defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__)

#if !defined(__LITTLE_ENDIAN)
#define __LITTLE_ENDIAN 1234
#endif

#if !defined(__BIG_ENDIAN)
#define __BIG_ENDIAN    4321
#endif

#if !defined(__BYTE_ORDER)
#define __BYTE_ORDER __BIG_ENDIAN
#endif

#if !defined(__BIG_ENDIAN__)
#define __BIG_ENDIAN__
#endif

// It's a big-endian target architecture
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
    defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || \
    defined(__THUMBEL__) || \
    defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)

#if !defined(__LITTLE_ENDIAN)
#define __LITTLE_ENDIAN 1234
#endif

#if !defined(__BIG_ENDIAN)
#define __BIG_ENDIAN    4321
#endif

#if !defined(__BYTE_ORDER)
#define __BYTE_ORDER  __LITTLE_ENDIAN
#endif

#if !defined(__LITTLE_ENDIAN__)
#define __LITTLE_ENDIAN__
#endif

#else
#error "Could not determine architecture byte-order at compile-time!"
#endif

#ifdef __LITTLE_ENDIAN__
#define IS_BIG_ENDIAN 0
#else
#define IS_BIG_ENDIAN 1
#endif

#ifdef __LITTLE_ENDIAN__
#define U16FROMLE(__v) ((uint16_t) (__v))
#define U32FROMLE(__v) ((uint32_t) (__v))
#define U64FROMLE(__v) ((uint64_t) (__v))
#define U16FROMBE(__v) (__builtin_bswap16((uint16_t) (__v)))
#define U32FROMBE(__v) (__builtin_bswap32((uint32_t) (__v)))
#define U64FROMBE(__v) (__builtin_bswap64((uint64_t) (__v)))
#else
#define U16FROMLE(__v) (__builtin_bswap16((uint16_t) (__v)))
#define U32FROMLE(__v) (__builtin_bswap32((uint32_t) (__v)))
#define U64FROMLE(__v) (__builtin_bswap64((uint64_t) (__v)))
#define U16FROMBE(__v) ((uint16_t) (__v))
#define U32FROMBE(__v) ((uint32_t) (__v))
#define U64FROMBE(__v) ((uint64_t) (__v))
#endif

#ifdef __LITTLE_ENDIAN__
#define U16TOLE(__v) ((uint16_t) (__v))
#define U32TOLE(__v) ((uint32_t) (__v))
#define U64TOLE(__v) ((uint64_t) (__v))
#define U16TOBE(__v) (__builtin_bswap16((uint16_t) (__v)))
#define U32TOBE(__v) (__builtin_bswap32((uint32_t) (__v)))
#define U64TOBE(__v) (__builtin_bswap64((uint64_t) (__v)))
#else
#define U16TOLE(__v) (__builtin_bswap16((uint16_t) (__v)))
#define U32TOLE(__v) (__builtin_bswap32((uint32_t) (__v)))
#define U64TOLE(__v) (__builtin_bswap64((uint64_t) (__v)))
#define U16TOBE(__v) ((uint16_t) (__v))
#define U32TOBE(__v) ((uint32_t) (__v))
#define U64TOBE(__v) ((uint64_t) (__v))
#endif

#endif /* ENDIAN_UTILS_H */

