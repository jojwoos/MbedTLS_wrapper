/*****************************************************************************
 *  Title:      Optimized swap and endianness macros for Mbed-TLS 2.28.x -   *
 *****************************************************************************
 * @file        mbedtls_swaper.h                                             *
 * @author      jojwoos                                                      *
 * @company     Open Source                                                  *
 * @date        22.12.2023                                                   *
 * @arch        generic                                                      *
 *****************************************************************************
 * @copyright (c) 2024 jojwoos                                               *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later					 *
 ****************************************************************************/

#ifndef MBEDTLS_SWAPER_H
#define MBEDTLS_SWAPER_H

#include <stdint.h>

// architecture independent macros --------------------------
#define MBEDTLS_PVAL_UINT16(data, offset)     *((uint16_t*)(&data[offset]))
#define MBEDTLS_PUT_UINT16(n, data, offset)   MBEDTLS_PVAL_UINT16(data, offset) = n

#define MBEDTLS_PVAL_UINT32(data, offset)     *((uint32_t*)(&data[offset]))
#define MBEDTLS_PUT_UINT32(n, data, offset)   MBEDTLS_PVAL_UINT32(data, offset) = n

#define MBEDTLS_PVAL_UINT64(data, offset)     *((uint64_t*)(&data[offset]))
#define MBEDTLS_PUT_UINT64(n, data, offset)   MBEDTLS_PVAL_UINT64(data, offset) = n


// system specific optimized swap macros --------------------
// MBEDTLS_BSWAP16
// MBEDTLS_BSWAP32
// MBEDTLS_BSWAP64
#ifdef __arm__
// Cortex-M CPU instructions (CMSIS)
#define MBEDTLS_BSWAP16   __REVSH
#define MBEDTLS_BSWAP32   __REV
// no direct CPU swap functions for 64bit values
// use general 64 bit optimization below

// GCC detection from alignment.h (Mbed TLS3.5.1)
// there are also some other detection routines for Clang, MSVC...
#elif defined(__GNUC__) && defined(__GNUC_PREREQ)
#if __GNUC_PREREQ(4, 8)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif /* __GNUC_PREREQ(4,8) */
#if __GNUC_PREREQ(4, 3)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#define MBEDTLS_BSWAP64 __builtin_bswap64

#endif /* __GNUC_PREREQ(4,3) */
// add optimizations for other systems here
//#elif
#endif

// macros to identify endianness------------------------------
#if !defined(MBEDTLS_IS_BIG_ENDIAN)

// GNU
#if defined(__BYTE_ORDER__)

  #define MBEDTLS_IS_BIG_ENDIAN ((__BYTE_ORDER__) == (__ORDER_BIG_ENDIAN__))

// ARM
#elif defined(__arm__) && (defined(__ARMEB__) || defined(__ARMEL__))

#if   defined(__ARMEB__)

#define MBEDTLS_IS_BIG_ENDIAN true

#elif defined(__ARMEL__)

#define MBEDTLS_IS_BIG_ENDIAN false

#endif

// add detection for other systems here
//#elif

#else // local identification needed

#error *** MBedTLS endianness detection failed ***
// manually check endianness on target system, e.g. with:
// static const uint16_t mbedtls_byte_order_detector = { 0x0100 };
// set MBEDTLS_IS_BIG_ENDIAN true if - (*((unsigned char *) (&mbedtls_byte_order_detector)) == 0x01)
// else false
// define MBEDTLS_IS_BIG_ENDIAN in the Mbed TLS config file before including this file
#endif
#endif  // end manually defined

#if defined(MBEDTLS_IS_BIG_ENDIAN)
#define MBEDTLS_IS_LITTLE_ENDIAN !MBEDTLS_IS_BIG_ENDIAN
#endif

// wrap optimizations for mbedTLS intern macros ----------------
#ifdef MBEDTLS_BSWAP16
#define MBEDTLS_GET_UINT16_SWAP(data, offset)     MBEDTLS_BSWAP16(MBEDTLS_PVAL_UINT16(data, offset))
#define MBEDTLS_PUT_UINT16_SWAP(n, data, offset)  MBEDTLS_PVAL_UINT16(data, offset) = MBEDTLS_BSWAP16(n)
#endif

#ifdef MBEDTLS_BSWAP32
#define MBEDTLS_GET_UINT32_SWAP(data, offset)     MBEDTLS_BSWAP32(MBEDTLS_PVAL_UINT32(data, offset))
#define MBEDTLS_PUT_UINT32_SWAP(n, data, offset)  MBEDTLS_PVAL_UINT32(data, offset) = MBEDTLS_BSWAP32(n)
#endif

#ifdef MBEDTLS_BSWAP64
#define MBEDTLS_GET_UINT64_SWAP(data, offset)     MBEDTLS_BSWAP64(MBEDTLS_PVAL_UINT64(data, offset))
#define MBEDTLS_PUT_UINT64_SWAP(n, data, offset)  MBEDTLS_PVAL_UINT64(data, offset) = MBEDTLS_BSWAP64(n)
#else
// general 64 bit optimization if only 32 bit optimization is available
#if defined(MBEDTLS_IS_BIG_ENDIAN) && !defined(MBEDTLS_GET_UINT64_SWAP) && defined(MBEDTLS_BSWAP32)
#if MBEDTLS_IS_BIG_ENDIAN
#define MBEDTLS_GET_UINT64_SWAP(data, offset)     ((uint64_t)(MBEDTLS_BSWAP32(MBEDTLS_PVAL_UINT32(data, offset)))) | ((uint64_t)(MBEDTLS_BSWAP32(MBEDTLS_PVAL_UINT32(data, (offset + 4)))) << 32)
#else
#define MBEDTLS_GET_UINT64_SWAP(data, offset)     ((uint64_t)(MBEDTLS_BSWAP32(MBEDTLS_PVAL_UINT32(data, offset))) << 32) | ((uint64_t)(MBEDTLS_BSWAP32(MBEDTLS_PVAL_UINT32(data, (offset + 4)))))
#endif
#endif
#if defined(MBEDTLS_IS_BIG_ENDIAN) && !defined(MBEDTLS_PUT_UINT64_SWAP) && defined(MBEDTLS_BSWAP32)
#if MBEDTLS_IS_BIG_ENDIAN
#define MBEDTLS_PUT_UINT64_SWAP(n, data, offset)  MBEDTLS_PVAL_UINT64(data, offset) = ((uint64_t)MBEDTLS_BSWAP32((uint32_t)(n >> 32))) | ((uint64_t)MBEDTLS_BSWAP32(*(uint32_t*)((uint8_t*)&n + 4)) << 32)
#else
#define MBEDTLS_PUT_UINT64_SWAP(n, data, offset)  MBEDTLS_PVAL_UINT64(data, offset) = ((uint64_t)MBEDTLS_BSWAP32((uint32_t)n) << 32) | (uint64_t)MBEDTLS_BSWAP32(*(uint32_t*)((uint8_t*)&n + 4))
#endif
#endif
#endif

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * bigMBEDTLS_IS_BIG_ENDIAN-endian order (MSB first).
 *
 * mbedTLS intern macro
 * MBEDTLS_GET_UINT32_BE(data, offset)
 *        ((uint32_t) (data)[(offset)] << 24)
 *        | ((uint32_t) (data)[(offset) + 1] << 16)
 *        | ((uint32_t) (data)[(offset) + 2] <<  8)
 *        | ((uint32_t) (data)[(offset) + 3])
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p base of the first and most significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PVAL_UINT32)

#define MBEDTLS_GET_UINT32_BE(data, offset)   MBEDTLS_PVAL_UINT32(data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_GET_UINT32_SWAP)

#define MBEDTLS_GET_UINT32_BE(data, offset)   MBEDTLS_GET_UINT32_SWAP(data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Put in memory a 32 bits unsigned integer in big-endian order.
 *
 * mbedTLS intern macro
 * MBEDTLS_PUT_UINT32_BE(n, data, offset)
 *        (data)[(offset)] = MBEDTLS_BYTE_3(n);
 *        (data)[(offset) + 1] = MBEDTLS_BYTE_2(n);
 *        (data)[(offset) + 2] = MBEDTLS_BYTE_1(n);
 *        (data)[(offset) + 3] = MBEDTLS_BYTE_0(n);
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the most significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PUT_UINT32)

#define MBEDTLS_PUT_UINT32_BE(n, data, offset)   MBEDTLS_PUT_UINT32(n, data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PUT_UINT32_SWAP)

#define MBEDTLS_PUT_UINT32_BE(n, data, offset)   MBEDTLS_PUT_UINT32_SWAP(n, data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * little-endian order (LSB first).
 *
 * mbedTLS intern macro
 * MBEDTLS_GET_UINT32_LE(data, offset)
 *        ((uint32_t) (data)[(offset)])
 *        | ((uint32_t) (data)[(offset) + 1] <<  8)
 *        | ((uint32_t) (data)[(offset) + 2] << 16)
 *        | ((uint32_t) (data)[(offset) + 3] << 24)
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_GET_UINT32_SWAP)

#define MBEDTLS_GET_UINT32_LE(data, offset)   MBEDTLS_GET_UINT32_SWAP(data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PVAL_UINT32)

#define MBEDTLS_GET_UINT32_LE(data, offset)   MBEDTLS_PVAL_UINT32(data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Put in memory a 32 bits unsigned integer in little-endian order.
 *
 * mbedTLS intern macro
 * MBEDTLS_PUT_UINT32_LE(n, data, offset)
 *        (data)[(offset)] = MBEDTLS_BYTE_0(n);
 *        (data)[(offset) + 1] = MBEDTLS_BYTE_1(n);
 *        (data)[(offset) + 2] = MBEDTLS_BYTE_2(n);
 *        (data)[(offset) + 3] = MBEDTLS_BYTE_3(n);
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PUT_UINT32_SWAP)

#define MBEDTLS_PUT_UINT32_LE(n, data, offset)   MBEDTLS_PUT_UINT32_SWAP(n, data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PUT_UINT32)

#define MBEDTLS_PUT_UINT32_LE(n, data, offset)   MBEDTLS_PUT_UINT32(n, data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Get the unsigned 16 bits integer corresponding to two bytes in
 * little-endian order (LSB first).
 *
 * mbedTLS intern macro
 * MBEDTLS_GET_UINT16_LE(data, offset)
 *        ((uint16_t) (data)[(offset)])
 *        | ((uint16_t) (data)[(offset) + 1] <<  8)
 *
 * \param   data    Base address of the memory to get the two bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the two bytes to build the 16 bits unsigned
 *                  integer from.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_GET_UINT16_SWAP)

#define MBEDTLS_GET_UINT16_LE(data, offset)   MBEDTLS_GET_UINT16_SWAP(data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PVAL_UINT16)

#define MBEDTLS_GET_UINT16_LE(data, offset)   MBEDTLS_PVAL_UINT16(data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Put in memory a 16 bits unsigned integer in little-endian order.
 *
 * mbedTLS intern macro
 * MBEDTLS_PUT_UINT16_LE(n, data, offset)
 *        (data)[(offset)] = MBEDTLS_BYTE_0(n);
 *        (data)[(offset) + 1] = MBEDTLS_BYTE_1(n);
 *
 * \param   n       16 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 16
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 16 bits unsigned integer \p n.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PUT_UINT16_SWAP)

#define MBEDTLS_PUT_UINT16_LE(n, data, offset)   MBEDTLS_PUT_UINT16_SWAP(n, data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PUT_UINT16)

#define MBEDTLS_PUT_UINT16_LE(n, data, offset)   MBEDTLS_PUT_UINT16(n, data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Get the unsigned 16 bits integer corresponding to two bytes in
 * big-endian order (MSB first).
 *
 * mbedTLS intern macro
 * MBEDTLS_GET_UINT16_BE(data, offset)
 *        ((uint16_t) (data)[(offset)] << 8)
 *        | ((uint16_t) (data)[(offset) + 1])
 *
 * \param   data    Base address of the memory to get the two bytes from.
 * \param   offset  Offset from \p base of the first and most significant
 *                  byte of the two bytes to build the 16 bits unsigned
 *                  integer from.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PVAL_UINT16)

#define MBEDTLS_GET_UINT16_BE(data, offset)   MBEDTLS_PVAL_UINT16(data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_GET_UINT16_SWAP)

#define MBEDTLS_GET_UINT16_BE(data, offset)   MBEDTLS_GET_UINT16_SWAP(data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Put in memory a 16 bits unsigned integer in big-endian order.
 *
 * mbedTLS intern macro
 * MBEDTLS_PUT_UINT16_BE(n, data, offset)
 *        (data)[(offset)] = MBEDTLS_BYTE_1(n);
 *        (data)[(offset) + 1] = MBEDTLS_BYTE_0(n);
 *
 * \param   n       16 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 16
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the most significant
 *                  byte of the 16 bits unsigned integer \p n.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PUT_UINT16)

#define MBEDTLS_PUT_UINT16_BE(n, data, offset)   MBEDTLS_PUT_UINT16(n, data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PUT_UINT16_SWAP)

#define MBEDTLS_PUT_UINT16_BE(n, data, offset)   MBEDTLS_PUT_UINT16_SWAP(n, data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Get the unsigned 64 bits integer corresponding to eight bytes in
 * big-endian order (MSB first).
 *
 * mbedTLS intern macro
 * MBEDTLS_GET_UINT64_BE(data, offset)
 *        ((uint64_t) (data)[(offset)] << 56)
 *        | ((uint64_t) (data)[(offset) + 1] << 48)
 *        | ((uint64_t) (data)[(offset) + 2] << 40)
 *        | ((uint64_t) (data)[(offset) + 3] << 32)
 *        | ((uint64_t) (data)[(offset) + 4] << 24)
 *        | ((uint64_t) (data)[(offset) + 5] << 16)
 *        | ((uint64_t) (data)[(offset) + 6] <<  8)
 *        | ((uint64_t) (data)[(offset) + 7])
 *
 * \param   data    Base address of the memory to get the eight bytes from.
 * \param   offset  Offset from \p base of the first and most significant
 *                  byte of the eight bytes to build the 64 bits unsigned
 *                  integer from.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PVAL_UINT64)

#define MBEDTLS_GET_UINT64_BE(data, offset)   MBEDTLS_PVAL_UINT64(data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_GET_UINT64_SWAP)

#define MBEDTLS_GET_UINT64_BE(data, offset)   MBEDTLS_GET_UINT64_SWAP(data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Put in memory a 64 bits unsigned integer in big-endian order.
 *
 * mbedTLS intern macro
 * MBEDTLS_PUT_UINT64_BE(n, data, offset)
 *        (data)[(offset)] = MBEDTLS_BYTE_7(n);
 *        (data)[(offset) + 1] = MBEDTLS_BYTE_6(n);
 *        (data)[(offset) + 2] = MBEDTLS_BYTE_5(n);
 *        (data)[(offset) + 3] = MBEDTLS_BYTE_4(n);
 *        (data)[(offset) + 4] = MBEDTLS_BYTE_3(n);
 *        (data)[(offset) + 5] = MBEDTLS_BYTE_2(n);
 *        (data)[(offset) + 6] = MBEDTLS_BYTE_1(n);
 *        (data)[(offset) + 7] = MBEDTLS_BYTE_0(n);
 *
 * \param   n       64 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 64
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the most significant
 *                  byte of the 64 bits unsigned integer \p n.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PUT_UINT64)

#define MBEDTLS_PUT_UINT64_BE(n, data, offset)   MBEDTLS_PUT_UINT64(n, data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PUT_UINT64_SWAP)

#define MBEDTLS_PUT_UINT64_BE(n, data, offset)   MBEDTLS_PUT_UINT64_SWAP(n, data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Get the unsigned 64 bits integer corresponding to eight bytes in
 * little-endian order (LSB first).
 *
 * mbedTLS intern macro
 * MBEDTLS_GET_UINT64_LE(data, offset)
 *        ((uint64_t) (data)[(offset) + 7] << 56)
 *        | ((uint64_t) (data)[(offset) + 6] << 48)
 *        | ((uint64_t) (data)[(offset) + 5] << 40)
 *        | ((uint64_t) (data)[(offset) + 4] << 32)
 *        | ((uint64_t) (data)[(offset) + 3] << 24)
 *        | ((uint64_t) (data)[(offset) + 2] << 16)
 *        | ((uint64_t) (data)[(offset) + 1] <<  8)
 *        | ((uint64_t) (data)[(offset)])
 *
 * \param   data    Base address of the memory to get the eight bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the eight bytes to build the 64 bits unsigned
 *                  integer from.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_GET_UINT64_SWAP)

#define MBEDTLS_GET_UINT64_LE(data, offset)   MBEDTLS_GET_UINT64_SWAP(data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PVAL_UINT64)

#define MBEDTLS_GET_UINT64_LE(data, offset)   MBEDTLS_PVAL_UINT64(data, offset)

#endif
// else mbedTLS intern macro is used

/**
 * Put in memory a 64 bits unsigned integer in little-endian order.
 *
 * mbedTLS intern macro
 * MBEDTLS_PUT_UINT64_LE(n, data, offset)
 *        (data)[(offset)] = MBEDTLS_BYTE_0(n);
 *        (data)[(offset) + 1] = MBEDTLS_BYTE_1(n);
 *        (data)[(offset) + 2] = MBEDTLS_BYTE_2(n);
 *        (data)[(offset) + 3] = MBEDTLS_BYTE_3(n);
 *        (data)[(offset) + 4] = MBEDTLS_BYTE_4(n);
 *        (data)[(offset) + 5] = MBEDTLS_BYTE_5(n);
 *        (data)[(offset) + 6] = MBEDTLS_BYTE_6(n);
 *        (data)[(offset) + 7] = MBEDTLS_BYTE_7(n);
 *
 * \param   n       64 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 64
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 64 bits unsigned integer \p n.
 */
#if MBEDTLS_IS_BIG_ENDIAN && defined(MBEDTLS_PUT_UINT64_SWAP)

#define MBEDTLS_PUT_UINT64_LE(n, data, offset)   MBEDTLS_PUT_UINT64_SWAP(n, data, offset)

#elif MBEDTLS_IS_LITTLE_ENDIAN && defined(MBEDTLS_PUT_UINT64)

#define MBEDTLS_PUT_UINT64_LE(n, data, offset)   MBEDTLS_PUT_UINT64(n, data, offset)

#endif
// else mbedTLS intern macro is used

#endif // MBEDTLS_SWAPER_H
