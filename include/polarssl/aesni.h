/**
 * \file aesni.h
 *
 * \brief Intel AES-NI for HW encryption/decryption
 *
 * Yawning Angel <yawning at schwanenlied dot me>
 *
 */
#ifndef POLARSSL_AESNI_H
#define POLARSSL_AESNI_H

#include "aes.h"

#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))

#ifndef POLARSSL_HAVE_IA
#define POLARSSL_HAVE_IA
#endif

#ifndef __GNUC__

/*
 * Strictly speaking the intrinsics I use work on other compilers, but I can't
 * be bothered to deal with the Microsoft ones. (The crypto++ code has some
 * scary comments suggesting that certain versions generate bad code for certain
 * intrinsics.)
 */

#error AES-NI support is currently only supported by clang/gcc/icc.

#endif

#define AESNI_ALIGN16(x) (uint32_t *) (16 + ((size_t) x & ~15))

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief       AES-NI detection routine
 *
 * \return      1 if CPU supports AES-NI, 0 otherwise
 */
int aesni_supported( void );

/**
 * \brief          AES-NI AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if success, 1 if operation failed
 */
int aesni_xcryptecb( aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] );

/**
 * \brief          AES-NI AES-CBC buffer en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if success, 1 if operation failed
 */
int aesni_xcryptcbc( aes_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[16],
                     const unsigned char *input,
                     unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif /* HAVE_IA */

#endif /* aesni.h */
