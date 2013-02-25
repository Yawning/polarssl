/*
 * Intel AES-NI support functions.
 *
 * Yawning Angel <yawning at schwanenlied.me>
 */
/*
 * This implementation is based on:
 *
 *  * Intel Advanced Encryption Standard (AES) New Instructions Set whitepaper:
 *
 *    http://software.intel.com/sites/default/files/article/165683/
 *    aes-wp-2012-09-22-v01.pdf
 *
 *  * Crypto++ 5.6.2:
 *
 *    http://www.cryptopp.com/
 */

#include "polarssl/config.h"


#if defined (POLARSSL_AESNI_C)

#include "polarssl/aesni.h"

#if defined(POLARSSL_HAVE_IA)

/* Note: cpuid.h is a GCC-ism, windows has __cpuid in intrin.h */
#include <cpuid.h>
#include <emmintrin.h>
#include <wmmintrin.h>

int aesni_supported( void )
{
    static uint32_t flags = 0xdeadbabe;
    uint32_t regs[4];

    if( flags == 0xdeadbabe )
    {
        __get_cpuid( 1, &regs[0], &regs[1], &regs[2], &regs[3] );
        flags = regs[2];
    }

    return( flags & 0x2000000 );
}

int aesni_xcryptecb( aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] )
{
    __m128i block;
    const __m128i *subkeys = (__m128i *) ctx->rk;
    const int rounds = ctx->nr;
    int i;

    /* This could be faster if more data was provided at once. */

    block = _mm_loadu_si128( (__m128i *) input );
    block = _mm_xor_si128( block, subkeys[0] );

    if( mode == AES_ENCRYPT ) {
        for( i = 1; i < rounds - 1; i += 2 ) {
            block = _mm_aesenc_si128( block, subkeys[i] );
            block = _mm_aesenc_si128( block, subkeys[i + 1] );
        }

        block = _mm_aesenc_si128( block, subkeys[rounds - 1] );
        block = _mm_aesenclast_si128( block, subkeys[rounds] );
    } else {
        for( i = 1; i < rounds - 1; i += 2 ) {
            block = _mm_aesdec_si128( block, subkeys[i] );
            block = _mm_aesdec_si128( block, subkeys[i + 1] );
        }

        block = _mm_aesdec_si128( block, subkeys[rounds - 1] );
        block = _mm_aesdeclast_si128( block, subkeys[rounds] );
    }

    _mm_storeu_si128( (__m128i *) output, block );

    return( 0 );
}

int aesni_xcryptcbc( aes_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[16],
                     const unsigned char *input,
                     unsigned char *output )
{
    const __m128i *subkeys = (__m128i *) ctx->rk;
    const int rounds = ctx->nr;
    const size_t blocks = length / 16;
    __m128i block0, block1, block2, block3;
    __m128i fb0, fb1, fb2, fb3;
    __m128i rk;
    __m128i last;
    size_t i;
    int j;

    fb0 = _mm_loadu_si128( (__m128i *) iv );

    if (mode == AES_ENCRYPT ) {
        for( i = 0 ; i < blocks; i++ ) {
            block0 = _mm_loadu_si128( &((__m128i *) input)[i] );

            fb0 = _mm_xor_si128( block0, fb0 );
            fb0 = _mm_xor_si128( fb0, subkeys[0] );

            for( j = 1; j < rounds - 1; j += 2 ) {
                fb0 = _mm_aesenc_si128( fb0, subkeys[j] );
                fb0 = _mm_aesenc_si128( fb0, subkeys[j + 1] );
            }

            fb0 = _mm_aesenc_si128( fb0, subkeys[rounds - 1] );
            fb0 = _mm_aesenclast_si128( fb0, subkeys[rounds] );

            _mm_storeu_si128( &((__m128i*) output)[i], fb0 );
        }
    } else {
        /* Take advantage of pipelining by decrypting 4 blocks at once. */

        for( i = 0; i < blocks / 4; i++ ) {
            block0 = _mm_loadu_si128( (__m128i *) input + i * 4 );
            block1 = _mm_loadu_si128( (__m128i *) input + i * 4 + 1 );
            block2 = _mm_loadu_si128( (__m128i *) input + i * 4 + 2 );
            block3 = _mm_loadu_si128( (__m128i *) input + i * 4 + 3 );

            fb1 = block0;
            fb2 = block1;
            fb3 = block2;
            last = block3;

            rk = subkeys[0];
            block0 = _mm_xor_si128( block0, rk );
            block1 = _mm_xor_si128( block1, rk );
            block2 = _mm_xor_si128( block2, rk );
            block3 = _mm_xor_si128( block3, rk );

            for( j = 1; j < rounds; j++ ) {
                rk = subkeys[j];
                block0 = _mm_aesdec_si128( block0, rk );
                block1 = _mm_aesdec_si128( block1, rk );
                block2 = _mm_aesdec_si128( block2, rk );
                block3 = _mm_aesdec_si128( block3, rk );
            }

            rk = subkeys[rounds];
            block0 = _mm_aesdeclast_si128( block0, rk );
            block1 = _mm_aesdeclast_si128( block1, rk );
            block2 = _mm_aesdeclast_si128( block2, rk );
            block3 = _mm_aesdeclast_si128( block3, rk );

            block0 = _mm_xor_si128( block0, fb0 );
            block1 = _mm_xor_si128( block1, fb1 );
            block2 = _mm_xor_si128( block2, fb2 );
            block3 = _mm_xor_si128( block3, fb3 );

            _mm_storeu_si128( ((__m128i *) output) + i * 4, block0 );
            _mm_storeu_si128( ((__m128i *) output) + i * 4 + 1, block1 );
            _mm_storeu_si128( ((__m128i *) output) + i * 4 + 2, block2 );
            _mm_storeu_si128( ((__m128i *) output) + i * 4 + 3, block3 );

            fb0 = last;
        }

        for( i *= 4; i < blocks; i++ ) {
            block0 = _mm_loadu_si128( (__m128i *) input + i );

            last = block0;

            block0 = _mm_xor_si128 (last, subkeys[0] );

            for( j = 1; j < rounds - 1; j += 2 ) {
                block0 = _mm_aesdec_si128( block0, subkeys[j] );
                block0 = _mm_aesdec_si128( block0, subkeys[j + 1] );
            }

            block0 = _mm_aesdec_si128( block0, subkeys[rounds - 1] );
            block0 = _mm_aesdeclast_si128( block0, subkeys[rounds] );

            block0 = _mm_xor_si128( block0, fb0 );

            _mm_storeu_si128( ((__m128i *) output) + i, block0 );

            fb0 = last;
        }
    }

    _mm_storeu_si128( (__m128i *) iv, fb0 );

    return( 0 );
}

#endif /* POLARSSL_HAVE_IA */

#endif /* POLARSSL_AESNI_C */
