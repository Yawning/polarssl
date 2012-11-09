/*
 *  Elliptic curves over GF(p)
 *
 *  Copyright (C) 2012, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 * FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECP_C)

#include "polarssl/ecp.h"

/*
 * Initialize (the components of) a point
 */
void ecp_point_init( ecp_point *pt )
{
    if( pt == NULL )
        return;

    pt->is_zero = 1;
    mpi_init( &pt->X );
    mpi_init( &pt->Y );
}

/*
 * Initialize (the components of) a group
 */
void ecp_group_init( ecp_group *grp )
{
    if( grp == NULL )
        return;

    mpi_init( &grp->P );
    mpi_init( &grp->B );
    ecp_point_init( &grp->G );
    mpi_init( &grp->N );

    grp->modp = NULL;
    grp->pbits = 0;
}

/*
 * Unallocate (the components of) a point
 */
void ecp_point_free( ecp_point *pt )
{
    if( pt == NULL )
        return;

    pt->is_zero = 1;
    mpi_free( &( pt->X ) );
    mpi_free( &( pt->Y ) );
}

/*
 * Unallocate (the components of) a group
 */
void ecp_group_free( ecp_group *grp )
{
    if( grp == NULL )
        return;

    mpi_free( &grp->P );
    mpi_free( &grp->B );
    ecp_point_free( &grp->G );
    mpi_free( &grp->N );
}

/*
 * Set point to zero
 */
void ecp_set_zero( ecp_point *pt )
{
    pt->is_zero = 1;
    mpi_free( &pt->X );
    mpi_free( &pt->Y );
}

/*
 * Copy the contents of Q into P
 */
int ecp_copy( ecp_point *P, const ecp_point *Q )
{
    int ret = 0;

    if( Q->is_zero ) {
        ecp_set_zero( P );
        return( ret );
    }

    P->is_zero = Q->is_zero;
    MPI_CHK( mpi_copy( &P->X, &Q->X ) );
    MPI_CHK( mpi_copy( &P->Y, &Q->Y ) );

cleanup:
    return( ret );
}

/*
 * Import a non-zero point from ASCII strings
 */
int ecp_point_read_string( ecp_point *P, int radix,
                           const char *x, const char *y )
{
    int ret = 0;

    P->is_zero = 0;
    MPI_CHK( mpi_read_string( &P->X, radix, x ) );
    MPI_CHK( mpi_read_string( &P->Y, radix, y ) );

cleanup:
    return( ret );
}

/*
 * Import an ECP group from ASCII strings
 */
int ecp_group_read_string( ecp_group *grp, int radix,
                           const char *p, const char *b,
                           const char *gx, const char *gy, const char *n)
{
    int ret = 0;

    MPI_CHK( mpi_read_string( &grp->P, radix, p ) );
    MPI_CHK( mpi_read_string( &grp->B, radix, b ) );
    MPI_CHK( ecp_point_read_string( &grp->G, radix, gx, gy ) );
    MPI_CHK( mpi_read_string( &grp->N, radix, n ) );

cleanup:
    return( ret );
}

/*
 * Wrapper around fast quasi-modp functions, with fallback to mpi_mod_mpi
 *
 * The quasi-modp functions expect an mpi N such that 0 <= N < 2^(2*pbits)
 * and change it in-place so that it can easily be brought in the 0..P-1
 * range by a few additions or substractions.
 */
static int ecp_modp( mpi *N, const ecp_group *grp )
{
    int ret = 0;

    if( grp->modp == NULL )
        return( mpi_mod_mpi( N, N, &grp->P ) );

    if( mpi_cmp_int( N, 0 ) < 0 || mpi_msb( N ) > 2 * grp->pbits )
        return( POLARSSL_ERR_ECP_GENERIC );

    MPI_CHK( grp->modp( N ) );

    while( mpi_cmp_int( N, 0 ) < 0 )
        MPI_CHK( mpi_add_mpi( N, N, &grp->P ) );

    while( mpi_cmp_mpi( N, &grp->P ) >= 0 )
        MPI_CHK( mpi_sub_mpi( N, N, &grp->P ) );

cleanup:
    return( ret );
}

/*
 * Size of p521 in terms of t_uint
 */
#define P521_SIZE_INT   ( 521 / (sizeof( t_uint ) << 3) + 1 )

/*
 * Bits to keep in the most significant t_uint
 */
#if defined(POLARSS_HAVE_INT8)
#define P521_MASK       0x01
#else
#define P521_MASK       0x01FF
#endif

/*
 * Fast quasi-reduction modulo p521 (FIPS 186-3 D.2.5)
 *
 * It is required that 0 <= N < 2^(2*521) on entry.
 * On exit, it is only guaranteed that 0 <= N < 2^(521+1).
 */
static int ecp_mod_p521( mpi *N )
{
    int ret = 0;
    t_uint Mp[P521_SIZE_INT];
    mpi M;

    if( N->n < P521_SIZE_INT )
        return( 0 );

    memset( Mp, 0, P521_SIZE_INT * sizeof( t_uint ) );
    memcpy( Mp, N->p, P521_SIZE_INT * sizeof( t_uint ) );
    Mp[P521_SIZE_INT - 1] &= P521_MASK;

    M.s = 1;
    M.n = P521_SIZE_INT;
    M.p = Mp;

    MPI_CHK( mpi_shift_r( N, 521 ) );

    MPI_CHK( mpi_add_abs( N, N, &M ) );

cleanup:
    return( ret );
}

/*
 * Set a group using well-known domain parameters
 */
int ecp_use_known_dp( ecp_group *grp, size_t index )
{
    switch( index )
    {
        case POLARSSL_ECP_DP_SECP192R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP192R1_P,
                        POLARSSL_ECP_SECP192R1_B,
                        POLARSSL_ECP_SECP192R1_GX,
                        POLARSSL_ECP_SECP192R1_GY,
                        POLARSSL_ECP_SECP192R1_N )
                    );
        case POLARSSL_ECP_DP_SECP224R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP224R1_P,
                        POLARSSL_ECP_SECP224R1_B,
                        POLARSSL_ECP_SECP224R1_GX,
                        POLARSSL_ECP_SECP224R1_GY,
                        POLARSSL_ECP_SECP224R1_N )
                    );
        case POLARSSL_ECP_DP_SECP256R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP256R1_P,
                        POLARSSL_ECP_SECP256R1_B,
                        POLARSSL_ECP_SECP256R1_GX,
                        POLARSSL_ECP_SECP256R1_GY,
                        POLARSSL_ECP_SECP256R1_N )
                    );
        case POLARSSL_ECP_DP_SECP384R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP384R1_P,
                        POLARSSL_ECP_SECP384R1_B,
                        POLARSSL_ECP_SECP384R1_GX,
                        POLARSSL_ECP_SECP384R1_GY,
                        POLARSSL_ECP_SECP384R1_N )
                    );
        case POLARSSL_ECP_DP_SECP521R1:
            grp->modp = ecp_mod_p521;
            grp->pbits = 521;
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP521R1_P,
                        POLARSSL_ECP_SECP521R1_B,
                        POLARSSL_ECP_SECP521R1_GX,
                        POLARSSL_ECP_SECP521R1_GY,
                        POLARSSL_ECP_SECP521R1_N )
                    );
    }

    return( POLARSSL_ERR_ECP_GENERIC );
}

/*
 * Reduce a mpi mod p in-place, general case, to use after mpi_mul_mpi
 */
#define MOD_MUL( N )    MPI_CHK( ecp_modp( &N, grp ) )

/*
 * Reduce a mpi mod p in-place, to use after mpi_sub_mpi
 */
#define MOD_SUB( N )                                \
    while( mpi_cmp_int( &N, 0 ) < 0 )               \
        MPI_CHK( mpi_add_mpi( &N, &N, &grp->P ) )

/*
 * Reduce a mpi mod p in-place, to use after mpi_add_mpi and mpi_mul_int
 */
#define MOD_ADD( N )                                \
    while( mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
        MPI_CHK( mpi_sub_mpi( &N, &N, &grp->P ) )

/*
 * Internal point format used for fast addition/doubling/multiplication:
 * Jacobian coordinates (GECC example 3.20)
 */
typedef struct
{
    mpi X, Y, Z;
}
ecp_ptjac;

/*
 * Initialize a point in Jacobian coordinates
 */
static void ecp_ptjac_init( ecp_ptjac *P )
{
    mpi_init( &P->X ); mpi_init( &P->Y ); mpi_init( &P->Z );
}

/*
 * Free a point in Jacobian coordinates
 */
static void ecp_ptjac_free( ecp_ptjac *P )
{
    mpi_free( &P->X ); mpi_free( &P->Y ); mpi_free( &P->Z );
}

/*
 * Copy P to R in Jacobian coordinates
 */
static int ecp_ptjac_copy( ecp_ptjac *R, const ecp_ptjac *P )
{
    int ret = 0;

    MPI_CHK( mpi_copy( &R->X, &P->X ) );
    MPI_CHK( mpi_copy( &R->Y, &P->Y ) );
    MPI_CHK( mpi_copy( &R->Z, &P->Z ) );

cleanup:
    return( ret );
}

/*
 * Set P to zero in Jacobian coordinates
 */
static int ecp_ptjac_set_zero( ecp_ptjac *P )
{
    int ret = 0;

    MPI_CHK( mpi_lset( &P->X, 1 ) );
    MPI_CHK( mpi_lset( &P->Y, 1 ) );
    MPI_CHK( mpi_lset( &P->Z, 0 ) );

cleanup:
    return( ret );
}

/*
 * Convert from affine to Jacobian coordinates
 */
static int ecp_aff_to_jac( ecp_ptjac *jac, const ecp_point *aff )
{
    int ret = 0;

    if( aff->is_zero )
        return( ecp_ptjac_set_zero( jac ) );

    MPI_CHK( mpi_copy( &jac->X, &aff->X ) );
    MPI_CHK( mpi_copy( &jac->Y, &aff->Y ) );
    MPI_CHK( mpi_lset( &jac->Z, 1       ) );

cleanup:
    return( ret );
}

/*
 * Convert from Jacobian to affine coordinates
 */
static int ecp_jac_to_aff( const ecp_group *grp,
                           ecp_point *aff, const ecp_ptjac *jac )
{
    int ret = 0;
    mpi Zi, ZZi, T;

    if( mpi_cmp_int( &jac->Z, 0 ) == 0 ) {
        ecp_set_zero( aff );
        return( 0 );
    }

    mpi_init( &Zi ); mpi_init( &ZZi ); mpi_init( &T );

    aff->is_zero = 0;

    /*
     * aff.X = jac.X / (jac.Z)^2  mod p
     */
    MPI_CHK( mpi_inv_mod( &Zi,      &jac->Z,  &grp->P ) );
    MPI_CHK( mpi_mul_mpi( &ZZi,     &Zi,      &Zi     ) ); MOD_MUL( ZZi );
    MPI_CHK( mpi_mul_mpi( &aff->X,  &jac->X,  &ZZi    ) ); MOD_MUL( aff->X );

    /*
     * aff.Y = jac.Y / (jac.Z)^3  mod p
     */
    MPI_CHK( mpi_mul_mpi( &aff->Y,  &jac->Y,  &ZZi    ) ); MOD_MUL( aff->Y );
    MPI_CHK( mpi_mul_mpi( &aff->Y,  &aff->Y,  &Zi     ) ); MOD_MUL( aff->Y );

cleanup:

    mpi_free( &Zi ); mpi_free( &ZZi ); mpi_free( &T );

    return( ret );
}

/*
 * Point doubling R = 2 P, Jacobian coordinates (GECC 3.21)
 */
static int ecp_double_jac( const ecp_group *grp, ecp_ptjac *R,
                           const ecp_ptjac *P )
{
    int ret = 0;
    mpi T1, T2, T3, X, Y, Z;

    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( ecp_ptjac_set_zero( R ) );

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    MPI_CHK( mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_sub_mpi( &T2,  &P->X,  &T1   ) ); MOD_SUB( T2 );
    MPI_CHK( mpi_add_mpi( &T1,  &P->X,  &T1   ) ); MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T2,    &T1   ) ); MOD_MUL( T2 );
    MPI_CHK( mpi_mul_int( &T2,  &T2,    3     ) ); MOD_ADD( T2 );
    MPI_CHK( mpi_copy   ( &Y,   &P->Y         ) );
    MPI_CHK( mpi_shift_l( &Y,   1             ) ); MOD_ADD( Y  );
    MPI_CHK( mpi_mul_mpi( &Z,   &Y,     &P->Z ) ); MOD_MUL( Z  );
    MPI_CHK( mpi_mul_mpi( &Y,   &Y,     &Y    ) ); MOD_MUL( Y  );
    MPI_CHK( mpi_mul_mpi( &T3,  &Y,     &P->X ) ); MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &Y,   &Y,     &Y    ) ); MOD_MUL( Y  );

    /*
     * For Y = Y / 2 mod p, we must make sure that Y is even before
     * using right-shift. No need to reduce mod p afterwards.
     */
    if( mpi_get_bit( &Y, 0 ) == 1 )
        MPI_CHK( mpi_add_mpi( &Y, &Y, &grp->P ) );
    MPI_CHK( mpi_shift_r( &Y,   1             ) );

    MPI_CHK( mpi_mul_mpi( &X,   &T2,    &T2   ) ); MOD_MUL( X  );
    MPI_CHK( mpi_copy   ( &T1,  &T3           ) );
    MPI_CHK( mpi_shift_l( &T1,  1             ) ); MOD_ADD( T1 );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T1   ) ); MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &T1,  &T3,    &X    ) ); MOD_SUB( T1 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &T2   ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_sub_mpi( &Y,   &T1,    &Y    ) ); MOD_SUB( Y  );

    MPI_CHK( mpi_copy( &R->X, &X ) );
    MPI_CHK( mpi_copy( &R->Y, &Y ) );
    MPI_CHK( mpi_copy( &R->Z, &Z ) );

cleanup:

    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );

    return( ret );
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 */
static int ecp_add_mixed( const ecp_group *grp, ecp_ptjac *R,
                          const ecp_ptjac *P, const ecp_point *Q )
{
    int ret = 0;
    mpi T1, T2, T3, T4, X, Y, Z;

    /*
     * Trivial cases: P == 0 or Q == 0
     */
    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( ecp_aff_to_jac( R, Q ) );

    if( Q->is_zero )
        return( ecp_ptjac_copy( R, P ) );

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 ); mpi_init( &T4 );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    MPI_CHK( mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T1,    &P->Z ) ); MOD_MUL( T2 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &Q->X ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T2,    &Q->Y ) ); MOD_MUL( T2 );
    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &P->X ) ); MOD_SUB( T1 );
    MPI_CHK( mpi_sub_mpi( &T2,  &T2,    &P->Y ) ); MOD_SUB( T2 );

    if( mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = ecp_ptjac_set_zero( R );
            goto cleanup;
        }
    }

    MPI_CHK( mpi_mul_mpi( &Z,   &P->Z,  &T1   ) ); MOD_MUL( Z  );
    MPI_CHK( mpi_mul_mpi( &T3,  &T1,    &T1   ) ); MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T4,  &T3,    &T1   ) ); MOD_MUL( T4 );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &P->X ) ); MOD_MUL( T3 );
    MPI_CHK( mpi_mul_int( &T1,  &T3,    2     ) ); MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &X,   &T2,    &T2   ) ); MOD_MUL( X  );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T1   ) ); MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T4   ) ); MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &T3,  &T3,    &X    ) ); MOD_SUB( T3 );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &T2   ) ); MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T4,  &T4,    &P->Y ) ); MOD_MUL( T4 );
    MPI_CHK( mpi_sub_mpi( &Y,   &T3,    &T4   ) ); MOD_SUB( Y  );

    MPI_CHK( mpi_copy( &R->X, &X ) );
    MPI_CHK( mpi_copy( &R->Y, &Y ) );
    MPI_CHK( mpi_copy( &R->Z, &Z ) );

cleanup:

    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 ); mpi_free( &T4 );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );

    return( ret );
}

/*
 * Addition: R = P + Q, affine wrapper
 */
int ecp_add( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q )
{
    int ret = 0;
    ecp_ptjac J;

    ecp_ptjac_init( &J );

    MPI_CHK( ecp_aff_to_jac( &J, P ) );
    MPI_CHK( ecp_add_mixed( grp, &J, &J, Q ) );
    MPI_CHK( ecp_jac_to_aff( grp, R, &J ) );

cleanup:

    ecp_ptjac_free( &J );

    return( ret );
}

/*
 * Integer multiplication: R = m * P (GECC 5.7, SPA-resistant variant)
 */
int ecp_mul( const ecp_group *grp, ecp_point *R,
             const mpi *m, const ecp_point *P )
{
    int ret = 0;
    size_t pos;
    ecp_ptjac Q[2];

    ecp_ptjac_init( &Q[0] ); ecp_ptjac_init( &Q[1] );

    /*
     * The general method works only for m >= 1
     */
    if( mpi_cmp_int( m, 0 ) == 0 ) {
        ecp_set_zero( R );
        goto cleanup;
    }

    ecp_ptjac_set_zero( &Q[0] );

    for( pos = mpi_msb( m ) - 1 ; ; pos-- )
    {
        MPI_CHK( ecp_double_jac( grp, &Q[0], &Q[0] ) );
        MPI_CHK( ecp_add_mixed( grp, &Q[1], &Q[0], P ) );
        MPI_CHK( ecp_ptjac_copy( &Q[0], &Q[ mpi_get_bit( m, pos ) ] ) );

        if( pos == 0 )
            break;
    }

    MPI_CHK( ecp_jac_to_aff( grp, R, &Q[0] ) );

cleanup:

    ecp_ptjac_free( &Q[0] ); ecp_ptjac_free( &Q[1] );

    return( ret );
}


#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecp_self_test( int verbose )
{
    return( verbose++ );
}

#endif

#endif