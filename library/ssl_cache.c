/*
 *  SSL session cache implementation
 *
 *  Copyright (C) 2006-2012, Brainspark B.V.
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
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */

#include "polarssl/config.h"

#if defined(POLARSSL_SSL_CACHE_C)

#include "polarssl/ssl_cache.h"

#include <stdlib.h>

void ssl_cache_init( ssl_cache_context *cache )
{
    memset( cache, 0, sizeof( ssl_cache_context ) );

    cache->timeout = SSL_CACHE_DEFAULT_TIMEOUT;
    cache->max_entries = SSL_CACHE_DEFAULT_MAX_ENTRIES;
}

int ssl_cache_get( void *data, ssl_session *session )
{
    time_t t = time( NULL );
    ssl_cache_context *cache = (ssl_cache_context *) data;
    ssl_cache_entry *entry;

    HASH_FIND( hh, cache->sessions, session->id, session->length, entry );

    /* Cache miss */

    if( entry == NULL )
        return( 1 );

    /* Entry expired */

    if( cache->timeout != 0 &&
            (int) ( t - entry->timestamp ) > cache->timeout )
        return( 1 );

    /* Ciphersuite/Compression changed, or hash collision */

    if( session->ciphersuite != entry->session.ciphersuite ||
        session->compression != entry->session.compression ||
        session->length != entry->session.length )
        return( 1 );

    /* Check for a hash collision */

    if( memcmp( session->id, entry->session.id,
                    entry->session.length ) != 0 )
        return( 1 );

    memcpy( session->master, entry->session.master, 48 );

    return( 0 );
}

int ssl_cache_set( void *data, const ssl_session *session )
{
    time_t t = time( NULL );
    ssl_cache_context *cache = (ssl_cache_context *) data;
    ssl_cache_entry *entry;

    HASH_FIND( hh, cache->sessions, session->id, session->length, entry );

    if( entry == NULL )
    {
        /* Add a fresh entry to the cache */

        if ( cache->max_entries > 0 && 
             HASH_COUNT( cache->sessions ) >= (size_t) cache->max_entries )
        {
            /* Reuse the oldest entry if max_entries reached */

            entry = cache->sessions;    /* uthash hash tables also are lists */

            HASH_DEL( cache->sessions, entry );

            memset( &entry->session, 0, sizeof( ssl_session ) );
        }
        else
        {
            entry = (ssl_cache_entry *) malloc( sizeof( ssl_cache_entry ) );

            if( entry == NULL )
                return( 1 );

            memset( entry, 0, sizeof( ssl_cache_entry ) );
        }

        entry->timestamp = t;
    }
    else
    {
        /* There is an existing entry for this already, re-use it. */

        if( cache->timeout == 0 || 
            (int) ( t - entry->timestamp ) <= cache->timeout )
        {
            /*
             * Update it and just return without removing/re-adding the entry
             * from/to the hash to ensure that the hash's internal list is
             * both in inertion order and in timestamp order.
             */

            memcpy( &entry->session, session, sizeof( ssl_session ) );

            // Do not include peer_cert in cache entry
            //
            entry->session.peer_cert = NULL;

            return( 0 );
        }

        /* expired, update timestamp */

        entry->timestamp = t;

        HASH_DEL( cache->sessions, entry );
    }

    memcpy( &entry->session, session, sizeof( ssl_session ) );

    // Do not include peer_cert in cache entry
    //
    entry->session.peer_cert = NULL;

    HASH_ADD( hh, cache->sessions, session.id, entry->session.length, entry );

    return( 0 );
}

void ssl_cache_set_timeout( ssl_cache_context *cache, int timeout )
{
    if( timeout < 0 ) timeout = 0;

    cache->timeout = timeout;
}

void ssl_cache_set_max_entries( ssl_cache_context *cache, int max )
{
    if( max < 0 ) max = 0;

    cache->max_entries = max;
}

void ssl_cache_free( ssl_cache_context *cache )
{
    ssl_cache_entry *entry, *tmp;

    HASH_ITER( hh, cache->sessions, entry, tmp )
    {
        HASH_DEL( cache->sessions, entry );
        ssl_session_free( &entry->session );
        free( entry );
    }
}

#endif /* POLARSSL_SSL_CACHE_C */
