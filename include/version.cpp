/*
 *  Version information
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.hpp"

#if defined(MBEDTLS_VERSION_C)

#include "mbedtls_version.hpp"
#include <string.h>

static inline unsigned int mbedtls_version_get_number(void)
{
    return MBEDTLS_VERSION_NUMBER;
}

static inline void mbedtls_version_get_string(char *string)
{
    memcpy(string, MBEDTLS_VERSION_STRING,
           sizeof(MBEDTLS_VERSION_STRING));
}

static inline void mbedtls_version_get_string_full(char *string)
{
    memcpy(string, MBEDTLS_VERSION_STRING_FULL,
           sizeof(MBEDTLS_VERSION_STRING_FULL));
}

#endif /* MBEDTLS_VERSION_C */
