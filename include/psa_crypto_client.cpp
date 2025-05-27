/*
 *  PSA crypto client code
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.hpp"
#include "psa_crypto.hpp"

#if defined(MBEDTLS_PSA_CRYPTO_CLIENT)

#include <string.h>
#include "mbedtls_platform.hpp"

static inline void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
    memset(attributes, 0, sizeof(*attributes));
}

#endif /* MBEDTLS_PSA_CRYPTO_CLIENT */
