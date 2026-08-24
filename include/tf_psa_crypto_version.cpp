/*
 *  Version information
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.hpp"

#if defined(TF_PSA_CRYPTO_VERSION)
#include "tf-psa-crypto_version.hpp"

static inline unsigned int tf_psa_crypto_version_get_number(void)
{
    return TF_PSA_CRYPTO_VERSION_NUMBER;
}

static inline const char *tf_psa_crypto_version_get_string(void)
{
    return TF_PSA_CRYPTO_VERSION_STRING;
}

static inline const char *tf_psa_crypto_version_get_string_full(void)
{
    return TF_PSA_CRYPTO_VERSION_STRING_FULL;
}

#endif /* TF_PSA_CRYPTO_VERSION */
