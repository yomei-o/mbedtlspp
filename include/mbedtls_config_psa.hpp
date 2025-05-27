/**
 * \file mbedtls/config_psa.h
 * \brief PSA crypto configuration options (set of defines)
 *
 *  This set of compile-time options takes settings defined in
 *  include/mbedtls/mbedtls_config.h and include/psa/crypto_config.h and uses
 *  those definitions to define symbols used in the library code.
 *
 *  Users and integrators should not edit this file, please edit
 *  include/mbedtls/mbedtls_config.h for MBEDTLS_XXX settings or
 *  include/psa/crypto_config.h for PSA_WANT_XXX settings.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CONFIG_PSA_H
#define MBEDTLS_CONFIG_PSA_H

#include "psa_crypto_legacy.hpp"

#include "psa_crypto_adjust_config_synonyms.hpp"

#include "psa_crypto_adjust_config_dependencies.hpp"

#include "mbedtls_config_adjust_psa_superset_legacy.hpp"

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)

/* Require built-in implementations based on PSA requirements */

/* We need this to have a complete list of requirements
 * before we deduce what built-ins are required. */
#include "psa_crypto_adjust_config_key_pair_types.hpp"

#if defined(MBEDTLS_PSA_CRYPTO_C)
/* If we are implementing PSA crypto ourselves, then we want to enable the
 * required built-ins. Otherwise, PSA features will be provided by the server. */
#include "mbedtls_config_adjust_legacy_from_psa.hpp"
#endif

#else /* MBEDTLS_PSA_CRYPTO_CONFIG */

/* Infer PSA requirements from Mbed TLS capabilities */

#include "mbedtls_config_adjust_psa_from_legacy.hpp"

/* Hopefully the file above will have enabled keypair symbols in a consistent
 * way, but including this here fixes them if that wasn't the case. */
#include "psa_crypto_adjust_config_key_pair_types.hpp"

#endif /* MBEDTLS_PSA_CRYPTO_CONFIG */

#if defined(PSA_WANT_ALG_JPAKE)
#define PSA_WANT_ALG_SOME_PAKE 1
#endif

#include "psa_crypto_adjust_auto_enabled.hpp"

#endif /* MBEDTLS_CONFIG_PSA_H */
