/**
 * \file mbedtls/config_adjust_psa_from_legacy.h
 * \brief Adjust PSA configuration: construct PSA configuration from legacy
 *
 * This is an internal header. Do not include it directly.
 *
 * When MBEDTLS_PSA_CRYPTO_CONFIG is disabled, we automatically enable
 * cryptographic mechanisms through the PSA interface when the corresponding
 * legacy mechanism is enabled. In many cases, this just enables the PSA
 * wrapper code around the legacy implementation, but we also do this for
 * some mechanisms where PSA has its own independent implementation so
 * that high-level modules that can use either cryptographic API have the
 * same feature set in both cases.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CONFIG_ADJUST_PSA_FROM_LEGACY_H
#define MBEDTLS_CONFIG_ADJUST_PSA_FROM_LEGACY_H

#if !defined(MBEDTLS_CONFIG_FILES_READ)
#error "Do not include mbedtls_config_adjust_*.hpp manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

/*
 * Ensure PSA_WANT_* defines are setup properly if MBEDTLS_PSA_CRYPTO_CONFIG
 * is not defined
 */

#if defined(MBEDTLS_CCM_C)
#define MBEDTLS_PSA_BUILTIN_ALG_CCM 1
#define PSA_WANT_ALG_CCM 1
#if defined(MBEDTLS_CIPHER_C)
#define MBEDTLS_PSA_BUILTIN_ALG_CCM_STAR_NO_TAG 1
#define PSA_WANT_ALG_CCM_STAR_NO_TAG 1
#endif /* MBEDTLS_CIPHER_C */
#endif /* MBEDTLS_CCM_C */

#if defined(MBEDTLS_CMAC_C)
#define MBEDTLS_PSA_BUILTIN_ALG_CMAC 1
#define PSA_WANT_ALG_CMAC 1
#endif /* MBEDTLS_CMAC_C */

#if defined(MBEDTLS_ECDH_C)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDH 1
#define PSA_WANT_ALG_ECDH 1
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_ECDSA_C)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDSA 1
#define PSA_WANT_ALG_ECDSA 1
#define PSA_WANT_ALG_ECDSA_ANY 1

// Only add in DETERMINISTIC support if ECDSA is also enabled
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#define MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA 1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA 1
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_ECP_C)
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
/* Normally we wouldn't enable this because it's not implemented in ecp.c,
 * but since it used to be available any time ECP_C was enabled, let's enable
 * it anyway for the sake of backwards compatibility */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_BASIC 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
/* See comment for PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE above. */
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY 1
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_DHM_C)
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC 1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT 1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY 1
#define PSA_WANT_ALG_FFDH 1
#define PSA_WANT_DH_RFC7919_2048 1
#define PSA_WANT_DH_RFC7919_3072 1
#define PSA_WANT_DH_RFC7919_4096 1
#define PSA_WANT_DH_RFC7919_6144 1
#define PSA_WANT_DH_RFC7919_8192 1
#define MBEDTLS_PSA_BUILTIN_ALG_FFDH 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_BASIC 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY 1
#define MBEDTLS_PSA_BUILTIN_DH_RFC7919_2048 1
#define MBEDTLS_PSA_BUILTIN_DH_RFC7919_3072 1
#define MBEDTLS_PSA_BUILTIN_DH_RFC7919_4096 1
#define MBEDTLS_PSA_BUILTIN_DH_RFC7919_6144 1
#define MBEDTLS_PSA_BUILTIN_DH_RFC7919_8192 1
#endif /* MBEDTLS_DHM_C */

#if defined(MBEDTLS_GCM_C)
#define MBEDTLS_PSA_BUILTIN_ALG_GCM 1
#define PSA_WANT_ALG_GCM 1
#endif /* MBEDTLS_GCM_C */

/* Enable PSA HKDF algorithm if mbedtls HKDF is supported.
 * PSA HKDF EXTRACT and PSA HKDF EXPAND have minimal cost when
 * PSA HKDF is enabled, so enable both algorithms together
 * with PSA HKDF. */
#if defined(MBEDTLS_HKDF_C)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC 1
#define PSA_WANT_ALG_HMAC 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF 1
#define PSA_WANT_ALG_HKDF 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT 1
#define PSA_WANT_ALG_HKDF_EXTRACT 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND 1
#define PSA_WANT_ALG_HKDF_EXPAND 1
#endif /* MBEDTLS_HKDF_C */

#define MBEDTLS_PSA_BUILTIN_ALG_HMAC 1
#define PSA_WANT_ALG_HMAC 1
#define PSA_WANT_KEY_TYPE_HMAC 1

#if defined(MBEDTLS_MD_C)
#define MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF 1
#define PSA_WANT_ALG_TLS12_PRF 1
#define MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS 1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS 1
#endif /* MBEDTLS_MD_C */

#if defined(MBEDTLS_MD5_C)
#define MBEDTLS_PSA_BUILTIN_ALG_MD5 1
#define PSA_WANT_ALG_MD5 1
#endif

#if defined(MBEDTLS_ECJPAKE_C)
#define MBEDTLS_PSA_BUILTIN_PAKE 1
#define MBEDTLS_PSA_BUILTIN_ALG_JPAKE 1
#define PSA_WANT_ALG_JPAKE 1
#endif

#if defined(MBEDTLS_RIPEMD160_C)
#define MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160 1
#define PSA_WANT_ALG_RIPEMD160 1
#endif

#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_PKCS1_V15)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT 1
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT 1
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN 1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN 1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW 1
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP 1
#define PSA_WANT_ALG_RSA_OAEP 1
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS 1
#define PSA_WANT_ALG_RSA_PSS 1
#endif /* MBEDTLS_PKCS1_V21 */
#if defined(MBEDTLS_GENPRIME)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
#endif /* MBEDTLS_GENPRIME */
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_BASIC 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY 1
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY 1
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_SHA1_C)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_1 1
#define PSA_WANT_ALG_SHA_1 1
#endif

#if defined(MBEDTLS_SHA224_C)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_224 1
#define PSA_WANT_ALG_SHA_224 1
#endif

#if defined(MBEDTLS_SHA256_C)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_256 1
#define PSA_WANT_ALG_SHA_256 1
#endif

#if defined(MBEDTLS_SHA384_C)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_384 1
#define PSA_WANT_ALG_SHA_384 1
#endif

#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_512 1
#define PSA_WANT_ALG_SHA_512 1
#endif

#if defined(MBEDTLS_SHA3_C)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA3_224 1
#define MBEDTLS_PSA_BUILTIN_ALG_SHA3_256 1
#define MBEDTLS_PSA_BUILTIN_ALG_SHA3_384 1
#define MBEDTLS_PSA_BUILTIN_ALG_SHA3_512 1
#define PSA_WANT_ALG_SHA3_224 1
#define PSA_WANT_ALG_SHA3_256 1
#define PSA_WANT_ALG_SHA3_384 1
#define PSA_WANT_ALG_SHA3_512 1
#endif

#if defined(MBEDTLS_AES_C)
#define PSA_WANT_KEY_TYPE_AES 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_AES 1
#endif

#if defined(MBEDTLS_ARIA_C)
#define PSA_WANT_KEY_TYPE_ARIA 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ARIA 1
#endif

#if defined(MBEDTLS_CAMELLIA_C)
#define PSA_WANT_KEY_TYPE_CAMELLIA 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_CAMELLIA 1
#endif

#if defined(MBEDTLS_DES_C)
#define PSA_WANT_KEY_TYPE_DES 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES 1
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_256)
#define MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS 1
#define PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS 1
#endif

#if defined(MBEDTLS_CHACHA20_C)
#define PSA_WANT_KEY_TYPE_CHACHA20 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_CHACHA20 1
/* ALG_STREAM_CIPHER requires CIPHER_C in order to be supported in PSA */
#if defined(MBEDTLS_CIPHER_C)
#define PSA_WANT_ALG_STREAM_CIPHER 1
#define MBEDTLS_PSA_BUILTIN_ALG_STREAM_CIPHER 1
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
#define PSA_WANT_ALG_CHACHA20_POLY1305 1
#define MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 1
#endif
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING 1
#define PSA_WANT_ALG_CBC_NO_PADDING 1
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
#define MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7 1
#define PSA_WANT_ALG_CBC_PKCS7 1
#endif
#endif

#if (defined(MBEDTLS_AES_C) || defined(MBEDTLS_DES_C) || \
    defined(MBEDTLS_ARIA_C) || defined(MBEDTLS_CAMELLIA_C)) && \
    defined(MBEDTLS_CIPHER_C)
#define MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING 1
#define PSA_WANT_ALG_ECB_NO_PADDING 1
#endif

#if defined(MBEDTLS_CIPHER_MODE_CFB)
#define MBEDTLS_PSA_BUILTIN_ALG_CFB 1
#define PSA_WANT_ALG_CFB 1
#endif

#if defined(MBEDTLS_CIPHER_MODE_CTR)
#define MBEDTLS_PSA_BUILTIN_ALG_CTR 1
#define PSA_WANT_ALG_CTR 1
#endif

#if defined(MBEDTLS_CIPHER_MODE_OFB)
#define MBEDTLS_PSA_BUILTIN_ALG_OFB 1
#define PSA_WANT_ALG_OFB 1
#endif

#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_BRAINPOOL_P_R1_256 1
#define PSA_WANT_ECC_BRAINPOOL_P_R1_256 1
#endif

#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_BRAINPOOL_P_R1_384 1
#define PSA_WANT_ECC_BRAINPOOL_P_R1_384 1
#endif

#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_BRAINPOOL_P_R1_512 1
#define PSA_WANT_ECC_BRAINPOOL_P_R1_512 1
#endif

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_MONTGOMERY_255 1
#define PSA_WANT_ECC_MONTGOMERY_255 1
#endif

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_MONTGOMERY_448 1
#define PSA_WANT_ECC_MONTGOMERY_448 1
#endif

#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_192 1
#define PSA_WANT_ECC_SECP_R1_192 1
#endif

#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_224 1
#define PSA_WANT_ECC_SECP_R1_224 1
#endif

#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_256 1
#define PSA_WANT_ECC_SECP_R1_256 1
#endif

#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_384 1
#define PSA_WANT_ECC_SECP_R1_384 1
#endif

#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_R1_521 1
#define PSA_WANT_ECC_SECP_R1_521 1
#endif

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_K1_192 1
#define PSA_WANT_ECC_SECP_K1_192 1
#endif

/* SECP224K1 is buggy via the PSA API (https://github.com/Mbed-TLS/mbedtls/issues/3541) */
#if 0 && defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_K1_224 1
#define PSA_WANT_ECC_SECP_K1_224 1
#endif

#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define MBEDTLS_PSA_BUILTIN_ECC_SECP_K1_256 1
#define PSA_WANT_ECC_SECP_K1_256 1
#endif

#endif /* MBEDTLS_CONFIG_ADJUST_PSA_FROM_LEGACY_H */
