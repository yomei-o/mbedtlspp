// Runs every mbedtls self test the configuration provides.
//
// Each one is guarded by the macro of the module that defines it, so the same
// file works across mbedtls 3.x and 4.x (which dropped DES, DHM and NIST-KW,
// among others).

#include <cstdio>
#include "mbedtlspp.hpp"

static int fails = 0, total = 0;

static void run(const char *name, int (*fn)(int))
{
    total++;
    int rc = fn(0);
    if (rc != 0) {
        fails++;
        printf("FAIL  %-34s rc=%d\n", name, rc);
    } else {
        printf("ok    %-34s\n", name);
    }
}

#define RUN(f) run(#f, f)

int main()
{
    psa_crypto_init();

#if defined(MBEDTLS_AES_C)
    RUN(mbedtls_aes_self_test);
#endif
#if defined(MBEDTLS_ARIA_C)
    RUN(mbedtls_aria_self_test);
#endif
#if defined(MBEDTLS_BASE64_C)
    RUN(mbedtls_base64_self_test);
#endif
#if defined(MBEDTLS_CAMELLIA_C)
    RUN(mbedtls_camellia_self_test);
#endif
#if defined(MBEDTLS_CCM_C)
    RUN(mbedtls_ccm_self_test);
#endif
#if defined(MBEDTLS_CHACHA20_C)
    RUN(mbedtls_chacha20_self_test);
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    RUN(mbedtls_chachapoly_self_test);
#endif
#if defined(MBEDTLS_CMAC_C)
    RUN(mbedtls_cmac_self_test);
#endif
#if defined(MBEDTLS_CTR_DRBG_C)
    RUN(mbedtls_ctr_drbg_self_test);
#endif
#if defined(MBEDTLS_DES_C)
    RUN(mbedtls_des_self_test);
#endif
#if defined(MBEDTLS_DHM_C)
    RUN(mbedtls_dhm_self_test);
#endif
#if defined(MBEDTLS_ECJPAKE_C)
    RUN(mbedtls_ecjpake_self_test);
#endif
#if defined(MBEDTLS_ECP_C)
    RUN(mbedtls_ecp_self_test);
#endif
#if defined(MBEDTLS_ENTROPY_C)
    RUN(mbedtls_entropy_self_test);
#endif
#if defined(MBEDTLS_GCM_C)
    RUN(mbedtls_gcm_self_test);
#endif
#if defined(MBEDTLS_HMAC_DRBG_C)
    RUN(mbedtls_hmac_drbg_self_test);
#endif
#if defined(MBEDTLS_MD5_C)
    RUN(mbedtls_md5_self_test);
#endif
#if defined(MBEDTLS_BIGNUM_C)
    RUN(mbedtls_mpi_self_test);
#endif
#if defined(MBEDTLS_NIST_KW_C) && MBEDTLS_VERSION_MAJOR < 4
    RUN(mbedtls_nist_kw_self_test);
#endif
#if defined(MBEDTLS_PKCS5_C)
    RUN(mbedtls_pkcs5_self_test);
#endif
#if defined(MBEDTLS_POLY1305_C)
    RUN(mbedtls_poly1305_self_test);
#endif
#if defined(MBEDTLS_RIPEMD160_C)
    RUN(mbedtls_ripemd160_self_test);
#endif
#if defined(MBEDTLS_RSA_C)
    RUN(mbedtls_rsa_self_test);
#endif
#if defined(MBEDTLS_SHA1_C)
    RUN(mbedtls_sha1_self_test);
#endif
#if defined(MBEDTLS_SHA224_C)
    RUN(mbedtls_sha224_self_test);
#endif
#if defined(MBEDTLS_SHA256_C)
    RUN(mbedtls_sha256_self_test);
#endif
#if defined(MBEDTLS_SHA384_C)
    RUN(mbedtls_sha384_self_test);
#endif
#if defined(MBEDTLS_SHA3_C)
    RUN(mbedtls_sha3_self_test);
#endif
#if defined(MBEDTLS_SHA512_C)
    RUN(mbedtls_sha512_self_test);
#endif

    printf("\n==== %d/%d passed, %d FAILED ====\n", total - fails, total, fails);
    return fails != 0;
}
