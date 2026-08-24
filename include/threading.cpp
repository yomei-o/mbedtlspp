/*
 *  Threading abstraction layer
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Ensure gmtime_r is available even with -std=c99; must be defined before
 * mbedtls_config.h, which pulls in glibc's features.h. Harmless on other platforms.
 */
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "common.hpp"

#if defined(MBEDTLS_THREADING_C)

#include "threading_internal.hpp"

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif /* !_WIN32 && (unix || __unix || __unix__ ||
        * (__APPLE__ && __MACH__)) */

#if !((defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L) ||     \
    (defined(_POSIX_THREAD_SAFE_FUNCTIONS) &&                     \
    _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L))
/*
 * This is a convenience shorthand macro to avoid checking the long
 * preprocessor conditions above. Ideally, we could expose this macro in
 * platform_util.h and simply use it in platform_util.c, threading.c and
 * threading.h. However, this macro is not part of the Mbed TLS public API, so
 * we keep it private by only defining it in this file
 */

#if !(defined(_WIN32) && !defined(EFIX64) && !defined(EFI32))
#define THREADING_USE_GMTIME
#endif /* ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) ) */

#endif /* !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) || \
             ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) && \
                _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L ) ) */

#endif /* MBEDTLS_HAVE_TIME_DATE && !MBEDTLS_PLATFORM_GMTIME_R_ALT */

#if defined(MBEDTLS_THREADING_PTHREAD)
static inline  void threading_mutex_init_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    /* One problem here is that calling lock on a pthread mutex without first
     * having initialised it is undefined behaviour. Obviously we cannot check
     * this here in a thread safe manner without a significant performance
     * hit, so state transitions are checked in tests only via the state
     * variable. Please make sure any new mutex that gets added is exercised in
     * tests; see framework/tests/src/threading_helpers.c for more details. */
    (void) pthread_mutex_init(&mutex->mutex, NULL);
}

static inline  void threading_mutex_free_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    (void) pthread_mutex_destroy(&mutex->mutex);
}

static inline  int threading_mutex_lock_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    if (pthread_mutex_lock(&mutex->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return 0;
}

static inline  int threading_mutex_unlock_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    if (pthread_mutex_unlock(&mutex->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return 0;
}

static inline void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *) = threading_mutex_init_pthread;
static inline void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *) = threading_mutex_free_pthread;
static inline int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *) = threading_mutex_lock_pthread;
static inline int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *) = threading_mutex_unlock_pthread;

/*
 * With pthreads we can statically initialize mutexes
 */
#define MUTEX_INIT  = { PTHREAD_MUTEX_INITIALIZER, 1 }

#endif /* MBEDTLS_THREADING_PTHREAD */

#if defined(MBEDTLS_THREADING_ALT)
static inline  int threading_mutex_fail(mbedtls_threading_mutex_t *mutex)
{
    ((void) mutex);
    return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
}
static inline  void threading_mutex_dummy(mbedtls_threading_mutex_t *mutex)
{
    ((void) mutex);
    return;
}

// 既定で実体確保版を使う（set_alt を呼ばなくても各 context の mutex が正しく確保される）。
// no-op の threading_mutex_dummy を既定にすると、set_alt 未登録の経路（サーバ側）で
// mtx が未初期化のままになり、mbedtls_mutex_lock() が不正な std::mutex* を触って落ちる。
static inline void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *) = threading_mutex_init;
static inline void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *) = threading_mutex_free;
static inline int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *) = threading_mutex_lock;
static inline int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *) = threading_mutex_unlock;

/*
 * Set functions pointers and initialize global mutexes
 */
static inline void mbedtls_threading_set_alt(void (*mutex_init)(mbedtls_threading_mutex_t *),
                               void (*mutex_free)(mbedtls_threading_mutex_t *),
                               int (*mutex_lock)(mbedtls_threading_mutex_t *),
                               int (*mutex_unlock)(mbedtls_threading_mutex_t *))
{
    mbedtls_mutex_init = mutex_init;
    mbedtls_mutex_free = mutex_free;
    mbedtls_mutex_lock = mutex_lock;
    mbedtls_mutex_unlock = mutex_unlock;

#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_init(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_init(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_init(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_rngdata_mutex);
#endif
}

/*
 * Free global mutexes
 */
static inline void mbedtls_threading_free_alt(void)
{
#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_free(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_free(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_free(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_rngdata_mutex);
#endif
}

/*
 * ライブラリ自動初期化。
 *
 *   プロセス起動時（main より前・スレッド生成前）に一度だけ mbedtls_threading_set_alt()
 *   を実行し、C++ std::mutex ベースの mutex コールバックを登録する。あわせて set_alt 内で
 *   グローバル mutex（PSA の key_slot / globaldata / rngdata、gmtime 等）も初期化される。
 *
 *   これにより、アプリ側が set_alt / ensure 系を呼ばなくても THREADING_ALT が完全に機能する。
 *   （各 context の mutex は threading_mutex_init が _init 時に確保し、グローバル mutex は
 *   ここで確保される。zeroize されても mtx は null になるだけで安全。）
 *
 *   注: mbedtls の context 生成はすべて実行時（main 以降）なので、この静的初期化が先行する。
 */
namespace {
struct mbedtls_threading_auto_init_t {
    mbedtls_threading_auto_init_t()
    {
        mbedtls_threading_set_alt(threading_mutex_init, threading_mutex_free,
                                  threading_mutex_lock, threading_mutex_unlock);
    }
};
static mbedtls_threading_auto_init_t mbedtls_threading_auto_init_instance;
}  // namespace
#endif /* MBEDTLS_THREADING_ALT */

/*
 * Define global mutexes
 */
#ifndef MUTEX_INIT
#define MUTEX_INIT
#endif

#if 0
#if defined(MBEDTLS_FS_IO)
static inline mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex MUTEX_INIT;
#endif
#if defined(THREADING_USE_GMTIME)
static inline mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex MUTEX_INIT;
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
static inline mbedtls_threading_mutex_t mbedtls_threading_key_slot_mutex MUTEX_INIT;
static inline mbedtls_threading_mutex_t mbedtls_threading_psa_globaldata_mutex MUTEX_INIT;
static inline mbedtls_threading_mutex_t mbedtls_threading_psa_rngdata_mutex MUTEX_INIT;
#endif
#endif

#endif /* MBEDTLS_THREADING_C */
