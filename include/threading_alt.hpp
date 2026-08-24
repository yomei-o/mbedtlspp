#pragma once

#include <mutex>
#include <condition_variable>

// ============================================================================
// MBEDTLS_THREADING_ALT implementation for mbedtls 4.x.
//
//   mbedtls 4.x asks the alternate threading implementation for two types,
//   mbedtls_platform_mutex_t and mbedtls_platform_condition_variable_t, and
//   wraps each of them in a struct of its own (mbedtls_threading_mutex_t /
//   mbedtls_threading_condition_variable_t) that the C code embeds in its
//   contexts and clears with memset / mbedtls_platform_zeroize().
//
//   That makes it fatal to embed a std::mutex by value:
//     - zeroizing wrecks the mutex's internal state, so the next lock touches
//       a corrupted object and faults;
//     - the C++ destructor would later run over zeroized memory.
//
//   So the platform types hold nothing but a pointer, and the real objects
//   live on the heap. Being plain pointers they survive memset and zeroize --
//   the field just becomes null, which every entry point below tolerates.
//
//   The callbacks are registered automatically (see the end of threading.cpp),
//   so an application never has to call mbedtls_threading_set_alt() itself.
// ============================================================================

typedef struct mbedtls_platform_mutex_t {
    std::mutex *mtx;   // POD: memset / zeroize only ever makes it null.
} mbedtls_platform_mutex_t;

typedef struct mbedtls_platform_condition_variable_t {
    std::condition_variable *cv;
} mbedtls_platform_condition_variable_t;

// mbedtls_threading.hpp defines MBEDTLS_ERR_THREADING_USAGE_ERROR, but this
// header is pulled in before that point, so spell the value out.
#define MBEDTLSPP_THREADING_USAGE_ERROR (-0x001E)

static inline int threading_mutex_init(mbedtls_platform_mutex_t *m)
{
    if (m == nullptr) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    try {
        m->mtx = new std::mutex();
    } catch (...) {
        m->mtx = nullptr;
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    return 0;
}

static inline void threading_mutex_destroy(mbedtls_platform_mutex_t *m)
{
    if (m == nullptr) {
        return;
    }
    delete m->mtx;
    m->mtx = nullptr;
}

static inline int threading_mutex_lock(mbedtls_platform_mutex_t *m)
{
    if (m == nullptr || m->mtx == nullptr) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    try {
        m->mtx->lock();
    } catch (...) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    return 0;
}

static inline int threading_mutex_unlock(mbedtls_platform_mutex_t *m)
{
    if (m == nullptr || m->mtx == nullptr) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    try {
        m->mtx->unlock();
    } catch (...) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    return 0;
}

static inline int threading_cond_init(mbedtls_platform_condition_variable_t *c)
{
    if (c == nullptr) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    try {
        c->cv = new std::condition_variable();
    } catch (...) {
        c->cv = nullptr;
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    return 0;
}

static inline void threading_cond_destroy(mbedtls_platform_condition_variable_t *c)
{
    if (c == nullptr) {
        return;
    }
    delete c->cv;
    c->cv = nullptr;
}

static inline int threading_cond_signal(mbedtls_platform_condition_variable_t *c)
{
    if (c == nullptr || c->cv == nullptr) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    c->cv->notify_one();
    return 0;
}

static inline int threading_cond_broadcast(mbedtls_platform_condition_variable_t *c)
{
    if (c == nullptr || c->cv == nullptr) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    c->cv->notify_all();
    return 0;
}

static inline int threading_cond_wait(mbedtls_platform_condition_variable_t *c,
                                      mbedtls_platform_mutex_t *m)
{
    if (c == nullptr || c->cv == nullptr || m == nullptr || m->mtx == nullptr) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    try {
        // The caller already holds the mutex and expects to still hold it when
        // we return, so adopt the lock and release the guard without
        // unlocking.
        std::unique_lock<std::mutex> lock(*m->mtx, std::adopt_lock);
        c->cv->wait(lock);
        lock.release();
    } catch (...) {
        return MBEDTLSPP_THREADING_USAGE_ERROR;
    }
    return 0;
}
