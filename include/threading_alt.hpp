#pragma once

#include<mutex>

typedef struct mbedtls_threading_mutex_t {
	//std::recursive_mutex mtx;
	std::mutex mtx;
} mbedtls_threading_mutex_t;


static inline int threading_mutex_lock(mbedtls_threading_mutex_t *m)
{
	m->mtx.lock();
	return 0;
}

static inline int threading_mutex_unlock(mbedtls_threading_mutex_t *m)
{
	m->mtx.unlock();
	return 0;
}
