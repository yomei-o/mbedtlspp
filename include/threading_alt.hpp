#pragma once

#include<mutex>

// ============================================================================
// MBEDTLS_THREADING_ALT 用の mutex 実装。
//
//   mbedtls_threading_mutex_t は mbedtls の C コードが各 context（ctr_drbg /
//   entropy / ssl 等）のメンバとして保持し、_init / _free 時に memset・
//   mbedtls_platform_zeroize() で構造体ごとゼロ化する。
//
//   このため std::mutex を「値」で埋め込むと致命的になる:
//     - ゼロ化で std::mutex の内部状態が壊れ、既定の lock(= std::mutex::lock())
//       がゼロ化済み mutex を触ってアクセス違反（例: SRP 認証で最初に
//       mbedtls_ctr_drbg_random を呼んだ瞬間にクラッシュ）。
//     - context 破棄時に C++ の ~std::mutex がゼロ化済みメモリ上で走り、
//       これもアクセス違反。
//
//   → mutex 実体はヒープに置き、構造体には「ポインタ（POD）」だけを持たせる。
//     ゼロ化されてもポインタが null になるだけで無害。C++ デストラクタが
//     埋め込み mutex 上で走ることも無い。ポインタは lock 時に遅延生成する
//     （既定の mutex_init は no-op のため。set_alt で別実装を登録しても可）。
// ============================================================================
typedef struct mbedtls_threading_mutex_t {
	std::mutex* mtx;   // POD。memset / zeroize されても null になるだけで安全。
} mbedtls_threading_mutex_t;


// mbedtls の作法では lock の前に必ず mutex_init が呼ばれる。init で mtx を
// 割り当てる実装（mbedtls_threading_set_alt で登録）を前提に、ここでは参照する。
// 念のため null ガードを入れる（未 init / ゼロ化済みは無視）。
static inline int threading_mutex_lock(mbedtls_threading_mutex_t *m)
{
try{
	if (m->mtx != nullptr) m->mtx->lock();
}catch(...){}
	return 0;
}

static inline int threading_mutex_unlock(mbedtls_threading_mutex_t *m)
{
try{
	if (m->mtx != nullptr) m->mtx->unlock();
}catch(...){}
	return 0;
}

// 既定の mutex_init / mutex_free 実装。
//   mbedtls は各 context の _init で必ず mutex_init を、_free で mutex_free を呼ぶ。
//   ここで実体（std::mutex）をヒープに確保／解放しておけば、
//   mbedtls_threading_set_alt() を呼ばなくても THREADING_ALT が正しく機能する。
//   （context が zeroize されても mtx が null になるだけで安全。free 済みも null。）
//   これにより、set_alt を呼ぶ経路（CLI）と呼ばない経路（サーバ）の非対称が消える。
static inline void threading_mutex_init(mbedtls_threading_mutex_t *m)
{
	try { m->mtx = new std::mutex(); } catch (...) { m->mtx = nullptr; }
}

static inline void threading_mutex_free(mbedtls_threading_mutex_t *m)
{
	delete m->mtx;
	m->mtx = nullptr;
}
