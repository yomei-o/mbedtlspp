# mbedtlspp

Mbed TLS as a header-only C++ library. No build system, no submodules, no
linking step: add two include directories and `#include` one header.

Tracks mbedtls 4.2.0 and works with cpp-httplib 0.53.1. Tags follow the
upstream mbedtls version, back to 3.6.3.

```cpp
#define CPPHTTPLIB_MBEDTLS_SUPPORT 1
#include "httplib.h"

int main() {
    httplib::SSLServer svr("cert.pem", "key.pem");
    svr.Get("/hi", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("Hello World!", "text/plain");
    });
    svr.listen("0.0.0.0", 8080);
}
```

```
cl mbedtlspp_sample_mbedtls.cpp /I . /I include /std:c++20
```

That is the whole build.

## Why

Mbed TLS is small, portable and permissively licensed, but getting it into a
project still means CMake, a submodule for the crypto half since 4.0, generated
sources, and a library to link. That is a lot of ceremony for "I want HTTPS in
this one tool". Here the entire library is a set of headers you drop in a
directory, so it works the same in Visual Studio, in a Makefile, in a single
`cl` invocation, or in someone else's build system you would rather not modify.

Everything is `static inline` in one translation unit, which also lets the
compiler inline and discard across the whole library.

## Usage

There are two ways to combine it with cpp-httplib. Both are supported and both
are exercised by the samples in this repository.

### 1. Native mbedTLS support (cpp-httplib 0.48 or later)

cpp-httplib talks to mbedtls directly. Define `CPPHTTPLIB_MBEDTLS_SUPPORT` and
put the repository root on the include path; the `mbedtls/`, `psa/` and
`tf-psa-crypto/` forwarding headers point cpp-httplib's `<mbedtls/...>` and
`<psa/...>` includes at the amalgamation. The `openssl/` bridge is not used.

See `mbedtlspp_sample_mbedtls.cpp`.

### 2. OpenSSL compatibility bridge (any cpp-httplib version)

Define `CPPHTTPLIB_OPENSSL_SUPPORT` and add the `openssl` folder to the
includes. `openssl/mbedtls.h` implements the slice of the OpenSSL API that
cpp-httplib uses, on top of mbedtls. This is the only option for cpp-httplib
0.47 or earlier, and it still works with the current release.

See `mbedtlspp_sample.cpp` and `mbedtlspp_sample_httpsd.cpp`.

### Without cpp-httplib

`#include "mbedtlspp.hpp"` and use the normal mbedtls API. `mbedtlspp_check.cpp`
is a compile-only smoke test that does exactly that.

## Build

### Windows Visual Studio 2022

    cl mbedtlspp_sample.cpp /I . /I include /std:c++20

### Windows mingw32

    g++ mbedtlspp_sample.cpp -I . -I include -lws2_32 -lcrypt32 -l bcrypt

### Mac clang

    g++ mbedtlspp_sample.cpp -I . -I include --std=c++17

### Linux gcc

    g++ mbedtlspp_sample.cpp -I . -I include --std=c++17

## Notes on mbedtls 4.x

Upstream removed things in 4.0 that 3.6 had:

* The static RSA key exchange, so the non-ECDHE `TLS_RSA_WITH_*` cipher suites
  no longer exist. ECDHE suites and TLS 1.3 are unaffected.
* DES, DHM and NIST-KW.
* Most of the legacy crypto headers moved under `mbedtls/private/`.

If you need any of those, use the `v3.6.7` tag, which is the last 3.6 release.

## Keeping up with upstream

`tools/` holds the scripts that move this port from one upstream mbedtls
release to the next, and `RESUME.md` explains how to use them.

## Link lists

### mbedtls
https://github.com/Mbed-TLS/mbedtls

### TF-PSA-Crypto (the crypto half of mbedtls 4.x)
https://github.com/Mbed-TLS/TF-PSA-Crypto

### cpp-httplib
https://github.com/yhirose/cpp-httplib

### cpp-httplib-mbedtls
https://github.com/crystalidea/cpp-httplib-mbedtls/blob/main/httplib.h
