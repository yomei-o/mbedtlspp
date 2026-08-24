# mbedtlspp

The mbedtlspp is a header only c++ SSL library based on mbedtls and works with cpp-httplib.

Tested with cpp-httplib v0.53.1 and mbedtls 3.6.7, should work with later versions.

## usage

There are two ways to combine it with cpp-httplib. Both are supported and both
are exercised by the samples in this repository.

### 1. native mbedTLS support (cpp-httplib 0.48 or later)

cpp-httplib can talk to mbedtls directly. Define `CPPHTTPLIB_MBEDTLS_SUPPORT`
and add the repository root to the includes; the `mbedtls/` and `psa/`
forwarding headers point cpp-httplib's `<mbedtls/...>` / `<psa/...>` includes at
the header only amalgamation. The `openssl/` bridge is not used at all.

```
#define CPPHTTPLIB_MBEDTLS_SUPPORT 1
#include "httplib.h"
```

See `mbedtlspp_sample_mbedtls.cpp`.

### 2. OpenSSL compatibility bridge (any cpp-httplib version)

Define `CPPHTTPLIB_OPENSSL_SUPPORT` and add the `openssl` folder to the
includes. `openssl/mbedtls.h` implements the OpenSSL API surface that
cpp-httplib uses on top of mbedtls. This is the only option for cpp-httplib
0.47 or earlier, and it keeps working with the current release.

```
#define CPPHTTPLIB_OPENSSL_SUPPORT 1
#include "httplib.h"
```

See `mbedtlspp_sample.cpp` and `mbedtlspp_sample_httpsd.cpp`.

## build

### Windows Visual Studio 2022

cl mbedtlspp_sample.cpp /I . /I include /std:c++20

### Windows mingw32

g++ mbedtlspp_sample.cpp -I . -I include -lws2_32 -lcrypt32 -l bcrypt

### Mac clang
g++ mbedtlspp_sample.cpp -I . -I include --std=c++17

### Linux gcc
g++ mbedtlspp_sample.cpp -I . -I include --std=c++17

## Link lists

### mbedtls
https://github.com/Mbed-TLS/mbedtls

### cpp-httplib
https://github.com/yhirose/cpp-httplib

### cpp-httplib-mbedtls
https://github.com/crystalidea/cpp-httplib-mbedtls/blob/main/httplib.h
