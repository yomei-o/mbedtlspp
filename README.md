# mbedtlspp

The mbedtlspp is a header only c++ SSL library based on mbedtls and work with cpp-httplib.

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


