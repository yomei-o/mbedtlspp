# mbedtlspp

The mbedtlspp is a header only c++ SSL library based on mbedtls and work with cpp-httplib.

## build

### Windows mingw32

g++ mbedtlspp_sample.cpp -I . -I include -lws2_32 -lcrypt32 -l bcrypt

### Mac Linux
g++ mbedtlspp_sample.cpp -I . -I include --std=c++17

## Link lists

### mbedtls
https://github.com/Mbed-TLS/mbedtls

### cpp-httplib
https://github.com/yhirose/cpp-httplib




