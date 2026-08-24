// cpp-httplib has native mbedTLS support since 0.48. With that option the
// openssl/ compatibility bridge is not used at all: httplib includes
// <mbedtls/...> directly and the mbedtls/ + psa/ forwarding headers in this
// repository point those at the header-only amalgamation.
//
//   cl mbedtlspp_sample_mbedtls.cpp /I . /I include /std:c++20
//
// See mbedtlspp_sample_httpsd.cpp for the same server over the OpenSSL
// compatibility bridge (CPPHTTPLIB_OPENSSL_SUPPORT).

#define CPPHTTPLIB_MBEDTLS_SUPPORT 1

#include <iostream>
#include "httplib.h"

int main()
{

    // HTTPS
    httplib::SSLServer svr("cert.pem", "key.pem");

    svr.Get("/hi", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("Hello World!", "text/plain");
        });

    svr.listen("0.0.0.0", 8080);

    return 0;

}
