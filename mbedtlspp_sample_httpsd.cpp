#define CPPHTTPLIB_OPENSSL_SUPPORT 1

#include <iostream>
#include "httplib.h"

int main()
{
    mbedtls_debug_set_threshold(2);


    // HTTPS
    httplib::SSLServer svr("cert.pem", "key.pem");

    svr.Get("/hi", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("Hello World!", "text/plain");
        });

    svr.listen("0.0.0.0", 8080);

    return 0;

}

