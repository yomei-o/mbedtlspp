#define CPPHTTPLIB_OPENSSL_SUPPORT 1

#include <iostream>
#include "httplib.h"

#if 0

int main()
{

    std::cout << "Hello World!\n";
    // Client
    httplib::Client cli("https://www.google.com"); // scheme + host
    auto res = cli.Get("/");
    printf("res=>>%s<< \n", res.value().body.c_str());
    return 0;

}

#endif


#if 1

int main()
{
    // Server
    httplib::SSLServer svr("cert.pem", "key.pem");

    svr.Get("/hi", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("Hello World!", "text/plain");
        });

    svr.listen("0.0.0.0", 8080);
    return 0;

}

#endif

