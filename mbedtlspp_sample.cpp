#define CPPHTTPLIB_OPENSSL_SUPPORT 1

#include <iostream>
#include "httplib.h"

int main()
{

    std::cout << "Hello World!\n";
    // Client
    httplib::Client cli("https://www.google.com"); // scheme + host
    auto res = cli.Get("/");
    printf("res=>>%s<< \n", res.value().body.c_str());
    return 0;

}

