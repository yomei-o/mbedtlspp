#include <iostream>
#include "httplib.h"

static void try_host(const char* host, const char* ca) {
    httplib::Client cli(host);
    cli.set_connection_timeout(15);
    cli.set_read_timeout(15);
    if (ca) cli.set_ca_cert_path(ca);
    cli.enable_server_certificate_verification(true);
    auto res = cli.Get("/");
    if (!res) {
        std::cout << "FAIL " << host << " err=" << httplib::to_string(res.error())
                  << "\n";
        return;
    }
    std::cout << "OK   " << host << " status=" << res->status
              << " bytes=" << res->body.size() << "\n";
}

int main(int argc, char** argv) {
    const char* ca = (argc > 1) ? argv[1] : nullptr;
    std::cout << "httplib " << CPPHTTPLIB_VERSION
#ifdef CPPHTTPLIB_MBEDTLS_SUPPORT
              << " [native mbedTLS]"
#else
              << " [openssl-compat bridge]"
#endif
              << "\n";
    try_host("https://www.google.com", ca);
    try_host("https://example.com", ca);
    try_host("https://github.com", ca);

    // hostname mismatch must be rejected
    {
        httplib::Client cli("https://wrong.host.badssl.com");
        cli.set_connection_timeout(15);
        if (ca) cli.set_ca_cert_path(ca);
        cli.enable_server_certificate_verification(true);
        auto res = cli.Get("/");
        std::cout << (res ? "*** BAD: wrong.host.badssl.com ACCEPTED ***"
                          : "OK   wrong.host.badssl.com rejected as expected") << "\n";
    }
    {
        httplib::Client cli("https://expired.badssl.com");
        cli.set_connection_timeout(15);
        if (ca) cli.set_ca_cert_path(ca);
        cli.enable_server_certificate_verification(true);
        auto res = cli.Get("/");
        std::cout << (res ? "*** BAD: expired.badssl.com ACCEPTED ***"
                          : "OK   expired.badssl.com rejected as expected") << "\n";
    }
    return 0;
}
