#ifndef CPPHTTPLIB_HTTPLIB_MBEDTLS_H
#define CPPHTTPLIB_HTTPLIB_MBEDTLS_H

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <string>
#include <vector>
#include <memory>

#include <mbedtlspp.hpp>

static inline int strncpy_s__(char* dest, size_t destsz, const char* src, size_t count) {
    if (!dest || !src || destsz == 0) return -1;
    size_t i;
    for (i = 0; i < count && i < destsz - 1 && src[i]; ++i)
        dest[i] = src[i];
    dest[i] = '\0';
    return 0;
}
static inline int memcpy_s__(void *dest, size_t destsz, const void *src, size_t count) {
    if (dest == NULL || src == NULL) {
        return EINVAL;
    }
    if (count > destsz) {
        if (destsz > 0) {
            memset(dest, 0, destsz); // optionally zero out
        }
        return ERANGE;
    }
    memcpy(dest, src, count);
    return 0;
}


#ifdef _WIN32
    
    #include <winsock2.h>

#if MBEDTLS_DEBUG_OUTPUT_LEVEL

    #include <shlwapi.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "Shlwapi.lib")
    #endif

#endif

#endif

#define OPENSSL_VERSION_NUMBER 0x31000000L

#define SSL_VERIFY_NONE         MBEDTLS_SSL_VERIFY_NONE
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02

#define SSL_FILETYPE_PEM    MBEDTLS_X509_FORMAT_PEM

// BIO

struct BIO
{
    // Socket-backed BIO (TLS transport).
    BIO(int s) : is_mem(false) {
        ctx.fd = s;
    }
    // Memory-backed BIO (httplib 0.46 in-memory PEM parsing).
    BIO(const void* buf, int len) : is_mem(true) {
        const unsigned char* p = static_cast<const unsigned char*>(buf);
        size_t n = (len < 0) ? (buf ? strlen(static_cast<const char*>(buf)) : 0)
                             : static_cast<size_t>(len);
        if (p && n) mem.assign(p, p + n);
    }
    ~BIO() {
        if (!is_mem) mbedtls_net_free(&ctx);
    }

    mbedtls_net_context ctx{};

    bool is_mem = false;
    std::vector<unsigned char> mem;
    size_t mem_pos = 0;
};

#define BIO_NOCLOSE 0

struct SSL;

BIO* BIO_new_socket(int sock, int close_flag)
{
    return new BIO(sock);
}

// If n is zero then blocking I/O is set. If n is 1 then non blocking I/O is set
// TODO: why is here vice versa?? Doesn't work otherwise

void BIO_set_nbio(BIO* bio, long blocking)
{
    if (blocking == 0)
        mbedtls_net_set_nonblock(&bio->ctx); 
    else
        mbedtls_net_set_block(&bio->ctx);
}

BIO* BIO_new_mem_buf(const void* buf, int len)
{
    return new BIO(buf, len);
}

void BIO_free(BIO* a)
{
    if (a) delete a;
}

void BIO_free_all(BIO* a)
{
    if (a) delete a;
}

// error codes

# define X509_V_OK                                       0
# define X509_V_ERR_UNSPECIFIED                          1
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            2
# define X509_V_ERR_UNABLE_TO_GET_CRL                    3
# define X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     4
# define X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      5
# define X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   6
# define X509_V_ERR_CERT_SIGNATURE_FAILURE               7
# define X509_V_ERR_CRL_SIGNATURE_FAILURE                8
# define X509_V_ERR_CERT_NOT_YET_VALID                   9
# define X509_V_ERR_CERT_HAS_EXPIRED                     10
# define X509_V_ERR_CRL_NOT_YET_VALID                    11
# define X509_V_ERR_CRL_HAS_EXPIRED                      12
# define X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       13
# define X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        14
# define X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       15
# define X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       16
# define X509_V_ERR_OUT_OF_MEM                           17
# define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          18
# define X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            19
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    20
# define X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      21
# define X509_V_ERR_CERT_CHAIN_TOO_LONG                  22
# define X509_V_ERR_CERT_REVOKED                         23
# define X509_V_ERR_NO_ISSUER_PUBLIC_KEY                 24
# define X509_V_ERR_PATH_LENGTH_EXCEEDED                 25
# define X509_V_ERR_INVALID_PURPOSE                      26
# define X509_V_ERR_CERT_UNTRUSTED                       27
# define X509_V_ERR_CERT_REJECTED                        28

#define SSL_ERROR_ZERO_RETURN           6 // see SSL_peek

#define SSL_ERROR_WANT_READ MBEDTLS_ERR_SSL_WANT_READ
#define SSL_ERROR_WANT_WRITE MBEDTLS_ERR_SSL_WANT_WRITE
#define SSL_ERROR_SYSCALL -0x6785 // TODO: match SSL_ERROR_SYSCALL error code to mbedtls

// x509 stuff

// ---- httplib 0.46 compatibility: ASN.1 time / integer helpers ----
struct ASN1_TIME {
    time_t epoch = 0;
    bool   is_set = false;
};

struct ASN1_INTEGER {
    std::vector<unsigned char> bytes;
};

static inline time_t mbedtls_x509_time_to_epoch(const mbedtls_x509_time* t) {
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = t->year - 1900;
    tmv.tm_mon  = t->mon  - 1;
    tmv.tm_mday = t->day;
    tmv.tm_hour = t->hour;
    tmv.tm_min  = t->min;
    tmv.tm_sec  = t->sec;
#ifdef _WIN32
    return _mkgmtime(&tmv);
#else
    return timegm(&tmv);
#endif
}

struct X509 {

    X509() // empty cert 
    {
        mbedtls_x509_crt_init(&crt);
    }
    X509(mbedtls_x509_crt* crt_another) // to be used in a SSLClient for example
        : X509()
    {
        int nParseResult = mbedtls_x509_crt_parse_der(&crt, crt_another->raw.p, crt_another->raw.len);

        assert(nParseResult == 0);
    }

    X509(const char* file)
        : X509()
    {   //yomei
        //int ret = mbedtls_x509_crt_parse_file(&crt, file, MBEDTLS_X509_FORMAT_PEM);
        int ret = mbedtls_x509_crt_parse_file(&crt, file);

        assert(ret == 0);
    }

    ~X509()
    {
        mbedtls_x509_crt_free(&crt);
    }

    mbedtls_x509_crt crt;

    // Caches backing httplib 0.46 accessors (must outlive the call).
    ASN1_TIME    not_before_;
    ASN1_TIME    not_after_;
    ASN1_INTEGER serial_cache_;
};

struct X509_CRL {
    // not used yet
};

struct X509_STORE {

    X509_STORE()
    {
        mbedtls_x509_crt_init(&chain);
        mbedtls_x509_crl_init(&crl_chain);
    }

    ~X509_STORE()
    {
        mbedtls_x509_crt_free(&chain);
        mbedtls_x509_crl_free(&crl_chain);
    }

    mbedtls_x509_crt chain;
    mbedtls_x509_crl crl_chain;
};

struct X509_INFO {
    X509* x509;
    X509_CRL* crl;
};

struct X509_NAME_ENTRY;

struct X509_NAME_OPENSSL // originally X509_NAME bug there's a name conflict on Windows
{
    X509_NAME_OPENSSL(const char* sz)
        : str(sz)
    {

    }
    ~X509_NAME_OPENSSL();

    std::string str;

    // RDN entries parsed out of `str` on demand; see X509_NAME_get_index_by_NID().
    std::vector<X509_NAME_ENTRY*> entries;
};

// httplib 0.46 refers to the type as X509_NAME directly. wincrypt.h defines
// X509_NAME as a macro on Windows, but httplib #undef's it before including us.
#ifdef X509_NAME
#undef X509_NAME
#endif
typedef X509_NAME_OPENSSL X509_NAME;

# define GEN_DNS         2
# define GEN_IPADD       7

#define NID_subject_alt_name            85

struct GENERAL_NAME_D
{
    const struct GENERAL_NAME* ia5;
    // httplib 0.46 accesses these named members; all alias the same node.
    const struct GENERAL_NAME* dNSName;
    const struct GENERAL_NAME* iPAddress;
    const struct GENERAL_NAME* rfc822Name;
    const struct GENERAL_NAME* uniformResourceIdentifier;
};

struct GENERAL_NAME
{
    GENERAL_NAME(int t, const std::vector<unsigned char>& b)
        : buffer(b), type(t)
    {
        set_self();
    }

    GENERAL_NAME(const GENERAL_NAME& copy)
    {
        this->type = copy.type;
        this->buffer = copy.buffer;
        set_self();
    }

    GENERAL_NAME(const GENERAL_NAME&& copy)
    {
        this->type = copy.type;
        this->buffer = copy.buffer;
        set_self();
    }

    void set_self()
    {
        d.ia5 = d.dNSName = d.iPAddress = d.rfc822Name =
            d.uniformResourceIdentifier = this;
    }

    std::vector<unsigned char> buffer;

    int type = 0;

    GENERAL_NAME_D d;
};

struct stack_st_GENERAL_NAME
{
    std::vector<GENERAL_NAME> names;
};

inline const char* ASN1_STRING_get0_data(const GENERAL_NAME* s) {
    // httplib 0.46 reads DNS / IP / email / URI SAN values through this.
    if (s && !s->buffer.empty())
        return (const char*)&s->buffer[0];
    return nullptr;
}

inline size_t ASN1_STRING_length(const GENERAL_NAME* s) {
    return s ? s->buffer.size() : 0;
}

#define STACK_OF(a) a

X509* d2i_X509(void* unused, const unsigned char** p, int len) // decode a DER buffer
{
    std::unique_ptr< X509> cert(new X509());

    int nParseResult = mbedtls_x509_crt_parse_der(&cert->crt, *p, len);

    if (nParseResult == 0)
        return cert.release();

    //assert(0); // failed on one certificate on my windows... (unknown sig)

    return nullptr;
}

X509* PEM_read_X509(FILE* fp, void*, void*, void*)
{
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        std::vector<unsigned char> data;
        data.resize(fsize);

        fread(&data[0], fsize, 1, fp);

        std::unique_ptr<X509> crt(new X509());
        //yomei
        //int ret = mbedtls_x509_crt_parse(&crt->crt, &data[0], fsize, MBEDTLS_X509_FORMAT_PEM);
        int ret = mbedtls_x509_crt_parse(&crt->crt, &data[0], fsize);

        if (ret == 0)
            return crt.release();
    }

    return nullptr;
}

int X509_STORE_add_cert(X509_STORE* store, X509* toAdd)
{
    // https://stackoverflow.com/questions/63478088/use-mbedtls-to-pull-public-certificate-chain-from-a-server-and-store-as-a-string

    int nParseResult = mbedtls_x509_crt_parse_der(&store->chain, toAdd->crt.raw.p, toAdd->crt.raw.len);

    assert(nParseResult == 0);

    return (nParseResult == 0) ? 1 : 0;
}

int X509_STORE_add_crl(X509_STORE* ctx, X509_CRL* x)
{
    assert("NOT IMPLEMENTED" == 0);

    return 0;
}

void X509_free(X509* cert)
{
    if (cert)
        delete cert;
}

X509_STORE* X509_STORE_new()
{
    return new X509_STORE();;
}

void X509_STORE_free(X509_STORE* store)
{
    if (store)
        delete store;
}

X509_INFO* PEM_X509_INFO_read_bio(BIO* bp, void*, void*, void*)
{
    assert("NOT IMPLEMENTED" == 0);

    return nullptr;
}

int sk_X509_INFO_num(X509_INFO*)
{
    assert("NOT IMPLEMENTED" == 0);

    return 0;
}

X509_INFO* sk_X509_INFO_value(X509_INFO* c, int num)
{
    assert("NOT IMPLEMENTED" == 0);

    return nullptr;
}

void X509_INFO_free(X509_INFO* info)
{
    assert("NOT IMPLEMENTED" == 0);
}

typedef void (*freefunc)(X509_INFO*);

void sk_X509_INFO_pop_free(X509_INFO* info, freefunc)
{
    assert("NOT IMPLEMENTED" == 0);
}

X509_NAME_OPENSSL* X509_get_subject_name(const X509* x)
{
    const mbedtls_x509_name* name = &x->crt.subject;

    char subject_name[512]; // same as BUFSIZ in httplib
    return (mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), name) > 0) ? new X509_NAME_OPENSSL(subject_name) : nullptr;
}

#define NID_commonName 1

int X509_NAME_get_text_by_NID(X509_NAME_OPENSSL* name, int nid, char* buf, int len)
{
    if (buf && nid == NID_commonName)
    {
        static const std::regex cn_regex = std::regex(".*CN=(.+?)");
        std::smatch match;
        std::string in_str = name->str;

        if (std::regex_match(in_str, match, cn_regex))
        {
            if (match.size() == 2) {
                std::string cname = match[1];

                strncpy_s__(buf, len, cname.c_str(), cname.size());

                return cname.size();
            }
        }
    }

    return -1; // error
}

stack_st_GENERAL_NAME* X509_get_ext_d2i(X509* x509, int nid, void*, void*)
{
    // taken from the x509_parse_san test

    const mbedtls_x509_crt* crt = &x509->crt;
    const mbedtls_x509_sequence* cur = &crt->subject_alt_names;

    char buf[2000];

    mbedtls_x509_subject_alternative_name san;

    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME)
    {
        if (nid == NID_subject_alt_name)
        {
            stack_st_GENERAL_NAME* retNames = new stack_st_GENERAL_NAME();

            while (cur)
            {
                memset(buf, 0, 2000);

                int ret = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
                assert(ret == 0 || ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE);

                if (ret == 0) {

                    if (san.type == MBEDTLS_X509_SAN_DNS_NAME || san.type == MBEDTLS_X509_SAN_IP_ADDRESS)
                    {
                        std::vector<unsigned char> data;
                        data.resize(san.san.unstructured_name.len);
                        memcpy_s__(&data[0], data.size(), san.san.unstructured_name.p, san.san.unstructured_name.len);

                        retNames->names.push_back(GENERAL_NAME(san.type == MBEDTLS_X509_SAN_DNS_NAME ? GEN_DNS : GEN_IPADD, data));
                    }

                    mbedtls_x509_free_subject_alt_name(&san);

                }
                cur = cur->next;
            }

            return retNames;
        }
    }

    return nullptr;
}

int sk_GENERAL_NAME_num(const stack_st_GENERAL_NAME* sgn)
{
    return sgn->names.size();
}

const GENERAL_NAME* sk_GENERAL_NAME_value(const stack_st_GENERAL_NAME* sgn, size_t num)
{
    if (num < sgn->names.size())
        return &sgn->names[num];
    return nullptr;
}

void GENERAL_NAMES_free(GENERAL_NAME* sgn)
{
    if (sgn)
    {
        stack_st_GENERAL_NAME* stkgn = reinterpret_cast<stack_st_GENERAL_NAME*>(sgn);

        delete stkgn;
    }

}

// SSL CTX

inline int TLS_client_method(void) {
    return MBEDTLS_SSL_IS_CLIENT;
}

inline int TLS_server_method() {
    return MBEDTLS_SSL_IS_SERVER;
}

inline int TLS_method() {
    return TLS_server_method(); // not sure
}

#if __has_include(<evp.h>)
#include <evp.h>
#endif
#if __has_include(<openssl/evp.h>)
#include <openssl/evp.h>
#endif

struct SSL_CTX
{
    SSL_CTX(int endpoint) {
        // own cert and private ket 
        mbedtls_x509_crt_init(&crt);
        mbedtls_pk_init(&pkey);

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "httplib";
        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

        assert(ret == 0);

        mbedtls_ssl_config_init(&conf_);
        mbedtls_ssl_config_defaults(&conf_, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

        // OPTIONAL is not optimal for security, but makes interop easier in this simplified example
        mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_OPTIONAL); // SSL_set_verify will set it to REQUIRED if needed
        //mbedtls_ssl_conf_ca_chain(&conf_, &cacert, NULL);
        mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg);

#if MBEDTLS_DEBUG_OUTPUT_LEVEL // if you want additional mbetls debug output
        mbedtls_ssl_conf_dbg(&conf_, &SSL_CTX::my_debug, stdout);
        mbedtls_debug_set_threshold(MBEDTLS_DEBUG_OUTPUT_LEVEL);
#endif

        store = X509_STORE_new();
    }

    ~SSL_CTX()
    {
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pkey);

        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        mbedtls_ssl_config_free(&conf_);

        X509_STORE_free(store);
    }

    static void my_debug(void* ctx, int debug_level, const char* file, int lineNumber, const char* message)
    {
        char path_short[255];
        strncpy_s__(path_short,sizeof(path_short), file, sizeof(path_short));

#if MBEDTLS_DEBUG_OUTPUT_LEVEL
        ::PathStripPathA(path_short);
#endif

        std::cout << path_short << ":" << lineNumber << " " << message << std::endl;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* Own cert & private key */
    mbedtls_x509_crt crt;
    mbedtls_pk_context pkey;

    mbedtls_ssl_config conf_;

    X509_STORE* store = nullptr;
};


SSL_CTX* SSL_CTX_new(int ssl_method)
{
    return new SSL_CTX(ssl_method);
}

void SSL_CTX_free(SSL_CTX* p)
{
    delete p;
}

int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath)
{
    return 1; // success
}

// SSL_CTX_set_default_verify_paths() specifies that the default locations from which CA certificates are loaded should be used. 
// There is one default directory, one default file and one default store.

int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx)
{
    return 1; // success, mbedtls doesn't have this
}

X509_STORE* SSL_CTX_get_cert_store(const SSL_CTX* ctx)
{
    return ctx->store;
}

void SSL_CTX_set_cert_store(SSL_CTX* ctx, X509_STORE* store)
{
    assert("NOT IMPLEMENTED" == 0);
}

int SSL_CTX_use_certificate(SSL_CTX* ctx, X509* x)
{
    int ret = mbedtls_x509_crt_parse_der(&ctx->crt, x->crt.raw.p, x->crt.raw.len);

    return (ret == 0);
}

// type is not used here, it's PEM only at the moment 

int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type)
{
    //yomei
    //int ret = mbedtls_x509_crt_parse_file(&ctx->crt, file, type);
    int ret = mbedtls_x509_crt_parse_file(&ctx->crt, file);

    return (ret == 0) ? 1 : 0;
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)
{
    if (mbedtls_pk_parse_keyfile(&ctx->pkey, file, NULL, mbedtls_ctr_drbg_random, &ctx->ctr_drbg) == 0)
    {
        return (mbedtls_ssl_conf_own_cert(&ctx->conf_, &ctx->crt, &ctx->pkey) == 0) ? 1 : 0;
    }

    return 0;
}

struct EVP_PKEY {

    EVP_PKEY(const char* file)
        : file_name(file)
    {

    }
    // In-memory key (httplib 0.46 PEM_read_bio_PrivateKey).
    EVP_PKEY(const std::vector<unsigned char>& pem, const char* password)
        : from_memory(true), key_pem(pem)
    {
        if (password) passwd = password;
    }
    ~EVP_PKEY() {

    }

    std::string file_name;
    bool from_memory = false;
    std::vector<unsigned char> key_pem;
    std::string passwd;
};

struct EVP_MD {

};

struct EVP_MD_CTX {

    EVP_MD_CTX();
    ~EVP_MD_CTX();

    void* context = nullptr;

    const EVP_MD* algo = nullptr;
};

const EVP_MD* EVP_md5()
{
    static EVP_MD md;

    return &md;
}

const EVP_MD* EVP_sha256()
{
    static EVP_MD md;

    return &md;
}

const EVP_MD* EVP_sha512()
{
    static EVP_MD md;

    return &md;
}

void EVP_PKEY_free(EVP_PKEY* pkey)
{
    if (pkey)
        delete pkey;
}

int SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey)
{
    if (pkey->from_memory)
    {
        std::vector<unsigned char> buf = pkey->key_pem;
        buf.push_back('\0'); // mbedtls PEM parsing requires a NUL within the length
        const unsigned char* pwd = pkey->passwd.empty()
                                       ? NULL
                                       : (const unsigned char*)pkey->passwd.c_str();
        if (mbedtls_pk_parse_key(&ctx->pkey, &buf[0], buf.size(), pwd,
                                 pkey->passwd.size(), mbedtls_ctr_drbg_random,
                                 &ctx->ctr_drbg) == 0)
        {
            return (mbedtls_ssl_conf_own_cert(&ctx->conf_, &ctx->crt, &ctx->pkey) == 0) ? 1 : 0;
        }
        return 0;
    }
    return SSL_CTX_use_PrivateKey_file(ctx, pkey->file_name.c_str(), 0);
}

#define SSL_OP_BIT(n)  ((uint64_t)1 << (uint64_t)n)

# define SSL_OP_NO_COMPRESSION                           SSL_OP_BIT(17)
# define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   SSL_OP_BIT(16)

long SSL_CTX_set_options(SSL_CTX* ctx, long options) // only for server
{
    // NOT YET IMPLEMENTED

    return 0;
}

# define TLS1_1_VERSION                  0x0302
# define TLS1_2_VERSION                  0x0303
int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version) // only for server
{
    mbedtls_ssl_conf_min_version(&ctx->conf_, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    return 1;
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX* ctx, void* u) // only for server
{
    assert("NOT IMPLEMENTED" == 0);
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file) // only for server
{
    return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

struct X509_STORE_CTX;
typedef int (*SSL_verify_cb)(int, X509_STORE_CTX*);

void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, SSL_verify_cb /*callback*/)
{
    // Map the OpenSSL verify mode onto an mbedTLS authmode. The verify
    // callback itself is not wired into mbedTLS (default verification via
    // SSL_get_verify_result is used); it is accepted for API compatibility
    // with httplib 0.46.
    int authmode = MBEDTLS_SSL_VERIFY_NONE;
    if (mode & SSL_VERIFY_PEER)
        authmode = (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                       ? MBEDTLS_SSL_VERIFY_REQUIRED
                       : MBEDTLS_SSL_VERIFY_OPTIONAL;
    mbedtls_ssl_conf_authmode(&ctx->conf_, authmode);
}


int SSL_CTX_check_private_key(SSL_CTX* ctx)
{
	return 1;
}

void OPENSSL_thread_stop()
{
}
// SSL

struct SSL
{
    SSL(SSL_CTX* ctx)
        : ssl_ctx(ctx)
    {
        mbedtls_ssl_init(&mbedtls_ctx);

        int ret = mbedtls_ssl_setup(&mbedtls_ctx, &ssl_ctx->conf_);
        assert(ret == 0);
    }

    ~SSL()
    {
        mbedtls_ssl_free(&mbedtls_ctx);

        if (rbio)
            delete rbio;

        if (wbio != rbio)
            delete wbio;
    }

    mbedtls_ssl_context mbedtls_ctx;

    BIO* rbio = nullptr;
    BIO* wbio = nullptr;

    /* last SSL error. see SSL_get_error implementation. */
    int last_error = 0;

    SSL_CTX* ssl_ctx = nullptr; // parent context
};

int SSL_get_error(const SSL* ssl, int ret) {
    (void)ret;
    return ssl->last_error;
}

SSL* SSL_new(SSL_CTX* ctx)
{
    return new SSL(ctx);
}

int SSL_shutdown(SSL* ssl)
{
    return 0;
}

void SSL_free(SSL* ssl)
{
    if (ssl)
        delete ssl;
}

void SSL_set_verify(SSL* ssl, int auth_mode, void*)
{
    // not used
}

int SSL_write(SSL* ssl, const void* buf, int num) {

    // use mbedtls_net_send ?

    ssl->last_error = mbedtls_ssl_write(&ssl->mbedtls_ctx, (const unsigned char*)buf, num);
    return ssl->last_error;
}

int SSL_pending(const SSL* ssl)
{
    // mbedtls_ssl_check_pending returns 0 if nothing’s pending, 1 otherwise.
    return mbedtls_ssl_check_pending(&ssl->mbedtls_ctx) > 0;
}

int SSL_read(SSL* ssl, void* buf, int num)
{
    // use mbedtls_net_recv ?
    // TODO: match SSL_ERROR_SYSCALL error code to mbedtls

    ssl->last_error = mbedtls_ssl_read(&ssl->mbedtls_ctx, (unsigned char*)buf, num);
    return ssl->last_error;
}

// SSL_peek_ex() and SSL_peek() are identical to SSL_read_ex() and SSL_read() respectively except 
// no bytes are actually removed from the underlying BIO during the read, so that a subsequent 
// call to SSL_read_ex() or SSL_read() will yield at least the same bytes.
int SSL_peek(SSL* ssl, void* buf, int num) // only used in ClientImpl::process_request
{
    // not supported in mbedtls, but you can use what mbedtls_net_accept uses
    // https://github.com/Mbed-TLS/mbedtls/pull/563
    // https://github.com/Mbed-TLS/mbedtls/issues/551
    // BTW: httlib has httplib::detail::read_socket

    int fd = ssl->rbio->ctx.fd;
    int ret = recvfrom(fd, (char*)buf, num, MSG_PEEK, nullptr, nullptr);

    ssl->last_error = 0;

    if (ret == 0)
        ssl->last_error = SSL_ERROR_ZERO_RETURN;

    return ret; // <= 0 - The read operation was not successful
}

// SSL_connect() initiates the TLS/SSL handshake with a server. The communication channel must already have been set and assigned to the ssl by setting an underlying BIO.
// https://www.openssl.org/docs/man3.1/man3/SSL_connect.html

int SSL_connect(SSL* ssl)
{
    //mbedtls_ssl_conf_verify(&conf, my_cert_verify, this);
    //mbedtls_ssl_set_verify()

    mbedtls_ssl_conf_ca_chain(&ssl->ssl_ctx->conf_, &ssl->ssl_ctx->store->chain, NULL);

    //int ret = mbedtls_ssl_setup(&ssl->mbedtls_ctx, &ssl->ssl_ctx->conf_);
    //assert(ret == 0);

    do {
        ssl->last_error = mbedtls_ssl_handshake(&ssl->mbedtls_ctx);

        if (ssl->last_error < 0)
        {
            assert(0);

            return 0;
        }

    } while (ssl->last_error == MBEDTLS_ERR_SSL_WANT_READ ||
        ssl->last_error == MBEDTLS_ERR_SSL_WANT_WRITE);

    return 1;
}

#define SSL_MODE_AUTO_RETRY 0

void SSL_clear_mode(SSL* ssl, long mode)
{
    // not implemented
}

int SSL_set_tlsext_host_name(SSL* s, const char* name)
{
    return (mbedtls_ssl_set_hostname(&s->mbedtls_ctx, name) == 0) ? 1 : 0;
}

void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio)
{
    ssl->rbio = rbio;
    ssl->wbio = wbio;

    mbedtls_ssl_set_bio(&ssl->mbedtls_ctx, &ssl->rbio->ctx, mbedtls_net_send, mbedtls_net_recv, NULL);
}

#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS    0x00100000L
#define OPENSSL_INIT_LOAD_SSL_STRINGS       0x00200000L
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L

int OPENSSL_init_ssl(uint64_t opts, int settings)
{

    return 1;
}

# define SSL_CTRL_SET_TLSEXT_HOSTNAME            55
/* NameType value from RFC3546 */
# define TLSEXT_NAMETYPE_host_name 0

long SSL_ctrl(SSL* ssl, int cmd, long larg, void* parg)
{
    if (cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME && larg == TLSEXT_NAMETYPE_host_name)
        return SSL_set_tlsext_host_name(ssl, (const char *)parg);
    else
    {
        assert(0);
    }

    return 0;
}

// verification stuff

long SSL_get_verify_result(const SSL* ssl)
{
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl->mbedtls_ctx);
    
    if (flags != 0)
    {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        // match some common error codes

        if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
            return X509_V_ERR_CERT_HAS_EXPIRED;
        else if (flags & MBEDTLS_X509_BADCERT_REVOKED)
            return X509_V_ERR_CERT_REVOKED;
        else if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
            return X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
        else if (flags & MBEDTLS_X509_BADCERT_FUTURE)
            return X509_V_ERR_CERT_NOT_YET_VALID;
        else if (flags & MBEDTLS_X509_BADCRL_FUTURE)
            return X509_V_ERR_CRL_NOT_YET_VALID;
        else
            return X509_V_OK + flags; // no match
    }

    return X509_V_OK;
}

X509* SSL_get_peer_certificate(const SSL* ssl)
{
    std::unique_ptr< X509> ret_cert(new X509());

    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl->mbedtls_ctx);

    if (crt)
    {
        int nParseResult = mbedtls_x509_crt_parse_der(&ret_cert->crt, crt->raw.p, crt->raw.len);

        if (nParseResult == 0)
            return ret_cert.release();
    }

    return nullptr;
}

X509* SSL_get1_peer_certificate(const SSL* ssl)
{
    return SSL_get_peer_certificate(ssl);
}

int SSL_accept(SSL* ssl)
{
    int ret = mbedtls_ssl_handshake(&ssl->mbedtls_ctx);

    if (ret == MBEDTLS_ERR_RSA_VERIFY_FAILED)
    {
        assert("MBEDTLS_ERR_RSA_VERIFY_FAILED issue not solved" == 0);
    }
    //yomei iranai!!
    //assert(ret == 0);

    return (ret == 0) ? 1 : 0;
}

// EVP STUF
/////////////////////////////////////////////////

# define EVP_MAX_MD_SIZE                 64 /* longest known is SHA512 */



EVP_MD_CTX* EVP_MD_CTX_new()
{
    return new EVP_MD_CTX();
}

void EVP_MD_CTX_free(EVP_MD_CTX* ctx)
{
    delete ctx;
}

int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* unused)
{
    ctx->algo = type;

    if (type == EVP_md5())
    {
        ctx->context = malloc(sizeof(mbedtls_md5_context));
        mbedtls_md5_init((mbedtls_md5_context *)ctx->context);
        mbedtls_md5_starts((mbedtls_md5_context*)ctx->context);
    }
    else if (type == EVP_sha256())
    {
        ctx->context = malloc(sizeof(mbedtls_sha256_context));
        mbedtls_sha256_init((mbedtls_sha256_context*)ctx->context);
        mbedtls_sha256_starts((mbedtls_sha256_context*)ctx->context, 0);
    }
    else if (type == EVP_sha512())
    {
        ctx->context = malloc(sizeof(mbedtls_sha512_context));
        mbedtls_sha512_init((mbedtls_sha512_context*)ctx->context);
        mbedtls_sha512_starts((mbedtls_sha512_context*)ctx->context, 0);
    }
    else
    {
        return 0;
    }

    return 1;
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)
{
    if (ctx->algo == EVP_md5())
    {
        mbedtls_md5_update((mbedtls_md5_context*)ctx->context, (const unsigned char* )d, cnt);
    }
    else if (ctx->algo == EVP_sha256())
    {
        mbedtls_sha256_update((mbedtls_sha256_context*)ctx->context, (const unsigned char*)d, cnt);
    }
    else if (ctx->algo == EVP_sha512())
    {
        mbedtls_sha512_update((mbedtls_sha512_context*)ctx->context, (const unsigned char*)d, cnt);
    }
    else
    {
        return 0;
    }

    return 1;
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s)
{
    if (ctx->algo == EVP_md5())
    {
        mbedtls_md5_finish((mbedtls_md5_context*)ctx->context, md);
        *s = 16;
    }
    else if (ctx->algo == EVP_sha256())
    {
        mbedtls_sha256_finish((mbedtls_sha256_context*)ctx->context, md);
        *s = 32;
    }
    else if (ctx->algo == EVP_sha512())
    {
        mbedtls_sha512_finish((mbedtls_sha512_context*)ctx->context, md);
        *s = 64;
    }
    else
    {
        return 0;
    }

    return 1;
}

EVP_MD_CTX::EVP_MD_CTX()
{
    
    
}

EVP_MD_CTX::~EVP_MD_CTX()
{
    if (context)
    {
        if (algo == EVP_md5())
        {
            mbedtls_md5_free((mbedtls_md5_context*)context);
        }
        else if (algo == EVP_sha256())
        {
            mbedtls_sha256_free((mbedtls_sha256_context*)context);
        }
        else if (algo == EVP_sha512())
        {
            mbedtls_sha512_free((mbedtls_sha512_context*)context);
        }

        free(context);
    }
}


// =====================================================================
//  httplib 0.46 compatibility shims (OpenSSL API surface on top of mbedTLS).
//  These are additive; httplib 0.20 does not reference them, so the same
//  bridge builds against both versions.
// =====================================================================

// ---- error queue (mbedTLS has none) --------------------------------
inline unsigned long ERR_get_error() { return 0; }
inline unsigned long ERR_peek_last_error() { return 0; }
inline void ERR_clear_error() {}
inline void ERR_error_string_n(unsigned long e, char* buf, size_t len) {
    if (buf && len) snprintf(buf, len, "error:%08lX", e);
}
#define ERR_GET_REASON(e) ((int)((e) & 0xFFFL))
#ifndef X509_R_CERT_ALREADY_IN_HASH_TABLE
#define X509_R_CERT_ALREADY_IN_HASH_TABLE 101
#endif

// ---- assorted error codes / GENERAL_NAME types ---------------------
#ifndef SSL_ERROR_NONE
#define SSL_ERROR_NONE 0
#endif
#ifndef SSL_ERROR_SSL
#define SSL_ERROR_SSL  1
#endif
#ifndef GEN_EMAIL
#define GEN_EMAIL 1
#endif
#ifndef GEN_URI
#define GEN_URI 6
#endif
#ifndef X509_V_ERR_HOSTNAME_MISMATCH
#define X509_V_ERR_HOSTNAME_MISMATCH 62
#endif

typedef stack_st_GENERAL_NAME GENERAL_NAMES;

// httplib 0.46 frees the SAN list as STACK_OF(GENERAL_NAME)* (== stack here).
inline void GENERAL_NAMES_free(stack_st_GENERAL_NAME* p) { if (p) delete p; }

// ---- BIO / SSL accessors -------------------------------------------
inline void SSL_CTX_clear_mode(SSL_CTX*, long) {}

inline BIO* SSL_get_rbio(const SSL* ssl) { return ssl ? ssl->rbio : nullptr; }

inline const char* SSL_get_servername(const SSL*, int) { return nullptr; }

// ---- hostname verification parameters ------------------------------
typedef SSL X509_VERIFY_PARAM; // the "param" is just the session in this bridge
#ifndef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
#define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4
#endif

inline X509_VERIFY_PARAM* SSL_get0_param(SSL* ssl) { return ssl; }
inline void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM*, unsigned int) {}
inline int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* p, const char* name,
                                       size_t namelen) {
    if (!p || !name) return 0;
    std::string h = (namelen > 0) ? std::string(name, namelen) : std::string(name);
    return (mbedtls_ssl_set_hostname(&p->mbedtls_ctx, h.c_str()) == 0) ? 1 : 0;
}

// ---- X509_NAME helpers ---------------------------------------------
inline X509_NAME* X509_get_issuer_name(const X509* x) {
    char buf[512];
    return (mbedtls_x509_dn_gets(buf, sizeof(buf), &x->crt.issuer) > 0)
               ? new X509_NAME(buf)
               : nullptr;
}

inline char* X509_NAME_oneline(const X509_NAME* name, char* buf, int size) {
    if (!name) return nullptr;
    if (buf && size > 0) {
        strncpy_s__(buf, (size_t)size, name->str.c_str(), name->str.size());
        return buf;
    }
    char* out = (char*)malloc(name->str.size() + 1);
    if (out) {
        memcpy(out, name->str.c_str(), name->str.size());
        out[name->str.size()] = '\0';
    }
    return out;
}

inline X509_NAME* X509_NAME_dup(X509_NAME* n) {
    return n ? new X509_NAME(n->str.c_str()) : nullptr;
}
inline void X509_NAME_free(X509_NAME* n) { if (n) delete n; }

// ---- STACK_OF(X509_NAME) (client CA name list) ---------------------
struct stack_st_X509_NAME { std::vector<X509_NAME*> names; };

inline X509_NAME* sk_X509_NAME_new_null() {
    return reinterpret_cast<X509_NAME*>(new stack_st_X509_NAME());
}
inline int sk_X509_NAME_push(X509_NAME* stk, X509_NAME* nm) {
    auto s = reinterpret_cast<stack_st_X509_NAME*>(stk);
    s->names.push_back(nm);
    return (int)s->names.size();
}
typedef void (*sk_X509_NAME_freefunc)(X509_NAME*);
inline void sk_X509_NAME_pop_free(X509_NAME* stk, sk_X509_NAME_freefunc f) {
    auto s = reinterpret_cast<stack_st_X509_NAME*>(stk);
    if (s) {
        if (f) for (auto n : s->names) f(n);
        delete s;
    }
}

inline void SSL_CTX_set_client_CA_list(SSL_CTX*, X509_NAME* list) {
    // mbedTLS does not send CA name hints; take ownership and release.
    if (list) sk_X509_NAME_pop_free(list, X509_NAME_free);
}

inline X509_NAME* SSL_load_client_CA_file(const char* file) {
    if (!file) return nullptr;
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    if (mbedtls_x509_crt_parse_file(&chain, file) != 0) {
        mbedtls_x509_crt_free(&chain);
        return nullptr;
    }
    X509_NAME* stk = sk_X509_NAME_new_null();
    for (mbedtls_x509_crt* c = &chain; c != nullptr; c = c->next) {
        char buf[512];
        if (mbedtls_x509_dn_gets(buf, sizeof(buf), &c->subject) > 0)
            sk_X509_NAME_push(stk, new X509_NAME(buf));
    }
    mbedtls_x509_crt_free(&chain);
    return stk;
}

// ---- certificate validity / serial ---------------------------------
inline const ASN1_TIME* X509_get0_notBefore(const X509* x) {
    X509* xx = const_cast<X509*>(x);
    xx->not_before_.epoch = mbedtls_x509_time_to_epoch(&xx->crt.valid_from);
    xx->not_before_.is_set = true;
    return &xx->not_before_;
}
inline const ASN1_TIME* X509_get0_notAfter(const X509* x) {
    X509* xx = const_cast<X509*>(x);
    xx->not_after_.epoch = mbedtls_x509_time_to_epoch(&xx->crt.valid_to);
    xx->not_after_.is_set = true;
    return &xx->not_after_;
}

inline ASN1_TIME* ASN1_TIME_new() { return new ASN1_TIME(); }
inline void ASN1_TIME_free(ASN1_TIME* t) { if (t) delete t; }
inline ASN1_TIME* ASN1_TIME_set(ASN1_TIME* t, time_t when) {
    if (t) { t->epoch = when; t->is_set = true; }
    return t;
}
inline int ASN1_TIME_diff(int* pday, int* psec, const ASN1_TIME* from,
                          const ASN1_TIME* to) {
    if (!from || !to) return 0;
    long long diff = (long long)to->epoch - (long long)from->epoch;
    if (pday) *pday = (int)(diff / 86400);
    if (psec) *psec = (int)(diff % 86400);
    return 1;
}

inline ASN1_INTEGER* X509_get_serialNumber(X509* x) {
    if (!x) return nullptr;
    x->serial_cache_.bytes.assign(x->crt.serial.p,
                                  x->crt.serial.p + x->crt.serial.len);
    return &x->serial_cache_;
}

struct BIGNUM { std::vector<unsigned char> bytes; };
inline BIGNUM* ASN1_INTEGER_to_BN(const ASN1_INTEGER* a, BIGNUM*) {
    BIGNUM* bn = new BIGNUM();
    if (a) bn->bytes = a->bytes;
    return bn;
}
inline char* BN_bn2hex(const BIGNUM* bn) {
    size_t n = bn ? bn->bytes.size() : 0;
    char* out = (char*)malloc(n * 2 + 1);
    if (!out) return nullptr;
    static const char* hex = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = hex[(bn->bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[bn->bytes[i] & 0xF];
    }
    out[n * 2] = '\0';
    return out;
}
inline void BN_free(BIGNUM* bn) { if (bn) delete bn; }
inline void OPENSSL_free(void* p) { if (p) free(p); }

// ---- DER export / refcount -----------------------------------------
inline int i2d_X509(X509* x, unsigned char** out) {
    if (!x) return -1;
    int len = (int)x->crt.raw.len;
    if (out && *out) {
        memcpy(*out, x->crt.raw.p, x->crt.raw.len);
        *out += len;
    }
    return len;
}
inline int X509_up_ref(X509*) { return 1; }

// ---- X509_STORE object enumeration (not backed by mbedTLS) ---------
struct X509_OBJECT {};
#ifndef X509_LU_X509
#define X509_LU_X509 1
#endif
inline X509_OBJECT* X509_STORE_get0_objects(X509_STORE*) { return nullptr; }
inline int sk_X509_OBJECT_num(const X509_OBJECT*) { return 0; }
inline X509_OBJECT* sk_X509_OBJECT_value(const X509_OBJECT*, int) { return nullptr; }
inline int X509_OBJECT_get_type(const X509_OBJECT*) { return 0; }
inline X509* X509_OBJECT_get0_X509(const X509_OBJECT*) { return nullptr; }

// ---- verify callback context (stubs; callback path not wired) ------
struct X509_STORE_CTX {};
inline int SSL_get_ex_data_X509_STORE_CTX_idx() { return 0; }
inline void* X509_STORE_CTX_get_ex_data(X509_STORE_CTX*, int) { return nullptr; }
inline X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX*) { return nullptr; }
inline int X509_STORE_CTX_get_error_depth(X509_STORE_CTX*) { return 0; }
inline int X509_STORE_CTX_get_error(X509_STORE_CTX*) { return 0; }

inline const char* X509_verify_cert_error_string(long n) {
    switch (n) {
    case X509_V_OK: return "ok";
    case X509_V_ERR_CERT_HAS_EXPIRED: return "certificate has expired";
    case X509_V_ERR_CERT_NOT_YET_VALID: return "certificate is not yet valid";
    case X509_V_ERR_CERT_REVOKED: return "certificate revoked";
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: return "self signed certificate";
    default: return "certificate verification failed";
    }
}

// ---- in-memory PEM reading -----------------------------------------
inline X509* PEM_read_bio_X509(BIO* bp, void*, void*, void*) {
    if (!bp || !bp->is_mem) return nullptr;
    static const std::string kBegin = "-----BEGIN CERTIFICATE-----";
    static const std::string kEnd   = "-----END CERTIFICATE-----";
    std::string hay((const char*)bp->mem.data(), bp->mem.size());
    size_t b = hay.find(kBegin, bp->mem_pos);
    if (b == std::string::npos) return nullptr;
    size_t e = hay.find(kEnd, b);
    if (e == std::string::npos) return nullptr;
    e += kEnd.size();
    bp->mem_pos = e;
    std::vector<unsigned char> pem(hay.begin() + b, hay.begin() + e);
    pem.push_back('\n');
    pem.push_back('\0'); // mbedtls PEM length must include the NUL terminator
    std::unique_ptr<X509> crt(new X509());
    if (mbedtls_x509_crt_parse(&crt->crt, pem.data(), pem.size()) == 0)
        return crt.release();
    return nullptr;
}

inline EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, void*, void*, void* u) {
    if (!bp || !bp->is_mem) return nullptr;
    std::vector<unsigned char> pem(bp->mem.begin() + bp->mem_pos, bp->mem.end());
    bp->mem_pos = bp->mem.size();
    if (pem.empty()) return nullptr;
    const char* password = static_cast<const char*>(u);
    return new EVP_PKEY(pem, password);
}

// ---- hostname matching (post-handshake) ----------------------------
inline bool bridge_ci_equal_(const char* a, size_t alen, const char* b, size_t blen) {
    if (alen != blen) return false;
    for (size_t i = 0; i < alen; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return true;
}
inline bool bridge_match_dns_(const char* pat, size_t patlen, const char* host) {
    if (patlen >= 2 && pat[0] == '*' && pat[1] == '.') {
        const char* dot = strchr(host, '.');
        if (!dot) return false;
        const char* hrest = dot + 1;
        return bridge_ci_equal_(pat + 2, patlen - 2, hrest, strlen(hrest));
    }
    return bridge_ci_equal_(pat, patlen, host, strlen(host));
}

inline int X509_check_host(X509* x, const char* name, size_t namelen,
                           unsigned int /*flags*/, char** /*peername*/) {
    if (!x || !name) return 0;
    std::string host = (namelen > 0) ? std::string(name, namelen) : std::string(name);
    bool san_dns_present = false;
    const mbedtls_x509_crt* crt = &x->crt;
    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        const mbedtls_x509_sequence* cur = &crt->subject_alt_names;
        mbedtls_x509_subject_alternative_name san;
        while (cur) {
            memset(&san, 0, sizeof(san));
            if (mbedtls_x509_parse_subject_alt_name(&cur->buf, &san) == 0) {
                if (san.type == MBEDTLS_X509_SAN_DNS_NAME) {
                    san_dns_present = true;
                    bool m = bridge_match_dns_(
                        (const char*)san.san.unstructured_name.p,
                        san.san.unstructured_name.len, host.c_str());
                    mbedtls_x509_free_subject_alt_name(&san);
                    if (m) return 1;
                    cur = cur->next;
                    continue;
                }
                mbedtls_x509_free_subject_alt_name(&san);
            }
            cur = cur->next;
        }
    }
    if (san_dns_present) return 0; // SAN present, none matched -> RFC6125: fail
    // Fall back to the subject CommonName.
    X509_NAME* subj = X509_get_subject_name(x);
    if (subj) {
        char cn[256];
        int l = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
        delete subj;
        if (l > 0) return bridge_match_dns_(cn, (size_t)l, host.c_str()) ? 1 : 0;
    }
    return 0;
}

inline int X509_check_ip_asc(X509* x, const char* ipasc, unsigned int /*flags*/) {
    if (!x || !ipasc) return 0;
    unsigned char target[16];
    size_t tlen = 0;
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ipasc, &a4) == 1) { memcpy(target, &a4, 4); tlen = 4; }
    else if (inet_pton(AF_INET6, ipasc, &a6) == 1) { memcpy(target, &a6, 16); tlen = 16; }
    else return 0;
    const mbedtls_x509_crt* crt = &x->crt;
    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        const mbedtls_x509_sequence* cur = &crt->subject_alt_names;
        mbedtls_x509_subject_alternative_name san;
        while (cur) {
            memset(&san, 0, sizeof(san));
            if (mbedtls_x509_parse_subject_alt_name(&cur->buf, &san) == 0) {
                if (san.type == MBEDTLS_X509_SAN_IP_ADDRESS &&
                    san.san.unstructured_name.len == tlen &&
                    memcmp(san.san.unstructured_name.p, target, tlen) == 0) {
                    mbedtls_x509_free_subject_alt_name(&san);
                    return 1;
                }
                mbedtls_x509_free_subject_alt_name(&san);
            }
            cur = cur->next;
        }
    }
    return 0;
}


// =====================================================================
//  httplib 0.53 compatibility shims.
//  Also additive: nothing here is referenced by httplib 0.20 / 0.46.
// =====================================================================

// ---- X509_STORE object snapshot ------------------------------------
// OpenSSL 3.3+ deprecated X509_STORE_get0_objects() in favour of the
// snapshot-taking X509_STORE_get1_objects(); OPENSSL_VERSION_NUMBER above
// puts httplib on that path. The bridge has no store enumeration, so both
// variants report an empty list and httplib bails out on the null check.
inline X509_OBJECT* X509_STORE_get1_objects(X509_STORE*) { return nullptr; }
inline void X509_OBJECT_free(X509_OBJECT*) {}
typedef void (*sk_X509_OBJECT_freefunc)(X509_OBJECT*);
inline void sk_X509_OBJECT_pop_free(X509_OBJECT*, sk_X509_OBJECT_freefunc) {}

// ---- X509_NAME entry enumeration -----------------------------------
// httplib 0.53 reads the subject CN through the index / entry / data
// triplet rather than the deprecated X509_NAME_get_text_by_NID(). mbedTLS
// only hands us the flattened DN produced by mbedtls_x509_dn_gets(), so
// parse that back into entries. Each value is kept in a GENERAL_NAME so the
// existing ASN1_STRING_get0_data() / ASN1_STRING_length() accessors apply.

// NID values as in OpenSSL, except commonName which the bridge already
// defines as 1 above.
#define NID_countryName            14
#define NID_localityName           15
#define NID_stateOrProvinceName    16
#define NID_organizationName       17
#define NID_organizationalUnitName 18
#define NID_pkcs9_emailAddress     48
#define NID_serialNumber           105

struct X509_NAME_ENTRY {
    X509_NAME_ENTRY(int n, const std::vector<unsigned char>& v)
        : nid(n), value(0, v)
    {
    }

    int nid;
    GENERAL_NAME value;
};

inline X509_NAME_OPENSSL::~X509_NAME_OPENSSL()
{
    for (size_t i = 0; i < entries.size(); i++) delete entries[i];
}

inline int bridge_nid_from_dn_attr_(const std::string& a) {
    if (a == "CN") return NID_commonName;
    if (a == "C") return NID_countryName;
    if (a == "L") return NID_localityName;
    if (a == "ST") return NID_stateOrProvinceName;
    if (a == "O") return NID_organizationName;
    if (a == "OU") return NID_organizationalUnitName;
    if (a == "emailAddress") return NID_pkcs9_emailAddress;
    if (a == "serialNumber") return NID_serialNumber;
    return 0;
}

// mbedtls_x509_dn_gets() writes `AT=value, AT=value, ...` and backslash-escapes
// any separator that occurs inside a value.
inline void bridge_parse_dn_(X509_NAME_OPENSSL* name) {
    if (!name->entries.empty()) return;
    const std::string& s = name->str;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == ',')) i++;
        size_t eq = s.find('=', i);
        if (eq == std::string::npos) break;
        std::string attr = s.substr(i, eq - i);
        std::vector<unsigned char> val;
        size_t j = eq + 1;
        for (; j < s.size(); j++) {
            if (s[j] == '\\' && j + 1 < s.size()) {
                val.push_back((unsigned char) s[++j]);
                continue;
            }
            if (s[j] == ',') break;
            val.push_back((unsigned char) s[j]);
        }
        name->entries.push_back(new X509_NAME_ENTRY(bridge_nid_from_dn_attr_(attr), val));
        i = j;
    }
}

inline int X509_NAME_entry_count(X509_NAME_OPENSSL* name) {
    if (!name) return 0;
    bridge_parse_dn_(name);
    return (int) name->entries.size();
}

inline int X509_NAME_get_index_by_NID(X509_NAME_OPENSSL* name, int nid, int lastpos) {
    if (!name) return -1;
    bridge_parse_dn_(name);
    for (int i = (lastpos < 0) ? 0 : lastpos + 1; i < (int) name->entries.size(); i++) {
        if (name->entries[i]->nid == nid) return i;
    }
    return -1;
}

inline X509_NAME_ENTRY* X509_NAME_get_entry(X509_NAME_OPENSSL* name, int idx) {
    if (!name) return nullptr;
    bridge_parse_dn_(name);
    if (idx < 0 || idx >= (int) name->entries.size()) return nullptr;
    return name->entries[idx];
}

inline const GENERAL_NAME* X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY* e) {
    return e ? &e->value : nullptr;
}

#endif // CPPHTTPLIB_HTTPLIB_MBEDTLS_H
