#include "observathor/core/tls/TlsContext.h"
#include <filesystem>
 #ifdef OBSERVATHOR_HAVE_OPENSSL
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#endif

namespace observathor::core::tls {
std::shared_ptr<TlsContext> TlsContext::create(const CertConfig& cfg){
    auto ctx = std::shared_ptr<TlsContext>(new TlsContext(cfg));
#ifdef OBSERVATHOR_HAVE_OPENSSL
    // Initialize OpenSSL once (idempotent)
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    auto loadPemFile = [](const std::string& path){ return std::filesystem::exists(path); };
    // Default paths if none provided
    std::string caCertPath = cfg.caCertPath.empty() ? "observathor_root_ca.pem" : cfg.caCertPath;
    std::string caKeyPath  = cfg.caKeyPath.empty()  ? "observathor_root_ca.key" : cfg.caKeyPath;

    bool haveCert = loadPemFile(caCertPath);
    bool haveKey  = loadPemFile(caKeyPath);
    auto log_fpr = [&](X509* cert){
        if(!cert) return;
        unsigned char md[EVP_MAX_MD_SIZE]; unsigned int n=0;
        if(!X509_digest(cert, EVP_sha256(), md, &n)) return;
        std::string fp; fp.reserve(n*3);
        static const char* h="0123456789ABCDEF"; for(unsigned i=0;i<n;++i){ unsigned char b=md[i]; fp.push_back(h[b>>4]); fp.push_back(h[b&0xF]); if(i+1<n) fp.push_back(':'); }
        fprintf(stdout, "[INFO] %lld CA SHA256 fingerprint %s\n", (long long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(), fp.c_str());
    };

    if (!haveCert || !haveKey) {
    fprintf(stdout, "[INFO] %lld generating new root CA (cert=%s key=%s)\n", (long long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(), caCertPath.c_str(), caKeyPath.c_str());
    if (!cfg.generateIfMissing) {
            return ctx; // leave init_ok_ false
        }
        // Generate new self-signed root CA (very minimal; improvement later)
        EVP_PKEY* pkey = EVP_PKEY_new();
        BIGNUM* bn = BN_new(); BN_set_word(bn, RSA_F4);
        RSA* rsa = RSA_new(); RSA_generate_key_ex(rsa, 2048, bn, nullptr); BN_free(bn);
        EVP_PKEY_assign_RSA(pkey, rsa);
        X509* cert = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 315360000L); // ~10 years
        X509_set_version(cert, 2);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"XX", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Observathor", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Observathor Root CA", -1, -1, 0);
        X509_set_issuer_name(cert, name);
        // CA basic constraints
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, (char*)"critical,CA:TRUE");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, (char*)"keyCertSign,cRLSign");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
        X509_sign(cert, pkey, EVP_sha256());
        ctx->caCert_ = cert; ctx->caKey_ = pkey; ctx->init_ok_ = true;
        // Persist if paths given
        {
            FILE* f = fopen(caCertPath.c_str(), "wb"); if(f){ PEM_write_X509(f, cert); fclose(f);} 
        }
        {
            FILE* f = fopen(caKeyPath.c_str(), "wb"); if(f){ PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr); fclose(f);} 
        }
        ctx->cfg_.caCertPath = caCertPath;        
        ctx->cfg_.caKeyPath = caKeyPath;
        log_fpr(cert);
    } else {
        fprintf(stdout, "[INFO] %lld loading existing root CA (cert=%s key=%s)\n", (long long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(), caCertPath.c_str(), caKeyPath.c_str());
        // Load existing
        FILE* fcert = fopen(caCertPath.c_str(), "rb"); if (fcert) { ctx->caCert_ = PEM_read_X509(fcert, nullptr, nullptr, nullptr); fclose(fcert);} 
        FILE* fkey  = fopen(caKeyPath.c_str(),  "rb"); if (fkey)  { ctx->caKey_  = PEM_read_PrivateKey(fkey, nullptr, nullptr, nullptr); fclose(fkey);} 
        if (ctx->caCert_ && ctx->caKey_) ctx->init_ok_ = true;
        ctx->cfg_.caCertPath = caCertPath;
        ctx->cfg_.caKeyPath = caKeyPath;
        log_fpr(ctx->caCert_);
    }
    if (ctx->init_ok_) {
        ctx->clientCtx_ = SSL_CTX_new(TLS_client_method());
        ctx->serverCtxTemplate_ = SSL_CTX_new(TLS_server_method());
        // We will supply per-connection certs later; set options
        SSL_CTX_set_options(ctx->serverCtxTemplate_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_options(ctx->clientCtx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    }
#endif
    return ctx;
}
#ifdef OBSERVATHOR_HAVE_OPENSSL
TlsContext::LeafCertKey TlsContext::generate_leaf(const std::string& hostname) {
    LeafCertKey out{};
    if (!init_ok_) return out;
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIGNUM* bn = BN_new(); BN_set_word(bn, RSA_F4);
    RSA* rsa = RSA_new(); RSA_generate_key_ex(rsa, 2048, bn, nullptr); BN_free(bn);
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509* cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)(std::hash<std::string>{}(hostname) & 0x7FFFFFFF));
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year
    X509_set_version(cert, 2);
    X509_set_pubkey(cert, pkey);
    // Subject / issuer
    X509_NAME* subj = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subj, "C", MBSTRING_ASC, (unsigned char*)"XX", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC, (unsigned char*)"Observathor", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (unsigned char*)hostname.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(caCert_));
    // SubjectAltName
    std::string san = "DNS:" + hostname;
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, (char*)san.c_str());
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    // Extended Key Usage (server auth)
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage, (char*)"serverAuth");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    // Basic constraints CA:FALSE
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, (char*)"CA:FALSE");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    // Key usage for TLS server cert
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, (char*)"digitalSignature,keyEncipherment");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    X509_sign(cert, caKey_, EVP_sha256());
    out.cert = cert; out.pkey = pkey; return out;
}

TlsContext::LeafCertKey TlsContext::get_or_create_leaf(const std::string& hostname) {
    auto it = leafCache_.find(hostname);
    if (it != leafCache_.end()) return it->second;
    auto leaf = generate_leaf(hostname);
    leafCache_[hostname] = leaf;
    return leaf;
}

std::string TlsContext::export_ca_pem() const {
    std::string out;
    if (!caCert_) return out;
    BIO* mem = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(mem, caCert_)) {
        char* data = nullptr; long len = BIO_get_mem_data(mem, &data);
        if (len > 0 && data) out.assign(data, (size_t)len);
    }
    BIO_free(mem);
    return out;
}

std::string TlsContext::export_ca_der() const {
    std::string out; if(!caCert_) return out; unsigned char* buf=nullptr; int len = i2d_X509(caCert_, &buf); if(len>0 && buf){ out.assign(reinterpret_cast<char*>(buf), (size_t)len); OPENSSL_free(buf);} return out;
}

std::string TlsContext::ca_fingerprint_sha256() const {
    if(!caCert_) return {};
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int n=0;
    if(!X509_digest(caCert_, EVP_sha256(), md, &n)) return {};
    std::string out; out.reserve(n*3);
    static const char* hex = "0123456789ABCDEF";
    for(unsigned i=0;i<n;++i){ unsigned char b=md[i]; out.push_back(hex[b>>4]); out.push_back(hex[b&0xF]); if(i+1<n) out.push_back(':'); }
    return out;
}
#endif
}
