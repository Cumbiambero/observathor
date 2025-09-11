#pragma once
#include <string>
#include <memory>
#include <unordered_map>

// export_ca_pem is available always (returns empty if OpenSSL absent)
#ifdef OBSERVATHOR_HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

namespace observathor::core::tls {
struct CertConfig {
    std::string caCertPath;   // path to root CA certificate (PEM)
    std::string caKeyPath;    // path to root CA private key (PEM)
    bool generateIfMissing{true};
};

class TlsContext {
public:
    static std::shared_ptr<TlsContext> create(const CertConfig& cfg);
    const CertConfig& config() const { return cfg_; }
    // Future: methods to create per-host certificates and wrap sockets in TLS.

#ifdef OBSERVATHOR_HAVE_OPENSSL
    SSL_CTX* client_ssl_ctx() const { return clientCtx_; }
    SSL_CTX* server_ssl_ctx_template() const { return serverCtxTemplate_; }
    bool has_ca() const { return init_ok_ && caCert_ && caKey_; }
    // Returns PEM string of root CA certificate (empty if unavailable)
    std::string export_ca_pem() const;
    // Returns DER (binary) of root CA certificate
    std::string export_ca_der() const;
    // Returns SHA-256 fingerprint (hex, colon separated) of root CA cert (empty if unavailable)
    std::string ca_fingerprint_sha256() const;
    // Get or create a server SSL* for a given hostname using a generated leaf cert.
    // For now we expose a method to obtain (cert, pkey) pair; later we can wrap socket creation.
    struct LeafCertKey { X509* cert{nullptr}; EVP_PKEY* pkey{nullptr}; };
    LeafCertKey get_or_create_leaf(const std::string& hostname);
#endif // OBSERVATHOR_HAVE_OPENSSL
private:
    explicit TlsContext(CertConfig cfg) : cfg_(std::move(cfg)) {}
    CertConfig cfg_;
#ifdef OBSERVATHOR_HAVE_OPENSSL
    bool init_ok_{false};
    X509* caCert_{nullptr};
    EVP_PKEY* caKey_{nullptr};
    SSL_CTX* clientCtx_{nullptr};
    SSL_CTX* serverCtxTemplate_{nullptr};
    std::unordered_map<std::string, LeafCertKey> leafCache_;
    LeafCertKey generate_leaf(const std::string& hostname);
#endif
};
}
