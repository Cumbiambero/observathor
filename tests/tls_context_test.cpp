#include "observathor/core/tls/TlsContext.h"
#include <cassert>
#include <filesystem>
#include <string>
#include <cstdio>
#include <iostream>

using namespace observathor::core::tls;

static std::string tmp_name(const char* base){
    // Simple unique-ish filename in current working directory
    static int counter = 0;
    return std::string(base) + std::to_string(++counter) + ".pem";
}

int main(){
#ifdef OBSERVATHOR_HAVE_OPENSSL
    // 1. Generate new CA when files missing
    std::string certPath = "test_root_ca_cert.pem";
    std::string keyPath  = "test_root_ca_key.pem";
    if (std::filesystem::exists(certPath)) std::filesystem::remove(certPath);
    if (std::filesystem::exists(keyPath)) std::filesystem::remove(keyPath);
    CertConfig cfg{certPath, keyPath, true};
    auto ctx1 = TlsContext::create(cfg);
    assert(ctx1->has_ca());
    assert(std::filesystem::exists(certPath));
    assert(std::filesystem::exists(keyPath));
    auto fp1 = ctx1->ca_fingerprint_sha256();
    assert(!fp1.empty());

    // 2. Reload existing CA (should not regenerate; fingerprint stable)
    auto ctx2 = TlsContext::create(cfg);
    assert(ctx2->has_ca());
    auto fp2 = ctx2->ca_fingerprint_sha256();
    assert(fp1 == fp2);

    // 3. export_ca_pem / export_ca_der sanity
    auto pemStr = ctx2->export_ca_pem();
    assert(!pemStr.empty());
    // Quick sanity: PEM contains BEGIN CERTIFICATE
    assert(pemStr.find("BEGIN CERTIFICATE") != std::string::npos);
    auto derStr = ctx2->export_ca_der();
    assert(!derStr.empty());

    // 4. generateIfMissing=false with missing files -> no CA
    std::string missingCert = "nonexistent_ca_cert_test.pem";
    std::string missingKey  = "nonexistent_ca_key_test.pem";
    if (std::filesystem::exists(missingCert)) std::filesystem::remove(missingCert);
    if (std::filesystem::exists(missingKey)) std::filesystem::remove(missingKey);
    CertConfig cfgNoGen{missingCert, missingKey, false};
    auto ctx3 = TlsContext::create(cfgNoGen);
    assert(!ctx3->has_ca());

    // 5. Leaf certificate generation and caching
    auto leaf1 = ctx2->get_or_create_leaf("example.com");
    assert(leaf1.cert && leaf1.pkey);
    auto leaf2 = ctx2->get_or_create_leaf("example.com");
    // Pointers should match (cached)
    assert(leaf1.cert == leaf2.cert);
    assert(leaf1.pkey == leaf2.pkey);

    // Cleanup generated files
    std::filesystem::remove(certPath);
    std::filesystem::remove(keyPath);
    return 0;
#else
    // OpenSSL absent: nothing to test
    return 0;
#endif
}
