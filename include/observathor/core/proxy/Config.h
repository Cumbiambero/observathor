#pragma once
#include <cstddef>
namespace observathor::core::proxy {
struct Config {
    // Deprecated: legacy single-shot capture limit (ignored by streaming path if >0)
    std::size_t capture_bytes_limit { 0 };
    const char* capture_file_path { nullptr };
    // New dynamic capture controls
    std::size_t perTransactionSoftLimit { 128 * 1024 }; // keep this much in memory before considering spill
    std::size_t perTransactionHardLimit { 8 * 1024 * 1024 }; // absolute max to buffer before forced spill (safety)
    std::size_t spillThreshold { 1024 * 1024 }; // when body size exceeds this, continue in file
    std::size_t globalMemoryBudget { 256 * 1024 * 1024 }; // total in‑RAM budget for captured bodies

    // TLS MITM settings
    bool enableTlsMitm { false };              // master switch to intercept CONNECT and perform TLS MITM
    const char* caCertPath { nullptr };        // path to root CA certificate (PEM) for signing issued leaf certs
    const char* caKeyPath { nullptr };         // path to root CA private key (PEM)
    bool generateCaIfMissing { true };         // auto-generate root CA if files not present
    // Runtime controls (populated after construction in server / UI)
    // These are raw pointers/strings for initial CLI config; dynamic runtime state lives elsewhere.
    const char* mitmAllowList { nullptr };     // comma-separated globs of hosts to intercept (nullptr => all unless denied)
    const char* mitmDenyList { nullptr };      // comma-separated globs of hosts to exclude from interception
};
}
