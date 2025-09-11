# Observathor

Cross-platform open-source HTTP(S) interception and inspection proxy (early prototype).

## Status
Early prototype. Core HTTP proxying, CONNECT tunneling, streaming capture, chunked decoding. TLS (OpenSSL) always compiled; a root CA is generated/loaded at startup so you can export it immediately. MITM interception is opt-in at runtime (`--enable-mitm`). GUI prototype (ImGui) shows captured transactions.

## Guiding Principles
- C++23 core, minimal third-party dependencies
- Clean, expressive code with self-documenting names instead of comments
- Pluggable UI (initially headless CLI; future native desktop or web front-end)
- Observable events, immutable transaction records
- Efficient streaming and low allocations

## Roadmap (High Level)
1. Core networking abstraction upgrade (platform-independent sockets, remove direct WinSock usage behind interface)
2. Basic HTTP request parsing and upstream forwarding
3. CONNECT handling (tunneling)
4. Transaction capture (headers, partial bodies, timings)
5. Pluggable storage (in-memory first, then optional SQLite)
6. Root CA generation and TLS MITM (configurable, safe defaults)
7. HTTP/2 and compression decoding
8. UI prototype (evaluate Qt vs native host vs web)
9. Filtering, search, rewriting rules
10. Scripting hooks (possibly WASM or embedded scripting)

## Build / Features Snapshot
- Single-thread accept loop with internal task queue polling
- HTTP/1.1 parsing & upstream forwarding (absolute-form rewritten)
- CONNECT: either tunnel (default) or decrypt (MITM) when enabled & trusted
- Streaming body capture with spill-to-disk and per/global memory budgets
- Chunked transfer decoding (request & response) captured decoded while forwarding raw
- NDJSON file store (one JSON object per line) + session export/import groundwork
- ImGui prototype UI (transaction table + detail pane, hex/raw toggles)
- TLS MITM: self-signed root CA generation & per-host leaf cert issuance (OpenSSL)

### Configure & Build (Windows PowerShell example)
Quick presets (Visual Studio generator by default on Windows via CMakePresets.json):
```
cmake --preset debug
cmake --build --preset debug --parallel
```
Or Release:
```
cmake --preset release
cmake --build --preset release --parallel
```
Static OpenSSL preference (debug):
```
cmake --preset debug-static-openssl
cmake --build --preset debug-static-openssl --parallel
```
Generated build directories (multi-config Ninja): `build`, `build-release`.
If you prefer Ninja instead of Visual Studio, install Ninja (e.g. `choco install ninja`) and change the `generator` field in `CMakePresets.json` to `Ninja Multi-Config`.

OpenSSL is required (set `OPENSSL_ROOT_DIR` if not autodetected).
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```
Static (preferred single-binary) build via vcpkg:
```
vcpkg install openssl:x64-windows-static
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static -DOBSERVATHOR_PREFER_STATIC_OPENSSL=ON -DOPENSSL_USE_STATIC_LIBS=ON
cmake --build build --config Release
```
Linux (example, using system OpenSSL static dev packages if available):
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOBSERVATHOR_PREFER_STATIC_OPENSSL=ON
cmake --build build --config Release
```
macOS (clang, system or brew OpenSSL):
```
brew install openssl
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOBSERVATHOR_PREFER_STATIC_OPENSSL=ON -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
cmake --build build --config Release
```
If static fails (missing static libs), disable with `-DOBSERVATHOR_PREFER_STATIC_OPENSSL=OFF`.
Run CLI proxy:
```
build/Release/observathor_cli.exe --port 8888 --capture-file captures.ndjson
```
Run GUI prototype:
### Run Helper Script
PowerShell helper (`scripts/run-observathor.ps1`) wraps launching GUI or CLI binary:
```
pwsh -File scripts/run-observathor.ps1 -BuildConfig Debug -Mitm -Allow "*.example.com" -Deny "auth.*"
```
Flags:
- `-Cli` run CLI instead of GUI
- `-BuildConfig` Debug/Release (default Debug)
- `-ListenHost` host bind (default 127.0.0.1)
- `-ListenPort` port (default 8080)
- `-Mitm` enable TLS MITM
- `-Allow` comma or semicolon separated glob list (optional)
- `-Deny` comma or semicolon separated glob list (optional)

```
build/Release/observathor_imgui.exe --port 8888 --capture-file captures.ndjson
```

### Tunneling vs MITM
By default HTTPS requests via CONNECT are tunneled: encrypted bytes pass through untouched (privacy-preserving, but opaque).

When TLS MITM is enabled (`--enable-mitm`), Observathor terminates TLS from the client using a locally-generated (or provided) root CA, issues a per-host leaf certificate on the fly, then establishes its own TLS connection upstream. This allows full inspection & modification of HTTP over TLS. Clients MUST trust the root CA or they will see certificate warnings.

Enable MITM (root CA auto-generated if absent):
```
observathor_cli --port 8888 --enable-mitm --ca-cert root_ca.pem --ca-key root_ca_key.pem --export-ca exported_root_ca.pem --export-ca-der exported_root_ca.der
```
GUI variant (same flags supported):
```
observathor_imgui --port 8888 --enable-mitm --ca-cert root_ca.pem --ca-key root_ca_key.pem
```
Export CA from GUI using the "Export CA (PEM / DER)" buttons or fetch via internal endpoints (below). The CA context exists even if MITM isn't enabled yet, so you can distribute and trust it first, then restart with `--enable-mitm`.

### Exporting the Root CA
CLI flags:
- `--export-ca <file>` (PEM)
- `--export-ca-der <file>` (DER)
 - `--regenerate-ca` (delete existing CA files before recreating)

GUI buttons always available (even if MITM currently off):
- Export CA (PEM) -> writes `observathor_root_ca.pem`
- Export CA (DER) -> writes `observathor_root_ca.der`

Internal HTTP endpoints (available regardless of MITM enabled state):
```
http://<proxy_host>:<port>/__observathor/ca.pem
http://<proxy_host>:<port>/__observathor/ca.der
```
These serve the same root CA the process generated/loaded at startup.

Default storage (if you don't pass `--ca-cert/--ca-key`):
- Windows: `%APPDATA%/Observathor/root_ca.pem` & `root_ca_key.pem`
- Unix-like: `$HOME/Observathor/root_ca.pem` & `root_ca_key.pem`

The CA fingerprint (SHA-256) is logged at startup; verify it before trusting on additional devices.

### Trusting the Root CA (Development Only!)
Only trust a CA you control. Remove it when done.

Windows:
1. Win+R -> `mmc`
2. File -> Add/Remove Snap-in -> Certificates -> Add -> Computer Account -> Local Computer
3. Navigate to Trusted Root Certification Authorities -> Certificates
4. Right-click -> All Tasks -> Import -> choose exported_root_ca.pem

macOS:
1. Open Keychain Access
2. Drag `exported_root_ca.pem` into System or login keychain
3. Double-click certificate -> Trust -> set "When using this certificate" to "Always Trust"
4. Close (enter password)

Linux (system-wide OpenSSL/NSS may vary):
Debian/Ubuntu (PEM -> hash form):
```
sudo cp exported_root_ca.pem /usr/local/share/ca-certificates/observathor_root_ca.crt
sudo update-ca-certificates
```
Firefox (separate store) -> Preferences -> Privacy & Security -> View Certificates -> Authorities -> Import.

Uninstall / Revoke trust:
Remove the installed cert from the same trust store locations; run `sudo update-ca-certificates --fresh` (Debian/Ubuntu) to prune.

### Safety Notes
- Generated root key is currently RSA 2048; future option for ECC/4096.
- Serial numbers simplistic; will be randomized later.
- No OCSP / CRL distribution points yet.
- MITM path shares streaming & chunked parity with plaintext path but still evolving; expect edge cases.

### Quick Automated MITM Sanity Test (Windows)
After building with OpenSSL (TLS enabled), you can run a convenience PowerShell script that exercises:
1. Simple HTTPS POST (form)
2. Chunked upload
3. Large body spill-to-disk
4. Chunked streaming response

Usage (from repo root PowerShell):
```
pwsh -File .\scripts\test_mitm.ps1 -Port 8888 -InstallCA
```
Flags:
- `-InstallCA` (optional) installs the exported root CA into the Windows Root store (admin). Use `-RemoveCA` to remove afterwards.
- `-CliPath` override path to `observathor_cli.exe` if different.
- `-LargeSize` adjust large body size (default 2MB).

Outputs:
- Temporary working directory under %TEMP% listing curl outputs and `transactions.ndjson`.
- Verifies `tls_mitm`, chunked flags, and file spill.

Remove CA when finished (if installed):
```
certutil -delstore Root Observathor
```

### Mobile / Device Trust & On-Device Download
Internal HTTP endpoints for device trust (active even if MITM not yet enabled):
```
http://<proxy_host>:<port>/__observathor/ca.pem
http://<proxy_host>:<port>/__observathor/ca.der
```
Usage:
1. Connect mobile device to the same network. Configure its HTTP(S) proxy settings to point to the machine running Observathor (host & port).
2. In the mobile browser visit `http://proxy_host:port/__observathor/ca.pem` (or `.der`).
3. Download & install the certificate (platform prompts):
	- Android: Settings -> Security -> Encryption & credentials -> Install a certificate -> CA certificate.
	- iOS: Open link, allow download, then Settings -> Profile Downloaded -> Install (may need to enable under Settings -> General -> About -> Certificate Trust Settings).

PEM vs DER:
- PEM is base64 with headers (good for desktops).
- DER is binary (often accepted by mobile OS stores).

Important: Remove the CA from the device when finished testing. Never distribute this CA outside your controlled environment.

### Planned Enhancements
- Robust per-host certificate caching persistence
- Full HTTP/2 (ALPN) upgrade in MITM
- Compression (gzip/br) automatic decode for viewing
- Rewrite rules & scripting
- Selective export/import via session tool
- Advanced filtering & search
- Improved error diagnostics for TLS handshake failures
```

## Contributing
Issues and PRs welcome once the core MVP lands. Proposed contributions should align with roadmap and keep dependency surface minimal.

## License
Apache 2.0
