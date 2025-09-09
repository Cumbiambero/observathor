# Observathor

Cross-platform open-source HTTP(S) interception and inspection proxy (early prototype).

## Status
Early scaffolding. Currently: builds, starts a TCP listener, returns a dummy HTTP 200 response for any accepted connection and shuts down cleanly.

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

## Build
Early scaffolding. Currently: builds, starts a TCP listener, returns a dummy HTTP 200 response for any accepted connection and shuts down cleanly.
- Single-thread accept loop with internal task queue polling
- Parses basic HTTP/1.1 request line + headers (tolerates last header without trailing CRLF)
- Basic upstream forwarding: rewrites absolute-form to origin-form and relays first upstream response chunk
- Transaction logging (request line + byte counts)
 - Optional request/response capture (headers + initial body fragment) via --capture-bytes N, stored in memory
 - Optional disk persistence: --capture-file path writes NDJSON lines (base64 bodies) suitable for future GUI indexing
 - (Optional) ImGui UI scaffolding: enable with -DOBSERVATHOR_ENABLE_IMGUI=ON (prototype stub only for now)

### Configure & Build (Windows PowerShell example)
Press ENTER to stop the process.

Stream upstream response instead of single read
Better error handling (timeouts, partial sends)
Add timing metrics to transactions
Expose captured transactions via future API / UI
Add lightweight index / query layer over NDJSON
ImGui prototype: integrate SDL2/OpenGL backend and live transaction table
```

## Contributing
Issues and PRs welcome once the core MVP lands. Proposed contributions should align with roadmap and keep dependency surface minimal.

## License
Apache 2.0
