# Next Steps

Short-term priorities:
1. Replace select loop with non-blocking accept + event driven abstraction (single thread) then move to edge triggered epoll/kqueue/IOCP or adopt std::experimental net when available.
2. Implement basic HTTP request forwarding: parse request line + headers, connect to upstream, relay, capture metadata.
3. Add graceful shutdown signal handling.
4. Introduce Transaction model and observer interface.
5. Implement simple in-memory store (bounded).
6. Add minimal configuration system (port, max transactions, log level) via CLI flags.
7. Add CONNECT tunneling (no interception) with byte counters.
8. Introduce TLS interception plan: root CA generation (OpenSSL), leaf cert cache.
9. Add unit test framework (Catch2) for parser and future components.
10. Evaluate UI path (Qt prototype vs local web UI) once data events are flowing.

Stretch (later):
- HTTP/2 frame decoding
- Compression decoding
- WebSocket upgrades capture
- Scripting API
- Persistent session save/load
