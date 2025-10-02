Changelog
=========

v0.1.0 — Initial release
------------------------
- Initial cargo project scaffold and MIT license
- Core dependencies (tokio, clap, serde, axum, if-addrs, anyhow)
- CLI scaffold with argument parsing
- Ports loader with ranges/comments parsing + unit tests
- Local network detection (/24 default) + expansion + tests
- Async TCP connect scanner with concurrency limits, timeouts, and banner grab
- JSON output and pretty CLI table
- Embedded axum HTTP server with /api/scan, /api/status, /api/results + static UI serving
- Minimal static web UI (index.html, app.js, style.css)
- GitHub Actions CI: build + test
- Code formatted and clippy-clean

Unreleased
----------
- Probes: HTTP header/title parsing; SSH banner read; TLS certificate summary (subject/issuer/expiry); optional Redis PING.
- TLS support via native-tls + x509-parser for certificate parsing.
- UI/Server: Stop button (POST /api/cancel), ETA in status, cache-busting + no-cache headers.
- UI options: Quick scan preset (smaller ports & faster timeouts), Skip DNS (53), Redis probe.
- API enhancements: exclude_ports, quick, probe_redis; improved static serving.
- CLI: --quick, --exclude-ports, --probe-redis flags; --bind for UI.
- Ports: expanded default list; quick_ports preset added.
- Example: example-run.sh spins up local services and runs scanner end-to-end.
