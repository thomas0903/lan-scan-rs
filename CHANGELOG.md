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
