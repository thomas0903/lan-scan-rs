lan-scan-rs — Fast, safe‑by‑default async LAN TCP connect scanner with a tiny embedded web UI.

Overview
- Educational, single-binary LAN scanner that detects local IPv4 networks (/24 by default), performs asynchronous TCP connect scans on a set of ports, grabs lightweight banners, and prints results as a pretty table and JSON. Includes a minimal embedded web UI served by the binary.
- Non-goals: raw SYN scans or privileged operations. This tool only uses standard TCP connects and is safe by default.

Installation
- Prerequisites: Rust stable toolchain (https://rustup.rs)
- Build release binary:
  - cargo build --release
- Run the binary (examples below):
  - ./target/release/lan-scan-rs --help

Quick Examples
- Scan localhost demo (fast):
  - ./target/release/lan-scan-rs --targets 127.0.0.1 --timeout-ms 300 --output out.json
- Auto-detect local /24 networks and use default ports:
  - ./target/release/lan-scan-rs --timeout-ms 400
- Use a custom ports file and control concurrency:
  - ./target/release/lan-scan-rs --ports ports.txt --concurrency 500 --timeout-ms 300 --output results.json

Embedded Web UI
- Start the embedded UI and API on 127.0.0.1:8080:
  - ./target/release/lan-scan-rs --serve-ui --bind 127.0.0.1:8080
- Then open in your browser:
  - http://127.0.0.1:8080
- Use the form to enter targets (CIDR/IP), optional port list, concurrency, timeout, then Start Scan. The UI polls progress and renders a results table when finished.

Outputs
- Pretty CLI table printed to stdout (open ports only: IP, port, banner snippet, latency).
- JSON export with --output path. Example output is included at:
  - examples/sample-output.json

Ports List Format (ports.txt)
- One port or range per line; comments with # are ignored.
  - 22
  - 80
  - 8000-8010
  - # comment lines are fine
- If the file is missing or empty, a conservative default list is used.

Architecture
- src/main.rs — CLI argument parsing and top-level wiring (optionally starts embedded HTTP server).
- src/ports.rs — Ports file loader and parser (single values, ranges, comments) with defaults.
- src/netdetect.rs — Local interface detection (non-loopback IPv4) and default /24 CIDR expansion.
- src/scanner.rs — Async TCP connect scanner (Semaphore-limited concurrency, timeouts, banner grab, progress).
- src/server.rs — Axum-based HTTP backend: serves static UI and exposes /api/scan, /api/status, /api/results.
- src/types.rs — Serializable types for ScanEntry and ScanResults.
- ui/ — Minimal static UI (index.html, app.js, style.css).

Development
- Run tests:
  - cargo test
- Format:
  - cargo fmt
- Lint (Clippy):
  - cargo clippy --all-targets -- -D warnings
- Build (release):
  - cargo build --release

License
- MIT — see LICENSE for details.

See also
- USAGE.md — safety notes and more examples.
