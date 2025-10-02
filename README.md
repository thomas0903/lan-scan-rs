lan-scan-rs — Fast, safe‑by‑default async LAN TCP connect scanner with a tiny embedded web UI.

Overview
- Educational, single-binary LAN scanner that detects local IPv4 networks (/24 by default), performs asynchronous TCP connect scans on a set of ports, grabs lightweight banners, and prints results as a pretty table and JSON. Includes a minimal embedded web UI served by the binary.
- Non-goals: raw SYN scans or privileged operations. This tool only uses standard TCP connects and is safe by default.
- Service hints: HTTP header/title parsing, SSH banner read, optional Redis PING, and TLS certificate summary (subject/issuer/expiry).

Installation
- Prerequisites: Rust stable toolchain (https://rustup.rs)
- Build release binary:
  - cargo build --release
- Run the binary (examples below):
  - ./target/release/lan-scan-rs --help

Quick Examples
- Scan localhost demo (fast):
  - ./target/release/lan-scan-rs --targets 127.0.0.1 --timeout-ms 300 --output out.json
- Auto-detect local /24 networks with quick preset (smaller ports, faster timeouts):
  - ./target/release/lan-scan-rs --quick --timeout-ms 300
- Use a custom ports file and control concurrency:
  - ./target/release/lan-scan-rs --ports ports.txt --concurrency 500 --timeout-ms 300 --output results.json
- Exclude noisy ports (e.g., DNS/53) and enable Redis probe:
  - ./target/release/lan-scan-rs --quick --exclude-ports 53 --probe-redis

Embedded Web UI
- Start the embedded UI and API on 127.0.0.1:8080 (no scan starts automatically; use the UI to start one):
  - ./target/release/lan-scan-rs --serve-ui --bind 127.0.0.1:8080
- Then open in your browser:
  - http://127.0.0.1:8080
- Features:
  - Quick scan preset (smaller port set) and Skip DNS (53) toggle
  - Optional Redis PING probe
  - Start/Stop buttons and ETA (based on recent scan rate)
  - Progress polling and results table (IP, port, service, latency, banner)

Outputs
- Pretty CLI table printed to stdout (open ports only: IP, port, service, banner snippet, latency).
- JSON export with --output path. Example output is included at:
  - examples/sample-output.json

Ports & Defaults
- ports.txt format: one port or inclusive range per line; lines can have # comments and whitespace.
  - 22
  - 80
  - 8000-8010
  - # comments are fine
- Defaults:
  - default_ports(): expanded list of common infra/web/DB/queue/management ports.
  - quick_ports(): smaller, high-signal subset used by the “Quick scan” preset.
  - You can also exclude specific ports with --exclude-ports "53,135-139" (or UI checkbox for DNS/53).

Architecture
- src/main.rs — CLI argument parsing and top-level wiring (optionally starts embedded HTTP server).
- src/ports.rs — Ports file loader and parser (single values, ranges, comments) with defaults and quick set.
- src/netdetect.rs — Local interface detection (non-loopback IPv4) and default /24 CIDR expansion.
- src/scanner.rs — Async TCP connect scanner (Semaphore-limited concurrency, timeouts, safe probes, progress).
- src/server.rs — Axum HTTP backend: static UI and API (/api/scan, /api/status, /api/results, /api/cancel).
- src/types.rs — Serializable types for ScanEntry and ScanResults.
- ui/ — Minimal static UI (index.html, app.js, style.css).

CLI Flags
- --targets <CIDR|IP|file>: CIDR/IP list or a file containing them (comments supported).
- --ports <path>: Ports file (one port/range per line). If empty: defaults or quick preset.
- --concurrency <n>: Max in-flight sockets (default 1000).
- --timeout-ms <n>: Connect timeout in milliseconds (default 400; quick preset may clamp to 250).
- --output <path>: Write results JSON (pretty) in addition to CLI table.
- --serve-ui: Start embedded UI server.
- --bind <addr:port>: UI bind address (default 127.0.0.1:8080).
- --probe-redis: Enable Redis PING detection on 6379.
- --quick: Use smaller port set and faster timeouts for quicker sweeps.
- --exclude-ports <list>: Skip ports (comma and ranges, e.g., 53,135-139).

HTTP API
- POST /api/scan
  - body: { "targets": ["CIDR|IP", ...], "ports": [u16], "exclude_ports": [u16], "concurrency": n, "timeout_ms": n, "probe_redis": bool, "quick": bool }
- GET /api/status
  - response: { "total": N, "scanned": M, "open": K, "state": "idle|running|done" }
- GET /api/results
  - response: last ScanResults JSON
- POST /api/cancel
  - cancels an in-progress scan

Service Detection (safe probes)
- HTTP: GET / with target Host header, extracts Server header and HTML <title> (first chunk).
- TLS: Performs a client handshake on common TLS ports, extracts certificate subject/issuer/not_after.
- SSH: Reads SSH identification banner (e.g., SSH-2.0-OpenSSH...).
- Redis (opt-in): Sends PING, expects +PONG.

Local Demo Script
- Run example-run.sh to spin up local HTTP/TLS/Redis/SSH-like services, run the scanner, and print results.
  - ./example-run.sh
  - Output is printed to terminal; services are cleaned up automatically.

Development
- Run tests:
  - cargo test
- Format:
  - cargo fmt
- Lint (Clippy):
  - cargo clippy --all-targets -- -D warnings
- Build (release):
  - cargo build --release
 - Quick local demo:
   - ./example-run.sh

License
- MIT — see LICENSE for details.
