<h1 align="center">lan‑scan‑rs</h1>

<p align="center">
  Fast, safe‑by‑default async LAN TCP connect scanner with a tiny embedded web UI.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
  <a href="https://github.com/thomas0903/lan-scan-rs/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/thomas0903/lan-scan-rs/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Rust Edition" src="https://img.shields.io/badge/Rust-2021-orange">
</p>

---

Table of Contents
- Features
- Install
- Quick Start
- Web UI
- Output Examples
- Ports & Presets
- Service Detection
- CLI Reference
- HTTP API
- Architecture
- Demo Script
- Star History
- License

Features
- Auto‑detects local IPv4 /24 networks (non‑loopback). Optional explicit targets via CIDR/IP/file.
- Async TCP connect scan with concurrency limit and timeouts.
- Service hints and safe probes:
  - HTTP: extracts Server header and HTML <title>
  - SSH: reads SSH identification banner
  - TLS: summarizes certificate (subject/issuer/expiry)
  - Redis (opt‑in): PING → PONG
- Outputs pretty CLI table and JSON (when --output is provided).
- Embedded web UI with Quick preset, Skip DNS (53), Redis toggle, Start/Stop, and ETA.

Install
```bash
# 1) Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2) Build release binary
cargo build --release

# 3) Show help
./target/release/lan-scan-rs --help
```

Quick Start
```bash
# Localhost demo (fast)
./target/release/lan-scan-rs --targets 127.0.0.1 --timeout-ms 300 --output demo.json

# Autodetect local /24s with quick preset (smaller ports + faster timeouts)
./target/release/lan-scan-rs --quick --timeout-ms 300

# Exclude noisy ports (e.g., DNS/53) and enable Redis probe
./target/release/lan-scan-rs --quick --exclude-ports 53 --probe-redis

# Use custom ports file
./target/release/lan-scan-rs --ports ports.txt --concurrency 800 --timeout-ms 300 --output results.json
```

Web UI
```bash
./target/release/lan-scan-rs --serve-ui --bind 127.0.0.1:8080
# open http://127.0.0.1:8080
```
UI highlights:
- Quick scan preset and Skip DNS (53) toggle
- Optional Redis PING probe
- Start/Stop buttons and ETA (based on recent scan rate)
- Progress polling and results table (IP, port, service, latency, banner)

Output Examples
- CLI table (example):
```
Open ports: 4 (scanned: 4)
ip         port  service  latency_ms  banner
---------  ----  -------  ----------  ------------------------------------------------------------
127.0.0.1  2222  ssh               3  SSH-2.0-OpenSSH_9.8\r\n
127.0.0.1  8443  https             0  TLS: subject_cn=localhost, issuer_cn=localhost, not_after=...
127.0.0.1  6379  redis             3  redis PONG
127.0.0.1  8080  http              3  HTTP server=SimpleHTTP/0.6 Python/3.12, title="Directory ..."
```

- JSON (see examples/sample-output.json):
```text
{
  "scanned_total": 4,
  "scanned_done": 4,
  "open_count": 4,
  "entries": [
    { "ip": "127.0.0.1", "port": 2222, "service": "ssh",   "banner": "SSH-2.0-OpenSSH_9.8\r\n" },
    { "ip": "127.0.0.1", "port": 8443, "service": "https", "banner": "TLS: subject_cn=localhost, issuer_cn=localhost, not_after=..." },
    { "ip": "127.0.0.1", "port": 6379, "service": "redis", "banner": "+PONG" },
    { "ip": "127.0.0.1", "port": 8080, "service": "http",  "banner": "HTTP server=SimpleHTTP/0.6 ..., title=\"...\"" }
  ]
}
```

Ports & Presets
- ports.txt format: one port or inclusive range per line; `#` comments allowed.
  ```
  22
  80
  8000-8010
  # comments are fine
  ```
- Defaults:
  - default_ports: expanded list of common infra/web/DB/queue/management ports.
  - quick_ports: smaller, high‑signal subset used by the Quick preset.
  - Exclude specific ports with `--exclude-ports "53,135-139"` (or UI toggle for DNS/53).

Service Detection
- HTTP: GET / with target Host header; extracts Server header and HTML `<title>`.
- TLS: client handshake (common TLS ports); extracts certificate subject/issuer/not_after.
- SSH: reads SSH identification banner.
- Redis (opt‑in): PING → `+PONG`.

CLI Reference
```text
--targets <CIDR|IP|file>   CIDR/IP list or file (comments supported)
--ports <path>             Ports file (one port/range per line)
--concurrency <n>          Max in‑flight sockets (default 1000)
--timeout-ms <n>           Connect timeout in ms (default 400; Quick may clamp to 250)
--output <path>            Write results JSON (pretty)
--serve-ui                 Start embedded UI server
--bind <addr:port>         UI bind address (default 127.0.0.1:8080)
--probe-redis              Enable Redis PING detection (6379)
--quick                    Use smaller port set + faster timeouts
--exclude-ports <list>     Skip ports (comma and ranges, e.g., 53,135-139)
```

HTTP API
```text
POST /api/scan
{ "targets": ["CIDR|IP", ...], "ports": [<u16>], "exclude_ports": [<u16>], "concurrency": <n>, "timeout_ms": <n>, "probe_redis": <bool>, "quick": <bool> }

GET /api/status
{ "total": <N>, "scanned": <M>, "open": <K>, "state": "idle|running|done" }

GET /api/results
// last ScanResults JSON

POST /api/cancel
// cancels an in‑progress scan
```

Architecture
```text
src/
  main.rs      # CLI + wiring; starts web UI when requested
  ports.rs     # ports loader/parser; defaults + quick preset
  netdetect.rs # local /24 detection; CIDR expansion
  scanner.rs   # async connect, timeouts, safe probes, progress
  server.rs    # axum API (/scan, /status, /results, /cancel) + static UI
  types.rs     # ScanEntry / ScanResults (serde)
ui/            # index.html, app.js, style.css
```

Demo Script
```bash
./example-run.sh
# Spins up HTTP/TLS/Redis/SSH-like services, runs the scanner, prints results, and cleans up.
```

Star History

[![Star History Chart](https://api.star-history.com/svg?repos=thomas0903/lan-scan-rs&type=Date)](https://star-history.com/#thomas0903/lan-scan-rs&Date)

License
- MIT — see [LICENSE](LICENSE).
