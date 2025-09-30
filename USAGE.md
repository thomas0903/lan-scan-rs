USAGE and Safety Notes
======================

lan-scan-rs performs TCP connect scans only. It does not send raw SYN packets or require elevated privileges. Even so, please follow these safety notes:

- Only scan networks and systems you own or have explicit permission to test.
- Keep timeouts conservative on busy networks to avoid excessive traffic.
- Avoid extremely high concurrency on small machines or when scanning over VPNs.
- Banners are read passively (no bytes are sent after connect), but some services may log connections; act responsibly.

Examples

- Autodetect local /24s and scan default ports:
  - `./target/release/lan-scan-rs --timeout-ms 400`
- Scan explicit targets (CIDR/IP mix) and write JSON:
  - `./target/release/lan-scan-rs --targets "192.168.1.0/24,10.0.0.10" --output results.json`
- Use a targets file (one token per line, comments with # allowed):
  - `./target/release/lan-scan-rs --targets targets.txt`
- Use custom ports file and adjust concurrency:
  - `./target/release/lan-scan-rs --ports ports.txt --concurrency 500 --timeout-ms 300`
- Start the UI and drive scans from the browser:
  - `./target/release/lan-scan-rs --serve-ui --bind 127.0.0.1:8080`

