#!/usr/bin/env bash
set -euo pipefail

# Local demo runner: spins up several test services on loopback, runs the scanner
# against them, writes JSON output, then shuts everything down.

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_PATH="${1:-$ROOT_DIR/examples/sample-output.json}"

TMP_DIR="$(mktemp -d -t lan-scan-demo-XXXX)"
HTTP_PID=""; TLS_PID=""; REDIS_PID=""; SSH_PID="";

cleanup() {
  set +e
  for pid in "$HTTP_PID" "$TLS_PID" "$REDIS_PID" "$SSH_PID"; do
    if [ -n "$pid" ] && ps -p "$pid" >/dev/null 2>&1; then kill "$pid" 2>/dev/null || true; fi
  done
  rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "[+] Building release binary"
cargo build --release >/dev/null

echo "[+] Starting HTTP server on 127.0.0.1:8080"
python3 -m http.server 8080 --bind 127.0.0.1 >"$TMP_DIR/http.log" 2>&1 &
HTTP_PID=$!

echo "[+] Generating self-signed TLS cert"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1 || true

echo "[+] Starting TLS server on 127.0.0.1:8443"
openssl s_server -accept 8443 -cert "$TMP_DIR/cert.pem" -key "$TMP_DIR/key.pem" -quiet >"$TMP_DIR/tls.log" 2>&1 &
TLS_PID=$!

echo "[+] Starting Redis-like PING server on 127.0.0.1:6379"
cat > "$TMP_DIR/redis_like.py" << 'PY'
import socket, threading
HOST='127.0.0.1'
PORT=6379
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.bind((HOST,PORT))
s.listen(50)
def handle(c):
    try:
        c.settimeout(2.0)
        data=c.recv(1024)
        if data and b'PING' in data.upper():
            c.sendall(b'+PONG\r\n')
        else:
            c.sendall(b'-ERR unknown\r\n')
    except Exception:
        pass
    finally:
        c.close()
while True:
    conn,addr=s.accept()
    threading.Thread(target=handle,args=(conn,),daemon=True).start()
PY
python3 "$TMP_DIR/redis_like.py" >"$TMP_DIR/redis.log" 2>&1 &
REDIS_PID=$!

echo "[+] Starting SSH-like banner server on 127.0.0.1:2222"
cat > "$TMP_DIR/ssh_like.py" << 'PY'
import socket, threading
HOST='127.0.0.1'
PORT=2222
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.bind((HOST,PORT))
s.listen(50)
def handle(c):
    try:
        c.sendall(b'SSH-2.0-OpenSSH_9.8\r\n')
    except Exception:
        pass
    finally:
        c.close()
while True:
    conn,addr=s.accept()
    threading.Thread(target=handle,args=(conn,),daemon=True).start()
PY
python3 "$TMP_DIR/ssh_like.py" >"$TMP_DIR/ssh.log" 2>&1 &
SSH_PID=$!

echo "[+] Preparing target and ports"
echo 127.0.0.1 > "$TMP_DIR/targets.txt"
cat > "$TMP_DIR/ports.txt" << 'EOF'
8080
8443
6379
2222
EOF

sleep 0.5

echo "[+] Running scanner -> $OUTPUT_PATH"
"$ROOT_DIR/target/release/lan-scan-rs" \
  --targets "$TMP_DIR/targets.txt" \
  --ports "$TMP_DIR/ports.txt" \
  --timeout-ms 300 \
  --probe-redis \
  --output "$OUTPUT_PATH"

echo "[+] Done. Output saved to: $OUTPUT_PATH"
