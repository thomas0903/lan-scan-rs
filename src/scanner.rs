use crate::types::{ScanEntry, ScanResults};
use ::time::{format_description::well_known, OffsetDateTime};
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{self, Instant};
use tokio_util::sync::CancellationToken;
use tokio_native_tls::native_tls::{self, Certificate};
use tokio_native_tls::TlsConnector;
use x509_parser::prelude::*;

/// Scan the provided targets and ports using asynchronous TCP connects with a concurrency limit.
///
/// - Limits concurrent socket attempts using a `Semaphore`.
/// - Uses `tokio::time::timeout` to bound connect time per socket.
/// - On successful connect, attempts a short, passive banner grab (up to 256 bytes, 200ms timeout).
/// - Tracks progress counters and returns them in `ScanResults`.
pub async fn scan_targets(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
) -> Result<ScanResults> {
    scan_targets_internal(targets, ports, concurrency, timeout, None, None, false).await
}

/// Run a scan with additional options.
pub async fn scan_targets_opts(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    probe_redis: bool,
) -> Result<ScanResults> {
    scan_targets_internal(targets, ports, concurrency, timeout, None, None, probe_redis).await
}

/// Variant that accepts a `CancellationToken` to allow external cancellation.
pub async fn scan_targets_with_cancel(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    cancel: CancellationToken,
) -> Result<ScanResults> {
    scan_targets_internal(targets, ports, concurrency, timeout, Some(cancel), None, false).await
}

#[derive(Clone, Debug)]
pub struct SharedProgress {
    pub scanned_done: Arc<AtomicU64>,
    pub open_count: Arc<AtomicU64>,
    pub entries: Arc<Mutex<Vec<ScanEntry>>>,
}

impl SharedProgress {
    pub fn new() -> Self {
        Self {
            scanned_done: Arc::new(AtomicU64::new(0)),
            open_count: Arc::new(AtomicU64::new(0)),
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for SharedProgress {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn scan_targets_with_shared(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    cancel: CancellationToken,
    shared: SharedProgress,
) -> Result<ScanResults> {
    scan_targets_internal(
        targets,
        ports,
        concurrency,
        timeout,
        Some(cancel),
        Some(shared),
        false,
    )
    .await
}

pub async fn scan_targets_with_shared_opts(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    cancel: CancellationToken,
    shared: SharedProgress,
    probe_redis: bool,
) -> Result<ScanResults> {
    scan_targets_internal(
        targets,
        ports,
        concurrency,
        timeout,
        Some(cancel),
        Some(shared),
        probe_redis,
    )
    .await
}

async fn scan_targets_internal(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    cancel_opt: Option<CancellationToken>,
    shared_opt: Option<SharedProgress>,
    probe_redis: bool,
) -> Result<ScanResults> {
    let total = targets.len() as u64 * ports.len() as u64;
    let (scanned_done, open_count, entries) = if let Some(s) = &shared_opt {
        (
            s.scanned_done.clone(),
            s.open_count.clone(),
            s.entries.clone(),
        )
    } else {
        (
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Vec::new())),
        )
    };

    let sem = Arc::new(Semaphore::new(concurrency.clamp(1, 5_000)));
    let mut set = JoinSet::new();
    let cancel = cancel_opt.unwrap_or_default();

    // Optional: Ctrl-C cancels the scan.
    let cancel_ctrlc = cancel.clone();
    tokio::spawn(async move {
        #[allow(unused_must_use)]
        {
            let _ = tokio::signal::ctrl_c().await;
            cancel_ctrlc.cancel();
        }
    });

    for &ip in targets {
        if cancel.is_cancelled() {
            break;
        }
        for &port in ports {
            if cancel.is_cancelled() {
                break;
            }
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore in scope");
            let entries = entries.clone();
            let scanned_done = scanned_done.clone();
            let open_count = open_count.clone();
            let cancel = cancel.clone();

            set.spawn(async move {
                let _permit = permit; // keep permit until task completes

                if cancel.is_cancelled() {
                    return;
                }

                let addr = SocketAddr::new(ip, port);
                let start = Instant::now();
                let connect_res = time::timeout(timeout, TcpStream::connect(addr)).await;
                match connect_res {
                    Ok(Ok(stream)) => {
                        let latency_ms = start.elapsed().as_millis() as u64;
                        let (service, banner) = if is_tls_port(port) {
                            match tls_probe(stream, ip, port).await {
                                Some((svc, bn)) => (svc, bn),
                                None => (Some("https".to_string()), None),
                            }
                        } else {
                            let mut stream = stream;
                            // Attempt a short, passive banner read; then light protocol-specific probes
                            let mut b = read_banner(&mut stream).await;
                            if port == 22 {
                                if let Some(sshb) = probe_ssh(&mut stream).await { b = Some(sshb); }
                            }
                            if b.is_none() {
                                if let Some(pb) = probe_protocol(&mut stream, ip, port, probe_redis).await {
                                    b = Some(pb);
                                }
                            }
                            let svc = guess_service(port, b.as_deref());
                            (svc, b)
                        };
                        open_count.fetch_add(1, Ordering::Relaxed);
                        let entry = ScanEntry {
                            ip: ip.to_string(),
                            port,
                            open: true,
                            latency_ms,
                            service,
                            banner,
                            timestamp: now_iso_like(),
                        };
                        let mut guard = entries.lock().await;
                        guard.push(entry);
                    }
                    _ => {
                        // Closed, filtered, or timed out. We don't record closed entries for brevity.
                    }
                }

                scanned_done.fetch_add(1, Ordering::Relaxed);
            });
        }
    }

    while let Some(_res) = set.join_next().await {}

    let entries_vec = Arc::try_unwrap(entries)
        .unwrap_or_else(futures_collect_vec_blocking)
        .into_inner();

    let results = ScanResults {
        scanned_total: total,
        scanned_done: scanned_done.load(Ordering::Relaxed),
        open_count: open_count.load(Ordering::Relaxed),
        entries: entries_vec,
    };
    Ok(results)
}

/// Try to read up to 256 bytes from the stream with a short timeout and convert to a lossy UTF-8 string.
async fn read_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 256];
    match time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            let s = String::from_utf8_lossy(&buf).to_string();
            let s = s.replace('\n', "\\n").replace('\r', "\\r");
            Some(s)
        }
        _ => None,
    }
}

/// Light, safe protocol-specific probes to coax a banner without being intrusive.
/// Currently only sends an HTTP/1.0 GET on common HTTP ports.
async fn probe_protocol(stream: &mut TcpStream, ip: IpAddr, port: u16, probe_redis: bool) -> Option<String> {
    if is_http_port(port) {
        return probe_http(stream, ip).await;
    }
    if probe_redis && port == 6379 {
        return probe_redis_ping(stream).await;
    }
    None
}

fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 9443 | 993 | 995 | 465)
}

async fn tls_probe(stream: TcpStream, ip: IpAddr, _port: u16) -> Option<(Option<String>, Option<String>)> {
    let domain = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    };
    let builder = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let cx = TlsConnector::from(builder);
    let tls = time::timeout(Duration::from_millis(600), cx.connect(&domain, stream))
        .await
        .ok()?
        .ok()?;
    let inner = tls.get_ref();
    let cert_summary = match inner.peer_certificate() {
        Ok(Some(cert)) => format_cert_summary(&cert),
        _ => None,
    };
    let banner = cert_summary.map(|c| format!("TLS: {}", c));
    let service = Some("https".to_string());
    Some((service, banner))
}

fn format_cert_summary(cert: &Certificate) -> Option<String> {
    let der = cert.to_der().ok()?;
    let (_rem, x509) = parse_x509_certificate(&der).ok()?;
    let subject_cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_string();
    let issuer_cn = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_string();
    let not_after = x509
        .validity()
        .not_after
        .to_rfc2822()
        .unwrap_or_else(|_| "invalid".to_string());
    let mut parts = Vec::new();
    if !subject_cn.is_empty() { parts.push(format!("subject_cn={}", subject_cn)); }
    if !issuer_cn.is_empty() { parts.push(format!("issuer_cn={}", issuer_cn)); }
    parts.push(format!("not_after={}", not_after));
    Some(parts.join(", "))
}

async fn probe_http(stream: &mut TcpStream, ip: IpAddr) -> Option<String> {
    let host = ip.to_string();
    let req = format!(
        "GET / HTTP/1.0\r\nUser-Agent: lan-scan-rs/0.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    );
    let _ = time::timeout(Duration::from_millis(200), stream.write_all(req.as_bytes())).await.ok()?;
    // Read a bit more to capture headers + potential <title>
    let deadline = Instant::now() + Duration::from_millis(400);
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        if Instant::now() >= deadline || buf.len() >= 4096 { break; }
        match time::timeout(Duration::from_millis(80), stream.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    if buf.is_empty() { return None; }
    let text = String::from_utf8_lossy(&buf).to_string();
    let mut parts = Vec::new();
    if let Some(server) = extract_header(&text, "server") {
        parts.push(format!("server={}", server));
    }
    if let Some(title) = extract_html_title(&text) {
        parts.push(format!("title=\"{}\"", title));
    }
    if parts.is_empty() { Some("HTTP".to_string()) } else { Some(format!("HTTP {}", parts.join(", "))) }
}

fn extract_header(resp: &str, name: &str) -> Option<String> {
    let name_lc = name.to_ascii_lowercase();
    for line in resp.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(&name_lc) {
                return Some(v.trim().to_string());
            }
        }
        if line.trim().is_empty() { break; }
    }
    None
}

fn extract_html_title(resp: &str) -> Option<String> {
    let lower = resp.to_ascii_lowercase();
    let body_start = lower.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body = &resp[body_start..];
    let lbody = &lower[body_start..];
    let t_start = lbody.find("<title")?;
    let after = &lbody[t_start..];
    let gt = after.find('>')?;
    let rest = &body[t_start + gt + 1..];
    let rest_l = &after[gt + 1..];
    let t_end_rel = rest_l.find("</title>")?;
    let mut title = rest[..t_end_rel].trim().to_string();
    if title.len() > 120 { title.truncate(120); }
    Some(title)
}

async fn probe_redis_ping(stream: &mut TcpStream) -> Option<String> {
    // RESP: *1 CRLF $4 CRLF PING CRLF
    let pkt = b"*1\r\n$4\r\nPING\r\n";
    let _ = time::timeout(Duration::from_millis(200), stream.write_all(pkt)).await.ok()?;
    let mut buf = [0u8; 64];
    if let Ok(Ok(n)) = time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
        if n > 0 {
            let s = String::from_utf8_lossy(&buf[..n]).to_string();
            if s.starts_with("+PONG") { return Some("redis PONG".to_string()); }
            return Some(s.replace('\n', "\\n").replace('\r', "\\r"));
        }
    }
    None
}

async fn probe_ssh(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 256];
    if let Ok(Ok(n)) = time::timeout(Duration::from_millis(400), stream.read(&mut buf)).await {
        if n > 0 {
            let s = String::from_utf8_lossy(&buf[..n]).to_string();
            if s.to_ascii_lowercase().starts_with("ssh-") || s.contains("OpenSSH") {
                return Some(s.trim().replace('\n', "\\n").replace('\r', "\\r"));
            }
        }
    }
    None
}

fn is_http_port(port: u16) -> bool {
    matches!(
        port,
        80 | 81 | 82 | 591 | 8000 | 8001 | 8008 | 8080 | 8081 | 8088 | 8888
    )
}

fn guess_service(port: u16, banner: Option<&str>) -> Option<String> {
    // Prefer protocol hints in banners (e.g., SSH-2.0-...)
    if let Some(b) = banner {
        let lb = b.to_ascii_lowercase();
        if lb.contains("ssh-") {
            return Some("ssh".to_string());
        }
        if lb.starts_with("http/") || lb.contains("http/1.") || lb.contains("server:") {
            return Some("http".to_string());
        }
        if lb.contains("smtp") {
            return Some("smtp".to_string());
        }
        if lb.contains("redis") {
            return Some("redis".to_string());
        }
        if lb.contains("mysql") {
            return Some("mysql".to_string());
        }
        if lb.contains("postgres") || lb.contains("postgresql") {
            return Some("postgresql".to_string());
        }
        if lb.contains("mongodb") {
            return Some("mongodb".to_string());
        }
        if lb.contains("mqtt") {
            return Some("mqtt".to_string());
        }
    }
    // Fallback to common well-known ports
    let name = match port {
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 | 81 | 82 | 591 | 8000 | 8001 | 8008 | 8080 | 8081 | 8088 | 8888 => Some("http"),
        110 => Some("pop3"),
        123 => Some("ntp"),
        139 | 445 => Some("smb"),
        143 => Some("imap"),
        161 => Some("snmp"),
        389 => Some("ldap"),
        443 | 8443 => Some("https"),
        465 | 587 => Some("smtps"),
        631 => Some("ipp"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        1883 => Some("mqtt"),
        2049 => Some("nfs"),
        2375 | 2376 => Some("docker"),
        2380 => Some("etcd"),
        3000 => Some("http"),
        3128 => Some("http-proxy"),
        3260 => Some("iscsi"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        4369 => Some("epmd"),
        5000 => Some("http"),
        5040 => Some("unknown"),
        5432 => Some("postgresql"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        5985 | 5986 => Some("winrm"),
        6379 => Some("redis"),
        7001 | 7002 => Some("http"),
        9000 => Some("http"),
        9092 => Some("kafka"),
        9200 | 9300 => Some("elasticsearch"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        _ => None,
    };
    name.map(|s| s.to_string())
}

/// Fallback to extract inner Vec when Arc still has references (rare here). Blocks to clone data.
fn futures_collect_vec_blocking(arc: Arc<Mutex<Vec<ScanEntry>>>) -> Mutex<Vec<ScanEntry>> {
    // In practice, this branch shouldn't trigger because we await all tasks before.
    // But if it does, we clone out the contents.
    let rt = tokio::runtime::Handle::try_current();
    if rt.is_ok() {
        // On runtime, block_in_place
        tokio::task::block_in_place(|| futures_collect_vec_sync(&arc))
    } else {
        futures_collect_vec_sync(&arc)
    }
}

fn futures_collect_vec_sync(arc: &Arc<Mutex<Vec<ScanEntry>>>) -> Mutex<Vec<ScanEntry>> {
    let guarded = arc.blocking_lock();
    Mutex::new(guarded.clone())
}

fn now_iso_like() -> String {
    // RFC3339-like UTC timestamp using `time` crate for correctness without heavy deps.
    let now = OffsetDateTime::now_utc();
    now.format(&well_known::Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}
