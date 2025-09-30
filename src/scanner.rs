use crate::types::{ScanEntry, ScanResults};
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{self, Instant};
use tokio_util::sync::CancellationToken;
use ::time::{format_description::well_known, OffsetDateTime};

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
    scan_targets_internal(targets, ports, concurrency, timeout, None, None).await
}

/// Variant that accepts a `CancellationToken` to allow external cancellation.
pub async fn scan_targets_with_cancel(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    cancel: CancellationToken,
) -> Result<ScanResults> {
    scan_targets_internal(targets, ports, concurrency, timeout, Some(cancel), None).await
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
                    Ok(Ok(mut stream)) => {
                        let latency_ms = start.elapsed().as_millis() as u64;
                        // Attempt a short, passive banner read
                        let banner = read_banner(&mut stream).await;
                        open_count.fetch_add(1, Ordering::Relaxed);
                        let entry = ScanEntry {
                            ip: ip.to_string(),
                            port,
                            open: true,
                            latency_ms,
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
