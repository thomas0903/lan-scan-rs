use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tower_http::services::ServeDir;

use crate::{
    netdetect,
    ports,
    scanner::{self, SharedProgress},
    types::ScanResults,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<RwLock<ServerState>>, // shared mutable state for progress/results
}

#[derive(Debug)]
struct ServerState {
    status: Status,
    results: Option<ScanResults>,
    progress: Option<SharedProgress>,
    cancel: Option<CancellationToken>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct Status {
    pub total: u64,
    pub scanned: u64,
    pub open: u64,
    pub state: String, // "idle" | "running" | "done"
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

pub async fn spawn_server(bind: &str) -> Result<()> {
    let state = AppState {
        inner: Arc::new(RwLock::new(ServerState {
            status: Status {
                total: 0,
                scanned: 0,
                open: 0,
                state: "idle".into(),
            },
            results: None,
            progress: None,
            cancel: None,
        })),
    };

    let api = Router::new()
        .route("/status", get(get_status))
        .route("/scan", post(post_scan))
        .route("/results", get(get_results))
        .with_state(state.clone());

    let static_svc = ServeDir::new("ui").append_index_html_on_directories(true);

    let app = Router::new()
        .nest("/api", api)
        .fallback_service(static_svc);

    println!("Serving UI on http://{}", bind);
    axum::serve(tokio::net::TcpListener::bind(bind).await?, app).await?;
    Ok(())
}

async fn get_status(State(app): State<AppState>) -> impl IntoResponse {
    let s = app.inner.read().await;
    let (scanned, open) = if let Some(p) = s.progress.as_ref() {
        (
            p.scanned_done.load(std::sync::atomic::Ordering::Relaxed),
            p.open_count.load(std::sync::atomic::Ordering::Relaxed),
        )
    } else {
        (s.status.scanned, s.status.open)
    };
    let out = Status { total: s.status.total, scanned, open, state: s.status.state.clone() };
    (StatusCode::OK, Json(out))
}

async fn get_results(State(app): State<AppState>) -> impl IntoResponse {
    let s = app.inner.read().await;
    if let Some(res) = s.results.as_ref() {
        (StatusCode::OK, Json(res.clone())).into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

async fn post_scan(State(app): State<AppState>, Json(req): Json<ScanRequest>) -> impl IntoResponse {
    // Parse targets into IPs (support CIDR strings or plain IPs)
    let mut all_ips: Vec<IpAddr> = Vec::new();
    for t in req.targets {
        if t.contains('/') {
            match t.parse::<IpNet>() {
                Ok(n) => all_ips.extend(netdetect::expand_cidr_to_ips(n)),
                Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid CIDR: {e}")).into_response(),
            }
        } else {
            match t.parse::<IpAddr>() {
                Ok(ip) => all_ips.push(ip),
                Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid IP: {e}")).into_response(),
            }
        }
    }

    let ports = if req.ports.is_empty() {
        ports::default_ports()
    } else {
        req.ports
    };

    let total = (all_ips.len() as u64) * (ports.len() as u64);
    let concurrency = req.concurrency.unwrap_or(1000);
    let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(400));

    // Prepare shared progress and cancel token
    let progress = SharedProgress::new();
    let cancel = CancellationToken::new();

    // Update state
    {
        let mut s = app.inner.write().await;
        // Cancel any existing scan
        if let Some(c) = s.cancel.take() {
            c.cancel();
        }
        s.status = Status { total, scanned: 0, open: 0, state: "running".into() };
        s.results = None;
        s.progress = Some(progress.clone());
        s.cancel = Some(cancel.clone());
    }

    // Spawn scan task
    let app2 = app.clone();
    tokio::spawn(async move {
        let res = scanner::scan_targets_with_shared(
            &all_ips,
            &ports,
            concurrency,
            timeout,
            cancel.clone(),
            progress.clone(),
        )
        .await;

        let mut s = app2.inner.write().await;
        match res {
            Ok(results) => {
                s.status.scanned = results.scanned_done;
                s.status.open = results.open_count;
                s.status.state = "done".into();
                s.results = Some(results);
                s.progress = None;
                s.cancel = None;
            }
            Err(e) => {
                s.status.state = "idle".into();
                s.progress = None;
                s.cancel = None;
                eprintln!("scan error: {e}");
            }
        }
    });

    (StatusCode::ACCEPTED, Json(Status { total, scanned: 0, open: 0, state: "running".into() })).into_response()
}
