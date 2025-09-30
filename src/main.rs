use std::path::PathBuf;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};

use lan_scan_rs::{netdetect, scanner, server};
use lan_scan_rs::types::ScanResults;
use serde_json;
use std::fs::File;

use anyhow::Result;
use clap::Parser;

/// lan-scan-rs — Fast, safe-by-default async LAN TCP port scanner with a tiny embedded web UI.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "lan-scan-rs",
    version,
    about = "Fast, safe-by-default async LAN TCP port scanner with a tiny embedded web UI.",
    long_about = None
)]
struct Cli {
    /// CIDR (e.g., 192.168.1.0/24) or path to file with CIDRs/IPs. If omitted, auto-detect local /24.
    #[arg(long)]
    targets: Option<String>,

    /// Path to ports list file (one port or range per line).
    #[arg(long, default_value = "ports.txt")]
    ports: PathBuf,

    /// Max concurrent TCP connect attempts.
    #[arg(long, default_value_t = 1000)]
    concurrency: usize,

    /// Socket connect timeout in milliseconds.
    #[arg(long = "timeout-ms", default_value_t = 400)]
    timeout_ms: u64,

    /// Write results as pretty JSON to this path (optional).
    #[arg(long)]
    output: Option<PathBuf>,

    /// Start the embedded HTTP UI server (serves static UI; endpoints TBD).
    #[arg(long = "serve-ui", default_value_t = false)]
    serve_ui: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("lan-scan-rs configuration:");
    println!(
        "  targets      : {}",
        cli.targets
            .as_deref()
            .unwrap_or("<auto-detect local IPv4 /24>")
    );
    println!("  ports        : {}", cli.ports.display());
    println!("  concurrency  : {}", cli.concurrency);
    println!("  timeout_ms   : {}", cli.timeout_ms);
    println!(
        "  output       : {}",
        cli.output
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".to_string())
    );
    println!("  serve_ui     : {}", cli.serve_ui);

    // If no explicit targets were provided, detect local CIDRs and show a brief summary.
    if cli.targets.is_none() {
        match netdetect::detect_local_cidrs() {
            Ok(cidrs) => {
                let mut total_ips = 0usize;
                println!("Detected local IPv4 CIDRs:");
                for cidr in &cidrs {
                    let ips = netdetect::expand_cidr_to_ips(cidr.clone());
                    total_ips += ips.len();
                    println!("  - {} ({} hosts)", cidr, ips.len());
                }
                println!("Total targets (approx): {}", total_ips);
            }
            Err(e) => {
                eprintln!("Warning: failed to detect local networks: {e}");
            }
        }
    }

    // Start embedded UI server if requested (non-blocking background task)
    if cli.serve_ui {
        let bind = "127.0.0.1:8080";
        tokio::spawn(async move {
            if let Err(e) = server::spawn_server(bind).await {
                eprintln!("HTTP UI server error: {e}");
            }
        });
        println!("UI server starting at http://{} (Ctrl+C to stop)", bind);
    }

    // Small demo: if targets == 127.0.0.1, run a quick scan to demonstrate engine.
    if let Some(t) = cli.targets.as_deref() {
        if t.trim() == "127.0.0.1" {
            let targets = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
            // Keep demo ports small and fast
            let demo_ports: Vec<u16> = vec![22, 80, 443, 8080];
            println!("\nRunning demo scan for 127.0.0.1 on ports {:?}...", demo_ports);
            let results = scanner::scan_targets(
                &targets,
                &demo_ports,
                cli.concurrency.min(64),
                Duration::from_millis(cli.timeout_ms),
            )
            .await?;
            print_results_table(&results);
            if let Some(path) = cli.output.as_deref() {
                if let Err(e) = write_results_json(path, &results) {
                    eprintln!("Failed to write JSON to {}: {}", path.display(), e);
                } else {
                    println!("Wrote JSON results to {}", path.display());
                }
            }
        }
    }

    // If UI is running, keep the process alive until Ctrl+C.
    if cli.serve_ui {
        println!("Press Ctrl+C to stop the server...");
        let _ = tokio::signal::ctrl_c().await;
    }

    Ok(())
}

fn print_results_table(results: &ScanResults) {
    let mut ip_w = 2usize.max("ip".len());
    let mut banner_w = 6usize.max("banner".len());
    for e in &results.entries {
        ip_w = ip_w.max(e.ip.len());
        if let Some(b) = &e.banner {
            banner_w = banner_w.max(b.len().min(60));
        }
    }
    let port_w = 4usize.max("port".len());
    let lat_w = 9usize.max("latency_ms".len());

    println!(
        "\nOpen ports: {} (scanned: {})",
        results.open_count, results.scanned_done
    );
    println!(
        "{:<ip_w$}  {:>port_w$}  {:>lat_w$}  {:<banner_w$}",
        "ip",
        "port",
        "latency_ms",
        "banner",
        ip_w = ip_w,
        port_w = port_w,
        lat_w = lat_w,
        banner_w = banner_w
    );
    println!(
        "{:-<ip_w$}  {:-<port_w$}  {:-<lat_w$}  {:-<banner_w$}",
        "",
        "",
        "",
        "",
        ip_w = ip_w,
        port_w = port_w,
        lat_w = lat_w,
        banner_w = banner_w
    );
    for e in &results.entries {
        let mut bsnip = e.banner.clone().unwrap_or_default();
        if bsnip.len() > 60 {
            bsnip.truncate(60);
        }
        println!(
            "{:<ip_w$}  {:>port_w$}  {:>lat_w$}  {:<banner_w$}",
            e.ip,
            e.port,
            e.latency_ms,
            bsnip,
            ip_w = ip_w,
            port_w = port_w,
            lat_w = lat_w,
            banner_w = banner_w
        );
    }
}

fn write_results_json(path: &std::path::Path, results: &ScanResults) -> anyhow::Result<()> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, results)?;
    Ok(())
}
