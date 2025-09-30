use std::path::PathBuf;

mod ports;

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

fn main() -> Result<()> {
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

    // Scanner, network detection, and UI server wiring will be implemented in later steps.
    // For now, we just return successfully after printing parsed options.
    Ok(())
}
