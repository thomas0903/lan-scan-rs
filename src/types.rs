use serde::{Deserialize, Serialize};

/// One discovered scan result entry for an IP:port.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ScanEntry {
    pub ip: String,
    pub port: u16,
    pub open: bool,
    pub latency_ms: u64,
    pub banner: Option<String>,
    pub timestamp: String,
}

/// Aggregate results and progress counters.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ScanResults {
    pub scanned_total: u64,
    pub scanned_done: u64,
    pub open_count: u64,
    pub entries: Vec<ScanEntry>,
}
