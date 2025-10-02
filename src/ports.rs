use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// Parse a ports file content into a deduplicated list of TCP ports (1..=65535).
///
/// Supported formats per line:
/// - single port number: `80`
/// - inclusive range: `8000-8010`
/// - comments: everything after `#` is ignored
/// - whitespace and blank lines are ignored
pub fn parse_ports_str(s: &str) -> Result<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (idx, raw_line) in s.lines().enumerate() {
        let line_no = idx + 1;
        // Strip comments and trim
        let line = raw_line.split('#').next().map(str::trim).unwrap_or("");
        if line.is_empty() {
            continue;
        }

        // Range `start-end`
        if let Some((a, b)) = line.split_once('-') {
            let start = parse_port_str(a.trim())
                .with_context(|| format!("line {line_no}: invalid start in range: {a}"))?;
            let end = parse_port_str(b.trim())
                .with_context(|| format!("line {line_no}: invalid end in range: {b}"))?;
            if start > end {
                bail!("line {line_no}: invalid range {start}-{end} (start > end)");
            }
            for p in start..=end {
                if seen.insert(p) {
                    out.push(p);
                }
            }
            continue;
        }

        // Single number
        let p = parse_port_str(line)
            .with_context(|| format!("line {line_no}: invalid port value: {line}"))?;
        if seen.insert(p) {
            out.push(p);
        }
    }

    Ok(out)
}

/// Load a ports list from a file path. Errors if the file cannot be read or parsed.
pub fn load_ports_from_path(path: impl AsRef<Path>) -> Result<Vec<u16>> {
    let content = fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read ports file: {}", path.as_ref().display()))?;
    parse_ports_str(&content)
}

/// Load a ports list from a file, or return a safe default list if missing or empty.
pub fn load_ports_or_default(path: impl AsRef<Path>) -> Vec<u16> {
    match load_ports_from_path(&path) {
        Ok(v) if !v.is_empty() => v,
        _ => default_ports(),
    }
}

/// A conservative default list of commonly used TCP ports.
/// This list is intentionally small-but-useful and safe for LAN scanning.
pub fn default_ports() -> Vec<u16> {
    // Expanded default list: widely used TCP services across infra, web, DBs, and tooling.
    // Can be filtered via --exclude-ports or UI toggles.
    const DEFAULT: &[u16] = &[
        // Core infra
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 179,
        389, 427, 443, 445, 465, 500, 512, 513, 514, 515, 520, 554, 587, 631, 636, 853, 873, 902,
        989, 990, 993, 995, // App servers / DBs / queues
        1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 2375,
        2376, 2380, 2483, 2484, 27017, 27018, 27019, 28017, 3000, 3128, 3260, 3306, 3333, 3389,
        3478, 4000, 4040, 4369, 4444, 4500, 4567, 5000, 5001, 5040, 5050, 5060, 5061, 5432, 5555,
        5671, 5672, 5696, 5900, 5901, 5984, 5985, 5986, 6000, 6080, 61616, 6379, 6380, 6443, 6666,
        6667, 7001, 7002, 7199, 7200, 7777, 8000, 8001, 8008, 8009, 8010, 8080, 8081, 8088, 8089,
        8090, 8161, 8181, 8200, 8222, 8333, 8443, 8500, 8529, 8888, 9000, 9001, 9042, 9071, 9090,
        9091, 9092, 9100, 9200, 9300, 9418, 9443, 9500, 9600, 9666, 9999, 10000, 11211,
    ];
    DEFAULT.to_vec()
}

/// A smaller set for quick scans, focusing on common interactive/web/DB ports.
pub fn quick_ports() -> Vec<u16> {
    const Q: &[u16] = &[
        21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 465, 500, 587, 631, 993, 995, 1433, 1521,
        1723, 1883, 3000, 3128, 3260, 3306, 3389, 5000, 5432, 5672, 5900, 5985, 5986, 6379, 7001,
        7002, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9092, 9200, 9300, 11211, 27017,
    ];
    Q.to_vec()
}

fn parse_port_str(s: &str) -> Result<u16> {
    let val: u32 = s.parse::<u32>().map_err(|e| anyhow::anyhow!(e))?;
    if val == 0 || val > 65535 {
        bail!("port out of range: {val}");
    }
    Ok(val as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_ports() {
        let input = "80\n22\n   443  \n";
        let ports = parse_ports_str(input).unwrap();
        assert_eq!(ports, vec![80, 22, 443]);
    }

    #[test]
    fn parse_ranges_and_dedup() {
        let input = "8000-8002\n80\n8001\n";
        let ports = parse_ports_str(input).unwrap();
        assert_eq!(ports, vec![8000, 8001, 8002, 80]);
    }

    #[test]
    fn parse_with_comments_and_whitespace() {
        let input = r#"
            # common web ports
            80  # http
            443 # https
            8000-8002   # dev servers

            # blank lines and spaces should be fine
        "#;
        let ports = parse_ports_str(input).unwrap();
        assert_eq!(ports, vec![80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn invalid_values_error() {
        let input = "70000\n"; // out of range
        let err = parse_ports_str(input);
        assert!(err.is_err());
    }

    #[test]
    fn default_has_common_ports() {
        let d = default_ports();
        assert!(!d.is_empty());
        assert!(d.contains(&80) && d.contains(&443));
    }
}
