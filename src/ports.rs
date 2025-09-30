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
    const DEFAULT: &[u16] = &[
        21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445,
        465, 500, 514, 587, 631, 993, 995, 1025, 1433, 1521, 1723, 1883, 2049, 2375, 2380, 3000,
        3128, 3260, 3306, 3389, 4369, 5000, 5040, 5432, 5672, 5900, 5985, 5986, 6379, 7001, 7002,
        8000, 8008, 8080, 8081, 8088, 8443, 8500, 8888, 9000, 9092, 9200, 9300, 11211, 27017,
    ];
    DEFAULT.to_vec()
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
