use lan_scan_rs::ports::parse_ports_str;

#[test]
fn parse_single_and_ranges_and_comments() {
    let input = r#"
        # common ports
        22
        80  # http
        443 # https
        8000-8002
        8001  # duplicate
        # blank line follows

    "#;

    let ports = parse_ports_str(input).expect("parse ok");
    // Dedup, preserve insertion order of first appearance in each range/line
    assert_eq!(ports, vec![22, 80, 443, 8000, 8001, 8002]);
}

#[test]
fn invalid_port_rejected() {
    let input = "0\n"; // invalid: out of range
    assert!(parse_ports_str(input).is_err());
}
