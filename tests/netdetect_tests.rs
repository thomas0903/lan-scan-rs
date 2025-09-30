use ipnet::Ipv4Net;
use lan_scan_rs::netdetect::{expand_cidr_to_ips, ipv4_to_default_cidr};
use std::net::Ipv4Addr;

#[test]
fn default_cidr_is_24() {
    let cidr = ipv4_to_default_cidr(Ipv4Addr::new(192, 168, 42, 99));
    assert_eq!(cidr.to_string(), "192.168.42.0/24");
}

#[test]
fn expand_excludes_network_and_broadcast() {
    let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 30).unwrap();
    let ips = expand_cidr_to_ips(ipnet::IpNet::V4(net));
    let list: Vec<_> = ips
        .into_iter()
        .map(|ip| match ip {
            std::net::IpAddr::V4(v) => v,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(
        list,
        vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
    );
}
