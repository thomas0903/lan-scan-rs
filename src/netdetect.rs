use anyhow::Result;
use if_addrs::{get_if_addrs, IfAddr};
use ipnet::{IpNet, Ipv4Net};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

/// Detect local non-loopback IPv4 addresses and convert each to a default /24 CIDR network.
///
/// For example, an interface IP `192.168.1.42` becomes `192.168.1.0/24`.
/// Duplicates are removed.
pub fn detect_local_cidrs() -> Result<Vec<IpNet>> {
    let mut set = HashSet::<Ipv4Net>::new();
    for iface in get_if_addrs()? {
        if let IfAddr::V4(v4) = iface.addr {
            let ip = v4.ip;
            if ip.is_loopback() {
                continue;
            }
            let cidr = ipv4_to_default_cidr(ip);
            set.insert(cidr);
        }
    }
    let mut cidrs: Vec<IpNet> = set.into_iter().map(IpNet::V4).collect();
    // Sort for stable output
    cidrs.sort_by_key(|n| match n {
        IpNet::V4(n4) => (u32::from(n4.network()), n4.prefix_len()),
        IpNet::V6(_) => (0, 0),
    });
    Ok(cidrs)
}

/// Expand a CIDR into individual IP addresses suitable for host scanning.
///
/// For IPv4, excludes the network and broadcast addresses.
/// IPv6 is not scanned in this project and returns an empty list.
pub fn expand_cidr_to_ips(cidr: IpNet) -> Vec<IpAddr> {
    match cidr {
        IpNet::V4(n4) => expand_ipv4net_hosts(n4)
            .into_iter()
            .map(IpAddr::V4)
            .collect(),
        IpNet::V6(_) => Vec::new(),
    }
}

/// Helper: convert an IPv4 address into its default /24 network.
pub fn ipv4_to_default_cidr(ip: Ipv4Addr) -> Ipv4Net {
    let o = ip.octets();
    let net = Ipv4Addr::new(o[0], o[1], o[2], 0);
    Ipv4Net::new(net, 24).expect("/24 is always valid")
}

fn expand_ipv4net_hosts(net: Ipv4Net) -> Vec<Ipv4Addr> {
    // Use inclusive range of numeric IPs, then skip network and broadcast.
    let start = u32::from(net.network());
    let end = u32::from(net.broadcast());
    if end <= start + 1 {
        // Too small to have host addresses
        return Vec::new();
    }
    (start + 1..end)
        .map(|n| Ipv4Addr::from(n))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cidr_from_ipv4() {
        let cidr = ipv4_to_default_cidr(Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(cidr.to_string(), "10.1.2.0/24");
    }

    #[test]
    fn expand_small_cidr_excludes_network_and_broadcast() {
        let net = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 30).unwrap();
        // /30 -> 4 addresses: .0 network, .1 host, .2 host, .3 broadcast
        let hosts = expand_cidr_to_ips(IpNet::V4(net));
        let ips: Vec<Ipv4Addr> = hosts
            .into_iter()
            .filter_map(|ip| match ip { IpAddr::V4(v4) => Some(v4), _ => None })
            .collect();
        assert_eq!(ips, vec![
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
        ]);
    }
}

