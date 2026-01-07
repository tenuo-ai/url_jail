//! Blocklists for hostnames and IP addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use crate::Policy;

/// Hostnames that are always blocked (checked before DNS resolution).
const BLOCKED_HOSTNAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.internal",
    "169.254.169.254", // Literal IP as hostname
    "instance-data",   // AWS alternate (EC2-Classic)
];

/// Check if a hostname is blocked.
pub fn is_hostname_blocked(host: &str) -> Option<&'static str> {
    let host_lower = host.to_lowercase();
    for &blocked in BLOCKED_HOSTNAMES {
        if host_lower == blocked || host_lower.ends_with(&format!(".{}", blocked)) {
            return Some(blocked);
        }
    }
    None
}

/// Check if an IP address is blocked by the given policy.
pub fn is_ip_blocked(ip: IpAddr, policy: Policy) -> Option<&'static str> {
    match ip {
        IpAddr::V4(ipv4) => is_ipv4_blocked(ipv4, policy),
        IpAddr::V6(ipv6) => is_ipv6_blocked(ipv6, policy),
    }
}

fn is_ipv4_blocked(ip: Ipv4Addr, policy: Policy) -> Option<&'static str> {
    // Always blocked: loopback
    if ip.is_loopback() {
        return Some("loopback address");
    }

    // Always blocked: link-local (169.254.0.0/16)
    if ip.is_link_local() {
        return Some("link-local address");
    }

    // Always blocked: metadata endpoints
    if is_metadata_ipv4(ip) {
        return Some("cloud metadata endpoint");
    }

    // PublicOnly: block private ranges
    if policy == Policy::PublicOnly && ip.is_private() {
        return Some("private address");
    }

    None
}

fn is_ipv6_blocked(ip: Ipv6Addr, policy: Policy) -> Option<&'static str> {
    // Check if this is an IPv4-mapped IPv6 address
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_ipv4_blocked(ipv4, policy);
    }

    // Always blocked: loopback (::1)
    if ip.is_loopback() {
        return Some("loopback address");
    }

    // Always blocked: link-local (fe80::/10)
    // Note: is_unicast_link_local is unstable, so we check manually
    if is_ipv6_link_local(ip) {
        return Some("link-local address");
    }

    // Always blocked: AWS metadata IPv6 (fd00:ec2::254)
    if is_metadata_ipv6(ip) {
        return Some("cloud metadata endpoint");
    }

    // PublicOnly: block unique local addresses (fc00::/7)
    if policy == Policy::PublicOnly && is_ipv6_unique_local(ip) {
        return Some("private address");
    }

    None
}

/// Check if IPv4 is a cloud metadata endpoint.
fn is_metadata_ipv4(ip: Ipv4Addr) -> bool {
    // AWS/GCP/Azure: 169.254.169.254
    if ip == Ipv4Addr::new(169, 254, 169, 254) {
        return true;
    }

    // Alibaba Cloud: 100.100.100.200
    if ip == Ipv4Addr::new(100, 100, 100, 200) {
        return true;
    }

    false
}

/// Check if IPv6 is a cloud metadata endpoint.
fn is_metadata_ipv6(ip: Ipv6Addr) -> bool {
    // AWS metadata IPv6: fd00:ec2::254
    let aws_metadata: Ipv6Net = "fd00:ec2::254/128".parse().unwrap();
    if aws_metadata.contains(&ip) {
        return true;
    }

    // Also check IPv4-mapped versions of metadata IPs
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_metadata_ipv4(ipv4);
    }

    false
}

/// Check if IPv6 is link-local (fe80::/10).
fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// Check if IPv6 is unique local (fc00::/7).
fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_blocklist() {
        assert!(is_hostname_blocked("metadata.google.internal").is_some());
        assert!(is_hostname_blocked("METADATA.GOOGLE.INTERNAL").is_some());
        assert!(is_hostname_blocked("metadata.azure.internal").is_some());
        assert!(is_hostname_blocked("example.com").is_none());
    }

    #[test]
    fn test_loopback_blocked() {
        assert!(is_ip_blocked("127.0.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("127.0.0.1".parse().unwrap(), Policy::AllowPrivate).is_some());
        assert!(is_ip_blocked("::1".parse().unwrap(), Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_private_ip_policy() {
        let private_ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(is_ip_blocked(private_ip, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(private_ip, Policy::AllowPrivate).is_none());
    }

    #[test]
    fn test_metadata_endpoints() {
        assert!(is_ip_blocked("169.254.169.254".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("169.254.169.254".parse().unwrap(), Policy::AllowPrivate).is_some());
        assert!(is_ip_blocked("100.100.100.200".parse().unwrap(), Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 should be blocked as loopback
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_ip_blocked(mapped, Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_public_ip_allowed() {
        let public_ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(is_ip_blocked(public_ip, Policy::PublicOnly).is_none());
    }
}
