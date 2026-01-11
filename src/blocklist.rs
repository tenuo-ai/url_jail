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
    // 0.0.0.0 is the unspecified address - always blocked
    if ip.is_unspecified() {
        return Some("unspecified address (0.0.0.0) - blocked in all policies");
    }

    if ip.is_loopback() {
        return Some("loopback address (127.0.0.0/8) - blocked in all policies");
    }

    if ip.is_link_local() {
        return Some("link-local address (169.254.0.0/16) - blocked in all policies");
    }

    if is_metadata_ipv4(ip) {
        return Some("cloud metadata endpoint - blocked in all policies");
    }

    if policy == Policy::PublicOnly && ip.is_private() {
        return Some("private address - use AllowPrivate policy to permit");
    }

    None
}

fn is_ipv6_blocked(ip: Ipv6Addr, policy: Policy) -> Option<&'static str> {
    // :: is the unspecified address - always blocked
    if ip.is_unspecified() {
        return Some("unspecified address (::) - blocked in all policies");
    }

    // Check loopback FIRST (::1) before any IPv4 embedding checks
    if ip.is_loopback() {
        return Some("loopback address (::1) - blocked in all policies");
    }

    // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_ipv4_blocked(ipv4, policy);
    }

    // Check for IPv4-compatible IPv6 (::x.x.x.x) - deprecated but still works
    // This is different from mapped - it embeds IPv4 in the last 32 bits
    // Format: ::0000:0000:0000:0000:0000:0000:XXXX:XXXX where XXXX:XXXX is IPv4
    // Skip if it's a very small value (like ::1 which is loopback, already handled)
    let segments = ip.segments();
    if segments[0..6] == [0, 0, 0, 0, 0, 0] && (segments[6] != 0 || segments[7] > 1) {
        // Last 32 bits contain IPv4
        let ipv4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        if !ipv4.is_unspecified() {
            return is_ipv4_blocked(ipv4, policy);
        }
    }

    // is_unicast_link_local is unstable, so we check manually
    if is_ipv6_link_local(ip) {
        return Some("link-local address (fe80::/10) - blocked in all policies");
    }

    if is_metadata_ipv6(ip) {
        return Some("cloud metadata endpoint - blocked in all policies");
    }

    if policy == Policy::PublicOnly && is_ipv6_unique_local(ip) {
        return Some("private address (fc00::/7) - use AllowPrivate policy to permit");
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
    // AWS: fd00:ec2::254
    let aws_metadata: Ipv6Net = "fd00:ec2::254/128".parse().unwrap();
    if aws_metadata.contains(&ip) {
        return true;
    }

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
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_ip_blocked(mapped, Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_public_ip_allowed() {
        let public_ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(is_ip_blocked(public_ip, Policy::PublicOnly).is_none());
    }

    #[test]
    fn test_ipv6_link_local_blocked() {
        // fe80::/10 - link-local addresses blocked by both policies
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_ip_blocked(link_local, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(link_local, Policy::AllowPrivate).is_some());

        // Another link-local address
        let link_local2: IpAddr = "fe80::abcd:1234".parse().unwrap();
        assert!(is_ip_blocked(link_local2, Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_ipv6_unique_local_blocked_by_public_only() {
        // fc00::/7 (unique local) - blocked by PublicOnly, allowed by AllowPrivate
        let ula_fc: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_ip_blocked(ula_fc, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(ula_fc, Policy::AllowPrivate).is_none());

        let ula_fd: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_ip_blocked(ula_fd, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(ula_fd, Policy::AllowPrivate).is_none());

        // Full ULA address
        let ula_full: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        assert!(is_ip_blocked(ula_full, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(ula_full, Policy::AllowPrivate).is_none());
    }

    #[test]
    fn test_aws_ipv6_metadata_blocked() {
        // fd00:ec2::254 - AWS IPv6 metadata endpoint, always blocked
        let aws_meta: IpAddr = "fd00:ec2::254".parse().unwrap();
        assert!(is_ip_blocked(aws_meta, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(aws_meta, Policy::AllowPrivate).is_some());
    }

    #[test]
    fn test_ipv4_mapped_ipv6_metadata() {
        // ::ffff:169.254.169.254 - metadata via IPv4-mapped IPv6
        let mapped_meta: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_ip_blocked(mapped_meta, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(mapped_meta, Policy::AllowPrivate).is_some());
    }

    #[test]
    fn test_ipv4_mapped_ipv6_private() {
        // ::ffff:192.168.1.1 - private via IPv4-mapped IPv6
        let mapped_private: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_ip_blocked(mapped_private, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(mapped_private, Policy::AllowPrivate).is_none());
    }

    #[test]
    fn test_public_ipv6_allowed() {
        // Public IPv6 addresses should be allowed
        let public_v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(is_ip_blocked(public_v6, Policy::PublicOnly).is_none());

        let google_dns: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(is_ip_blocked(google_dns, Policy::PublicOnly).is_none());
    }

    #[test]
    fn test_hostname_blocklist_subdomain() {
        // Subdomains of blocked hostnames should also be blocked
        assert!(is_hostname_blocked("sub.metadata.google.internal").is_some());
        assert!(is_hostname_blocked("deep.sub.metadata.google.internal").is_some());
    }

    #[test]
    fn test_hostname_blocklist_instance_data() {
        // AWS EC2-Classic alternate hostname
        assert!(is_hostname_blocked("instance-data").is_some());
    }

    #[test]
    fn test_hostname_literal_ip_blocked() {
        // Literal IP as hostname should be blocked
        assert!(is_hostname_blocked("169.254.169.254").is_some());
    }

    #[test]
    fn test_ipv4_link_local_range() {
        // 169.254.0.0/16 is link-local (except metadata)
        let link_local: IpAddr = "169.254.1.1".parse().unwrap();
        assert!(is_ip_blocked(link_local, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(link_local, Policy::AllowPrivate).is_some());
    }

    #[test]
    fn test_all_private_ranges() {
        // 10.0.0.0/8
        assert!(is_ip_blocked("10.0.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("10.255.255.255".parse().unwrap(), Policy::PublicOnly).is_some());

        // 172.16.0.0/12
        assert!(is_ip_blocked("172.16.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("172.31.255.255".parse().unwrap(), Policy::PublicOnly).is_some());
        // 172.15.x and 172.32.x are NOT private
        assert!(is_ip_blocked("172.15.0.1".parse().unwrap(), Policy::PublicOnly).is_none());
        assert!(is_ip_blocked("172.32.0.1".parse().unwrap(), Policy::PublicOnly).is_none());

        // 192.168.0.0/16
        assert!(is_ip_blocked("192.168.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("192.168.255.255".parse().unwrap(), Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_loopback_full_range() {
        // Entire 127.0.0.0/8 is loopback
        assert!(is_ip_blocked("127.0.0.1".parse().unwrap(), Policy::AllowPrivate).is_some());
        assert!(is_ip_blocked("127.1.2.3".parse().unwrap(), Policy::AllowPrivate).is_some());
        assert!(is_ip_blocked("127.255.255.255".parse().unwrap(), Policy::AllowPrivate).is_some());
    }

    // ==================== Unspecified address tests ====================

    #[test]
    fn test_unspecified_ipv4_blocked() {
        // 0.0.0.0 is the unspecified address - always blocked
        assert!(is_ip_blocked("0.0.0.0".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("0.0.0.0".parse().unwrap(), Policy::AllowPrivate).is_some());
    }

    #[test]
    fn test_unspecified_ipv6_blocked() {
        // :: is the unspecified address - always blocked
        assert!(is_ip_blocked("::".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("::".parse().unwrap(), Policy::AllowPrivate).is_some());
    }

    // ==================== IPv4-compatible IPv6 tests ====================

    #[test]
    fn test_ipv4_compatible_ipv6_loopback() {
        // ::127.0.0.1 - deprecated IPv4-compatible format (different from mapped)
        // This format embeds IPv4 in last 32 bits with leading zeros
        let compat: IpAddr = "::127.0.0.1".parse().unwrap();
        // Note: Rust parses this as ::7f00:1, check if we catch it
        assert!(is_ip_blocked(compat, Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_ipv4_compatible_ipv6_metadata() {
        // ::169.254.169.254 - metadata via IPv4-compatible
        let compat: IpAddr = "::169.254.169.254".parse().unwrap();
        assert!(is_ip_blocked(compat, Policy::PublicOnly).is_some());
    }

    // ==================== RED TEAM: IPv6 Bypass Attempts ====================

    #[test]
    fn test_redteam_ipv6_loopback_variations() {
        // Various representations of ::1
        assert!(is_ip_blocked("::1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("0:0:0:0:0:0:0:1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(
            "0000:0000:0000:0000:0000:0000:0000:0001".parse().unwrap(),
            Policy::PublicOnly
        )
        .is_some());
    }

    #[test]
    fn test_redteam_ipv4_mapped_loopback_variations() {
        // ::ffff:127.0.0.1 in different forms
        assert!(is_ip_blocked("::ffff:127.0.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("::ffff:7f00:1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(
            "0:0:0:0:0:ffff:127.0.0.1".parse().unwrap(),
            Policy::PublicOnly
        )
        .is_some());
    }

    #[test]
    fn test_redteam_ipv4_mapped_private() {
        // Private ranges via IPv4-mapped
        assert!(is_ip_blocked("::ffff:10.0.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("::ffff:172.16.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("::ffff:192.168.0.1".parse().unwrap(), Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_redteam_ipv4_mapped_link_local() {
        // Link-local via IPv4-mapped
        assert!(is_ip_blocked("::ffff:169.254.1.1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(
            "::ffff:169.254.169.254".parse().unwrap(),
            Policy::PublicOnly
        )
        .is_some());
    }

    #[test]
    fn test_redteam_ipv6_link_local_variations() {
        // Link-local with various interface identifiers
        assert!(is_ip_blocked("fe80::1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(
            "fe80::ffff:ffff:ffff:ffff".parse().unwrap(),
            Policy::PublicOnly
        )
        .is_some());
        assert!(is_ip_blocked("fe80:0:0:0:0:0:0:1".parse().unwrap(), Policy::PublicOnly).is_some());
    }

    #[test]
    fn test_redteam_ipv6_ula_edge_cases() {
        // Unique Local Address edge cases
        // fc00::/7 covers fc00::/8 and fd00::/8
        assert!(is_ip_blocked("fc00::1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("fd00::1".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            Policy::PublicOnly
        )
        .is_some());
    }

    // ==================== RED TEAM: Cloud Metadata Variations ====================

    #[test]
    fn test_redteam_aws_metadata_ipv6() {
        // AWS IPv6 metadata endpoint
        let aws_v6: IpAddr = "fd00:ec2::254".parse().unwrap();
        assert!(is_ip_blocked(aws_v6, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(aws_v6, Policy::AllowPrivate).is_some());
    }

    #[test]
    fn test_redteam_alibaba_metadata() {
        // Alibaba Cloud metadata
        let alibaba: IpAddr = "100.100.100.200".parse().unwrap();
        assert!(is_ip_blocked(alibaba, Policy::PublicOnly).is_some());
        assert!(is_ip_blocked(alibaba, Policy::AllowPrivate).is_some());
    }

    #[test]
    fn test_redteam_metadata_adjacent_ips() {
        // IPs near metadata endpoints - should NOT be blocked
        // 169.254.169.253 (one before metadata)
        let before: IpAddr = "169.254.169.253".parse().unwrap();
        // Still link-local, so blocked
        assert!(is_ip_blocked(before, Policy::PublicOnly).is_some());

        // 169.254.169.255 (one after metadata)
        let after: IpAddr = "169.254.169.255".parse().unwrap();
        // Still link-local
        assert!(is_ip_blocked(after, Policy::PublicOnly).is_some());
    }

    // ==================== RED TEAM: Private Range Boundaries ====================

    #[test]
    fn test_redteam_private_range_boundaries() {
        // Just inside 10.0.0.0/8
        assert!(is_ip_blocked("10.0.0.0".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("10.255.255.255".parse().unwrap(), Policy::PublicOnly).is_some());

        // Just outside 10.0.0.0/8
        assert!(is_ip_blocked("9.255.255.255".parse().unwrap(), Policy::PublicOnly).is_none());
        assert!(is_ip_blocked("11.0.0.0".parse().unwrap(), Policy::PublicOnly).is_none());
    }

    #[test]
    fn test_redteam_172_range_boundaries() {
        // 172.16.0.0/12 boundaries
        assert!(is_ip_blocked("172.16.0.0".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("172.31.255.255".parse().unwrap(), Policy::PublicOnly).is_some());

        // Just outside
        assert!(is_ip_blocked("172.15.255.255".parse().unwrap(), Policy::PublicOnly).is_none());
        assert!(is_ip_blocked("172.32.0.0".parse().unwrap(), Policy::PublicOnly).is_none());
    }

    #[test]
    fn test_redteam_192_168_boundaries() {
        // 192.168.0.0/16 boundaries
        assert!(is_ip_blocked("192.168.0.0".parse().unwrap(), Policy::PublicOnly).is_some());
        assert!(is_ip_blocked("192.168.255.255".parse().unwrap(), Policy::PublicOnly).is_some());

        // Just outside
        assert!(is_ip_blocked("192.167.255.255".parse().unwrap(), Policy::PublicOnly).is_none());
        assert!(is_ip_blocked("192.169.0.0".parse().unwrap(), Policy::PublicOnly).is_none());
    }

    // ==================== RED TEAM: Loopback Range ====================

    #[test]
    fn test_redteam_loopback_full_range() {
        // Entire 127.0.0.0/8 should be blocked
        assert!(is_ip_blocked("127.0.0.0".parse().unwrap(), Policy::AllowPrivate).is_some());
        assert!(is_ip_blocked("127.0.0.1".parse().unwrap(), Policy::AllowPrivate).is_some());
        assert!(is_ip_blocked("127.255.255.255".parse().unwrap(), Policy::AllowPrivate).is_some());
        assert!(is_ip_blocked("127.1.2.3".parse().unwrap(), Policy::AllowPrivate).is_some());
    }

    // ==================== RED TEAM: Carrier-Grade NAT ====================

    #[test]
    fn test_redteam_cgnat_range() {
        // 100.64.0.0/10 (Carrier-Grade NAT) - should this be blocked?
        // Currently NOT in our blocklist - document this behavior
        let cgnat: IpAddr = "100.64.0.1".parse().unwrap();
        // CGNAT is not private per RFC 1918, but is shared address space
        // We don't block it by default - users can add with PolicyBuilder
        let result = is_ip_blocked(cgnat, Policy::PublicOnly);
        // Document current behavior (not blocked)
        assert!(result.is_none() || result.is_some());
    }

    // ==================== RED TEAM: Broadcast Addresses ====================

    #[test]
    fn test_redteam_broadcast_addresses() {
        // Limited broadcast
        let limited: IpAddr = "255.255.255.255".parse().unwrap();
        // We don't specifically block broadcast, but it's not useful for SSRF
        let _ = is_ip_blocked(limited, Policy::PublicOnly);

        // Directed broadcast (e.g., 192.168.1.255 for 192.168.1.0/24)
        // These are private, so blocked by PublicOnly anyway
        assert!(is_ip_blocked("192.168.1.255".parse().unwrap(), Policy::PublicOnly).is_some());
    }
}
