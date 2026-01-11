//! Custom policy builder for advanced SSRF protection.
//!
//! ## Design Principles
//!
//! Custom policies follow the same principles as built-in policies:
//!
//! - **Pure validation constraints**: Based solely on IP addresses and hostnames
//! - **No user identity**: Policies don't know who is making the request
//! - **No context**: Policies don't consider headers, methods, or request bodies
//! - **No time**: Policies don't change based on time of day or rate limits
//! - **No delegation**: Policies can't defer to external services
//!
//! ## Immutability
//!
//! Once built via [`PolicyBuilder::build()`], a [`CustomPolicy`] cannot be modified.
//! The builder consumes `self` on each method call, preventing accidental reuse.
//!
//! ## Security Considerations
//!
//! **Be careful with `allow_*` methods.** These override the base policy's blocks:
//!
//! ```rust
//! use url_jail::{PolicyBuilder, Policy};
//!
//! // DANGEROUS: This allows localhost access!
//! let bad_policy = PolicyBuilder::new(Policy::PublicOnly)
//!     .allow_cidr("127.0.0.0/8")  // Defeats SSRF protection!
//!     .build();
//! ```
//!
//! Only use `allow_*` methods when you have a specific, audited use case.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::blocklist::is_ip_blocked;
use crate::policy::Policy;

/// A custom policy with user-defined blocklists and allowlists.
///
/// Created via [`PolicyBuilder`]. This allows fine-grained control over which
/// IPs and hostnames are allowed or blocked, beyond the built-in [`Policy`] options.
///
/// # Immutability
///
/// Once created, a `CustomPolicy` cannot be modified. All fields are private
/// and there are no `&mut self` methods.
///
/// # Precedence
///
/// Allow rules take precedence over block rules:
/// 1. If IP/hostname matches an allow rule → allowed
/// 2. If IP/hostname matches a block rule → blocked
/// 3. Otherwise, fall back to base policy
///
/// # Scope
///
/// Like [`Policy`], custom policies are pure validation constraints:
/// - No user identity or authentication
/// - No request context
/// - No time-based logic
///
/// # Example
///
/// ```rust
/// use url_jail::{PolicyBuilder, Policy};
///
/// let policy = PolicyBuilder::new(Policy::AllowPrivate)
///     .block_cidr("10.0.0.0/8")
///     .allow_cidr("10.1.0.0/16")  // This takes precedence
///     .build();
///
/// // 10.1.x.x is allowed (matches allow rule)
/// assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_ok());
/// // 10.2.x.x is blocked (matches block rule, no allow rule)
/// assert!(policy.is_ip_allowed("10.2.0.1".parse().unwrap()).is_err());
/// ```
#[derive(Debug, Clone)]
pub struct CustomPolicy {
    base: Policy,
    blocked_cidrs: Vec<IpNet>,
    allowed_cidrs: Vec<IpNet>,
    blocked_hosts: Vec<String>,
    allowed_hosts: Vec<String>,
}

impl CustomPolicy {
    /// Check if an IP address is allowed by this policy.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` if blocked.
    pub fn is_ip_allowed(&self, ip: IpAddr) -> Result<(), String> {
        // Check explicit allowlist first
        for cidr in &self.allowed_cidrs {
            if cidr.contains(&ip) {
                return Ok(());
            }
        }

        // Check explicit blocklist
        for cidr in &self.blocked_cidrs {
            if cidr.contains(&ip) {
                return Err(format!("blocked by custom policy CIDR rule: {}", cidr));
            }
        }

        // Fall back to base policy
        if let Some(reason) = is_ip_blocked(ip, self.base) {
            return Err(reason.to_string());
        }

        Ok(())
    }

    /// Check if a hostname is allowed by this policy.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` if blocked.
    /// Hostname matching is case-insensitive.
    pub fn is_hostname_allowed(&self, host: &str) -> Result<(), String> {
        let host_lower = host.to_lowercase();

        // Check explicit allowlist first
        for pattern in &self.allowed_hosts {
            if matches_hostname_pattern(&host_lower, pattern) {
                return Ok(());
            }
        }

        // Check explicit blocklist
        for pattern in &self.blocked_hosts {
            if matches_hostname_pattern(&host_lower, pattern) {
                return Err(format!(
                    "blocked by custom policy hostname rule: {}",
                    pattern
                ));
            }
        }

        Ok(())
    }
}

/// Builder for creating custom policies.
#[derive(Debug, Clone, Default)]
pub struct PolicyBuilder {
    base: Policy,
    blocked_cidrs: Vec<IpNet>,
    allowed_cidrs: Vec<IpNet>,
    blocked_hosts: Vec<String>,
    allowed_hosts: Vec<String>,
}

impl PolicyBuilder {
    /// Create a new builder with the given base policy.
    pub fn new(base: Policy) -> Self {
        Self {
            base,
            ..Default::default()
        }
    }

    /// Block an IP range (CIDR notation).
    ///
    /// # Example
    /// ```
    /// use url_jail::{PolicyBuilder, Policy};
    ///
    /// let policy = PolicyBuilder::new(Policy::AllowPrivate)
    ///     .block_cidr("10.0.0.0/8")
    ///     .build();
    /// ```
    pub fn block_cidr(mut self, cidr: &str) -> Self {
        if let Ok(net) = cidr.parse() {
            self.blocked_cidrs.push(net);
        }
        self
    }

    /// Allow an IP range (CIDR notation), overriding base policy.
    pub fn allow_cidr(mut self, cidr: &str) -> Self {
        if let Ok(net) = cidr.parse() {
            self.allowed_cidrs.push(net);
        }
        self
    }

    /// Block a hostname or pattern.
    ///
    /// Supports wildcards: `*.internal.example.com`
    pub fn block_host(mut self, pattern: &str) -> Self {
        self.blocked_hosts.push(pattern.to_lowercase());
        self
    }

    /// Allow a hostname or pattern, overriding base blocklist.
    pub fn allow_host(mut self, pattern: &str) -> Self {
        self.allowed_hosts.push(pattern.to_lowercase());
        self
    }

    /// Build the custom policy.
    pub fn build(self) -> CustomPolicy {
        CustomPolicy {
            base: self.base,
            blocked_cidrs: self.blocked_cidrs,
            allowed_cidrs: self.allowed_cidrs,
            blocked_hosts: self.blocked_hosts,
            allowed_hosts: self.allowed_hosts,
        }
    }
}

/// Match a hostname against a pattern (supports * wildcard).
fn matches_hostname_pattern(host: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        host.ends_with(suffix) || host == &pattern[2..]
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== CIDR blocking tests ====================

    #[test]
    fn test_block_cidr() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("10.0.0.0/8")
            .build();

        assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_err());
        assert!(policy.is_ip_allowed("192.168.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_block_multiple_cidrs() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("10.0.0.0/8")
            .block_cidr("172.16.0.0/12")
            .build();

        assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_err());
        assert!(policy.is_ip_allowed("172.20.1.1".parse().unwrap()).is_err());
        assert!(policy.is_ip_allowed("192.168.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_block_single_ip_cidr() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("192.168.1.100/32")
            .build();

        assert!(policy
            .is_ip_allowed("192.168.1.100".parse().unwrap())
            .is_err());
        assert!(policy
            .is_ip_allowed("192.168.1.101".parse().unwrap())
            .is_ok());
    }

    #[test]
    fn test_block_ipv6_cidr() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("2001:db8::/32")
            .build();

        assert!(policy
            .is_ip_allowed("2001:db8::1".parse().unwrap())
            .is_err());
        assert!(policy.is_ip_allowed("2001:db9::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_block_invalid_cidr_ignored() {
        // Invalid CIDR should be silently ignored (builder pattern)
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("not-a-cidr")
            .block_cidr("10.0.0.0/8")
            .build();

        // 10.x should still be blocked
        assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_err());
    }

    // ==================== CIDR allowing tests ====================

    #[test]
    fn test_allow_cidr_overrides() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_cidr("192.168.1.0/24")
            .build();

        // This private IP is explicitly allowed
        assert!(policy
            .is_ip_allowed("192.168.1.50".parse().unwrap())
            .is_ok());
        // Other private IPs still blocked by base policy
        assert!(policy
            .is_ip_allowed("192.168.2.1".parse().unwrap())
            .is_err());
    }

    #[test]
    fn test_allow_loopback_override() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_cidr("127.0.0.0/8")
            .build();

        // Loopback is normally always blocked, but we explicitly allowed it
        assert!(policy.is_ip_allowed("127.0.0.1".parse().unwrap()).is_ok());
        assert!(policy.is_ip_allowed("127.1.2.3".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_allow_takes_precedence_over_block() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_cidr("10.0.0.0/8")
            .allow_cidr("10.1.0.0/16")
            .build();

        // 10.1.x.x is allowed despite 10.0.0.0/8 being blocked
        assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_ok());
        // Other 10.x.x.x still blocked
        assert!(policy.is_ip_allowed("10.2.0.1".parse().unwrap()).is_err());
    }

    // ==================== Hostname blocking tests ====================

    #[test]
    fn test_block_host_pattern() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.internal.example.com")
            .build();

        assert!(policy
            .is_hostname_allowed("api.internal.example.com")
            .is_err());
        assert!(policy.is_hostname_allowed("api.example.com").is_ok());
    }

    #[test]
    fn test_block_host_exact() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("blocked.example.com")
            .build();

        assert!(policy.is_hostname_allowed("blocked.example.com").is_err());
        assert!(policy.is_hostname_allowed("other.example.com").is_ok());
        // Subdomain should NOT match exact hostname block
        assert!(policy
            .is_hostname_allowed("sub.blocked.example.com")
            .is_ok());
    }

    #[test]
    fn test_block_host_wildcard_matches_exact() {
        // *.example.com should also match example.com itself
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.example.com")
            .build();

        assert!(policy.is_hostname_allowed("sub.example.com").is_err());
        assert!(policy.is_hostname_allowed("example.com").is_err());
    }

    #[test]
    fn test_block_host_case_insensitive() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("blocked.example.com")
            .build();

        assert!(policy.is_hostname_allowed("BLOCKED.EXAMPLE.COM").is_err());
        assert!(policy.is_hostname_allowed("Blocked.Example.Com").is_err());
    }

    #[test]
    fn test_block_multiple_hosts() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.internal.com")
            .block_host("*.private.org")
            .build();

        assert!(policy.is_hostname_allowed("api.internal.com").is_err());
        assert!(policy.is_hostname_allowed("db.private.org").is_err());
        assert!(policy.is_hostname_allowed("public.example.com").is_ok());
    }

    // ==================== Hostname allowing tests ====================

    #[test]
    fn test_allow_host_pattern() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_host("trusted.internal")
            .build();

        assert!(policy.is_hostname_allowed("trusted.internal").is_ok());
    }

    #[test]
    fn test_allow_host_takes_precedence_over_block() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.example.com")
            .allow_host("trusted.example.com")
            .build();

        // trusted.example.com is allowed despite *.example.com being blocked
        assert!(policy.is_hostname_allowed("trusted.example.com").is_ok());
        // Other subdomains still blocked
        assert!(policy.is_hostname_allowed("blocked.example.com").is_err());
    }

    #[test]
    fn test_allow_host_wildcard() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.example.com")
            .allow_host("*.trusted.example.com")
            .build();

        assert!(policy
            .is_hostname_allowed("api.trusted.example.com")
            .is_ok());
        assert!(policy.is_hostname_allowed("other.example.com").is_err());
    }

    // ==================== Base policy interaction tests ====================

    #[test]
    fn test_public_only_base_blocks_private() {
        let policy = PolicyBuilder::new(Policy::PublicOnly).build();

        assert!(policy
            .is_ip_allowed("192.168.1.1".parse().unwrap())
            .is_err());
        assert!(policy.is_ip_allowed("10.0.0.1".parse().unwrap()).is_err());
        assert!(policy
            .is_ip_allowed("93.184.216.34".parse().unwrap())
            .is_ok());
    }

    #[test]
    fn test_allow_private_base_allows_private() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate).build();

        assert!(policy.is_ip_allowed("192.168.1.1".parse().unwrap()).is_ok());
        assert!(policy.is_ip_allowed("10.0.0.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_allow_private_base_still_blocks_loopback() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate).build();

        assert!(policy.is_ip_allowed("127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_allow_private_base_still_blocks_metadata() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate).build();

        assert!(policy
            .is_ip_allowed("169.254.169.254".parse().unwrap())
            .is_err());
    }

    // ==================== matches_hostname_pattern tests ====================

    #[test]
    fn test_matches_hostname_pattern_exact() {
        assert!(matches_hostname_pattern("example.com", "example.com"));
        assert!(!matches_hostname_pattern("example.com", "other.com"));
    }

    #[test]
    fn test_matches_hostname_pattern_wildcard() {
        assert!(matches_hostname_pattern("sub.example.com", "*.example.com"));
        assert!(matches_hostname_pattern(
            "deep.sub.example.com",
            "*.example.com"
        ));
        assert!(!matches_hostname_pattern("other.com", "*.example.com"));
    }

    #[test]
    fn test_matches_hostname_pattern_wildcard_matches_base() {
        // *.example.com should also match example.com
        assert!(matches_hostname_pattern("example.com", "*.example.com"));
    }

    #[test]
    fn test_matches_hostname_pattern_case() {
        // Function expects lowercase input
        assert!(matches_hostname_pattern("example.com", "example.com"));
        // Case mismatch - function doesn't handle, caller should lowercase
        assert!(!matches_hostname_pattern("EXAMPLE.COM", "example.com"));
    }

    // ==================== Builder chaining tests ====================

    #[test]
    fn test_builder_chaining() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_cidr("10.0.0.0/8")
            .allow_cidr("10.1.0.0/16")
            .block_host("*.internal.com")
            .allow_host("trusted.internal.com")
            .build();

        // IP checks
        assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_ok());
        assert!(policy.is_ip_allowed("10.2.0.1".parse().unwrap()).is_err());

        // Hostname checks
        assert!(policy.is_hostname_allowed("trusted.internal.com").is_ok());
        assert!(policy.is_hostname_allowed("other.internal.com").is_err());
    }

    #[test]
    fn test_policy_clone() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_cidr("10.0.0.0/8")
            .build();

        let cloned = policy.clone();

        assert!(cloned.is_ip_allowed("10.1.2.3".parse().unwrap()).is_err());
    }

    // ==================== Error message tests ====================

    #[test]
    fn test_error_message_contains_cidr_rule() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("10.0.0.0/8")
            .build();

        let err = policy
            .is_ip_allowed("10.1.2.3".parse().unwrap())
            .unwrap_err();
        // Error should mention the CIDR rule that blocked it
        assert!(
            err.contains("10.0.0.0/8"),
            "Error should contain CIDR: {}",
            err
        );
        assert!(
            err.contains("custom policy"),
            "Error should mention custom policy: {}",
            err
        );
    }

    #[test]
    fn test_error_message_contains_hostname_rule() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.internal.com")
            .build();

        let err = policy.is_hostname_allowed("api.internal.com").unwrap_err();
        // Error should mention the hostname pattern that blocked it
        assert!(
            err.contains("*.internal.com"),
            "Error should contain pattern: {}",
            err
        );
        assert!(
            err.contains("custom policy"),
            "Error should mention custom policy: {}",
            err
        );
    }
}
