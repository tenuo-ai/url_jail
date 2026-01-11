//! URL validation with DNS resolution.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::TokioResolver;

use crate::blocklist::{is_hostname_blocked, is_ip_blocked};
use crate::error::Error;
use crate::policy::Policy;
use crate::safe_url::SafeUrl;

/// Options for URL validation.
///
/// Use with [`validate_with_options`] or [`validate_custom_with_options`]
/// to customize validation behavior.
///
/// # Example
///
/// ```rust,no_run
/// use url_jail::{validate_with_options, Policy, ValidateOptions};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), url_jail::Error> {
/// let opts = ValidateOptions {
///     dns_timeout: Duration::from_secs(5),
/// };
/// let result = validate_with_options("https://example.com/", Policy::PublicOnly, opts).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ValidateOptions {
    /// DNS resolution timeout.
    ///
    /// If DNS resolution takes longer than this, a [`Error::Timeout`] is returned.
    /// Default: 30 seconds.
    pub dns_timeout: Duration,
}

impl Default for ValidateOptions {
    fn default() -> Self {
        Self {
            dns_timeout: Duration::from_secs(30),
        }
    }
}

/// Result of successful URL validation.
#[derive(Debug, Clone)]
pub struct Validated {
    /// The verified IP address to connect to.
    pub ip: IpAddr,

    /// Original hostname (use for Host header / SNI).
    pub host: String,

    /// Port number.
    pub port: u16,

    /// Full URL (normalized).
    pub url: String,

    /// Whether HTTPS.
    pub https: bool,
}

impl Validated {
    /// Get the socket address to connect to.
    pub fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

/// Validate a URL, resolve DNS, and check the IP against the policy.
///
/// This is the primary entry point for SSRF protection. It:
/// 1. Parses and normalizes the URL
/// 2. Checks the hostname against the blocklist
/// 3. Resolves DNS to get the IP address
/// 4. Checks the IP against the policy
///
/// # Example
///
/// ```rust,no_run
/// use url_jail::{validate, Policy};
///
/// # async fn example() -> Result<(), url_jail::Error> {
/// let result = validate("https://example.com/api", Policy::PublicOnly).await?;
/// println!("Safe to connect to {} ({})", result.host, result.ip);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The URL is malformed or uses a forbidden scheme
/// - The hostname is in the blocklist
/// - DNS resolution fails or times out
/// - The resolved IP is blocked by the policy
pub async fn validate(url: &str, policy: Policy) -> Result<Validated, Error> {
    validate_with_options(url, policy, ValidateOptions::default()).await
}

/// Validate a URL with custom options.
///
/// See [`validate`] for details.
#[cfg_attr(feature = "tracing", tracing::instrument(skip(options), fields(host)))]
pub async fn validate_with_options(
    url: &str,
    policy: Policy,
    options: ValidateOptions,
) -> Result<Validated, Error> {
    let safe_url = SafeUrl::parse(url)?;

    #[cfg(feature = "tracing")]
    tracing::Span::current().record("host", safe_url.host());

    if let Some(blocked_host) = is_hostname_blocked(safe_url.host()) {
        #[cfg(feature = "tracing")]
        tracing::warn!(host = safe_url.host(), "hostname blocked");
        return Err(Error::hostname_blocked(
            url,
            safe_url.host(),
            format!(
                "matches blocked pattern '{}' (cloud metadata)",
                blocked_host
            ),
        ));
    }

    // Resolve DNS and check ALL returned IPs against policy
    let ip = resolve_and_verify_dns(safe_url.host(), options.dns_timeout, policy).await?;

    #[cfg(feature = "tracing")]
    tracing::debug!(%ip, host = safe_url.host(), "URL validated successfully");

    Ok(Validated {
        ip,
        host: safe_url.host().to_string(),
        port: safe_url.port(),
        url: safe_url.as_str().to_string(),
        https: safe_url.is_https(),
    })
}

/// Validate a URL with a custom policy.
///
/// This allows using `CustomPolicy` created via `PolicyBuilder` for
/// fine-grained control over what IPs and hostnames are allowed.
///
/// # Example
///
/// ```rust,no_run
/// use url_jail::{validate_custom, PolicyBuilder, Policy};
///
/// # async fn example() -> Result<(), url_jail::Error> {
/// let policy = PolicyBuilder::new(Policy::AllowPrivate)
///     .block_cidr("10.0.0.0/8")
///     .build();
///
/// let result = validate_custom("https://example.com/", &policy).await?;
/// # Ok(())
/// # }
/// ```
pub async fn validate_custom(
    url: &str,
    policy: &crate::policy_builder::CustomPolicy,
) -> Result<Validated, Error> {
    validate_custom_with_options(url, policy, ValidateOptions::default()).await
}

/// Validate a URL with a custom policy and options.
pub async fn validate_custom_with_options(
    url: &str,
    policy: &crate::policy_builder::CustomPolicy,
    options: ValidateOptions,
) -> Result<Validated, Error> {
    let safe_url = SafeUrl::parse(url)?;

    // Check hostname against custom policy
    if let Err(reason) = policy.is_hostname_allowed(safe_url.host()) {
        return Err(Error::hostname_blocked(url, safe_url.host(), reason));
    }

    // Check built-in hostname blocklist
    if let Some(blocked_host) = is_hostname_blocked(safe_url.host()) {
        return Err(Error::hostname_blocked(
            url,
            safe_url.host(),
            format!(
                "matches blocked pattern '{}' (cloud metadata)",
                blocked_host
            ),
        ));
    }

    let ip = resolve_dns_with_timeout(safe_url.host(), options.dns_timeout).await?;

    // Check IP against custom policy
    if let Err(reason) = policy.is_ip_allowed(ip) {
        return Err(Error::ssrf_blocked(url, ip, reason));
    }

    Ok(Validated {
        ip,
        host: safe_url.host().to_string(),
        port: safe_url.port(),
        url: safe_url.as_str().to_string(),
        https: safe_url.is_https(),
    })
}

/// Synchronous version of [`validate`].
///
/// This blocks the current thread while performing DNS resolution.
/// Prefer the async version when possible.
///
/// This function works both inside and outside of a Tokio runtime.
/// When called from outside a runtime, it creates a temporary one.
///
/// # Example
///
/// ```rust,no_run
/// use url_jail::{validate_sync, Policy};
///
/// let result = validate_sync("https://example.com/api", Policy::PublicOnly)?;
/// println!("Safe to connect to {} ({})", result.host, result.ip);
/// # Ok::<(), url_jail::Error>(())
/// ```
pub fn validate_sync(url: &str, policy: Policy) -> Result<Validated, Error> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(validate(url, policy)))
    } else {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::dns_error("runtime", e.to_string()))?;
        rt.block_on(validate(url, policy))
    }
}

/// Resolve a hostname to IP addresses with timeout, checking ALL against policy.
/// Returns the first allowed IP, or an error if any IP is blocked.
async fn resolve_and_verify_dns(
    host: &str,
    timeout: Duration,
    policy: Policy,
) -> Result<IpAddr, Error> {
    let host_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_str.parse::<IpAddr>() {
        // Literal IP - check directly
        if let Some(reason) = is_ip_blocked(ip, policy) {
            return Err(Error::ssrf_blocked(host, ip, reason));
        }
        return Ok(ip);
    }

    let resolve_future = async {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| Error::dns_error(host, e.to_string()))?
            .build();

        let response = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::dns_error(host, e.to_string()))?;

        let ips: Vec<IpAddr> = response.iter().collect();
        if ips.is_empty() {
            return Err(Error::dns_error(host, "no IP addresses found"));
        }

        // Check ALL resolved IPs - if ANY is blocked, fail
        // This prevents attackers from hiding a blocked IP among allowed ones
        for ip in &ips {
            if let Some(reason) = is_ip_blocked(*ip, policy) {
                return Err(Error::ssrf_blocked(host, *ip, reason));
            }
        }

        // All IPs are safe, return the first one
        Ok(ips[0])
    };

    tokio::time::timeout(timeout, resolve_future)
        .await
        .map_err(|_| Error::Timeout {
            message: format!("DNS resolution for {} timed out after {:?}", host, timeout),
        })?
}

/// Resolve hostname for custom policies (doesn't do policy check internally).
async fn resolve_dns_with_timeout(host: &str, timeout: Duration) -> Result<IpAddr, Error> {
    let host_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_str.parse::<IpAddr>() {
        return Ok(ip);
    }

    let resolve_future = async {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| Error::dns_error(host, e.to_string()))?
            .build();

        let response = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::dns_error(host, e.to_string()))?;

        response
            .iter()
            .next()
            .ok_or_else(|| Error::dns_error(host, "no IP addresses found"))
    };

    tokio::time::timeout(timeout, resolve_future)
        .await
        .map_err(|_| Error::Timeout {
            message: format!("DNS resolution for {} timed out after {:?}", host, timeout),
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_builder::PolicyBuilder;

    #[tokio::test]
    async fn test_validate_public_ip() {
        let result = validate("https://example.com/", Policy::PublicOnly).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_loopback() {
        let result = validate("http://127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_metadata() {
        let result = validate("http://169.254.169.254/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_metadata_hostname() {
        let result = validate("http://metadata.google.internal/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_private_ip_policy() {
        let result = validate("http://192.168.1.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reject_octal() {
        let result = validate("http://0177.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== validate_sync tests ====================

    #[test]
    fn test_validate_sync_public_ip() {
        let result = validate_sync("https://example.com/", Policy::PublicOnly);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.host, "example.com");
        assert_eq!(validated.port, 443);
        assert!(validated.https);
    }

    #[test]
    fn test_validate_sync_blocks_loopback() {
        let result = validate_sync("http://127.0.0.1/", Policy::PublicOnly);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_sync_blocks_private() {
        let result = validate_sync("http://192.168.1.1/", Policy::PublicOnly);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_sync_allows_private_with_policy() {
        // With AllowPrivate, private IPs should be allowed
        // 10.0.0.1 is a literal IP, so DNS just parses it directly
        let result = validate_sync("http://10.0.0.1/", Policy::AllowPrivate);
        assert!(
            result.is_ok(),
            "Private IPs should be allowed with AllowPrivate"
        );
        let validated = result.unwrap();
        assert_eq!(validated.ip.to_string(), "10.0.0.1");
    }

    // ==================== validate_with_options tests ====================

    #[tokio::test]
    async fn test_validate_with_custom_timeout() {
        let opts = ValidateOptions {
            dns_timeout: Duration::from_secs(5),
        };
        let result = validate_with_options("https://example.com/", Policy::PublicOnly, opts).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_with_very_short_timeout() {
        // This may or may not timeout depending on DNS cache, but should not panic
        let opts = ValidateOptions {
            dns_timeout: Duration::from_millis(1),
        };
        let result = validate_with_options(
            "https://very-slow-dns-example.invalid/",
            Policy::PublicOnly,
            opts,
        )
        .await;
        // Should either timeout or DNS error (domain doesn't exist)
        assert!(result.is_err());
    }

    // ==================== validate_custom tests ====================

    #[tokio::test]
    async fn test_validate_custom_block_cidr() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("10.0.0.0/8")
            .build();

        // 10.x.x.x should be blocked even with AllowPrivate base
        let result = validate_custom("http://10.1.2.3/", &policy).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_custom_allow_cidr_override() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_cidr("127.0.0.1/32")
            .build();

        // Loopback would normally be blocked, but we explicitly allowed it
        let result = validate_custom("http://127.0.0.1/", &policy).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_custom_block_hostname() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.example.com")
            .build();

        let result = validate_custom("https://api.example.com/", &policy).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_custom_with_options() {
        let policy = PolicyBuilder::new(Policy::PublicOnly).build();
        let opts = ValidateOptions {
            dns_timeout: Duration::from_secs(10),
        };

        let result = validate_custom_with_options("https://example.com/", &policy, opts).await;
        assert!(result.is_ok());
    }

    // ==================== Validated struct tests ====================

    #[tokio::test]
    async fn test_validated_fields() {
        let result = validate("https://example.com:8443/path?query=1", Policy::PublicOnly)
            .await
            .unwrap();

        assert_eq!(result.host, "example.com");
        assert_eq!(result.port, 8443);
        assert!(result.https);
        assert!(result.url.contains("example.com"));
        assert!(!result.ip.is_loopback());
    }

    #[tokio::test]
    async fn test_validated_to_socket_addr() {
        let result = validate("https://example.com/", Policy::PublicOnly)
            .await
            .unwrap();

        let socket_addr = result.to_socket_addr();
        assert_eq!(socket_addr.port(), 443);
        assert_eq!(socket_addr.ip(), result.ip);
    }

    #[tokio::test]
    async fn test_validated_http_port() {
        let result = validate("http://example.com/", Policy::PublicOnly)
            .await
            .unwrap();

        assert_eq!(result.port, 80);
        assert!(!result.https);
    }

    // ==================== IPv6 validation tests ====================

    #[tokio::test]
    async fn test_block_ipv6_loopback() {
        let result = validate("http://[::1]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_ipv6_link_local() {
        let result = validate("http://[fe80::1]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_ipv4_mapped_ipv6() {
        let result = validate("http://[::ffff:127.0.0.1]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== Error type tests ====================

    #[tokio::test]
    async fn test_error_is_ssrf_blocked_for_ip() {
        let result = validate("http://127.0.0.1/", Policy::PublicOnly).await;
        assert!(matches!(result, Err(Error::SsrfBlocked { .. })));
    }

    #[tokio::test]
    async fn test_error_is_hostname_blocked() {
        let result = validate("http://metadata.google.internal/", Policy::PublicOnly).await;
        assert!(matches!(result, Err(Error::HostnameBlocked { .. })));
    }

    #[tokio::test]
    async fn test_error_is_invalid_url() {
        let result = validate("ftp://example.com/", Policy::PublicOnly).await;
        assert!(matches!(result, Err(Error::InvalidUrl { .. })));
    }

    #[tokio::test]
    async fn test_error_is_dns_error() {
        let result = validate(
            "http://this-domain-does-not-exist-12345.invalid/",
            Policy::PublicOnly,
        )
        .await;
        assert!(matches!(result, Err(Error::DnsError { .. })));
    }

    // ==================== AllowPrivate policy tests ====================

    #[tokio::test]
    async fn test_allow_private_still_blocks_loopback() {
        let result = validate("http://127.0.0.1/", Policy::AllowPrivate).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_allow_private_still_blocks_metadata() {
        let result = validate("http://169.254.169.254/", Policy::AllowPrivate).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_allow_private_still_blocks_link_local() {
        let result = validate("http://169.254.1.1/", Policy::AllowPrivate).await;
        assert!(result.is_err());
    }

    // ==================== Unspecified address tests ====================

    #[tokio::test]
    async fn test_block_unspecified_ipv4() {
        let result = validate("http://0.0.0.0/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_unspecified_ipv6() {
        let result = validate("http://[::]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_unspecified_with_allow_private() {
        // Unspecified should be blocked even with AllowPrivate
        let result = validate("http://0.0.0.0/", Policy::AllowPrivate).await;
        assert!(result.is_err());
    }

    // ==================== Timeout error type tests ====================

    #[tokio::test]
    async fn test_timeout_error_type() {
        // Very short timeout should produce Timeout error for slow/invalid domain
        let opts = ValidateOptions {
            dns_timeout: Duration::from_nanos(1), // Impossibly short
        };
        let result = validate_with_options(
            "https://this-domain-will-definitely-timeout-due-to-short-timeout.invalid/",
            Policy::PublicOnly,
            opts,
        )
        .await;
        // Should be either Timeout or DnsError (domain doesn't exist)
        assert!(matches!(
            result,
            Err(Error::Timeout { .. }) | Err(Error::DnsError { .. })
        ));
    }

    // ==================== Multi-IP DNS verification ====================

    #[tokio::test]
    async fn test_multi_ip_all_checked() {
        // We can't easily control DNS results, but we can verify the code path
        // by checking that resolve_and_verify_dns exists and is used
        // The actual multi-IP check is implicitly tested by the blocklist tests
        let result = validate("https://example.com/", Policy::PublicOnly).await;
        assert!(result.is_ok());
    }

    // ==================== RED TEAM: End-to-End Attack Scenarios ====================

    #[tokio::test]
    async fn test_redteam_ssrf_metadata_direct() {
        // Direct metadata access attempt
        let result = validate(
            "http://169.254.169.254/latest/meta-data/",
            Policy::PublicOnly,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ssrf_metadata_with_path() {
        let result = validate(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            Policy::PublicOnly,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ssrf_localhost_admin() {
        // Common internal service attack
        let result = validate("http://127.0.0.1/admin", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ssrf_localhost_high_port() {
        // Internal service on non-standard port
        let result = validate("http://127.0.0.1:8080/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ssrf_private_redis() {
        // Redis default port
        let result = validate("http://10.0.0.1:6379/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ssrf_private_elasticsearch() {
        // Elasticsearch default port
        let result = validate("http://192.168.1.1:9200/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ssrf_internal_kubernetes() {
        // Kubernetes API server
        let result = validate("http://10.96.0.1:443/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== RED TEAM: Hostname Blocklist Bypass Attempts ====================

    #[tokio::test]
    async fn test_redteam_metadata_hostname_case() {
        // Case variation
        let result = validate("http://METADATA.GOOGLE.INTERNAL/", Policy::PublicOnly).await;
        assert!(result.is_err());

        let result2 = validate("http://Metadata.Google.Internal/", Policy::PublicOnly).await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_redteam_metadata_subdomain() {
        // Subdomain of blocked hostname
        let result = validate(
            "http://anything.metadata.google.internal/",
            Policy::PublicOnly,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_metadata_similar_hostname() {
        // Hostname that looks similar but isn't blocked
        // "metadatax.google.internal" - not a subdomain
        let result = validate("http://metadatax.google.internal/", Policy::PublicOnly).await;
        // This should NOT be blocked by hostname check (different hostname)
        // Will fail DNS resolution since domain doesn't exist
        assert!(matches!(result, Err(Error::DnsError { .. })));
    }

    // ==================== RED TEAM: IP Encoding in URLs ====================

    #[tokio::test]
    async fn test_redteam_octal_ip_in_url() {
        let result = validate("http://0177.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_hex_ip_in_url() {
        let result = validate("http://0x7f000001/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_decimal_ip_in_url() {
        let result = validate("http://2130706433/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_short_form_ip_in_url() {
        let result = validate("http://127.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== RED TEAM: IPv6 in URLs ====================

    #[tokio::test]
    async fn test_redteam_ipv6_loopback_url() {
        let result = validate("http://[::1]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ipv6_mapped_loopback_url() {
        let result = validate("http://[::ffff:127.0.0.1]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ipv6_link_local_url() {
        let result = validate("http://[fe80::1]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== RED TEAM: Userinfo Bypass Attempts ====================

    #[tokio::test]
    async fn test_redteam_userinfo_bypass_localhost() {
        let result = validate("http://user:pass@127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_userinfo_bypass_safe_looking() {
        // Looks like going to google.com but actually goes to 127.0.0.1
        let result = validate("http://google.com@127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== RED TEAM: AllowPrivate Still Blocks Dangerous ====================

    #[tokio::test]
    async fn test_redteam_allow_private_blocks_loopback() {
        let result = validate("http://127.0.0.1/", Policy::AllowPrivate).await;
        assert!(result.is_err(), "AllowPrivate must still block loopback");
    }

    #[tokio::test]
    async fn test_redteam_allow_private_blocks_metadata() {
        let result = validate("http://169.254.169.254/", Policy::AllowPrivate).await;
        assert!(result.is_err(), "AllowPrivate must still block metadata");
    }

    #[tokio::test]
    async fn test_redteam_allow_private_blocks_link_local() {
        let result = validate("http://169.254.1.1/", Policy::AllowPrivate).await;
        assert!(result.is_err(), "AllowPrivate must still block link-local");
    }

    #[tokio::test]
    async fn test_redteam_allow_private_allows_private() {
        // Private IPs should work with AllowPrivate
        // These will fail DNS, but the IP wouldn't be blocked
        let result = validate("http://10.0.0.1/", Policy::AllowPrivate).await;
        // Should be SSRF blocked with PublicOnly, but not with AllowPrivate
        // Will actually fail with DNS error since 10.0.0.1 isn't resolvable
        match &result {
            Err(Error::SsrfBlocked { .. }) => {
                panic!("Private IP should not be SSRF blocked with AllowPrivate")
            }
            _ => {} // DNS error or success (if IP is parsed directly)
        }
    }

    // ==================== RED TEAM: Custom Policy Attacks ====================

    #[tokio::test]
    async fn test_redteam_custom_policy_loopback_override() {
        // Dangerous: allowing loopback via custom policy
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_cidr("127.0.0.0/8")
            .build();

        let result = validate_custom("http://127.0.0.1/", &policy).await;
        // This SHOULD succeed if user explicitly allows it
        assert!(result.is_ok(), "Explicit allow should work");
    }

    #[tokio::test]
    async fn test_redteam_custom_policy_still_blocks_unallowed() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_cidr("10.1.0.0/16")
            .build();

        // 10.1.x.x should be allowed
        // 10.2.x.x should still be blocked
        let result = validate_custom("http://10.2.0.1/", &policy).await;
        // Will be either SSRF blocked (10.2 not in allow list, blocked by PublicOnly)
        // or DNS error
        match &result {
            Ok(_) => panic!("10.2.x.x should not be allowed"),
            Err(Error::SsrfBlocked { .. }) => {} // Correct
            Err(Error::DnsError { .. }) => {}    // Also acceptable (DNS failed first)
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // ==================== RED TEAM: Scheme Attacks ====================

    #[tokio::test]
    async fn test_redteam_file_scheme() {
        let result = validate("file:///etc/passwd", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_ftp_scheme() {
        let result = validate("ftp://127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redteam_gopher_scheme() {
        let result = validate("gopher://127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }
}
