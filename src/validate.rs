//! URL validation with DNS resolution.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::TokioResolver;

use crate::blocklist::{is_hostname_blocked, is_ip_blocked};
use crate::error::Error;
use crate::policy::Policy;
use crate::safe_url::SafeUrl;

/// Options for URL validation.
#[derive(Debug, Clone)]
pub struct ValidateOptions {
    /// DNS resolution timeout. Default: 30 seconds.
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
            format!("hostname {} is blocked", blocked_host),
        ));
    }

    let ip = resolve_dns_with_timeout(safe_url.host(), options.dns_timeout).await?;

    if let Some(reason) = is_ip_blocked(ip, policy) {
        #[cfg(feature = "tracing")]
        tracing::warn!(%ip, %reason, "IP blocked");
        return Err(Error::ssrf_blocked(url, ip, reason));
    }

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
            format!("hostname {} is blocked", blocked_host),
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
pub fn validate_sync(url: &str, policy: Policy) -> Result<Validated, Error> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(validate(url, policy)))
    } else {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::dns_error("runtime", e.to_string()))?;
        rt.block_on(validate(url, policy))
    }
}

/// Resolve a hostname to an IP address with timeout.
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
}
