//! Error types for url_jail.

use std::net::IpAddr;
use thiserror::Error;

/// Errors that can occur during URL validation.
#[derive(Debug, Error)]
pub enum Error {
    /// IP address is blocked by policy.
    #[error("SSRF blocked: {url} resolved to {ip} - {reason}")]
    SsrfBlocked {
        url: String,
        ip: IpAddr,
        reason: String,
    },

    /// Hostname is blocked by policy.
    #[error("Hostname blocked: {host} - {reason}")]
    HostnameBlocked {
        url: String,
        host: String,
        reason: String,
    },

    /// Invalid URL syntax or forbidden scheme.
    #[error("Invalid URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },

    /// DNS resolution failed.
    #[error("DNS error for {host}: {message}")]
    DnsError { host: String, message: String },

    /// A redirect pointed to a blocked URL.
    #[cfg(feature = "fetch")]
    #[error("Redirect blocked: {original_url} -> {redirect_url} - {reason}")]
    RedirectBlocked {
        original_url: String,
        redirect_url: String,
        reason: String,
    },

    /// Too many redirects.
    #[cfg(feature = "fetch")]
    #[error("Too many redirects from {url} (limit: {max})")]
    TooManyRedirects { url: String, max: u8 },

    /// HTTP request failed.
    #[cfg(feature = "fetch")]
    #[error("HTTP error for {url}: {message}")]
    HttpError { url: String, message: String },

    /// Operation timed out.
    #[error("Timeout: {message}")]
    Timeout { message: String },
}

impl Error {
    /// Returns `true` if this error represents a security block.
    ///
    /// This includes:
    /// - `SsrfBlocked` - IP address blocked by policy
    /// - `HostnameBlocked` - Hostname blocked by policy  
    /// - `RedirectBlocked` - Redirect to blocked URL (with `fetch` feature)
    ///
    /// Use this to distinguish security rejections from other errors like DNS failures.
    ///
    /// # Example
    ///
    /// ```rust
    /// use url_jail::{validate_sync, Policy, Error};
    ///
    /// let result = validate_sync("http://127.0.0.1/", Policy::PublicOnly);
    /// if let Err(e) = result {
    ///     if e.is_blocked() {
    ///         println!("Security block: {}", e);
    ///     }
    /// }
    /// ```
    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            Error::SsrfBlocked { .. } | Error::HostnameBlocked { .. }
        ) || {
            #[cfg(feature = "fetch")]
            {
                matches!(self, Error::RedirectBlocked { .. })
            }
            #[cfg(not(feature = "fetch"))]
            {
                false
            }
        }
    }

    /// Returns `true` if this error might be temporary and worth retrying.
    ///
    /// This includes:
    /// - `DnsError` - DNS resolution failed (server might recover)
    /// - `Timeout` - Operation timed out (might succeed with longer timeout)
    /// - `HttpError` - HTTP request failed (server might recover)
    ///
    /// **Note**: Be cautious retrying with untrusted URLs. An attacker could
    /// use retries to time DNS rebinding attacks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use url_jail::{validate_sync, Policy, Error};
    ///
    /// let result = validate_sync("https://flaky-dns.example.com/", Policy::PublicOnly);
    /// if let Err(e) = result {
    ///     if e.is_retriable() {
    ///         println!("Temporary error, might retry: {}", e);
    ///     }
    /// }
    /// ```
    pub fn is_retriable(&self) -> bool {
        matches!(self, Error::DnsError { .. } | Error::Timeout { .. }) || {
            #[cfg(feature = "fetch")]
            {
                matches!(self, Error::HttpError { .. })
            }
            #[cfg(not(feature = "fetch"))]
            {
                false
            }
        }
    }

    /// Returns the URL associated with this error, if any.
    ///
    /// Most errors include the URL that caused them. This is useful for logging.
    ///
    /// # Example
    ///
    /// ```rust
    /// use url_jail::{validate_sync, Policy};
    ///
    /// let result = validate_sync("http://127.0.0.1/admin", Policy::PublicOnly);
    /// if let Err(e) = result {
    ///     if let Some(url) = e.url() {
    ///         println!("Failed URL: {}", url);
    ///     }
    /// }
    /// ```
    pub fn url(&self) -> Option<&str> {
        match self {
            Error::SsrfBlocked { url, .. } => Some(url),
            Error::HostnameBlocked { url, .. } => Some(url),
            Error::InvalidUrl { url, .. } => Some(url),
            Error::DnsError { .. } => None, // Only has host, not full URL
            Error::Timeout { .. } => None,
            #[cfg(feature = "fetch")]
            Error::RedirectBlocked { original_url, .. } => Some(original_url),
            #[cfg(feature = "fetch")]
            Error::TooManyRedirects { url, .. } => Some(url),
            #[cfg(feature = "fetch")]
            Error::HttpError { url, .. } => Some(url),
        }
    }

    pub(crate) fn ssrf_blocked(
        url: impl Into<String>,
        ip: IpAddr,
        reason: impl Into<String>,
    ) -> Self {
        Self::SsrfBlocked {
            url: url.into(),
            ip,
            reason: reason.into(),
        }
    }

    pub(crate) fn hostname_blocked(
        url: impl Into<String>,
        host: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::HostnameBlocked {
            url: url.into(),
            host: host.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn invalid_url(url: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidUrl {
            url: url.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn dns_error(host: impl Into<String>, message: impl Into<String>) -> Self {
        Self::DnsError {
            host: host.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_blocked_ssrf() {
        let err = Error::SsrfBlocked {
            url: "http://127.0.0.1/".into(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            reason: "loopback".into(),
        };
        assert!(err.is_blocked());
        assert!(!err.is_retriable());
    }

    #[test]
    fn test_is_blocked_hostname() {
        let err = Error::HostnameBlocked {
            url: "http://metadata.google.internal/".into(),
            host: "metadata.google.internal".into(),
            reason: "cloud metadata".into(),
        };
        assert!(err.is_blocked());
        assert!(!err.is_retriable());
    }

    #[test]
    fn test_is_retriable_dns() {
        let err = Error::DnsError {
            host: "example.com".into(),
            message: "NXDOMAIN".into(),
        };
        assert!(!err.is_blocked());
        assert!(err.is_retriable());
    }

    #[test]
    fn test_is_retriable_timeout() {
        let err = Error::Timeout {
            message: "DNS timed out".into(),
        };
        assert!(!err.is_blocked());
        assert!(err.is_retriable());
    }

    #[test]
    fn test_url_extraction() {
        let err = Error::SsrfBlocked {
            url: "http://127.0.0.1/admin".into(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            reason: "loopback".into(),
        };
        assert_eq!(err.url(), Some("http://127.0.0.1/admin"));

        let err = Error::InvalidUrl {
            url: "not-a-url".into(),
            reason: "missing scheme".into(),
        };
        assert_eq!(err.url(), Some("not-a-url"));

        let err = Error::DnsError {
            host: "example.com".into(),
            message: "failed".into(),
        };
        assert_eq!(err.url(), None); // DNS error only has host

        let err = Error::Timeout {
            message: "timed out".into(),
        };
        assert_eq!(err.url(), None);
    }

    #[test]
    fn test_invalid_url_not_blocked_or_retriable() {
        let err = Error::InvalidUrl {
            url: "ftp://example.com".into(),
            reason: "unsupported scheme".into(),
        };
        assert!(!err.is_blocked()); // Invalid URL is user error, not security block
        assert!(!err.is_retriable()); // Won't become valid by retrying
    }
}
