//! Error types for airlock.

use std::net::IpAddr;
use thiserror::Error;

/// Errors that can occur during URL validation.
#[derive(Debug, Error)]
pub enum Error {
    /// IP address is blocked by policy.
    #[error("SSRF blocked: {ip} - {reason}")]
    SsrfBlocked {
        url: String,
        ip: IpAddr,
        reason: String,
    },

    /// Hostname is blocked by policy.
    #[error("SSRF blocked: {host} - {reason}")]
    HostnameBlocked { url: String, host: String, reason: String },

    /// Invalid URL syntax or forbidden scheme.
    #[error("Invalid URL: {reason}")]
    InvalidUrl { url: String, reason: String },

    /// DNS resolution failed.
    #[error("DNS error for {host}: {message}")]
    DnsError { host: String, message: String },

    /// A redirect pointed to a blocked URL.
    #[cfg(feature = "fetch")]
    #[error("Redirect blocked: {redirect_url} - {reason}")]
    RedirectBlocked {
        original_url: String,
        redirect_url: String,
        reason: String,
    },

    /// Too many redirects.
    #[cfg(feature = "fetch")]
    #[error("Too many redirects (max {max})")]
    TooManyRedirects { url: String, max: u8 },

    /// HTTP request failed.
    #[cfg(feature = "fetch")]
    #[error("HTTP error: {message}")]
    HttpError { url: String, message: String },
}

impl Error {
    pub(crate) fn ssrf_blocked(url: impl Into<String>, ip: IpAddr, reason: impl Into<String>) -> Self {
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
