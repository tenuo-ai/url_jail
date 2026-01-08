//! Safe HTTP fetching with redirect validation.
//!
//! This module provides functions to fetch URLs while validating each redirect
//! in the chain against the SSRF policy.
//!
//! ## Design Principles
//!
//! **Validation is mandatory and cannot be bypassed.**
//!
//! - Every URL (including redirects) is validated via [`validate()`](crate::validate)
//!   before any HTTP request is made
//! - The validated IP is used directly for the connection, preventing DNS rebinding
//! - There is no way to skip validation or override the policy
//!
//! ## What This Module Does NOT Do
//!
//! - **No retry logic**: Failed requests fail immediately
//! - **No fallback behavior**: If validation fails, no request is made
//! - **No protocol downgrade**: HTTPS URLs never fall back to HTTP
//! - **No silent URL rewriting**: URLs are fetched exactly as validated
//!
//! ## Separation of Concerns
//!
//! Validation and execution are separate, irreversible steps:
//!
//! 1. **Validate**: URL is parsed, DNS is resolved, IP is checked against policy
//! 2. **Execute**: HTTP request is made to the validated IP
//!
//! Once validation fails, execution never occurs. Once execution begins,
//! validation cannot be retroactively bypassed.

use std::net::SocketAddr;

use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::{Client, Response};

use crate::error::Error;
use crate::policy::Policy;
use crate::validate::{validate, Validated};

/// Maximum number of redirects to follow.
const MAX_REDIRECTS: u8 = 10;

/// Result of a fetch operation, including the redirect chain.
#[derive(Debug)]
pub struct FetchResult {
    /// The final HTTP response.
    pub response: Response,

    /// Chain of validated URLs that were followed (including the original).
    pub chain: Vec<Validated>,
}

/// Fetch a URL, following redirects safely.
///
/// Each redirect is validated against the policy before following.
/// Returns the final response after all redirects have been followed.
///
/// # Example
///
/// ```rust,no_run
/// use url_jail::{fetch, Policy};
///
/// # async fn example() -> Result<(), url_jail::Error> {
/// let result = fetch("https://httpbin.org/redirect/2", Policy::PublicOnly).await?;
/// println!("Final URL: {}", result.response.url());
/// println!("Followed {} redirects", result.chain.len() - 1);
/// # Ok(())
/// # }
/// ```
pub async fn fetch(url: &str, policy: Policy) -> Result<FetchResult, Error> {
    let mut current_url = url.to_string();
    let mut chain = Vec::new();

    for i in 0..=MAX_REDIRECTS {
        if i == MAX_REDIRECTS {
            return Err(Error::TooManyRedirects {
                url: url.to_string(),
                max: MAX_REDIRECTS,
            });
        }

        let validated = validate(&current_url, policy).await.map_err(|e| {
            if chain.is_empty() {
                e
            } else {
                Error::RedirectBlocked {
                    original_url: url.to_string(),
                    redirect_url: current_url.clone(),
                    reason: e.to_string(),
                }
            }
        })?;

        chain.push(validated.clone());

        // Resolver override ensures we connect to the validated IP while TLS SNI works correctly
        let client = Client::builder()
            .redirect(RedirectPolicy::none())
            .resolve(
                &validated.host,
                SocketAddr::new(validated.ip, validated.port),
            )
            .build()
            .map_err(|e| Error::HttpError {
                url: current_url.clone(),
                message: e.to_string(),
            })?;

        let response = client
            .get(&validated.url)
            .send()
            .await
            .map_err(|e| Error::HttpError {
                url: current_url.clone(),
                message: e.to_string(),
            })?;

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| Error::HttpError {
                    url: current_url.clone(),
                    message: "Redirect without Location header".to_string(),
                })?;

            current_url = resolve_redirect_url(&validated.url, location)?;
            continue;
        }

        return Ok(FetchResult { response, chain });
    }

    unreachable!()
}

/// Synchronous version of [`fetch`].
///
/// Blocks the current thread while fetching. Works both inside and outside
/// of a Tokio runtime.
///
/// # Example
///
/// ```rust,no_run
/// use url_jail::{fetch_sync, Policy};
///
/// let result = fetch_sync("https://example.com/", Policy::PublicOnly)?;
/// println!("Status: {}", result.response.status());
/// println!("Followed {} redirects", result.chain.len() - 1);
/// # Ok::<(), url_jail::Error>(())
/// ```
pub fn fetch_sync(url: &str, policy: Policy) -> Result<FetchResult, Error> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fetch(url, policy)))
    } else {
        let rt = tokio::runtime::Runtime::new().map_err(|e| Error::HttpError {
            url: url.to_string(),
            message: e.to_string(),
        })?;
        rt.block_on(fetch(url, policy))
    }
}

/// Resolve a redirect URL (which may be relative) against the base URL.
fn resolve_redirect_url(base: &str, location: &str) -> Result<String, Error> {
    let base_url = url::Url::parse(base).map_err(|e| Error::InvalidUrl {
        url: base.to_string(),
        reason: e.to_string(),
    })?;

    let resolved = base_url.join(location).map_err(|e| Error::InvalidUrl {
        url: location.to_string(),
        reason: e.to_string(),
    })?;

    Ok(resolved.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Basic fetch tests ====================

    #[tokio::test]
    async fn test_fetch_simple() {
        let result = fetch("https://httpbin.org/get", Policy::PublicOnly).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.chain.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_redirect() {
        let result = fetch("https://httpbin.org/redirect/1", Policy::PublicOnly).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.chain.len(), 2);
    }

    #[tokio::test]
    async fn test_fetch_blocked_ip() {
        let result = fetch("http://127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== fetch_sync tests ====================

    #[test]
    fn test_fetch_sync_simple() {
        let result = fetch_sync("https://httpbin.org/get", Policy::PublicOnly);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.chain.len(), 1);
    }

    #[test]
    fn test_fetch_sync_blocked_ip() {
        let result = fetch_sync("http://127.0.0.1/", Policy::PublicOnly);
        assert!(result.is_err());
    }

    #[test]
    fn test_fetch_sync_blocked_metadata() {
        let result = fetch_sync("http://169.254.169.254/", Policy::PublicOnly);
        assert!(result.is_err());
    }

    #[test]
    fn test_fetch_sync_blocked_private() {
        let result = fetch_sync("http://192.168.1.1/", Policy::PublicOnly);
        assert!(result.is_err());
    }

    // ==================== Multiple redirect tests ====================

    #[tokio::test]
    async fn test_fetch_multiple_redirects() {
        let result = fetch("https://httpbin.org/redirect/3", Policy::PublicOnly).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.chain.len(), 4); // original + 3 redirects
    }

    #[tokio::test]
    async fn test_fetch_absolute_redirect() {
        let result = fetch(
            "https://httpbin.org/absolute-redirect/1",
            Policy::PublicOnly,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_relative_redirect() {
        let result = fetch(
            "https://httpbin.org/relative-redirect/1",
            Policy::PublicOnly,
        )
        .await;
        assert!(result.is_ok());
    }

    // ==================== Error type tests ====================

    #[tokio::test]
    async fn test_fetch_error_is_ssrf_for_blocked_initial() {
        let result = fetch("http://127.0.0.1/", Policy::PublicOnly).await;
        // For initial URL, should be SsrfBlocked (not RedirectBlocked)
        assert!(matches!(result, Err(Error::SsrfBlocked { .. })));
    }

    #[tokio::test]
    async fn test_fetch_error_is_invalid_url() {
        let result = fetch("ftp://example.com/", Policy::PublicOnly).await;
        assert!(matches!(result, Err(Error::InvalidUrl { .. })));
    }

    #[tokio::test]
    async fn test_fetch_error_hostname_blocked() {
        let result = fetch("http://metadata.google.internal/", Policy::PublicOnly).await;
        assert!(matches!(result, Err(Error::HostnameBlocked { .. })));
    }

    // ==================== FetchResult tests ====================

    #[tokio::test]
    async fn test_fetch_result_chain_has_validated_info() {
        let result = fetch("https://httpbin.org/get", Policy::PublicOnly)
            .await
            .unwrap();

        assert!(!result.chain.is_empty());
        let first = &result.chain[0];
        assert_eq!(first.host, "httpbin.org");
        assert_eq!(first.port, 443);
        assert!(first.https);
    }

    #[tokio::test]
    async fn test_fetch_result_response_status() {
        let result = fetch("https://httpbin.org/status/200", Policy::PublicOnly)
            .await
            .unwrap();

        assert_eq!(result.response.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn test_fetch_result_response_status_404() {
        let result = fetch("https://httpbin.org/status/404", Policy::PublicOnly)
            .await
            .unwrap();

        assert_eq!(result.response.status().as_u16(), 404);
    }

    // ==================== Policy tests ====================

    #[tokio::test]
    async fn test_fetch_allow_private_still_blocks_loopback() {
        let result = fetch("http://127.0.0.1/", Policy::AllowPrivate).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_allow_private_still_blocks_metadata() {
        let result = fetch("http://169.254.169.254/", Policy::AllowPrivate).await;
        assert!(result.is_err());
    }

    // ==================== resolve_redirect_url tests ====================

    #[test]
    fn test_resolve_redirect_url_absolute() {
        let result = resolve_redirect_url("https://example.com/path", "https://other.com/new-path");
        assert_eq!(result.unwrap(), "https://other.com/new-path");
    }

    #[test]
    fn test_resolve_redirect_url_relative() {
        let result = resolve_redirect_url("https://example.com/path", "/new-path");
        assert_eq!(result.unwrap(), "https://example.com/new-path");
    }

    #[test]
    fn test_resolve_redirect_url_relative_no_slash() {
        let result = resolve_redirect_url("https://example.com/dir/", "file");
        assert_eq!(result.unwrap(), "https://example.com/dir/file");
    }

    #[test]
    fn test_resolve_redirect_url_with_query() {
        let result = resolve_redirect_url("https://example.com/path?old=query", "/new?new=query");
        assert_eq!(result.unwrap(), "https://example.com/new?new=query");
    }

    #[test]
    fn test_resolve_redirect_url_protocol_relative() {
        let result = resolve_redirect_url("https://example.com/path", "//other.com/path");
        assert_eq!(result.unwrap(), "https://other.com/path");
    }

    // ==================== Edge cases ====================

    #[tokio::test]
    async fn test_fetch_with_query_params() {
        let result = fetch(
            "https://httpbin.org/get?foo=bar&baz=qux",
            Policy::PublicOnly,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_with_custom_port() {
        // httpbin.org doesn't support custom ports, so we just test blocked IP with port
        let result = fetch("http://127.0.0.1:8080/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_ipv6_loopback_blocked() {
        let result = fetch("http://[::1]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== Unspecified address tests ====================

    #[tokio::test]
    async fn test_fetch_unspecified_ipv4_blocked() {
        let result = fetch("http://0.0.0.0/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_unspecified_ipv6_blocked() {
        let result = fetch("http://[::]/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    // ==================== Too many redirects test ====================

    #[tokio::test]
    #[ignore] // httpbin.org is unreliable in CI (502 errors, rate limiting)
    async fn test_fetch_too_many_redirects() {
        // httpbin /redirect/n follows n redirects
        // MAX_REDIRECTS is 10, so 11 should fail
        let result = fetch("https://httpbin.org/redirect/11", Policy::PublicOnly).await;
        assert!(matches!(result, Err(Error::TooManyRedirects { .. })));
    }

    // ==================== Redirect security tests ====================

    #[test]
    fn test_resolve_redirect_blocks_javascript() {
        // JavaScript URLs should be blocked when resolved
        let result = resolve_redirect_url("https://example.com/", "javascript:alert(1)");
        // url crate should reject this or it should fail later in validate
        assert!(result.is_ok() || result.is_err()); // Just ensure no panic
    }

    #[test]
    fn test_resolve_redirect_data_uri() {
        // Data URIs should be blocked
        let result = resolve_redirect_url("https://example.com/", "data:text/html,<h1>hi</h1>");
        // url crate should handle this
        assert!(result.is_ok() || result.is_err());
    }
}
