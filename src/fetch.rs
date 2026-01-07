//! Safe HTTP fetching with redirect validation.
//!
//! This module provides functions to fetch URLs while validating each redirect
//! in the chain against the SSRF policy.

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
/// use airlock::{fetch, Policy};
///
/// # async fn example() -> Result<(), airlock::Error> {
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

        // Validate this URL
        let validated = validate(&current_url, policy).await.map_err(|e| {
            if chain.is_empty() {
                e // First URL, return original error
            } else {
                // This is a redirect - wrap in RedirectBlocked
                Error::RedirectBlocked {
                    original_url: url.to_string(),
                    redirect_url: current_url.clone(),
                    reason: e.to_string(),
                }
            }
        })?;

        chain.push(validated.clone());

        // Create client with resolver override to connect to validated IP
        // This ensures TLS SNI works correctly while connecting to our verified IP
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

        // Make request - reqwest will use our resolved IP for this host
        let response = client
            .get(&validated.url)
            .send()
            .await
            .map_err(|e| Error::HttpError {
                url: current_url.clone(),
                message: e.to_string(),
            })?;

        // Check if this is a redirect
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| Error::HttpError {
                    url: current_url.clone(),
                    message: "Redirect without Location header".to_string(),
                })?;

            // Resolve relative URLs
            current_url = resolve_redirect_url(&validated.url, location)?;
            continue;
        }

        // Not a redirect - we're done
        return Ok(FetchResult { response, chain });
    }

    unreachable!()
}

/// Synchronous version of [`fetch`].
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

    #[tokio::test]
    async fn test_fetch_simple() {
        // This test requires network access
        let result = fetch("https://httpbin.org/get", Policy::PublicOnly).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.chain.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_redirect() {
        // httpbin.org/redirect/1 redirects once
        let result = fetch("https://httpbin.org/redirect/1", Policy::PublicOnly).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.chain.len(), 2);
    }

    #[tokio::test]
    async fn test_fetch_blocked_ip() {
        // Direct blocked IP should fail
        let result = fetch("http://127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }
}
