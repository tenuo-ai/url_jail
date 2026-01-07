//! Safe URL parsing and normalization.

use url::Url;

use crate::Error;

/// A parsed and normalized URL that is safe for further processing.
///
/// This struct represents a URL after parsing and normalization, but before
/// DNS resolution and IP validation. Use [`validate`](crate::validate) to
/// perform the full validation including DNS resolution.
#[derive(Debug, Clone)]
pub struct SafeUrl {
    inner: Url,
    host: String,
}

impl SafeUrl {
    /// Parse and normalize a URL string.
    ///
    /// This performs:
    /// - Scheme validation (only http/https allowed)
    /// - Hostname normalization (lowercase, no trailing dot)
    /// - Rejection of userinfo (user:pass@)
    /// - Rejection of non-standard IP formats (octal, decimal)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUrl`] if the URL is malformed or uses a
    /// forbidden scheme.
    pub fn parse(input: &str) -> Result<Self, Error> {
        // First, check the raw input for non-standard IP formats
        // We must do this BEFORE url::Url::parse because it normalizes them
        reject_non_standard_ip_in_raw_url(input)?;

        let url = Url::parse(input).map_err(|e| Error::invalid_url(input, e.to_string()))?;

        // Only allow http and https
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(Error::invalid_url(
                    input,
                    format!("scheme '{}' not allowed, only http/https", scheme),
                ));
            }
        }

        // Must have a host
        let host = url
            .host_str()
            .ok_or_else(|| Error::invalid_url(input, "URL must have a host"))?;

        // Reject userinfo
        if url.username() != "" || url.password().is_some() {
            return Err(Error::invalid_url(
                input,
                "userinfo (user:pass@) not allowed",
            ));
        }

        // Normalize hostname
        let normalized_host = normalize_host(host, input)?;

        Ok(Self {
            inner: url,
            host: normalized_host,
        })
    }

    /// Get the normalized hostname.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port, defaulting to 80 for http and 443 for https.
    pub fn port(&self) -> u16 {
        self.inner.port_or_known_default().unwrap_or(80)
    }

    /// Get the path.
    pub fn path(&self) -> &str {
        self.inner.path()
    }

    /// Get the full URL as a string.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Check if the URL uses HTTPS.
    pub fn is_https(&self) -> bool {
        self.inner.scheme() == "https"
    }

    /// Get the underlying URL.
    pub fn into_url(self) -> Url {
        self.inner
    }
}

/// Normalize a hostname: lowercase, remove trailing dot.
fn normalize_host(host: &str, original_url: &str) -> Result<String, Error> {
    let mut normalized = host.to_lowercase();

    // Remove trailing dot (FQDN notation)
    if normalized.ends_with('.') {
        normalized.pop();
    }

    // Reject empty hostname
    if normalized.is_empty() {
        return Err(Error::invalid_url(original_url, "empty hostname"));
    }

    // Reject bracketed hostnames that aren't IPv6
    if normalized.starts_with('[') && !normalized.ends_with(']') {
        return Err(Error::invalid_url(
            original_url,
            "invalid bracketed hostname",
        ));
    }

    Ok(normalized)
}

/// Reject non-standard IP address formats (octal, decimal encoding) in the raw URL.
/// This must be done BEFORE url::Url::parse because it normalizes these formats.
fn reject_non_standard_ip_in_raw_url(url: &str) -> Result<(), Error> {
    // Extract the host portion from the raw URL
    // Format: scheme://[userinfo@]host[:port][/path]
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .or_else(|| url.strip_prefix("HTTP://"))
        .or_else(|| url.strip_prefix("HTTPS://"));

    let Some(after_scheme) = without_scheme else {
        // Not http/https, will be rejected later
        return Ok(());
    };

    // Find the host portion (before /, ?, #, or :port)
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());

    let authority = &after_scheme[..host_end];

    // Remove userinfo if present
    let host_with_port = authority
        .rfind('@')
        .map(|i| &authority[i + 1..])
        .unwrap_or(authority);

    // Remove port if present (but be careful with IPv6 brackets)
    let host = if host_with_port.starts_with('[') {
        // IPv6 - find closing bracket
        host_with_port
            .find(']')
            .map(|i| &host_with_port[..=i])
            .unwrap_or(host_with_port)
    } else {
        // IPv4 or hostname - split on colon for port
        host_with_port
            .rfind(':')
            .map(|i| &host_with_port[..i])
            .unwrap_or(host_with_port)
    };

    // Now check if this looks like a non-standard IP
    check_non_standard_ip(host, url)
}

/// Check if a host string contains non-standard IP encoding.
fn check_non_standard_ip(host: &str, original_url: &str) -> Result<(), Error> {
    // Skip if it's an IPv6 address (bracketed)
    if host.starts_with('[') {
        return Ok(());
    }

    let parts: Vec<&str> = host.split('.').collect();

    // Single number could be decimal IP (e.g., 2130706433)
    if parts.len() == 1 && !host.is_empty() && host.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::invalid_url(
            original_url,
            "decimal IP encoding not allowed",
        ));
    }

    // Check for octal encoding in IPv4-like format
    if parts.len() == 4 {
        for part in &parts {
            if part.is_empty() {
                continue;
            }

            // All digits and has leading zero with more digits = octal
            if part.len() > 1
                && part.starts_with('0')
                && part.chars().all(|c| c.is_ascii_digit())
            {
                return Err(Error::invalid_url(
                    original_url,
                    "octal IP encoding not allowed",
                ));
            }

            // If any part has non-digits, it's a hostname
            if !part.chars().all(|c| c.is_ascii_digit()) {
                return Ok(());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_urls() {
        let url = SafeUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.port(), 443);
        assert!(url.is_https());
    }

    #[test]
    fn test_normalize_hostname() {
        let url = SafeUrl::parse("https://EXAMPLE.COM./path").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_reject_userinfo() {
        assert!(SafeUrl::parse("https://user:pass@example.com").is_err());
    }

    #[test]
    fn test_reject_non_http() {
        assert!(SafeUrl::parse("ftp://example.com").is_err());
        assert!(SafeUrl::parse("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_reject_octal_ip() {
        assert!(SafeUrl::parse("http://0177.0.0.1/").is_err());
        assert!(SafeUrl::parse("http://0127.0.0.1/").is_err());
    }

    #[test]
    fn test_reject_decimal_ip() {
        assert!(SafeUrl::parse("http://2130706433/").is_err());
    }

    #[test]
    fn test_allow_standard_ip() {
        let url = SafeUrl::parse("http://127.0.0.1/").unwrap();
        assert_eq!(url.host(), "127.0.0.1");
    }

    #[test]
    fn test_allow_ipv6() {
        let url = SafeUrl::parse("http://[::1]/").unwrap();
        assert_eq!(url.host(), "[::1]");
    }
}
