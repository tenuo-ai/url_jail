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
    /// - Rejection of non-standard IP formats (octal, decimal, hexadecimal, short-form)
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

        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(Error::invalid_url(
                    input,
                    format!("scheme '{}' not allowed, only http/https", scheme),
                ));
            }
        }

        let host = url
            .host_str()
            .ok_or_else(|| Error::invalid_url(input, "URL must have a host"))?;

        if url.username() != "" || url.password().is_some() {
            return Err(Error::invalid_url(
                input,
                "userinfo (user:pass@) not allowed",
            ));
        }

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

    if normalized.is_empty() {
        return Err(Error::invalid_url(original_url, "empty hostname"));
    }

    if normalized.starts_with('[') {
        if !normalized.ends_with(']') {
            return Err(Error::invalid_url(
                original_url,
                "invalid bracketed hostname",
            ));
        }
        let inner = &normalized[1..normalized.len() - 1];
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(Error::invalid_url(
                original_url,
                "brackets only allowed for IPv6 addresses",
            ));
        }
    }

    Ok(normalized)
}

/// Reject non-standard IP address formats (octal, decimal, hex) in the raw URL.
/// This must be done BEFORE url::Url::parse because it normalizes these formats.
fn reject_non_standard_ip_in_raw_url(url: &str) -> Result<(), Error> {
    // Format: scheme://[userinfo@]host[:port][/path]
    let url_lower = url.to_lowercase();
    let without_scheme = url_lower
        .strip_prefix("http://")
        .or_else(|| url_lower.strip_prefix("https://"));

    let Some(after_scheme) = without_scheme else {
        return Ok(());
    };

    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());

    let authority = &after_scheme[..host_end];

    let host_with_port = authority
        .rfind('@')
        .map(|i| &authority[i + 1..])
        .unwrap_or(authority);

    // Be careful with IPv6 brackets when removing port
    let host = if host_with_port.starts_with('[') {
        host_with_port
            .find(']')
            .map(|i| &host_with_port[..=i])
            .unwrap_or(host_with_port)
    } else {
        host_with_port
            .rfind(':')
            .map(|i| &host_with_port[..i])
            .unwrap_or(host_with_port)
    };

    check_non_standard_ip(host, url)
}

/// Check if a host string contains non-standard IP encoding.
fn check_non_standard_ip(host: &str, original_url: &str) -> Result<(), Error> {
    if host.starts_with('[') {
        return Ok(());
    }

    let parts: Vec<&str> = host.split('.').collect();

    for part in &parts {
        if part.starts_with("0x") || part.starts_with("0X") {
            return Err(Error::invalid_url(
                original_url,
                "hexadecimal IP encoding not allowed",
            ));
        }
    }

    // Single number (e.g., 2130706433 = 127.0.0.1)
    if parts.len() == 1 && !host.is_empty() {
        if host.chars().all(|c| c.is_ascii_digit()) {
            return Err(Error::invalid_url(
                original_url,
                "decimal IP encoding not allowed",
            ));
        }
        if host.chars().all(|c| c.is_ascii_hexdigit()) && host.chars().any(|c| c.is_ascii_alphabetic()) {
            return Err(Error::invalid_url(
                original_url,
                "hexadecimal IP encoding not allowed",
            ));
        }
    }

    // Short-form: 127.1 → 127.0.0.1, 127.0.1 → 127.0.0.1
    if (parts.len() == 2 || parts.len() == 3)
        && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(Error::invalid_url(
            original_url,
            "short-form IP encoding not allowed",
        ));
    }

    if parts.len() == 4 {
        for part in &parts {
            if part.is_empty() {
                continue;
            }

            // Leading zero with more digits = octal (e.g., 0177 = 127)
            if part.len() > 1
                && part.starts_with('0')
                && part.chars().all(|c| c.is_ascii_digit())
            {
                return Err(Error::invalid_url(
                    original_url,
                    "octal IP encoding not allowed",
                ));
            }

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

    // ==================== Valid URL Tests ====================

    #[test]
    fn test_parse_valid_urls() {
        let url = SafeUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.port(), 443);
        assert!(url.is_https());
    }

    #[test]
    fn test_parse_http_url() {
        let url = SafeUrl::parse("http://example.com/path").unwrap();
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.port(), 80);
        assert!(!url.is_https());
    }

    #[test]
    fn test_parse_with_port() {
        let url = SafeUrl::parse("https://example.com:8443/path").unwrap();
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.port(), 8443);
    }

    #[test]
    fn test_parse_with_query_and_fragment() {
        let url = SafeUrl::parse("https://example.com/path?query=1#fragment").unwrap();
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.path(), "/path");
    }

    #[test]
    fn test_allow_standard_ipv4() {
        let url = SafeUrl::parse("http://127.0.0.1/").unwrap();
        assert_eq!(url.host(), "127.0.0.1");
    }

    #[test]
    fn test_allow_standard_ipv4_with_port() {
        let url = SafeUrl::parse("http://192.168.1.1:8080/").unwrap();
        assert_eq!(url.host(), "192.168.1.1");
        assert_eq!(url.port(), 8080);
    }

    #[test]
    fn test_allow_ipv6() {
        let url = SafeUrl::parse("http://[::1]/").unwrap();
        assert_eq!(url.host(), "[::1]");
    }

    #[test]
    fn test_allow_ipv6_full() {
        let url = SafeUrl::parse("http://[2001:db8::1]/").unwrap();
        assert_eq!(url.host(), "[2001:db8::1]");
    }

    #[test]
    fn test_allow_ipv6_with_port() {
        let url = SafeUrl::parse("http://[::1]:8080/").unwrap();
        assert_eq!(url.host(), "[::1]");
        assert_eq!(url.port(), 8080);
    }

    // ==================== Hostname Normalization Tests ====================

    #[test]
    fn test_normalize_hostname_lowercase() {
        let url = SafeUrl::parse("https://EXAMPLE.COM/path").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_normalize_hostname_trailing_dot() {
        let url = SafeUrl::parse("https://example.com./path").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_normalize_hostname_mixed_case_and_trailing_dot() {
        let url = SafeUrl::parse("https://EXAMPLE.COM./path").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    // ==================== Scheme Tests ====================

    #[test]
    fn test_reject_non_http_schemes() {
        assert!(SafeUrl::parse("ftp://example.com").is_err());
        assert!(SafeUrl::parse("file:///etc/passwd").is_err());
        assert!(SafeUrl::parse("gopher://example.com").is_err());
        assert!(SafeUrl::parse("javascript:alert(1)").is_err());
        assert!(SafeUrl::parse("data:text/html,<h1>hi</h1>").is_err());
    }

    #[test]
    fn test_allow_mixed_case_http_scheme() {
        let url = SafeUrl::parse("HTTP://example.com/").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_allow_mixed_case_https_scheme() {
        let url = SafeUrl::parse("HTTPS://example.com/").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_mixed_case_scheme_ip_check() {
        assert!(SafeUrl::parse("HtTp://0177.0.0.1/").is_err());
        assert!(SafeUrl::parse("hTTpS://127.1/").is_err());
    }

    // ==================== Userinfo Tests ====================

    #[test]
    fn test_reject_userinfo() {
        assert!(SafeUrl::parse("https://user:pass@example.com").is_err());
        assert!(SafeUrl::parse("https://user@example.com").is_err());
    }

    #[test]
    fn test_reject_userinfo_with_ip() {
        assert!(SafeUrl::parse("http://admin:password@127.0.0.1/").is_err());
    }

    // ==================== Octal IP Tests ====================

    #[test]
    fn test_reject_octal_ip_full() {
        // 0177.0.0.1 = 127.0.0.1
        assert!(SafeUrl::parse("http://0177.0.0.1/").is_err());
        // 0127.0.0.1 = 87.0.0.1
        assert!(SafeUrl::parse("http://0127.0.0.1/").is_err());
    }

    #[test]
    fn test_reject_octal_ip_partial() {
        // Only one octet in octal
        assert!(SafeUrl::parse("http://127.0.0.01/").is_err());
        assert!(SafeUrl::parse("http://0177.0.0.01/").is_err());
    }

    #[test]
    fn test_reject_octal_ip_metadata() {
        // 0251.0376.0251.0376 = 169.254.169.254
        assert!(SafeUrl::parse("http://0251.0376.0251.0376/").is_err());
    }

    // ==================== Decimal IP Tests ====================

    #[test]
    fn test_reject_decimal_ip() {
        // 2130706433 = 127.0.0.1
        assert!(SafeUrl::parse("http://2130706433/").is_err());
    }

    #[test]
    fn test_reject_decimal_ip_metadata() {
        // 2852039166 = 169.254.169.254
        assert!(SafeUrl::parse("http://2852039166/").is_err());
    }

    // ==================== Hexadecimal IP Tests ====================

    #[test]
    fn test_reject_hex_ip_integer() {
        // 0x7f000001 = 127.0.0.1
        assert!(SafeUrl::parse("http://0x7f000001/").is_err());
    }

    #[test]
    fn test_reject_hex_ip_dotted() {
        // 0x7f.0x00.0x00.0x01 = 127.0.0.1
        assert!(SafeUrl::parse("http://0x7f.0x00.0x00.0x01/").is_err());
        assert!(SafeUrl::parse("http://0x7f.0.0.1/").is_err());
    }

    #[test]
    fn test_reject_hex_ip_uppercase() {
        assert!(SafeUrl::parse("http://0X7F000001/").is_err());
        assert!(SafeUrl::parse("http://0X7F.0X00.0X00.0X01/").is_err());
    }

    #[test]
    fn test_reject_hex_ip_metadata() {
        // 0xa9fea9fe = 169.254.169.254
        assert!(SafeUrl::parse("http://0xa9fea9fe/").is_err());
    }

    #[test]
    fn test_reject_hex_ip_without_prefix() {
        // Pure hex digits that look like an IP
        assert!(SafeUrl::parse("http://7f000001/").is_err());
    }

    // ==================== Short-form IP Tests ====================

    #[test]
    fn test_reject_short_form_ip_two_parts() {
        // 127.1 = 127.0.0.1
        assert!(SafeUrl::parse("http://127.1/").is_err());
        // 10.1 = 10.0.0.1
        assert!(SafeUrl::parse("http://10.1/").is_err());
    }

    #[test]
    fn test_reject_short_form_ip_three_parts() {
        // 127.0.1 = 127.0.0.1
        assert!(SafeUrl::parse("http://127.0.1/").is_err());
        // 192.168.1 = 192.168.0.1
        assert!(SafeUrl::parse("http://192.168.1/").is_err());
    }

    #[test]
    fn test_reject_short_form_ip_metadata() {
        // 169.16689918 would expand to metadata IP
        assert!(SafeUrl::parse("http://169.16689918/").is_err());
    }

    // ==================== Bracketed Hostname Tests ====================

    #[test]
    fn test_reject_bracketed_hostname() {
        // Brackets only allowed for IPv6
        assert!(SafeUrl::parse("http://[example.com]/").is_err());
    }

    #[test]
    fn test_reject_invalid_bracketed_ipv6() {
        assert!(SafeUrl::parse("http://[not:valid:ipv6]/").is_err());
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_hostname_with_numbers() {
        let url = SafeUrl::parse("http://host123.example.com/").unwrap();
        assert_eq!(url.host(), "host123.example.com");
    }

    #[test]
    fn test_hostname_starting_with_number() {
        let url = SafeUrl::parse("http://123host.example.com/").unwrap();
        assert_eq!(url.host(), "123host.example.com");
    }

    #[test]
    fn test_tld_with_numbers() {
        let url = SafeUrl::parse("http://example.co2/").unwrap();
        assert_eq!(url.host(), "example.co2");
    }

    #[test]
    fn test_subdomain_looks_like_ip_octet() {
        let url = SafeUrl::parse("http://0177.example.com/").unwrap();
        assert_eq!(url.host(), "0177.example.com");
    }

    #[test]
    fn test_url_with_empty_path() {
        let url = SafeUrl::parse("http://example.com").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_path_accessor() {
        let url = SafeUrl::parse("http://example.com/foo/bar").unwrap();
        assert_eq!(url.path(), "/foo/bar");
    }

    #[test]
    fn test_as_str() {
        let url = SafeUrl::parse("http://example.com/path").unwrap();
        assert!(url.as_str().contains("example.com"));
    }

    #[test]
    fn test_into_url() {
        let safe_url = SafeUrl::parse("http://example.com/").unwrap();
        let inner_url = safe_url.into_url();
        assert_eq!(inner_url.host_str(), Some("example.com"));
    }

    // ==================== Real-world Bypass Attempts ====================

    #[test]
    fn test_bypass_attempt_localhost_octal() {
        assert!(SafeUrl::parse("http://0x7f.0x0.0x0.0x1/admin").is_err());
        assert!(SafeUrl::parse("http://0177.0000.0000.0001/admin").is_err());
    }

    #[test]
    fn test_bypass_attempt_metadata_variations() {
        assert!(SafeUrl::parse("http://0xa9.0xfe.0xa9.0xfe/").is_err()); // hex
        assert!(SafeUrl::parse("http://0251.0376.0251.0376/").is_err()); // octal
        assert!(SafeUrl::parse("http://2852039166/").is_err()); // decimal
        assert!(SafeUrl::parse("http://169.254.43518/").is_err()); // 3-part
    }

    #[test]
    fn test_bypass_attempt_mixed_with_path() {
        assert!(SafeUrl::parse("http://0x7f000001/latest/meta-data/").is_err());
        assert!(SafeUrl::parse("http://127.1/admin/config").is_err());
    }
}
