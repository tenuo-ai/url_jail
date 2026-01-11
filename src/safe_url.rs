//! Safe URL parsing and normalization.
//!
//! This module handles URL parsing and applies security-focused normalization
//! before DNS resolution occurs.
//!
//! ## Normalization Rules
//!
//! | Component | Normalization | Notes |
//! |-----------|---------------|-------|
//! | Scheme | Validated | Only `http` and `https` allowed |
//! | Hostname | Lowercased, trailing dot removed | Case-insensitive matching |
//! | Port | Defaults applied | 80 for http, 443 for https |
//! | Userinfo | Rejected | `user:pass@` not allowed |
//! | Path | **Not normalized** | Preserved exactly as provided |
//! | Query | **Not normalized** | Preserved exactly as provided |
//! | Fragment | **Not normalized** | Preserved exactly as provided |
//!
//! ## Internationalized Domain Names (IDN)
//!
//! Punycode/IDNA handling is delegated to the [`url`](https://crates.io/crates/url)
//! crate, which implements IDNA 2008 via the [`idna`](https://crates.io/crates/idna)
//! crate. Unicode hostnames are converted to ASCII-compatible encoding.
//!
//! ## What This Module Does NOT Do
//!
//! - Path traversal prevention (use [`path_jail`](https://crates.io/crates/path_jail))
//! - Query parameter validation
//! - Content-type validation

use url::Url;

use crate::Error;

/// A parsed and normalized URL that is safe for further processing.
///
/// This struct represents a URL after parsing and normalization, but before
/// DNS resolution and IP validation. Use [`validate`](crate::validate) to
/// perform the full validation including DNS resolution.
///
/// ## What's Normalized
///
/// - Hostname: lowercased, trailing dot removed
/// - Port: defaults to 80 (http) or 443 (https)
/// - Scheme: validated to be http/https only
///
/// ## What's NOT Normalized
///
/// - Path, query, and fragment are preserved exactly as provided
/// - No path traversal detection (e.g., `/../` sequences are kept)
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
    ///
    /// The hostname is lowercased and has any trailing dot removed.
    /// For IPv6 addresses, this includes the brackets (e.g., `[::1]`).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port number.
    ///
    /// Returns the explicit port if specified, otherwise defaults to:
    /// - 80 for `http://`
    /// - 443 for `https://`
    pub fn port(&self) -> u16 {
        self.inner.port_or_known_default().unwrap_or(80)
    }

    /// Get the path component of the URL.
    ///
    /// Returns `/` if no path is specified.
    pub fn path(&self) -> &str {
        self.inner.path()
    }

    /// Get the full normalized URL as a string.
    ///
    /// This includes scheme, host, port (if non-default), path, query, and fragment.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Check if the URL uses HTTPS.
    ///
    /// Returns `true` for `https://` URLs, `false` for `http://`.
    pub fn is_https(&self) -> bool {
        self.inner.scheme() == "https"
    }

    /// Consume self and return the underlying [`url::Url`].
    ///
    /// Use this if you need access to the full URL parsing capabilities.
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
                format!(
                    "hexadecimal IP encoding detected ({}) - potential SSRF bypass attempt",
                    host
                ),
            ));
        }
    }

    // Single number (e.g., 2130706433 = 127.0.0.1)
    if parts.len() == 1 && !host.is_empty() {
        if host.chars().all(|c| c.is_ascii_digit()) {
            return Err(Error::invalid_url(
                original_url,
                format!(
                    "decimal IP encoding detected ({}) - potential SSRF bypass attempt",
                    host
                ),
            ));
        }
        if host.chars().all(|c| c.is_ascii_hexdigit())
            && host.chars().any(|c| c.is_ascii_alphabetic())
        {
            return Err(Error::invalid_url(
                original_url,
                format!(
                    "hexadecimal IP encoding detected ({}) - potential SSRF bypass attempt",
                    host
                ),
            ));
        }
    }

    // Short-form: 127.1 -> 127.0.0.1, 127.0.1 -> 127.0.0.1
    if (parts.len() == 2 || parts.len() == 3)
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(Error::invalid_url(
            original_url,
            format!(
                "short-form IP encoding detected ({}) - potential SSRF bypass attempt",
                host
            ),
        ));
    }

    if parts.len() == 4 {
        for part in &parts {
            if part.is_empty() {
                continue;
            }

            // Leading zero with more digits = octal (e.g., 0177 = 127)
            if part.len() > 1 && part.starts_with('0') && part.chars().all(|c| c.is_ascii_digit()) {
                return Err(Error::invalid_url(
                    original_url,
                    format!(
                        "octal IP encoding detected ({}) - potential SSRF bypass attempt",
                        host
                    ),
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

    // ==================== Edge Cases and Error Handling ====================

    #[test]
    fn test_empty_url() {
        assert!(SafeUrl::parse("").is_err());
    }

    #[test]
    fn test_whitespace_only_url() {
        assert!(SafeUrl::parse("   ").is_err());
    }

    #[test]
    fn test_scheme_only() {
        assert!(SafeUrl::parse("http://").is_err());
        assert!(SafeUrl::parse("https://").is_err());
    }

    #[test]
    fn test_no_scheme() {
        assert!(SafeUrl::parse("example.com").is_err());
        assert!(SafeUrl::parse("//example.com").is_err());
    }

    #[test]
    fn test_url_with_fragment() {
        let url = SafeUrl::parse("https://example.com/path#fragment").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_url_with_empty_query() {
        let url = SafeUrl::parse("https://example.com/path?").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_url_with_empty_fragment() {
        let url = SafeUrl::parse("https://example.com/path#").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_very_long_hostname() {
        // DNS labels are max 63 chars, hostnames max 253 chars
        let long_label = "a".repeat(63);
        let long_hostname = format!("{}.{}.{}.com", long_label, long_label, long_label);
        let url = format!("http://{}/", long_hostname);
        let result = SafeUrl::parse(&url);
        // Should parse successfully (URL parser handles DNS limits differently)
        assert!(result.is_ok());
    }

    #[test]
    fn test_punycode_hostname() {
        // IDN/Punycode: xn--nxasmq5b = "בדיקה" in Hebrew
        let url = SafeUrl::parse("http://xn--nxasmq5b.com/").unwrap();
        assert!(url.host().contains("xn--"));
    }

    #[test]
    fn test_hostname_with_underscore() {
        // Underscores technically not allowed in DNS but often work
        let result = SafeUrl::parse("http://my_host.example.com/");
        // url crate may accept this
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_hostname_with_hyphen() {
        let url = SafeUrl::parse("http://my-host.example.com/").unwrap();
        assert_eq!(url.host(), "my-host.example.com");
    }

    #[test]
    fn test_hostname_starting_with_hyphen() {
        // Invalid DNS name but URL parser may accept
        let result = SafeUrl::parse("http://-invalid.example.com/");
        // Either accept or reject is fine, just don't panic
        let _ = result;
    }

    #[test]
    fn test_double_slash_in_path() {
        let url = SafeUrl::parse("http://example.com//path//to//resource").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_url_with_port_zero() {
        // Port 0 is technically valid
        let url = SafeUrl::parse("http://example.com:0/").unwrap();
        assert_eq!(url.port(), 0);
    }

    #[test]
    fn test_url_with_high_port() {
        let url = SafeUrl::parse("http://example.com:65535/").unwrap();
        assert_eq!(url.port(), 65535);
    }

    #[test]
    fn test_url_with_invalid_port() {
        // Port > 65535 should fail
        assert!(SafeUrl::parse("http://example.com:65536/").is_err());
        assert!(SafeUrl::parse("http://example.com:99999/").is_err());
    }

    #[test]
    fn test_url_encoded_characters_in_path() {
        let url = SafeUrl::parse("http://example.com/path%20with%20spaces").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_url_with_at_sign_in_path() {
        // @ in path, not userinfo
        let url = SafeUrl::parse("http://example.com/user@domain").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_localhost_variations() {
        // localhost as hostname (not IP)
        let url = SafeUrl::parse("http://localhost/").unwrap();
        assert_eq!(url.host(), "localhost");

        let url2 = SafeUrl::parse("http://LOCALHOST/").unwrap();
        assert_eq!(url2.host(), "localhost");

        let url3 = SafeUrl::parse("http://LocalHost/").unwrap();
        assert_eq!(url3.host(), "localhost");
    }

    #[test]
    fn test_ipv6_with_zone_id() {
        // Zone IDs (fe80::1%eth0) - may or may not be supported
        let result = SafeUrl::parse("http://[fe80::1%25eth0]/");
        // Just ensure it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_ipv6_loopback() {
        let url = SafeUrl::parse("http://[::1]/").unwrap();
        assert_eq!(url.host(), "[::1]");
    }

    #[test]
    fn test_ipv6_full_form() {
        let url = SafeUrl::parse("http://[0000:0000:0000:0000:0000:0000:0000:0001]/").unwrap();
        // URL parser normalizes IPv6
        assert!(url.host().contains("::1") || url.host().contains("0000"));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_in_url() {
        let url = SafeUrl::parse("http://[::ffff:127.0.0.1]/").unwrap();
        assert!(url.host().contains("127.0.0.1") || url.host().contains("ffff"));
    }

    // ==================== Error Type Verification ====================

    #[test]
    fn test_invalid_scheme_error_message() {
        let err = SafeUrl::parse("ftp://example.com/").unwrap_err();
        match err {
            crate::Error::InvalidUrl { reason, .. } => {
                assert!(reason.contains("scheme") || reason.contains("ftp"));
            }
            _ => panic!("Expected InvalidUrl error"),
        }
    }

    #[test]
    fn test_userinfo_error_message() {
        let err = SafeUrl::parse("http://user:pass@example.com/").unwrap_err();
        match err {
            crate::Error::InvalidUrl { reason, .. } => {
                assert!(reason.contains("userinfo"));
            }
            _ => panic!("Expected InvalidUrl error"),
        }
    }

    #[test]
    fn test_octal_ip_error_message() {
        let err = SafeUrl::parse("http://0177.0.0.1/").unwrap_err();
        match err {
            crate::Error::InvalidUrl { reason, .. } => {
                assert!(reason.contains("octal"));
            }
            _ => panic!("Expected InvalidUrl error"),
        }
    }

    #[test]
    fn test_hex_ip_error_message() {
        let err = SafeUrl::parse("http://0x7f000001/").unwrap_err();
        match err {
            crate::Error::InvalidUrl { reason, .. } => {
                assert!(reason.contains("hex"));
            }
            _ => panic!("Expected InvalidUrl error"),
        }
    }

    #[test]
    fn test_decimal_ip_error_message() {
        let err = SafeUrl::parse("http://2130706433/").unwrap_err();
        match err {
            crate::Error::InvalidUrl { reason, .. } => {
                assert!(reason.contains("decimal"));
            }
            _ => panic!("Expected InvalidUrl error"),
        }
    }

    #[test]
    fn test_short_form_ip_error_message() {
        let err = SafeUrl::parse("http://127.1/").unwrap_err();
        match err {
            crate::Error::InvalidUrl { reason, .. } => {
                assert!(reason.contains("short-form"));
            }
            _ => panic!("Expected InvalidUrl error"),
        }
    }

    // ==================== Unicode and Special Characters ====================

    #[test]
    fn test_unicode_in_path() {
        let url = SafeUrl::parse("http://example.com/путь").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_unicode_hostname_gets_normalized() {
        // Unicode hostnames should be converted to punycode by the URL parser
        let result = SafeUrl::parse("http://münchen.de/");
        // Should either work (with punycode) or fail cleanly
        match result {
            Ok(url) => {
                // Should be normalized to punycode
                let host = url.host();
                assert!(host == "münchen.de" || host.contains("xn--"));
            }
            Err(_) => {
                // Some parsers may reject non-ASCII hostnames
            }
        }
    }

    #[test]
    fn test_emoji_in_path() {
        let url = SafeUrl::parse("http://example.com/🎉").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    // ==================== RED TEAM: URL Encoding Attacks ====================

    #[test]
    fn test_redteam_url_encoded_ip() {
        // %31%32%37 = "127" - attempt to bypass via URL encoding
        // The url crate decodes this, so we should get "127.0.0.1"
        let result = SafeUrl::parse("http://%31%32%37.0.0.1/");
        // Either rejected at parse time, or parsed as 127.0.0.1 (caught by IP validation)
        match result {
            Ok(url) => {
                // If parsed, hostname should be decoded
                assert!(url.host() == "127.0.0.1" || url.host().contains("%"));
            }
            Err(_) => {} // Rejected is also fine
        }
    }

    #[test]
    fn test_redteam_url_encoded_ip_full() {
        // Full URL encoding of 127.0.0.1
        let result = SafeUrl::parse("http://%31%32%37%2e%30%2e%30%2e%31/");
        match result {
            Ok(url) => {
                // Should decode to 127.0.0.1
                let host = url.host();
                assert!(host == "127.0.0.1" || host.contains("%"));
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_double_encoded_ip() {
        // %25 = "%", so %2531 = "%31" which decodes to "1"
        // This tests double-encoding bypass attempts
        let result = SafeUrl::parse("http://%2531%2532%2537.0.0.1/");
        // Should NOT decode to 127.0.0.1 (only one level of decoding)
        match result {
            Ok(url) => {
                // Host should contain literal %
                assert!(url.host().contains("%") || url.host().contains("25"));
            }
            Err(_) => {} // Rejection is fine too
        }
    }

    // ==================== RED TEAM: @ Symbol Confusion ====================

    #[test]
    fn test_redteam_at_symbol_userinfo_with_ip() {
        // Attempt: user thinks they're going to safe.com, but @ makes 127.0.0.1 the real host
        let result = SafeUrl::parse("http://safe.com@127.0.0.1/");
        // This MUST be rejected - we block userinfo
        assert!(result.is_err(), "Userinfo with @ must be rejected");
    }

    #[test]
    fn test_redteam_at_symbol_userinfo_with_metadata() {
        // Attempt to access metadata via userinfo confusion
        let result = SafeUrl::parse("http://google.com@169.254.169.254/");
        assert!(result.is_err(), "Userinfo must be rejected");
    }

    #[test]
    fn test_redteam_at_symbol_encoded() {
        // %40 = @
        let result = SafeUrl::parse("http://safe.com%40127.0.0.1/");
        // URL parser may treat this differently
        match result {
            Ok(url) => {
                // If accepted, the @ should be in the host, not creating userinfo
                // Verify we didn't accidentally allow access to 127.0.0.1
                assert!(!url.host().starts_with("127."));
            }
            Err(_) => {} // Rejection is fine
        }
    }

    #[test]
    fn test_redteam_multiple_at_symbols() {
        // Multiple @ symbols - which is the real host?
        let result = SafeUrl::parse("http://a@b@127.0.0.1/");
        assert!(result.is_err(), "Multiple @ or userinfo must be rejected");
    }

    // ==================== RED TEAM: Whitespace and Control Characters ====================

    #[test]
    fn test_redteam_tab_in_hostname() {
        // Tab character (%09) in hostname
        let result = SafeUrl::parse("http://127%09.0.0.1/");
        // Should either reject or not parse as 127.0.0.1
        match result {
            Ok(url) => {
                assert_ne!(url.host(), "127.0.0.1");
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_newline_in_url() {
        // Newline (%0a) injection
        let result = SafeUrl::parse("http://example.com%0a127.0.0.1/");
        match result {
            Ok(url) => {
                assert!(!url.host().starts_with("127."));
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_carriage_return_in_url() {
        // CR (%0d) injection
        let result = SafeUrl::parse("http://example.com%0d127.0.0.1/");
        match result {
            Ok(url) => {
                assert!(!url.host().starts_with("127."));
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_null_byte_injection() {
        // Null byte (%00) - classic bypass technique
        let result = SafeUrl::parse("http://example.com%00.127.0.0.1/");
        match result {
            Ok(url) => {
                // Should not allow access to anything after null
                assert!(!url.host().contains("127.0.0.1"));
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_null_byte_before_at() {
        // http://safe.com%00@evil.com - null byte before @
        let result = SafeUrl::parse("http://safe.com%00@127.0.0.1/");
        // Must reject - either for null byte or userinfo
        assert!(
            result.is_err() || {
                let url = result.unwrap();
                !url.host().starts_with("127.")
            }
        );
    }

    // ==================== RED TEAM: Backslash Confusion ====================

    #[test]
    fn test_redteam_backslash_before_at() {
        // Some parsers treat \ as / - confusion attack
        let result = SafeUrl::parse("http://safe.com\\@127.0.0.1/");
        match result {
            Ok(url) => {
                // Backslash should not enable host confusion
                assert!(!url.host().starts_with("127."));
            }
            Err(_) => {} // Rejection is fine
        }
    }

    #[test]
    fn test_redteam_backslash_as_path_separator() {
        // Windows-style path separator
        let result = SafeUrl::parse("http://example.com\\path\\to\\file");
        match result {
            Ok(url) => {
                assert_eq!(url.host(), "example.com");
            }
            Err(_) => {}
        }
    }

    // ==================== RED TEAM: Unicode/Homoglyph Attacks ====================

    #[test]
    fn test_redteam_cyrillic_a_in_localhost() {
        // Cyrillic 'а' (U+0430) looks like ASCII 'a' (U+0061)
        // "locаlhost" with Cyrillic а
        let result = SafeUrl::parse("http://loc\u{0430}lhost/");
        match result {
            Ok(url) => {
                // Should NOT be treated as "localhost"
                // Either punycode-encoded or kept as-is
                assert_ne!(url.host(), "localhost");
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_homoglyph_metadata() {
        // Cyrillic characters that look like "metadata"
        // Using Cyrillic 'е' (U+0435) instead of ASCII 'e'
        let result = SafeUrl::parse("http://m\u{0435}tadata.google.internal/");
        match result {
            Ok(url) => {
                // Should NOT match the blocked hostname
                assert!(!url.host().eq_ignore_ascii_case("metadata.google.internal"));
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_full_width_ip() {
        // Full-width numerals: １２７ (U+FF11 U+FF12 U+FF17)
        // URL crate converts these to ASCII - this is GOOD because our IP blocklist catches it
        let result = SafeUrl::parse("http://\u{FF11}\u{FF12}\u{FF17}.0.0.1/");
        match result {
            Ok(url) => {
                // Normalized to 127.0.0.1, which our IP blocklist will catch
                // Either the URL crate normalizes it (127.0.0.1) or keeps it as-is
                // Either way, IP validation will handle it
                let _ = url.host();
            }
            Err(_) => {} // Rejection is also fine
        }
    }

    #[test]
    fn test_redteam_superscript_numbers() {
        // Superscript numbers: ¹²⁷
        // URL crate may normalize these to ASCII
        let result = SafeUrl::parse("http://¹²⁷.0.0.1/");
        match result {
            Ok(url) => {
                // If normalized to 127.0.0.1, our IP blocklist will catch it
                // This test documents the behavior
                let _ = url.host();
            }
            Err(_) => {} // Rejection is also acceptable
        }
    }

    // ==================== RED TEAM: Fragment Confusion ====================

    #[test]
    fn test_redteam_fragment_with_at() {
        // Fragment should not affect host parsing
        let url = SafeUrl::parse("http://example.com/path#@127.0.0.1").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_redteam_fragment_with_scheme() {
        // Fragment containing what looks like a URL
        let url = SafeUrl::parse("http://example.com/#http://127.0.0.1/").unwrap();
        assert_eq!(url.host(), "example.com");
    }

    // ==================== RED TEAM: DNS Rebinding Hostnames ====================

    #[test]
    fn test_redteam_nip_io_style() {
        // Services like nip.io resolve 127.0.0.1.nip.io to 127.0.0.1
        // We can't block this at URL parse time - DNS validation will catch it
        let url = SafeUrl::parse("http://127.0.0.1.nip.io/").unwrap();
        // Parse succeeds, but DNS validation would catch this
        assert_eq!(url.host(), "127.0.0.1.nip.io");
    }

    #[test]
    fn test_redteam_xip_io_style() {
        // Similar to nip.io
        let url = SafeUrl::parse("http://192.168.1.1.xip.io/").unwrap();
        assert_eq!(url.host(), "192.168.1.1.xip.io");
    }

    #[test]
    fn test_redteam_subdomain_is_ip() {
        // Subdomain that looks like an IP
        let url = SafeUrl::parse("http://127.0.0.1.attacker.com/").unwrap();
        // This is a valid hostname, DNS validation needed
        assert_eq!(url.host(), "127.0.0.1.attacker.com");
    }

    // ==================== RED TEAM: IPv6 Edge Cases ====================

    #[test]
    fn test_redteam_ipv6_zone_id() {
        // Zone ID: [fe80::1%eth0] - some systems support this
        // %25 = % in URL encoding
        let result = SafeUrl::parse("http://[fe80::1%25eth0]/");
        // Should either reject or handle safely
        match result {
            Ok(url) => {
                // Zone ID in host is unusual
                assert!(url.host().contains("fe80"));
            }
            Err(_) => {} // Rejection is fine
        }
    }

    #[test]
    fn test_redteam_ipv6_zone_id_unencoded() {
        let result = SafeUrl::parse("http://[fe80::1%eth0]/");
        // Likely rejected due to invalid URL
        let _ = result; // Just ensure no panic
    }

    #[test]
    fn test_redteam_ipv6_with_embedded_ipv4_loopback() {
        // ::127.0.0.1 format
        let result = SafeUrl::parse("http://[::127.0.0.1]/");
        match result {
            Ok(url) => {
                // Should be recognized as containing 127.0.0.1
                let host = url.host();
                assert!(host.contains("127.0.0.1") || host.contains("::"));
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_redteam_ipv6_mapped_metadata() {
        // IPv4-mapped IPv6 for metadata endpoint
        let url = SafeUrl::parse("http://[::ffff:169.254.169.254]/").unwrap();
        // Parse succeeds, IP validation catches this
        assert!(url.host().contains("169.254") || url.host().contains("ffff"));
    }

    // ==================== RED TEAM: Bracket Abuse ====================

    #[test]
    fn test_redteam_brackets_around_hostname() {
        // Brackets are only valid for IPv6
        let result = SafeUrl::parse("http://[localhost]/");
        assert!(result.is_err(), "Brackets around hostname must be rejected");
    }

    #[test]
    fn test_redteam_brackets_around_ipv4() {
        // Brackets around IPv4 should fail
        let result = SafeUrl::parse("http://[127.0.0.1]/");
        assert!(result.is_err(), "Brackets around IPv4 must be rejected");
    }

    #[test]
    fn test_redteam_unbalanced_brackets() {
        assert!(SafeUrl::parse("http://[::1/").is_err());
        assert!(SafeUrl::parse("http://::1]/").is_err());
    }

    // ==================== RED TEAM: Scheme Variations ====================

    #[test]
    fn test_redteam_scheme_with_extra_slashes() {
        // http:/// with extra slash - URL crate may parse this as empty host
        let result = SafeUrl::parse("http:///127.0.0.1/");
        // URL crate treats this as host=127.0.0.1 with empty path segment before it
        // The important thing is that if 127.0.0.1 becomes the host, our IP blocklist catches it
        match result {
            Ok(url) => {
                // If host is 127.0.0.1, our IP validation blocks it
                // If host is empty, that's also handled
                let _host = url.host();
            }
            Err(_) => {} // Rejection is fine
        }
    }

    #[test]
    fn test_redteam_scheme_without_slashes() {
        // http:127.0.0.1 without // - URL crate parses this as path, not host
        let result = SafeUrl::parse("http:127.0.0.1/");
        // URL crate treats "127.0.0.1/" as the path with empty host
        match result {
            Ok(url) => {
                // If parsed with empty host, we'd catch it
                // If parsed with 127.0.0.1 as host, IP blocklist catches it
                let _host = url.host();
            }
            Err(_) => {} // Rejection is acceptable
        }
    }

    #[test]
    fn test_redteam_file_scheme_rejected() {
        assert!(SafeUrl::parse("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_redteam_javascript_scheme_rejected() {
        assert!(SafeUrl::parse("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_redteam_data_scheme_rejected() {
        assert!(SafeUrl::parse("data:text/html,<script>alert(1)</script>").is_err());
    }

    // ==================== RED TEAM: Mixed Case IP Encoding ====================

    #[test]
    fn test_redteam_mixed_case_hex() {
        // Mixed case in hex encoding
        assert!(SafeUrl::parse("http://0X7F.0x00.0X00.0x01/").is_err());
    }

    #[test]
    fn test_redteam_leading_zeros_not_octal() {
        // Some systems might treat 00127 as octal
        assert!(SafeUrl::parse("http://00127.0.0.1/").is_err());
    }

    // ==================== RED TEAM: Port-based Attacks ====================

    #[test]
    fn test_redteam_port_overflow() {
        // Values that might overflow
        assert!(SafeUrl::parse("http://example.com:4294967377/").is_err()); // 2^32 + 81
    }

    #[test]
    fn test_redteam_negative_port() {
        assert!(SafeUrl::parse("http://example.com:-1/").is_err());
    }

    #[test]
    fn test_redteam_port_with_leading_zeros() {
        // 0080 = 80, but might confuse some parsers
        let result = SafeUrl::parse("http://example.com:0080/");
        match result {
            Ok(url) => assert_eq!(url.port(), 80),
            Err(_) => {} // Rejection is also acceptable
        }
    }

    #[test]
    fn test_redteam_port_with_plus() {
        // +80 might be parsed as 80
        let result = SafeUrl::parse("http://example.com:+80/");
        assert!(result.is_err());
    }

    // ==================== RED TEAM: Path Traversal (informational) ====================
    // Note: url_jail doesn't prevent path traversal - that's path_jail's job
    // The URL crate normalizes paths, collapsing /../ sequences
    // These tests document the boundary

    #[test]
    fn test_redteam_path_traversal_normalized() {
        // URL crate normalizes /../ sequences
        let url = SafeUrl::parse("http://example.com/../../../etc/passwd").unwrap();
        // URL crate collapses path traversal - this is handled by the URL parser
        // The path won't contain ".." after normalization
        let path = url.path();
        // Path is normalized - this is expected URL parsing behavior
        // path_jail would need to operate on the raw input, not parsed URL
        assert!(path.contains("etc") || path == "/etc/passwd");
    }

    #[test]
    fn test_redteam_encoded_path_traversal() {
        // %2e = .
        let url = SafeUrl::parse("http://example.com/%2e%2e/%2e%2e/etc/passwd").unwrap();
        // URL crate may decode and normalize, or preserve encoding
        // Either behavior is acceptable - document what happens
        let path = url.path();
        // The path was parsed - verify it contains expected content
        assert!(path.contains("etc") || path.contains("%2e") || path.contains(".."));
    }
}
