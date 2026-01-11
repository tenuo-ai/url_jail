"""
Comprehensive tests for url_jail Python bindings.

Run with: pytest tests/
"""

import pytest
from url_jail import (
    validate_sync,
    validate_custom_sync,
    Policy,
    PolicyBuilder,
    Validated,
    UrlJailError,
    SsrfBlocked,
    HostnameBlocked,
    InvalidUrl,
    DnsError,
)


class TestValidateSync:
    """Tests for validate_sync function."""

    def test_valid_public_url(self):
        """Public URLs should validate successfully."""
        result = validate_sync("https://example.com/", Policy.PUBLIC_ONLY)
        assert isinstance(result, Validated)
        assert result.host == "example.com"
        assert result.port == 443
        assert result.https is True

    def test_valid_http_url(self):
        """HTTP URLs should work with default port 80."""
        result = validate_sync("http://example.com/path", Policy.PUBLIC_ONLY)
        assert result.port == 80
        assert result.https is False

    def test_custom_port(self):
        """Custom ports should be preserved."""
        result = validate_sync("https://example.com:8443/", Policy.PUBLIC_ONLY)
        assert result.port == 8443

    def test_blocks_loopback(self):
        """Loopback addresses should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://127.0.0.1/", Policy.PUBLIC_ONLY)

    def test_blocks_loopback_with_allow_private(self):
        """Loopback should be blocked even with ALLOW_PRIVATE."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://127.0.0.1/", Policy.ALLOW_PRIVATE)

    def test_blocks_private_ip(self):
        """Private IPs should be blocked with PUBLIC_ONLY."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://192.168.1.1/", Policy.PUBLIC_ONLY)

    def test_allows_private_ip_with_policy(self):
        """Private IPs should be allowed with ALLOW_PRIVATE."""
        result = validate_sync("http://10.0.0.1/", Policy.ALLOW_PRIVATE)
        assert result.ip == "10.0.0.1"

    def test_blocks_metadata_endpoint(self):
        """Cloud metadata endpoints should always be blocked."""
        # Can be SsrfBlocked (IP) or HostnameBlocked (pattern)
        with pytest.raises((SsrfBlocked, HostnameBlocked)):
            validate_sync("http://169.254.169.254/", Policy.PUBLIC_ONLY)

    def test_blocks_metadata_with_allow_private(self):
        """Metadata should be blocked even with ALLOW_PRIVATE."""
        with pytest.raises((SsrfBlocked, HostnameBlocked)):
            validate_sync("http://169.254.169.254/", Policy.ALLOW_PRIVATE)

    def test_blocks_metadata_hostname(self):
        """Metadata hostnames should be blocked."""
        with pytest.raises((HostnameBlocked, UrlJailError)):
            validate_sync("http://metadata.google.internal/", Policy.PUBLIC_ONLY)

    def test_blocks_ipv6_loopback(self):
        """IPv6 loopback should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://[::1]/", Policy.PUBLIC_ONLY)

    def test_blocks_ipv4_mapped_ipv6(self):
        """IPv4-mapped IPv6 loopback should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://[::ffff:127.0.0.1]/", Policy.PUBLIC_ONLY)

    def test_blocks_unspecified_ipv4(self):
        """0.0.0.0 should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://0.0.0.0/", Policy.PUBLIC_ONLY)

    def test_blocks_unspecified_ipv6(self):
        """:: should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://[::]/", Policy.PUBLIC_ONLY)


class TestInvalidUrls:
    """Tests for invalid URL handling."""

    def test_rejects_ftp_scheme(self):
        """FTP scheme should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("ftp://example.com/", Policy.PUBLIC_ONLY)

    def test_rejects_file_scheme(self):
        """File scheme should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("file:///etc/passwd", Policy.PUBLIC_ONLY)

    def test_rejects_javascript_scheme(self):
        """JavaScript scheme should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("javascript:alert(1)", Policy.PUBLIC_ONLY)

    def test_rejects_octal_ip(self):
        """Octal IP encoding should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("http://0177.0.0.1/", Policy.PUBLIC_ONLY)

    def test_rejects_decimal_ip(self):
        """Decimal IP encoding should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("http://2130706433/", Policy.PUBLIC_ONLY)

    def test_rejects_hex_ip(self):
        """Hex IP encoding should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("http://0x7f000001/", Policy.PUBLIC_ONLY)

    def test_rejects_short_form_ip(self):
        """Short-form IP should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("http://127.1/", Policy.PUBLIC_ONLY)

    def test_rejects_userinfo(self):
        """URLs with userinfo should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("http://user:pass@example.com/", Policy.PUBLIC_ONLY)


class TestAdversarialInputs:
    """Tests for SSRF bypass attempts using various encoding tricks."""

    def test_backslash_url_bypass(self):
        """Backslash should not bypass host parsing."""
        # Some parsers treat \ as / (Windows path separator)
        with pytest.raises((InvalidUrl, UrlJailError)):
            validate_sync("http://localhost\\@evil.com/", Policy.PUBLIC_ONLY)

    def test_url_fragment_bypass(self):
        """Fragment should not affect host parsing."""
        # The host should be 127.0.0.1, not evil.com
        with pytest.raises(SsrfBlocked):
            validate_sync("http://127.0.0.1#@evil.com/", Policy.PUBLIC_ONLY)

    def test_port_userinfo_bypass(self):
        """Port in userinfo should not bypass validation."""
        with pytest.raises(InvalidUrl):
            validate_sync("http://127.0.0.1:80@evil.com/", Policy.PUBLIC_ONLY)

    def test_mixed_case_localhost(self):
        """Mixed case localhost variants should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://LocalHost/", Policy.PUBLIC_ONLY)

    def test_localhost_with_dot(self):
        """localhost. (with trailing dot) should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://localhost./", Policy.PUBLIC_ONLY)

    def test_zero_padded_ip(self):
        """Zero-padded IPs should be rejected."""
        with pytest.raises(InvalidUrl):
            validate_sync("http://127.000.000.001/", Policy.PUBLIC_ONLY)

    def test_ipv6_localhost_variants(self):
        """IPv6 localhost variants should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://[0:0:0:0:0:0:0:1]/", Policy.PUBLIC_ONLY)

    def test_ipv6_compressed_localhost(self):
        """Compressed IPv6 localhost should be blocked."""
        with pytest.raises(SsrfBlocked):
            validate_sync("http://[::1]/", Policy.PUBLIC_ONLY)

    def test_aws_metadata_ip_variants(self):
        """AWS metadata IP variants should be blocked."""
        with pytest.raises((SsrfBlocked, InvalidUrl, HostnameBlocked)):
            validate_sync("http://169.254.169.254/", Policy.PUBLIC_ONLY)
        with pytest.raises((SsrfBlocked, InvalidUrl, HostnameBlocked)):
            validate_sync("http://[::ffff:169.254.169.254]/", Policy.PUBLIC_ONLY)

    def test_gcp_metadata_hostname(self):
        """GCP metadata hostname should be blocked."""
        with pytest.raises((HostnameBlocked, DnsError, UrlJailError)):
            validate_sync("http://metadata.google.internal/", Policy.PUBLIC_ONLY)

    def test_azure_metadata_hostname(self):
        """Azure metadata hostname should be blocked."""
        with pytest.raises((HostnameBlocked, DnsError, UrlJailError)):
            validate_sync("http://169.254.169.254/metadata/instance", Policy.PUBLIC_ONLY)


class TestDnsErrors:
    """Tests for DNS error handling."""

    def test_nonexistent_domain(self):
        """Non-existent domains should raise DnsError."""
        with pytest.raises(DnsError):
            validate_sync("http://this-domain-does-not-exist-12345.invalid/", Policy.PUBLIC_ONLY)


class TestPolicyBuilder:
    """Tests for PolicyBuilder and CustomPolicy."""

    def test_block_cidr(self):
        """Should be able to block a CIDR range."""
        policy = PolicyBuilder(Policy.ALLOW_PRIVATE).block_cidr("10.0.0.0/8").build()
        # 10.x.x.x should be blocked
        with pytest.raises(SsrfBlocked):
            validate_custom_sync("http://10.1.2.3/", policy)

    def test_allow_cidr_override(self):
        """Should be able to allow a CIDR range that would normally be blocked."""
        policy = PolicyBuilder(Policy.PUBLIC_ONLY).allow_cidr("127.0.0.1/32").build()
        # Loopback should now be allowed
        result = validate_custom_sync("http://127.0.0.1/", policy)
        assert result.ip == "127.0.0.1"

    def test_block_hostname(self):
        """Should be able to block hostname patterns."""
        policy = PolicyBuilder(Policy.PUBLIC_ONLY).block_host("*.internal.example.com").build()
        with pytest.raises((SsrfBlocked, UrlJailError)):
            validate_custom_sync("http://api.internal.example.com/", policy)

    def test_fluent_api(self):
        """PolicyBuilder should support fluent API."""
        policy = (
            PolicyBuilder(Policy.ALLOW_PRIVATE)
            .block_cidr("10.0.0.0/8")
            .block_cidr("172.16.0.0/12")
            .block_host("*.internal.example.com")
            .allow_cidr("10.1.1.0/24")  # Allow specific subnet
            .build()
        )
        assert policy is not None


class TestValidatedObject:
    """Tests for Validated result object."""

    def test_validated_fields(self):
        """Validated should have all expected fields."""
        result = validate_sync("https://example.com:8443/path?query=1", Policy.PUBLIC_ONLY)
        
        assert hasattr(result, "ip")
        assert hasattr(result, "host")
        assert hasattr(result, "port")
        assert hasattr(result, "url")
        assert hasattr(result, "https")
        
        assert result.host == "example.com"
        assert result.port == 8443
        assert result.https is True
        assert "example.com" in result.url

    def test_ip_is_string(self):
        """IP should be returned as a string."""
        result = validate_sync("https://example.com/", Policy.PUBLIC_ONLY)
        assert isinstance(result.ip, str)
        # Should be a valid IP format
        parts = result.ip.split(".")
        assert len(parts) == 4 or ":" in result.ip  # IPv4 or IPv6


class TestErrorTypes:
    """Tests for error type hierarchy."""

    def test_ssrf_blocked_is_url_jail_error(self):
        """SsrfBlocked should be a subclass of UrlJailError."""
        with pytest.raises(UrlJailError):
            validate_sync("http://127.0.0.1/", Policy.PUBLIC_ONLY)

    def test_invalid_url_is_url_jail_error(self):
        """InvalidUrl should be a subclass of UrlJailError."""
        with pytest.raises(UrlJailError):
            validate_sync("ftp://example.com/", Policy.PUBLIC_ONLY)

    def test_dns_error_is_url_jail_error(self):
        """DnsError should be a subclass of UrlJailError."""
        with pytest.raises(UrlJailError):
            validate_sync("http://nonexistent.invalid/", Policy.PUBLIC_ONLY)
