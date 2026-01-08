"""Type stubs for url_jail - SSRF-safe URL validation."""

from typing import Optional

class Policy:
    """Validation policy determining what IPs are allowed."""
    PUBLIC_ONLY: Policy
    ALLOW_PRIVATE: Policy

class Validated:
    """Result of successful URL validation."""
    ip: str
    """The verified IP address to connect to."""
    host: str
    """Original hostname (use for Host header / SNI)."""
    port: int
    """Port number."""
    url: str
    """Full URL (normalized)."""
    https: bool
    """Whether HTTPS."""

class UrlJailError(Exception):
    """Base exception for url_jail errors."""
    ...

class SsrfBlocked(UrlJailError):
    """IP address or hostname is blocked by policy."""
    ...

class InvalidUrl(UrlJailError):
    """Invalid URL syntax or forbidden scheme."""
    ...

class DnsError(UrlJailError):
    """DNS resolution failed."""
    ...

class CustomPolicy:
    """Custom policy with user-defined blocklists and allowlists."""
    ...

class PolicyBuilder:
    """Builder for creating custom policies."""
    
    def __init__(self, base: Policy) -> None:
        """Create a new PolicyBuilder with a base policy."""
        ...
    
    def block_cidr(self, cidr: str) -> "PolicyBuilder":
        """Block an IP range (CIDR notation, e.g., '10.0.0.0/8')."""
        ...
    
    def allow_cidr(self, cidr: str) -> "PolicyBuilder":
        """Allow an IP range, overriding base policy."""
        ...
    
    def block_host(self, pattern: str) -> "PolicyBuilder":
        """Block a hostname pattern (supports wildcards like '*.internal.example.com')."""
        ...
    
    def allow_host(self, pattern: str) -> "PolicyBuilder":
        """Allow a hostname pattern."""
        ...
    
    def build(self) -> CustomPolicy:
        """Build the custom policy."""
        ...

def validate_sync(url: str, policy: Policy) -> Validated:
    """Validate a URL synchronously.
    
    Args:
        url: The URL to validate.
        policy: The validation policy to apply.
    
    Returns:
        Validated result with IP, host, port, and URL.
    
    Raises:
        SsrfBlocked: If the IP or hostname is blocked.
        InvalidUrl: If the URL is malformed.
        DnsError: If DNS resolution fails.
    """
    ...

async def validate(url: str, policy: Policy) -> Validated:
    """Validate a URL asynchronously.
    
    Args:
        url: The URL to validate.
        policy: The validation policy to apply.
    
    Returns:
        Validated result with IP, host, port, and URL.
    
    Raises:
        SsrfBlocked: If the IP or hostname is blocked.
        InvalidUrl: If the URL is malformed.
        DnsError: If DNS resolution fails.
    """
    ...

def validate_custom_sync(url: str, policy: CustomPolicy) -> Validated:
    """Validate a URL with a custom policy synchronously.
    
    Args:
        url: The URL to validate.
        policy: The custom policy created via PolicyBuilder.
    
    Returns:
        Validated result with IP, host, port, and URL.
    """
    ...

def get_sync(url: str, policy: Optional[Policy] = None) -> str:
    """Fetch a URL synchronously with SSRF protection.
    
    Validates the URL and all redirects against the policy.
    
    Args:
        url: The URL to fetch.
        policy: Validation policy (defaults to PUBLIC_ONLY).
    
    Returns:
        Response body as string.
    
    Raises:
        SsrfBlocked: If any URL in the redirect chain is blocked.
        InvalidUrl: If a URL is malformed.
        DnsError: If DNS resolution fails.
        UrlJailError: On HTTP errors or too many redirects.
    """
    ...

async def get(url: str, policy: Optional[Policy] = None) -> str:
    """Fetch a URL asynchronously with SSRF protection.
    
    Validates the URL and all redirects against the policy.
    
    Args:
        url: The URL to fetch.
        policy: Validation policy (defaults to PUBLIC_ONLY).
    
    Returns:
        Response body as string.
    
    Raises:
        SsrfBlocked: If any URL in the redirect chain is blocked.
        InvalidUrl: If a URL is malformed.
        DnsError: If DNS resolution fails.
        UrlJailError: On HTTP errors or too many redirects.
    """
    ...
