"""Type stubs for url_jail - SSRF-safe URL validation for Python.

This module provides SSRF (Server-Side Request Forgery) protection by validating
URLs and their resolved IP addresses before making HTTP requests.

Helps prevent vulnerabilities like:
- CVE-2024-0243: LangChain RecursiveUrlLoader SSRF
- CVE-2025-2828: LangChain RequestsToolkit SSRF

Example:
    >>> from url_jail import get_sync, Policy
    >>> body = get_sync("https://example.com/api")  # Safe!
    >>> body = get_sync(url, Policy.ALLOW_PRIVATE)  # Allow private IPs
"""

from typing import Optional

class Policy:
    """Validation policy determining what IPs are allowed.
    
    Attributes:
        PUBLIC_ONLY: Block private IPs, loopback, link-local, and metadata endpoints.
            This is the default and recommended for most use cases.
        ALLOW_PRIVATE: Allow private IPs (10.x, 172.16.x, 192.168.x), but still
            block loopback and metadata endpoints. Use for internal services.
    
    Example:
        >>> from url_jail import validate_sync, Policy
        >>> result = validate_sync("https://example.com", Policy.PUBLIC_ONLY)
    """
    PUBLIC_ONLY: Policy
    ALLOW_PRIVATE: Policy

class Validated:
    """Result of successful URL validation.
    
    Contains the verified IP address to connect to, preventing DNS rebinding attacks.
    Use the `ip` field when making the actual HTTP connection.
    
    Attributes:
        ip: The verified IP address to connect to (as string).
        host: Original hostname (use for Host header / SNI).
        port: Port number (80 for http, 443 for https, or custom).
        url: Full URL (normalized).
        https: Whether the URL uses HTTPS.
    
    Example:
        >>> result = validate_sync("https://example.com:8443/path", Policy.PUBLIC_ONLY)
        >>> print(f"Connect to {result.ip}:{result.port}")
        >>> print(f"Host header: {result.host}")
    """
    ip: str
    host: str
    port: int
    url: str
    https: bool

class CustomPolicy:
    """Custom policy with user-defined blocklists and allowlists.
    
    Created via PolicyBuilder. Allows fine-grained control over which IPs
    and hostnames are allowed or blocked.
    
    Example:
        >>> policy = PolicyBuilder(Policy.ALLOW_PRIVATE).block_cidr("10.0.0.0/8").build()
        >>> result = validate_custom_sync("https://example.com", policy)
    """
    ...

class PolicyBuilder:
    """Builder for creating custom policies.
    
    Allows you to customize IP and hostname filtering beyond the built-in policies.
    Allow rules take precedence over block rules.
    
    Example:
        >>> from url_jail import PolicyBuilder, Policy, validate_custom_sync
        >>> 
        >>> # Block a specific internal range while allowing other private IPs
        >>> policy = (PolicyBuilder(Policy.ALLOW_PRIVATE)
        ...     .block_cidr("10.0.0.0/8")
        ...     .block_host("*.internal.example.com")
        ...     .allow_host("trusted.internal.example.com")
        ...     .build())
        >>> 
        >>> result = validate_custom_sync("https://api.example.com", policy)
    """
    
    def __init__(self, base: Policy) -> None:
        """Create a new PolicyBuilder with a base policy.
        
        Args:
            base: The base policy (PUBLIC_ONLY or ALLOW_PRIVATE) to extend.
        """
        ...
    
    def block_cidr(self, cidr: str) -> "PolicyBuilder":
        """Block an IP range (CIDR notation).
        
        Args:
            cidr: CIDR notation like '10.0.0.0/8' or '192.168.1.0/24'.
        
        Returns:
            Self for method chaining.
        
        Example:
            >>> builder.block_cidr("10.0.0.0/8").block_cidr("172.16.0.0/12")
        """
        ...
    
    def allow_cidr(self, cidr: str) -> "PolicyBuilder":
        """Allow an IP range, overriding base policy blocks.
        
        Allow rules take precedence over block rules.
        
        Args:
            cidr: CIDR notation like '192.168.1.0/24'.
        
        Returns:
            Self for method chaining.
        
        Example:
            >>> # Allow a specific subnet even though base policy blocks private IPs
            >>> builder = PolicyBuilder(Policy.PUBLIC_ONLY).allow_cidr("192.168.1.0/24")
        """
        ...
    
    def block_host(self, pattern: str) -> "PolicyBuilder":
        """Block a hostname pattern.
        
        Supports wildcards: '*.internal.example.com' matches any subdomain.
        
        Args:
            pattern: Exact hostname or wildcard pattern.
        
        Returns:
            Self for method chaining.
        
        Example:
            >>> builder.block_host("*.internal.example.com")
            >>> builder.block_host("blocked.example.com")
        """
        ...
    
    def allow_host(self, pattern: str) -> "PolicyBuilder":
        """Allow a hostname pattern, overriding blocks.
        
        Allow rules take precedence over block rules.
        
        Args:
            pattern: Exact hostname or wildcard pattern.
        
        Returns:
            Self for method chaining.
        """
        ...
    
    def build(self) -> CustomPolicy:
        """Build the custom policy.
        
        Returns:
            A CustomPolicy that can be used with validate_custom_sync().
        """
        ...

class UrlJailError(Exception):
    """Base exception for all url_jail errors.
    
    Catch this to handle any url_jail error generically.
    """
    ...

class SsrfBlocked(UrlJailError):
    """IP address or hostname is blocked by policy.
    
    Raised when the URL points to a blocked IP (loopback, private, metadata)
    or a blocked hostname (cloud metadata endpoints).
    """
    ...

class InvalidUrl(UrlJailError):
    """Invalid URL syntax or forbidden scheme.
    
    Raised when:
    - URL is malformed
    - Scheme is not http or https
    - URL contains userinfo (user:pass@)
    - IP is encoded in non-standard format (octal, hex, decimal)
    """
    ...

class DnsError(UrlJailError):
    """DNS resolution failed.
    
    Raised when the hostname cannot be resolved to an IP address.
    """
    ...

def validate_sync(url: str, policy: Policy) -> Validated:
    """Validate a URL synchronously.
    
    Parses the URL, resolves DNS, and checks the IP against the policy.
    Returns a Validated result containing the verified IP to connect to.
    
    Args:
        url: The URL to validate (must be http or https).
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE).
    
    Returns:
        Validated result with verified IP, host, port, and URL.
    
    Raises:
        SsrfBlocked: If the IP or hostname is blocked by policy.
        InvalidUrl: If the URL is malformed or uses forbidden scheme.
        DnsError: If DNS resolution fails.
    
    Example:
        >>> from url_jail import validate_sync, Policy
        >>> result = validate_sync("https://example.com/api", Policy.PUBLIC_ONLY)
        >>> print(f"Safe to connect to {result.ip}")
    """
    ...

async def validate(url: str, policy: Policy) -> Validated:
    """Validate a URL asynchronously.
    
    Async version of validate_sync(). Use in async contexts.
    
    Args:
        url: The URL to validate (must be http or https).
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE).
    
    Returns:
        Validated result with verified IP, host, port, and URL.
    
    Raises:
        SsrfBlocked: If the IP or hostname is blocked by policy.
        InvalidUrl: If the URL is malformed or uses forbidden scheme.
        DnsError: If DNS resolution fails.
    
    Example:
        >>> import asyncio
        >>> from url_jail import validate, Policy
        >>> 
        >>> async def main():
        ...     result = await validate("https://example.com", Policy.PUBLIC_ONLY)
        ...     print(f"Safe to connect to {result.ip}")
        >>> 
        >>> asyncio.run(main())
    """
    ...

def validate_custom_sync(url: str, policy: CustomPolicy) -> Validated:
    """Validate a URL with a custom policy synchronously.
    
    Use this with policies created via PolicyBuilder for fine-grained control.
    
    Args:
        url: The URL to validate (must be http or https).
        policy: A CustomPolicy created via PolicyBuilder.
    
    Returns:
        Validated result with verified IP, host, port, and URL.
    
    Raises:
        SsrfBlocked: If the IP or hostname is blocked by policy.
        InvalidUrl: If the URL is malformed or uses forbidden scheme.
        DnsError: If DNS resolution fails.
    
    Example:
        >>> from url_jail import PolicyBuilder, Policy, validate_custom_sync
        >>> 
        >>> policy = PolicyBuilder(Policy.ALLOW_PRIVATE).block_cidr("10.0.0.0/8").build()
        >>> result = validate_custom_sync("https://example.com", policy)
    """
    ...

def get_sync(url: str, policy: Optional[Policy] = None) -> str:
    """Fetch a URL synchronously with full SSRF protection.
    
    This is the recommended way to safely fetch user-provided URLs.
    Validates the initial URL and all redirects against the policy.
    
    Args:
        url: The URL to fetch.
        policy: Validation policy (defaults to PUBLIC_ONLY).
    
    Returns:
        Response body as string.
    
    Raises:
        SsrfBlocked: If any URL in the redirect chain is blocked.
        InvalidUrl: If a URL is malformed or uses forbidden scheme.
        DnsError: If DNS resolution fails.
        UrlJailError: On HTTP errors or too many redirects.
    
    Example:
        >>> from url_jail import get_sync
        >>> 
        >>> # Safe! Validates URL and all redirects
        >>> body = get_sync(user_provided_url)
        >>> 
        >>> # With explicit policy
        >>> body = get_sync(url, Policy.ALLOW_PRIVATE)
    """
    ...

async def get(url: str, policy: Optional[Policy] = None) -> str:
    """Fetch a URL asynchronously with full SSRF protection.
    
    Async version of get_sync(). Validates the initial URL and all
    redirects against the policy.
    
    Args:
        url: The URL to fetch.
        policy: Validation policy (defaults to PUBLIC_ONLY).
    
    Returns:
        Response body as string.
    
    Raises:
        SsrfBlocked: If any URL in the redirect chain is blocked.
        InvalidUrl: If a URL is malformed or uses forbidden scheme.
        DnsError: If DNS resolution fails.
        UrlJailError: On HTTP errors or too many redirects.
    
    Example:
        >>> import asyncio
        >>> from url_jail import get
        >>> 
        >>> async def main():
        ...     body = await get("https://api.example.com/data")
        ...     print(body)
        >>> 
        >>> asyncio.run(main())
    """
    ...
