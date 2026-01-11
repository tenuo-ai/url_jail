"""
SSRF-safe adapter for urllib3.

Usage:
    from url_jail.adapters import safe_urllib3_pool
    
    pool = safe_urllib3_pool()
    response = pool.request("GET", "https://example.com/api")
    print(response.data)
"""

from typing import Optional
from urllib.parse import urlparse, urlunparse

import urllib3
from urllib3.poolmanager import PoolManager

from url_jail import Policy, validate_sync


class SafePoolManager(PoolManager):
    """urllib3 PoolManager with SSRF protection.
    
    This pool manager validates all URLs via url_jail before allowing
    connections.
    
    HTTP vs HTTPS:
        - HTTP: Full protection. Connections are pinned to the validated IP,
          preventing DNS rebinding attacks.
        - HTTPS: Validates URL at request time, but cannot pin to the validated
          IP without breaking TLS certificate validation. There is a small
          window (~100ms) where DNS could change between validation and
          connection.
    
    For maximum HTTPS security, use url_jail.get_sync() or safe_httpx_client().
    In practice, the HTTPS limitation is low-risk for most microservice
    architectures (see adapters/README.md for details).
    """
    
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs):
        self.policy = policy
        super().__init__(**kwargs)
    
    def urlopen(
        self,
        method: str,
        url: str,
        redirect: bool = True,
        **kwargs,
    ):
        """Validate URL and pin to IP before making the request."""
        # Validate the URL
        validated = validate_sync(url, self.policy)
        
        parsed = urlparse(url)
        
        # For HTTP, we can pin to the validated IP for DNS rebinding protection
        # For HTTPS, we must keep the hostname for TLS certificate validation
        if parsed.scheme == "http":
            ip_netloc = str(validated.ip)
            if parsed.port:
                ip_netloc = f"{validated.ip}:{parsed.port}"
            
            ip_url = urlunparse((
                parsed.scheme,
                ip_netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))
            
            # Set Host header to original hostname
            headers = kwargs.get("headers", {})
            if isinstance(headers, dict):
                headers = headers.copy()
            else:
                headers = dict(headers) if headers else {}
            
            if "Host" not in headers and "host" not in headers:
                headers["Host"] = validated.host
            
            kwargs["headers"] = headers
            url = ip_url
        
        # Make the request
        return super().urlopen(method, url, redirect=redirect, **kwargs)


def safe_urllib3_pool(
    policy: Policy = Policy.PUBLIC_ONLY,
    **kwargs,
) -> SafePoolManager:
    """Create a urllib3.PoolManager with SSRF protection.
    
    All requests made through this pool will be validated against the
    url_jail blocklist before being sent. HTTP requests are pinned to
    the validated IP for DNS rebinding protection.
    
    Args:
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE)
        **kwargs: Additional arguments passed to urllib3.PoolManager
    
    Returns:
        A configured urllib3.PoolManager
    
    Example:
        >>> pool = safe_urllib3_pool()
        >>> response = pool.request("GET", "https://example.com/api")
        >>> print(response.status)
    """
    return SafePoolManager(policy=policy, **kwargs)

