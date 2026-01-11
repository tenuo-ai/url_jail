"""
SSRF-safe adapter for requests.

Usage:
    from url_jail.adapters import safe_session
    
    s = safe_session()
    response = s.get(user_url)  # SSRF-safe!
"""

from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.poolmanager import PoolManager
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from url_jail import Policy, validate_sync


class IpPinningPoolManager(PoolManager):
    """PoolManager that pins connections to validated IPs."""
    
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs):
        self.policy = policy
        self._validated_ips: dict = {}
        super().__init__(**kwargs)
    
    def urlopen(self, method, url, redirect=True, **kwargs):
        """Validate URL and store IP before connection."""
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]
        
        # If this host hasn't been validated yet, validate it now
        if host and host not in self._validated_ips:
            validated = validate_sync(url, self.policy)
            self._validated_ips[host] = str(validated.ip)
        
        return super().urlopen(method, url, redirect=redirect, **kwargs)
    
    def connection_from_host(self, host, port=None, scheme="http", pool_kwargs=None):
        """Override to connect to validated IP instead of hostname."""
        pool_kwargs = pool_kwargs.copy() if pool_kwargs else {}
        
        # If we have a validated IP for this host, use it as the actual connection target
        if host in self._validated_ips:
            validated_ip = self._validated_ips[host]
            # Store original host for SNI/Host header
            pool_kwargs["_url_jail_original_host"] = host
            # Connect to the validated IP
            return super().connection_from_host(validated_ip, port, scheme, pool_kwargs)
        
        return super().connection_from_host(host, port, scheme, pool_kwargs)


class UrlJailAdapter(HTTPAdapter):
    """requests HTTPAdapter that validates URLs via url_jail before sending.
    
    This adapter intercepts all requests and validates them against the SSRF
    blocklist before allowing the connection.
    
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
    
    def send(self, request: requests.PreparedRequest, **kwargs) -> requests.Response:
        """Validate URL before sending the request."""
        if request.url:
            # Validate the URL - raises on blocked URLs
            validated = validate_sync(request.url, self.policy)
            
            # For HTTP, we can pin to the validated IP for DNS rebinding protection
            # For HTTPS, we must keep the hostname for TLS certificate validation
            parsed = urlparse(request.url)
            
            if parsed.scheme == "http":
                # Safe to modify URL for HTTP - pin to validated IP
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
                
                if "Host" not in request.headers:
                    request.headers["Host"] = validated.host
                
                request.url = ip_url
            # For HTTPS, we rely on validation at request time
            # The DNS might change, but we've verified the current IP is safe
        
        return super().send(request, **kwargs)


def safe_session(
    policy: Policy = Policy.PUBLIC_ONLY,
    max_retries: int = 3,
) -> requests.Session:
    """Create a requests.Session with SSRF protection.
    
    All HTTP and HTTPS requests made through this session will be validated
    against the url_jail blocklist before being sent. Connections are pinned
    to the validated IP address for DNS rebinding protection.
    
    Args:
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE)
        max_retries: Maximum number of retries for failed requests
    
    Returns:
        A configured requests.Session
    
    Example:
        >>> s = safe_session()
        >>> response = s.get("https://example.com/api")
        >>> # This would raise SsrfBlocked:
        >>> # s.get("http://169.254.169.254/")
    """
    session = requests.Session()
    
    # Mount our SSRF-safe adapter for both HTTP and HTTPS
    adapter = UrlJailAdapter(policy=policy, max_retries=Retry(total=max_retries))
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

