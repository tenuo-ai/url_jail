"""
SSRF-safe adapter for httpx.

Usage:
    from url_jail.adapters import safe_httpx_client, safe_httpx_async_client
    
    # Sync
    client = safe_httpx_client()
    response = client.get(user_url)
    
    # Async
    async with safe_httpx_async_client() as client:
        response = await client.get(user_url)
"""

from typing import Optional

import httpx

from url_jail import Policy, validate_sync, validate


class UrlJailTransport(httpx.BaseTransport):
    """httpx transport that validates URLs via url_jail.
    
    This transport wraps the default HTTPTransport and validates all URLs
    before allowing them through.
    """
    
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs):
        self.policy = policy
        self._transport = httpx.HTTPTransport(**kwargs)
    
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Validate URL before handling the request."""
        # Validate the URL
        validated = validate_sync(str(request.url), self.policy)
        
        # Create a new request with resolver override pointing to validated IP
        # This provides DNS rebinding protection
        extensions = dict(request.extensions)
        extensions["sni_hostname"] = validated.host
        
        # Modify the URL to use the validated IP while keeping the Host header
        ip_url = request.url.copy_with(host=str(validated.ip))
        
        modified_request = httpx.Request(
            method=request.method,
            url=ip_url,
            headers=request.headers,
            content=request.content,
            extensions=extensions,
        )
        
        return self._transport.handle_request(modified_request)
    
    def close(self) -> None:
        self._transport.close()


class UrlJailAsyncTransport(httpx.AsyncBaseTransport):
    """Async httpx transport that validates URLs via url_jail."""
    
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs):
        self.policy = policy
        self._transport = httpx.AsyncHTTPTransport(**kwargs)
    
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Validate URL before handling the request."""
        # Validate the URL (async)
        validated = await validate(str(request.url), self.policy)
        
        # Create request with validated IP
        extensions = dict(request.extensions)
        extensions["sni_hostname"] = validated.host
        
        ip_url = request.url.copy_with(host=str(validated.ip))
        
        modified_request = httpx.Request(
            method=request.method,
            url=ip_url,
            headers=request.headers,
            content=request.content,
            extensions=extensions,
        )
        
        return await self._transport.handle_async_request(modified_request)
    
    async def aclose(self) -> None:
        await self._transport.aclose()


def safe_httpx_client(
    policy: Policy = Policy.PUBLIC_ONLY,
    **kwargs,
) -> httpx.Client:
    """Create an httpx.Client with SSRF protection.
    
    All requests made through this client will be validated against the
    url_jail blocklist and will connect to the validated IP address.
    
    Args:
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE)
        **kwargs: Additional arguments passed to httpx.Client
    
    Returns:
        A configured httpx.Client
    
    Example:
        >>> client = safe_httpx_client()
        >>> response = client.get("https://example.com/api")
    """
    transport = UrlJailTransport(policy=policy)
    return httpx.Client(transport=transport, **kwargs)


def safe_httpx_async_client(
    policy: Policy = Policy.PUBLIC_ONLY,
    **kwargs,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with SSRF protection.
    
    Args:
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE)
        **kwargs: Additional arguments passed to httpx.AsyncClient
    
    Returns:
        A configured httpx.AsyncClient
    
    Example:
        >>> async with safe_httpx_async_client() as client:
        ...     response = await client.get("https://example.com/api")
    """
    transport = UrlJailAsyncTransport(policy=policy)
    return httpx.AsyncClient(transport=transport, **kwargs)
