"""
url_jail HTTP Client Adapters

SSRF-safe adapters for popular Python HTTP clients.

HTTPS Note:
    For HTTPS URLs, httpx and aiohttp adapters provide full DNS rebinding
    protection by pinning connections to the validated IP. The requests and
    urllib3 adapters validate URLs but cannot pin HTTPS connections without
    breaking TLS certificate validation.

    For maximum security with user-provided HTTPS URLs, use:
    - url_jail.get_sync() (built-in, validates redirects too)
    - safe_httpx_client() (proper SNI handling)

    In practice, the requests/urllib3 HTTPS limitation is low-risk for most
    microservice architectures. See adapters/README.md for details.

Usage:
    # requests (good for HTTP, acceptable for HTTPS)
    from url_jail.adapters import safe_session
    s = safe_session()
    response = s.get(user_url)

    # httpx - recommended for HTTPS (full DNS rebinding protection)
    from url_jail.adapters import safe_httpx_client
    client = safe_httpx_client()
    response = client.get(user_url)

    # httpx async
    from url_jail.adapters import safe_httpx_async_client
    async with safe_httpx_async_client() as client:
        response = await client.get(user_url)

    # aiohttp (full DNS rebinding protection)
    from url_jail.adapters import safe_aiohttp_session
    async with safe_aiohttp_session() as session:
        async with session.get(user_url) as response:
            body = await response.text()

    # urllib3 (good for HTTP, acceptable for HTTPS)
    from url_jail.adapters import safe_urllib3_pool
    pool = safe_urllib3_pool()
    response = pool.request("GET", user_url)
"""

from url_jail import Policy

# Lazy imports to avoid requiring all client libraries
__all__ = [
    "Policy",
    "safe_session",
    "safe_httpx_client",
    "safe_httpx_async_client",
    "safe_aiohttp_session",
    "safe_urllib3_pool",
]


def safe_session(policy: Policy = Policy.PUBLIC_ONLY):
    """Create a requests.Session with SSRF protection.
    
    Requires: pip install requests
    """
    from .requests_adapter import safe_session as _safe_session
    return _safe_session(policy)


def safe_httpx_client(policy: Policy = Policy.PUBLIC_ONLY):
    """Create an httpx.Client with SSRF protection.
    
    Requires: pip install httpx
    """
    from .httpx_adapter import safe_httpx_client as _safe_httpx_client
    return _safe_httpx_client(policy)


def safe_httpx_async_client(policy: Policy = Policy.PUBLIC_ONLY):
    """Create an httpx.AsyncClient with SSRF protection.
    
    Requires: pip install httpx
    """
    from .httpx_adapter import safe_httpx_async_client as _safe_httpx_async_client
    return _safe_httpx_async_client(policy)


def safe_aiohttp_session(policy: Policy = Policy.PUBLIC_ONLY):
    """Create an aiohttp.ClientSession with SSRF protection.
    
    Requires: pip install aiohttp
    """
    from .aiohttp_adapter import safe_aiohttp_session as _safe_aiohttp_session
    return _safe_aiohttp_session(policy)


def safe_urllib3_pool(policy: Policy = Policy.PUBLIC_ONLY):
    """Create a urllib3.PoolManager with SSRF protection.
    
    Requires: pip install urllib3
    """
    from .urllib3_adapter import safe_urllib3_pool as _safe_urllib3_pool
    return _safe_urllib3_pool(policy)

