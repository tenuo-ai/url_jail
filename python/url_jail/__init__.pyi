"""Type stubs for url_jail.adapters"""

from typing import Optional
from url_jail import Policy

# Re-export Policy
__all__ = [
    "Policy",
    "safe_session",
    "safe_httpx_client",
    "safe_httpx_async_client",
    "safe_aiohttp_session",
    "safe_urllib3_pool",
]

def safe_session(policy: Policy = Policy.PUBLIC_ONLY) -> "requests.Session":
    """Create a requests.Session with SSRF protection."""
    ...

def safe_httpx_client(policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> "httpx.Client":
    """Create an httpx.Client with SSRF protection."""
    ...

def safe_httpx_async_client(policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> "httpx.AsyncClient":
    """Create an httpx.AsyncClient with SSRF protection."""
    ...

def safe_aiohttp_session(policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> "aiohttp.ClientSession":
    """Create an aiohttp.ClientSession with SSRF protection."""
    ...

def safe_urllib3_pool(policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> "urllib3.PoolManager":
    """Create a urllib3.PoolManager with SSRF protection."""
    ...


# Adapter classes
class UrlJailAdapter:
    """requests HTTPAdapter with SSRF protection."""
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> None: ...

class UrlJailTransport:
    """httpx transport with SSRF protection."""
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> None: ...

class UrlJailAsyncTransport:
    """httpx async transport with SSRF protection."""
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> None: ...

class UrlJailConnector:
    """aiohttp connector with SSRF protection."""
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> None: ...

class SafeClientSession:
    """aiohttp ClientSession with SSRF protection."""
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> None: ...

class SafePoolManager:
    """urllib3 PoolManager with SSRF protection."""
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs) -> None: ...
