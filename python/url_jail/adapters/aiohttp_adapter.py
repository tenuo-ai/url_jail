"""
SSRF-safe adapter for aiohttp.

Usage:
    from url_jail.adapters import safe_aiohttp_session
    
    async with safe_aiohttp_session() as session:
        async with session.get(user_url) as response:
            body = await response.text()
"""

from typing import Any, Optional
import socket

import aiohttp
from aiohttp import ClientSession, TCPConnector

from url_jail import Policy, validate


class UrlJailConnector(TCPConnector):
    """aiohttp connector that validates URLs via url_jail.
    
    This connector intercepts connection attempts and validates the target
    URL before allowing the connection. It also pins the connection to the
    validated IP address for DNS rebinding protection.
    """
    
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs):
        self.policy = policy
        super().__init__(**kwargs)
    
    async def _resolve_host(
        self,
        host: str,
        port: int,
        traces: Optional[Any] = None,
    ) -> list:
        """Override DNS resolution to use url_jail validated IP."""
        # Construct URL for validation
        url = f"http://{host}:{port}/"
        
        # Validate via url_jail
        validated = await validate(url, self.policy)
        
        # Return the validated IP as the only resolution result
        # This ensures we connect to the IP we validated
        return [
            {
                "hostname": host,
                "host": str(validated.ip),
                "port": port,
                "family": socket.AF_INET if "." in str(validated.ip) else socket.AF_INET6,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]


def safe_aiohttp_session(
    policy: Policy = Policy.PUBLIC_ONLY,
    **kwargs,
) -> ClientSession:
    """Create an aiohttp.ClientSession with SSRF protection.
    
    All requests made through this session will be validated against the
    url_jail blocklist and will connect to the validated IP address.
    
    Args:
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE)
        **kwargs: Additional arguments passed to aiohttp.ClientSession
    
    Returns:
        A configured aiohttp.ClientSession
    
    Example:
        >>> async with safe_aiohttp_session() as session:
        ...     async with session.get("https://example.com/api") as response:
        ...         body = await response.text()
    """
    connector = kwargs.pop("connector", None)
    if connector is not None:
        import warnings
        warnings.warn(
            "Custom connector provided and will be ignored. "
            "Use UrlJailConnector for SSRF protection.",
            UserWarning,
        )
    
    connector = UrlJailConnector(policy=policy)
    return ClientSession(connector=connector, **kwargs)

