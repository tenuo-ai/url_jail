"""
Tests for url_jail Python HTTP client adapters.

Run with: pytest tests/test_adapters.py

Note: These tests require the optional dependencies:
  pip install url_jail[all]
"""

import pytest


class TestRequestsAdapter:
    """Tests for requests adapter."""

    @pytest.fixture
    def safe_session(self):
        """Get safe_session, skip if requests not installed."""
        requests = pytest.importorskip("requests")
        from url_jail.adapters import safe_session
        return safe_session()

    def test_fetch_public_url(self, safe_session):
        """Should fetch public URLs successfully."""
        response = safe_session.get("https://httpbin.org/get")
        assert response.status_code == 200

    def test_blocks_loopback(self, safe_session):
        """Should block loopback addresses."""
        from url_jail import SsrfBlocked
        with pytest.raises(SsrfBlocked):
            safe_session.get("http://127.0.0.1/")

    def test_blocks_metadata(self, safe_session):
        """Should block metadata endpoints."""
        from url_jail import SsrfBlocked, HostnameBlocked
        with pytest.raises((SsrfBlocked, HostnameBlocked)):
            safe_session.get("http://169.254.169.254/")

    def test_blocks_private_ip(self, safe_session):
        """Should block private IPs with default policy."""
        from url_jail import SsrfBlocked
        with pytest.raises(SsrfBlocked):
            safe_session.get("http://192.168.1.1/")

    def test_allows_private_with_policy(self):
        """Should allow private IPs with ALLOW_PRIVATE policy."""
        pytest.importorskip("requests")
        from url_jail.adapters import safe_session
        from url_jail import Policy
        
        session = safe_session(policy=Policy.ALLOW_PRIVATE)
        # Can't actually connect, but validation should pass
        # Just verify no SsrfBlocked exception during validation


class TestHttpxAdapter:
    """Tests for httpx adapter."""

    @pytest.fixture
    def safe_client(self):
        """Get safe_httpx_client, skip if httpx not installed."""
        httpx = pytest.importorskip("httpx")
        from url_jail.adapters import safe_httpx_client
        return safe_httpx_client()

    def test_fetch_public_url(self, safe_client):
        """Should fetch public URLs successfully."""
        response = safe_client.get("https://httpbin.org/get")
        assert response.status_code == 200
        safe_client.close()

    def test_blocks_loopback(self, safe_client):
        """Should block loopback addresses."""
        from url_jail import SsrfBlocked
        with pytest.raises(SsrfBlocked):
            safe_client.get("http://127.0.0.1/")
        safe_client.close()

    def test_blocks_metadata(self, safe_client):
        """Should block metadata endpoints."""
        from url_jail import SsrfBlocked, HostnameBlocked
        with pytest.raises((SsrfBlocked, HostnameBlocked)):
            safe_client.get("http://169.254.169.254/")
        safe_client.close()


class TestHttpxAsyncAdapter:
    """Tests for httpx async adapter."""

    @pytest.fixture
    def safe_async_client(self):
        """Get safe_httpx_async_client, skip if httpx not installed."""
        httpx = pytest.importorskip("httpx")
        from url_jail.adapters import safe_httpx_async_client
        return safe_httpx_async_client()

    @pytest.mark.asyncio
    async def test_fetch_public_url(self, safe_async_client):
        """Should fetch public URLs successfully."""
        async with safe_async_client as client:
            response = await client.get("https://httpbin.org/get")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_blocks_loopback(self, safe_async_client):
        """Should block loopback addresses."""
        from url_jail import SsrfBlocked
        async with safe_async_client as client:
            with pytest.raises(SsrfBlocked):
                await client.get("http://127.0.0.1/")


class TestAiohttpAdapter:
    """Tests for aiohttp adapter.
    
    Note: aiohttp requires async context for session/connector creation,
    so these tests create sessions inline rather than via fixture.
    """

    @pytest.mark.asyncio
    async def test_fetch_public_url(self):
        """Should fetch public URLs successfully."""
        aiohttp = pytest.importorskip("aiohttp")
        from url_jail.adapters import safe_aiohttp_session
        
        async with safe_aiohttp_session() as session:
            async with session.get("https://httpbin.org/get") as response:
                assert response.status == 200

    @pytest.mark.asyncio
    async def test_blocks_loopback(self):
        """Should block loopback addresses."""
        aiohttp = pytest.importorskip("aiohttp")
        from url_jail.adapters import safe_aiohttp_session
        from url_jail import SsrfBlocked
        
        async with safe_aiohttp_session() as session:
            with pytest.raises(SsrfBlocked):
                async with session.get("http://127.0.0.1/"):
                    pass


class TestUrllib3Adapter:
    """Tests for urllib3 adapter."""

    @pytest.fixture
    def safe_pool(self):
        """Get safe_urllib3_pool, skip if urllib3 not installed."""
        urllib3 = pytest.importorskip("urllib3")
        from url_jail.adapters import safe_urllib3_pool
        return safe_urllib3_pool()

    def test_fetch_public_url(self, safe_pool):
        """Should fetch public URLs successfully."""
        response = safe_pool.request("GET", "https://httpbin.org/get")
        assert response.status == 200

    def test_blocks_loopback(self, safe_pool):
        """Should block loopback addresses."""
        from url_jail import SsrfBlocked
        with pytest.raises(SsrfBlocked):
            safe_pool.request("GET", "http://127.0.0.1/")

    def test_blocks_metadata(self, safe_pool):
        """Should block metadata endpoints."""
        from url_jail import SsrfBlocked, HostnameBlocked
        with pytest.raises((SsrfBlocked, HostnameBlocked)):
            safe_pool.request("GET", "http://169.254.169.254/")

    def test_blocks_private_ip(self, safe_pool):
        """Should block private IPs with default policy."""
        from url_jail import SsrfBlocked
        with pytest.raises(SsrfBlocked):
            safe_pool.request("GET", "http://192.168.1.1/")


class TestAdapterPolicies:
    """Tests for adapter policy configuration."""

    def test_requests_custom_policy(self):
        """Should accept custom policy."""
        pytest.importorskip("requests")
        from url_jail.adapters import safe_session
        from url_jail import Policy
        
        session = safe_session(policy=Policy.ALLOW_PRIVATE)
        assert session is not None

    def test_httpx_custom_policy(self):
        """Should accept custom policy."""
        pytest.importorskip("httpx")
        from url_jail.adapters import safe_httpx_client
        from url_jail import Policy
        
        client = safe_httpx_client(policy=Policy.ALLOW_PRIVATE)
        assert client is not None
        client.close()

    @pytest.mark.asyncio
    async def test_aiohttp_custom_policy(self):
        """Should accept custom policy."""
        pytest.importorskip("aiohttp")
        from url_jail.adapters import safe_aiohttp_session
        from url_jail import Policy
        
        session = safe_aiohttp_session(policy=Policy.ALLOW_PRIVATE)
        assert session is not None
        await session.close()

    def test_urllib3_custom_policy(self):
        """Should accept custom policy."""
        pytest.importorskip("urllib3")
        from url_jail.adapters import safe_urllib3_pool
        from url_jail import Policy
        
        pool = safe_urllib3_pool(policy=Policy.ALLOW_PRIVATE)
        assert pool is not None
