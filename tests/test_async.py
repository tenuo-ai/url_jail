"""
Async tests for url_jail Python bindings.

Run with: pytest tests/test_async.py
"""

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"


class TestValidateAsync:
    """Tests for async validate function."""

    @pytest.mark.asyncio
    async def test_validate_public_url(self):
        """Public URLs should validate successfully."""
        from url_jail import validate, Policy
        
        result = await validate("https://example.com/", Policy.PUBLIC_ONLY)
        assert result.host == "example.com"
        assert result.port == 443

    @pytest.mark.asyncio
    async def test_validate_blocks_loopback(self):
        """Loopback should be blocked."""
        from url_jail import validate, Policy, SsrfBlocked
        
        with pytest.raises(SsrfBlocked):
            await validate("http://127.0.0.1/", Policy.PUBLIC_ONLY)

    @pytest.mark.asyncio
    async def test_validate_blocks_metadata(self):
        """Metadata endpoints should be blocked."""
        from url_jail import validate, Policy, SsrfBlocked
        
        with pytest.raises(SsrfBlocked):
            await validate("http://169.254.169.254/", Policy.PUBLIC_ONLY)


class TestGetAsync:
    """Tests for async get function (requires fetch feature)."""

    @pytest.mark.asyncio
    async def test_get_public_url(self):
        """Should fetch public URLs."""
        try:
            from url_jail import get, Policy
            body = await get("https://httpbin.org/robots.txt")
            assert "User-agent" in body or len(body) > 0
        except ImportError:
            pytest.skip("fetch feature not enabled")

    @pytest.mark.asyncio
    async def test_get_blocks_loopback(self):
        """Should block loopback."""
        try:
            from url_jail import get, Policy, SsrfBlocked
            with pytest.raises(SsrfBlocked):
                await get("http://127.0.0.1/")
        except ImportError:
            pytest.skip("fetch feature not enabled")


class TestGetSync:
    """Tests for sync get function (requires fetch feature)."""

    def test_get_sync_public_url(self):
        """Should fetch public URLs."""
        try:
            from url_jail import get_sync
            body = get_sync("https://httpbin.org/robots.txt")
            assert len(body) > 0
        except ImportError:
            pytest.skip("fetch feature not enabled")

    def test_get_sync_blocks_loopback(self):
        """Should block loopback."""
        try:
            from url_jail import get_sync, SsrfBlocked
            with pytest.raises(SsrfBlocked):
                get_sync("http://127.0.0.1/")
        except ImportError:
            pytest.skip("fetch feature not enabled")

    def test_get_sync_blocks_metadata(self):
        """Should block metadata."""
        try:
            from url_jail import get_sync, SsrfBlocked
            with pytest.raises(SsrfBlocked):
                get_sync("http://169.254.169.254/")
        except ImportError:
            pytest.skip("fetch feature not enabled")
