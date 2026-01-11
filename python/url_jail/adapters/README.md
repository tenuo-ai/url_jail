# url_jail Python HTTP Client Adapters

SSRF-safe wrappers for popular Python HTTP clients.

## Quick Start

```python
# requests
from url_jail.adapters import safe_session
s = safe_session()
response = s.get(user_url)

# httpx (recommended for HTTPS)
from url_jail.adapters import safe_httpx_client
client = safe_httpx_client()
response = client.get(user_url)

# aiohttp
from url_jail.adapters import safe_aiohttp_session
async with safe_aiohttp_session() as session:
    async with session.get(user_url) as response:
        body = await response.text()

# urllib3
from url_jail.adapters import safe_urllib3_pool
pool = safe_urllib3_pool()
response = pool.request("GET", user_url)
```

## HTTPS and DNS Rebinding

### The Issue

DNS rebinding attacks exploit the time gap between validation and connection:

```
1. validate("https://evil.com") -> DNS returns 93.184.216.34 (safe)
2. HTTP client connects to "evil.com" -> Does its own DNS lookup
3. Attacker's DNS now returns 127.0.0.1 -> Connection goes to localhost!
```

### How Adapters Handle It

| Adapter | HTTP | HTTPS | Full DNS Rebinding Protection |
|---------|------|-------|-------------------------------|
| `safe_httpx_client` | Yes | Yes | Yes (uses SNI extension) |
| `safe_httpx_async_client` | Yes | Yes | Yes (uses SNI extension) |
| `safe_aiohttp_session` | Yes | Yes | Yes (overrides resolver) |
| `safe_session` (requests) | Yes | Validates only | No* |
| `safe_urllib3_pool` | Yes | Validates only | No* |

*For HTTPS, requests/urllib3 validate the URL but cannot pin to the validated IP
without breaking TLS certificate validation. There's a small window where DNS
could change between validation and connection.

### Recommendation

For maximum security with HTTPS user-provided URLs:

```python
# Best: Use url_jail's built-in fetch (validates every redirect too)
from url_jail import get_sync
body = get_sync(user_url)

# Good: Use httpx adapter (proper SNI handling)
from url_jail.adapters import safe_httpx_client
client = safe_httpx_client()
response = client.get(user_url)

# Acceptable: requests adapter (see "In Practice" below)
from url_jail.adapters import safe_session
s = safe_session()
response = s.get(user_url)
```

## In Practice: Microservices

For most microservice architectures, the HTTPS limitation is low-risk:

### Why It's Usually Fine

1. **Internal services use HTTP**: Most Kubernetes/Docker services communicate
   over HTTP within the cluster. TLS termination happens at the ingress/load
   balancer or service mesh sidecar.

2. **Short rebinding window**: The gap between validation and connection is
   typically <100ms. An attacker needs to:
   - Control DNS for the target domain
   - Predict when your service will make the request
   - Change DNS response in that exact window

3. **Service mesh handles TLS**: If you use Istio, Linkerd, or similar, mTLS
   is handled at the sidecar level. Your app sees HTTP, not HTTPS.

4. **Outbound traffic is often proxied**: Many clusters route external traffic
   through a proxy, which does its own DNS resolution.

### When to Care More

Use `get_sync()` or httpx adapter when:

- Fetching URLs from **untrusted users** (e.g., webhook URLs, RSS feeds)
- The attacker **controls the domain** being fetched
- You're in a **high-security environment** (financial, healthcare)
- You're fetching from **known-hostile sources** (security scanning)

### Typical Microservice Setup

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Kubernetes Cluster                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐    HTTP     ┌─────────┐    HTTP    ┌─────────┐   │
│   │ Ingress │ ──────────► │ Service │ ─────────► │ Service │   │
│   │  (TLS)  │             │    A    │            │    B    │   │
│   └─────────┘             └─────────┘            └─────────┘   │
│        ▲                       │                               │
│        │                       │ User-provided URL             │
│     HTTPS                      ▼                               │
│        │                 ┌───────────┐                         │
│   External               │ url_jail  │ ◄── Validates here      │
│   Traffic                │ safe_*()  │                         │
│                          └───────────┘                         │
│                                │                               │
│                                ▼                               │
│                          ┌───────────┐                         │
│                          │  Egress   │ ◄── Often HTTP to proxy │
│                          │  Proxy    │                         │
│                          └───────────┘                         │
│                                │                               │
└────────────────────────────────┼───────────────────────────────┘
                                 │ HTTPS
                                 ▼
                            External API
```

In this setup:
- User-provided URLs are validated by url_jail
- Even if using `safe_session()` (requests), the egress proxy often does its
  own DNS resolution, adding another layer
- Internal service-to-service calls are HTTP (not user-controlled URLs)

## Policy Configuration

All adapters accept a `policy` parameter:

```python
from url_jail import Policy
from url_jail.adapters import safe_session

# Default: Block private IPs (recommended for user-provided URLs)
s = safe_session(policy=Policy.PUBLIC_ONLY)

# Allow private IPs (for internal service calls with user-provided paths)
s = safe_session(policy=Policy.ALLOW_PRIVATE)
```

## Error Handling

All adapters raise url_jail exceptions:

```python
from url_jail import SsrfBlocked, HostnameBlocked, InvalidUrl, DnsError
from url_jail.adapters import safe_session

s = safe_session()
try:
    response = s.get(user_url)
except SsrfBlocked as e:
    # IP was in blocked range (private, loopback, metadata)
    log.warning(f"SSRF blocked: {e}")
except HostnameBlocked as e:
    # Hostname matched blocked pattern (metadata.google.internal, etc.)
    log.warning(f"Hostname blocked: {e}")
except InvalidUrl as e:
    # URL was malformed or used blocked scheme
    log.warning(f"Invalid URL: {e}")
except DnsError as e:
    # DNS resolution failed
    log.warning(f"DNS error: {e}")
```
