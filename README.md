# url_jail

SSRF-safe URL validation for Rust and Python.

Helps mitigate SSRF vulnerabilities like [CVE-2024-0243](https://nvd.nist.gov/vuln/detail/CVE-2024-0243) and [CVE-2025-2828](https://nvd.nist.gov/vuln/detail/CVE-2025-2828) (LangChain SSRF).

> **Note**: This library has not undergone a formal security audit. See [SECURITY.md](SECURITY.md) for details.

## The Problem

```python
response = requests.get(user_url)  # AWS credentials leaked via 169.254.169.254
```

## Why url_jail?

String-based URL blocklists fail because attackers can encode IPs in unexpected ways:

| Attack | Naive Blocklist | url_jail |
|--------|-----------------|----------|
| `http://0x7f000001/` (hex IP) | PASS | BLOCKED |
| `http://0177.0.0.1/` (octal IP) | PASS | BLOCKED |
| `http://2130706433/` (decimal IP) | PASS | BLOCKED |
| `http://127.1/` (short-form) | PASS | BLOCKED |
| `http://[::ffff:127.0.0.1]/` (IPv6-mapped) | PASS | BLOCKED |
| `http://169.254.169.254/` | BLOCKED | BLOCKED |
| `http://metadata.google.internal/` | Maybe | BLOCKED |
| DNS rebinding (resolves to 127.0.0.1) | PASS | BLOCKED* |

\* When using `get_sync()` or the returned `Validated.ip` directly.

**url_jail validates after DNS resolution**, so encoding tricks and DNS rebinding don't work.

## The Solution

**Python (recommended):**
```python
from url_jail import get_sync

body = get_sync(user_url)  # Validates URL and all redirects
```

**Python (with existing HTTP client):**
```python
from url_jail.adapters import safe_session

s = safe_session()
response = s.get(user_url)  # SSRF-safe requests.Session
```

**Rust:**
```rust
use url_jail::{validate, Policy};
use reqwest::Client;

let v = validate("https://example.com/api", Policy::PublicOnly).await?;

let client = Client::builder()
    .resolve(&v.host, v.to_socket_addr())
    .build()?;

let response = client.get(&v.url).send().await?;
```

## Installation

```bash
pip install url_jail

# With HTTP client adapters
pip install url_jail[requests]  # or [httpx], [aiohttp], [urllib3], [all]
```

```toml
[dependencies]
url_jail = "0.2"

# Enable fetch() for redirect chain validation
url_jail = { version = "0.2", features = ["fetch"] }
```

## Policies

| Policy | Allows | Blocks |
|--------|--------|--------|
| `PublicOnly` | Public IPs only | Private, loopback, link-local, metadata |
| `AllowPrivate` | Private + public | Loopback, metadata (for internal services) |

## HTTP Client Adapters (Python)

```python
# requests
from url_jail.adapters import safe_session
s = safe_session()
response = s.get(user_url)

# httpx (sync)
from url_jail.adapters import safe_httpx_client
client = safe_httpx_client()
response = client.get(user_url)

# httpx (async)
from url_jail.adapters import safe_httpx_async_client
async with safe_httpx_async_client() as client:
    response = await client.get(user_url)

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

## Advanced: Custom Blocklist

```rust
use url_jail::{PolicyBuilder, Policy};

let policy = PolicyBuilder::new(Policy::AllowPrivate)
    .block_cidr("10.0.0.0/8")
    .block_host("*.internal.example.com")
    .build();
```

## What's Blocked

- Cloud metadata endpoints (AWS, GCP, Azure, Alibaba)
- Private IPs (10.x, 172.16.x, 192.168.x) with `PublicOnly`
- Loopback (127.x, ::1)
- Link-local (169.254.x, fe80::)
- IP encoding tricks: octal (`0177.0.0.1`), decimal (`2130706433`), hex (`0x7f000001`), short-form (`127.1`)
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`)

## Features

| Feature | Description |
|---------|-------------|
| `fetch` | `fetch()` / `get_sync()` with redirect validation |
| `tracing` | Logging for validation decisions |

## License

MIT OR Apache-2.0

