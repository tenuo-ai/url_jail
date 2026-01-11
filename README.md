# url_jail

SSRF-safe URL validation for Rust and Python.

## The Problem

Your application fetches a user-provided URL:

```python
response = requests.get(user_url)
```

An attacker submits `http://169.254.169.254/latest/meta-data/iam/credentials`.

**Result**: Your AWS keys are in their inbox. Your S3 buckets are public. Your cloud bill is six figures.

This is Server-Side Request Forgery (SSRF), the vulnerability behind:
- [CVE-2024-0243](https://nvd.nist.gov/vuln/detail/CVE-2024-0243): LangChain RecursiveUrlLoader (CVSS 8.6)
- [CVE-2025-2828](https://nvd.nist.gov/vuln/detail/CVE-2025-2828): LangChain RequestsToolkit (CVSS 9.1)
- Capital One 2019 breach (100M+ records)

### "I'll just block 169.254.169.254"

Attackers encode IPs in ways your blocklist won't catch:

| Attack | Your Blocklist | url_jail |
|--------|----------------|----------|
| `http://0x7f000001/` (hex) | Passes | Blocked |
| `http://0177.0.0.1/` (octal) | Passes | Blocked |
| `http://2130706433/` (decimal) | Passes | Blocked |
| `http://127.1/` (short-form) | Passes | Blocked |
| `http://[::ffff:127.0.0.1]/` (IPv6-mapped) | Passes | Blocked |
| `http://metadata.google.internal/` | Maybe | Blocked |
| DNS rebinding | Passes | Blocked* |

\* When using `get_sync()` or the returned `Validated.ip` directly.

**url_jail validates after DNS resolution.** Encoding tricks don't work.

> **Note**: This library has not undergone a formal security audit. See [SECURITY.md](SECURITY.md).

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

## Error Handling

```rust
use url_jail::{validate_sync, Policy, Error};

match validate_sync("http://127.0.0.1/", Policy::PublicOnly) {
    Ok(v) => println!("Safe: {}", v.ip),
    Err(e) if e.is_blocked() => {
        // Security rejection (SSRF, hostname, redirect)
        println!("Blocked: {}", e);
    }
    Err(e) if e.is_retriable() => {
        // Temporary error (DNS, timeout) - retry with caution
        println!("Temporary: {}", e);
    }
    Err(e) => println!("Error: {}", e),
}
```

| Method | Returns `true` for |
|--------|-------------------|
| `is_blocked()` | `SsrfBlocked`, `HostnameBlocked`, `RedirectBlocked` |
| `is_retriable()` | `DnsError`, `Timeout`, `HttpError` |
| `url()` | Extracts the URL that caused the error |

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

