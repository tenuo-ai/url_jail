# url_jail

SSRF-safe URL validation for Rust and Python.

Helps mitigate SSRF vulnerabilities like [CVE-2024-0243](https://nvd.nist.gov/vuln/detail/CVE-2024-0243) and [CVE-2025-2828](https://nvd.nist.gov/vuln/detail/CVE-2025-2828) (LangChain SSRF).

> **Note**: This library has not undergone a formal security audit. See [SECURITY.md](SECURITY.md) for details.

## The Problem

```python
response = requests.get(user_url)  # AWS credentials leaked via 169.254.169.254
```

## The Solution

**Python (recommended):**
```python
from url_jail import get_sync

body = get_sync(user_url)  # Validates URL and all redirects
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
```

```toml
[dependencies]
url_jail = "0.1"

# Enable fetch() for redirect chain validation
url_jail = { version = "0.1", features = ["fetch"] }
```

## Policies

| Policy | Allows | Blocks |
|--------|--------|--------|
| `PublicOnly` | Public IPs only | Private, loopback, link-local, metadata |
| `AllowPrivate` | Private + public | Loopback, metadata (for internal services) |

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
