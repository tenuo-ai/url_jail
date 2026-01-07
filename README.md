# airlock

SSRF-safe URL validation for Rust and Python.

## The Problem

```python
response = requests.get(user_url)  # AWS credentials leaked via 169.254.169.254
```

## The Solution

**Python (recommended - full DNS rebinding protection):**
```python
from airlock import get_sync

body = get_sync(user_url)  # Safe! Validates URL and all redirects
```

**Rust:**
```rust
use airlock::{validate, Policy};
use reqwest::Client;

let v = validate("https://example.com/api", Policy::PublicOnly).await?;

// Use the validated IP with reqwest
let client = Client::builder()
    .resolve(&v.host, v.to_socket_addr())
    .build()?;

let response = client.get(&v.url).send().await?;
```

## Installation

```bash
pip install airlock
```

```toml
[dependencies]
airlock = "0.1"

# Enable fetch() for full redirect chain validation
airlock = { version = "0.1", features = ["fetch"] }
```

## Policies

| Policy | Allows | Blocks |
|--------|--------|--------|
| `PublicOnly` | Public IPs only | Private, loopback, link-local, metadata |
| `AllowPrivate` | Private + public | Loopback, metadata (for internal services) |

## What's Blocked

- Cloud metadata endpoints (AWS, GCP, Azure, Alibaba)
- Private IPs (10.x, 172.16.x, 192.168.x) with `PublicOnly`
- Loopback (127.x, ::1)
- Link-local (169.254.x, fe80::)
- IP encoding tricks: octal (`0177.0.0.1`), decimal (`2130706433`), hex (`0x7f000001`), short-form (`127.1`)
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`)

## License

MIT OR Apache-2.0
