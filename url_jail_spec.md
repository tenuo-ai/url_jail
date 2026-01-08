# Specification: `url_jail`

**Version:** 0.2.0

**Tagline:** SSRF-safe URL validation for Rust and Python.

---

## 1. Overview

`url_jail` validates URLs and resolved IPs to prevent Server-Side Request Forgery (SSRF). It provides both validation-only APIs and full fetch helpers with redirect chain validation.

Like `path_jail` prevents path traversal and `safe_unzip` prevents Zip Slip, `url_jail` prevents SSRF. Same philosophy: security by default, minimal API, zero configuration required.

---

## 2. The Problem

Standard HTTP clients trust DNS blindly:

```python
# Agent receives URL from untrusted input
url = "http://169.254.169.254/latest/meta-data/iam/credentials"
response = requests.get(url)  # 💀 AWS credentials leaked
```

SSRF attacks exploit this to:
- Steal cloud credentials (AWS/GCP/Azure metadata endpoints)
- Scan internal networks
- Access localhost services
- Bypass firewalls

---

## 3. The Solution

**Python (recommended - full DNS rebinding protection):**
```python
from url_jail import get_sync

body = get_sync(user_url)  # Safe! Validates URL and all redirects
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

---

## 4. Threat Model

| Threat | Attack | Defense |
|--------|--------|---------|
| **Cloud metadata theft** | Fetch `169.254.169.254` | Metadata IPs blocked |
| **Internal network scan** | Fetch `192.168.1.1` | Private IPs blocked |
| **Localhost access** | Fetch `127.0.0.1` | Loopback blocked |
| **DNS rebinding** | DNS returns `1.2.3.4`, then `127.0.0.1` | Returns verified IP to connect to |
| **Redirect bypass** | `https://safe.com` → `http://127.0.0.1` | `fetch()` validates each hop |
| **IPv6 bypass** | `::ffff:127.0.0.1` | All IPv6 variants normalized |
| **Hostname tricks** | `LOCALHOST`, `127.0.0.1.` | Hostname normalized before resolution |
| **IP encoding bypass** | `0177.0.0.1`, `0x7f000001`, `127.1` | Octal/hex/short-form rejected |

---

## 5. Rust API

### Core Functions

```rust
use url_jail::{validate, validate_sync, validate_with_options, Policy, ValidateOptions, Validated};

// Async validation (requires tokio runtime)
let result: Validated = validate("https://example.com/path", Policy::PublicOnly).await?;

// Sync validation (blocks current thread)
let result: Validated = validate_sync("https://example.com/path", Policy::PublicOnly)?;

// With custom timeout
let opts = ValidateOptions { dns_timeout: Duration::from_secs(10) };
let result = validate_with_options(url, Policy::PublicOnly, opts).await?;
```

### Fetch with Redirect Validation (feature = "fetch")

```rust
use url_jail::{fetch, fetch_sync, FetchResult};

// Full redirect chain validation - DNS rebinding safe
let result: FetchResult = fetch("https://example.com/", Policy::PublicOnly).await?;
println!("Final response: {:?}", result.response);
println!("Redirect chain: {:?}", result.chain);
```

### Validated Result

```rust
pub struct Validated {
    pub ip: IpAddr,      // The verified IP address to connect to
    pub host: String,    // Original hostname (use for Host header / SNI)
    pub port: u16,       // Port number
    pub url: String,     // Full URL (normalized)
    pub https: bool,     // Whether HTTPS
}

impl Validated {
    pub fn to_socket_addr(&self) -> SocketAddr;
}
```

### Policy

```rust
pub enum Policy {
    /// Block private IPs, loopback, link-local, metadata endpoints.
    PublicOnly,
    
    /// Allow private IPs, but still block loopback and metadata.
    AllowPrivate,
}
```

### Custom Policy (PolicyBuilder)

```rust
use url_jail::{PolicyBuilder, Policy, CustomPolicy};

let policy: CustomPolicy = PolicyBuilder::new(Policy::AllowPrivate)
    .block_cidr("10.0.0.0/8")         // Block specific internal range
    .allow_cidr("192.168.1.0/24")     // Allow specific subnet
    .block_host("*.internal.example.com")  // Block hostname pattern
    .build();

assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_err());
assert!(policy.is_ip_allowed("192.168.1.50".parse().unwrap()).is_ok());
```

---

## 6. Python API

### Fetch (Recommended)

```python
from url_jail import get, get_sync

# Async (full redirect chain validation)
body = await get("https://example.com/api")

# Sync
body = get_sync("https://example.com/api")

# With explicit policy (default is PUBLIC_ONLY)
body = get_sync(url, Policy.ALLOW_PRIVATE)
```

### Validation Only

```python
from url_jail import validate, validate_sync, Policy

# Async validation
result = await validate("https://example.com", Policy.PUBLIC_ONLY)

# Sync validation  
result = validate_sync("https://example.com", Policy.PUBLIC_ONLY)

# Result fields
print(result.ip)      # "93.184.216.34"
print(result.host)    # "example.com"
print(result.port)    # 443
print(result.https)   # True
```

### Error Handling

```python
from url_jail import get_sync, UrlJailError, SsrfBlocked, InvalidUrl, DnsError

try:
    body = get_sync(user_input)
except SsrfBlocked as e:
    print(f"Blocked: {e}")
except InvalidUrl as e:
    print(f"Bad URL: {e}")
except DnsError as e:
    print(f"DNS failed: {e}")
except UrlJailError as e:
    print(f"Error: {e}")  # Timeout, TooManyRedirects, HttpError
```

### Custom Policy (Python)

```python
from url_jail import PolicyBuilder, Policy, validate_custom_sync

policy = PolicyBuilder(Policy.ALLOW_PRIVATE) \
    .block_cidr("10.0.0.0/8") \
    .block_host("*.internal.example.com") \
    .build()

result = validate_custom_sync("https://example.com/", policy)
```

---

## 7. What's Blocked

### Hostname Blocklist (Checked Before DNS)

| Hostname | Description |
|----------|-------------|
| `metadata.google.internal` | GCP metadata |
| `metadata.goog` | GCP alternate |
| `metadata.azure.internal` | Azure metadata |
| `169.254.169.254` | Literal IP as hostname |
| `instance-data` | AWS alternate (EC2-Classic) |

### IP Blocklist - Always Blocked (Both Policies)

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | Loopback (IPv4) |
| `::1` | Loopback (IPv6) |
| `169.254.0.0/16` | Link-local (IPv4) |
| `fe80::/10` | Link-local (IPv6) |
| `169.254.169.254` | AWS/GCP/Azure metadata |
| `fd00:ec2::254` | AWS metadata (IPv6) |
| `100.100.100.200` | Alibaba Cloud metadata |

### IP Blocklist - Blocked by `PublicOnly` (Default)

| Range | Description |
|-------|-------------|
| `10.0.0.0/8` | Private (Class A) |
| `172.16.0.0/12` | Private (Class B) |
| `192.168.0.0/16` | Private (Class C) |
| `fc00::/7` | Private (IPv6 ULA) |

### IP Encoding Rejected

| Format | Example | Description |
|--------|---------|-------------|
| Octal | `0177.0.0.1` | `= 127.0.0.1` |
| Decimal | `2130706433` | `= 127.0.0.1` |
| Hex | `0x7f000001` | `= 127.0.0.1` |
| Short-form | `127.1` | `= 127.0.0.1` |
| Bracketed | `[example.com]` | Only valid for IPv6 |

---

## 8. Error Types

### Rust

```rust
pub enum Error {
    SsrfBlocked { url: String, ip: IpAddr, reason: String },
    HostnameBlocked { url: String, host: String, reason: String },
    InvalidUrl { url: String, reason: String },
    DnsError { host: String, message: String },
    Timeout { message: String },
    
    // feature = "fetch"
    RedirectBlocked { original_url: String, redirect_url: String, reason: String },
    TooManyRedirects { url: String, max: u8 },
    HttpError { url: String, message: String },
}
```

### Python

| Exception | Description |
|-----------|-------------|
| `UrlJailError` | Base class for all errors |
| `SsrfBlocked` | IP/hostname blocked by policy |
| `InvalidUrl` | Malformed URL or forbidden scheme |
| `DnsError` | DNS resolution failed |

---

## 9. Features

```toml
[dependencies]
url_jail = "0.2"

# Enable fetch() with redirect validation
url_jail = { version = "0.2", features = ["fetch"] }

# Enable tracing for logging
url_jail = { version = "0.2", features = ["tracing"] }
```

| Feature | Description |
|---------|-------------|
| `fetch` | `fetch()`, `fetch_sync()`, `get()`, `get_sync()` |
| `tracing` | Debug/warn logs for validation decisions |
| `python` | Python bindings (via maturin) |

---

## 10. Dependencies

```toml
url = "2"
ipnet = "2"
idna = "1"
thiserror = "2"
tokio = { version = "1", features = ["net", "rt", "time"] }
hickory-resolver = "0.25"
reqwest = { version = "0.12", optional = true }
tracing = { version = "0.1", optional = true }
```

Minimal. HTTP client optional.

---

## 11. Changelog

### v0.2.0

- **Python type stubs** (`url_jail.pyi`)
- **Timeout configuration** (`ValidateOptions`, `Timeout` error)
- **Custom blocklists** (`PolicyBuilder`, `CustomPolicy`, `validate_custom()`)
- **Python PolicyBuilder** (`PolicyBuilder`, `validate_custom_sync()`)
- **Multi-IP DNS security** - checks ALL resolved IPs, fails if any is blocked
- **Tracing support** (optional feature)
- Expanded IP encoding rejection (hex, short-form)
- Bracket validation for hostnames

### v0.1.0

- Core validation (`validate`, `validate_sync`)
- Fetch with redirect chain validation (`fetch`, `fetch_sync`)
- Python bindings (`get`, `get_sync`, `validate`, `validate_sync`)
- Hostname/IP blocklists
- IPv6 handling

---

## License

MIT OR Apache-2.0
