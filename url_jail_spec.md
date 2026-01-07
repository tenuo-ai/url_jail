# Specification: `url_jail`

**Version:** 0.1.0

**Tagline:** SSRF-safe URL validation for Rust and Python.

---

## 1. Overview

`url_jail` validates URLs and resolved IPs to prevent Server-Side Request Forgery (SSRF). It does not make HTTP requests itself—it tells you whether a URL is safe to fetch and which IP to connect to.

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

```python
from url_jail import validate, Policy

# Validate before fetching
result = validate("http://169.254.169.254/credentials", Policy.PUBLIC_ONLY)
# Raises: SsrfBlocked("169.254.169.254 is a metadata endpoint")

result = validate("https://example.com/api", Policy.PUBLIC_ONLY)
# Ok: result.ip = "93.184.216.34", result.host = "example.com"

# Now safe to fetch with your preferred client
response = requests.get("https://example.com/api")
```

```rust
use url_jail::{validate, Policy};

let result = validate("https://example.com/api", Policy::PublicOnly).await?;
// result.ip = 93.184.216.34
// result.host = "example.com"
// result.port = 443
```

---

## 4. Threat Model

| Threat | Attack | Defense |
|--------|--------|---------|
| **Cloud metadata theft** | Fetch `169.254.169.254` | Metadata IPs blocked |
| **Internal network scan** | Fetch `192.168.1.1` | Private IPs blocked |
| **Localhost access** | Fetch `127.0.0.1` | Loopback blocked |
| **DNS rebinding** | DNS returns `1.2.3.4`, then `127.0.0.1` | Returns verified IP to connect to |
| **Redirect bypass** | `https://safe.com` → `http://127.0.0.1` | Validate each URL before following |
| **IPv6 bypass** | `::ffff:127.0.0.1` | All IPv6 variants normalized |
| **Hostname tricks** | `LOCALHOST`, `127.0.0.1.` | Hostname normalized before resolution |

---

## 5. Rust API

### Core Functions

```rust
use url_jail::{validate, validate_sync, Policy, Validated};

// Async validation (requires tokio runtime)
let result: Validated = validate(
    "https://example.com/path", 
    Policy::PublicOnly
).await?;

// Sync validation (blocks current thread)
let result: Validated = validate_sync(
    "https://example.com/path",
    Policy::PublicOnly
)?;

println!("Safe to connect to {} ({})", result.host, result.ip);
```

### Validated Result

```rust
pub struct Validated {
    /// The verified IP address to connect to
    pub ip: IpAddr,
    
    /// Original hostname (use for Host header / SNI)
    pub host: String,
    
    /// Port number
    pub port: u16,
    
    /// Full URL (normalized)
    pub url: String,
    
    /// Whether HTTPS
    pub https: bool,
}
```

### Policy

```rust
pub enum Policy {
    /// Block private IPs, loopback, link-local, metadata endpoints.
    /// This is the default.
    PublicOnly,
    
    /// Allow private IPs, but still block loopback and metadata.
    /// Use for internal service-to-service calls.
    AllowPrivate,
}
```

### URL Parsing Only

```rust
use url_jail::SafeUrl;

// Parse and normalize without DNS resolution
let url = SafeUrl::parse("https://EXAMPLE.COM./path")?;
assert_eq!(url.host(), "example.com");
assert_eq!(url.path(), "/path");
```

---

## 6. Python API

### Core Functions

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
from url_jail import validate_sync, SsrfBlocked, InvalidUrl

try:
    result = validate_sync(user_input, Policy.PUBLIC_ONLY)
except SsrfBlocked as e:
    print(f"Blocked: {e.ip} - {e.reason}")
except InvalidUrl as e:
    print(f"Bad URL: {e.reason}")
```

---

## 7. How It Works

### Step 1: Parse & Normalize

```
Input: "https://USER:PASS@EXAMPLE.COM.:443/path"

Normalized:
  - Scheme: https
  - Host: example.com  (lowercase, no trailing dot, no userinfo)
  - Port: 443
  - Path: /path
```

### Step 2: Resolve DNS

```
DNS lookup: example.com → 93.184.216.34
```

### Step 3: Check IP Against Policy

```
Policy: PublicOnly
IP: 93.184.216.34
Result: ✅ Public IP, allowed
```

### Step 4: Return Verified Target

```rust
Validated {
    ip: 93.184.216.34,
    host: "example.com",  // Use for Host header and SNI
    port: 443,
    https: true,
}
```

---

## 8. Using with HTTP Clients

`url_jail` validates. You fetch. This gives you control over the HTTP client.

### Python + requests

```python
from url_jail import validate_sync, Policy
import requests

result = validate_sync(user_url, Policy.PUBLIC_ONLY)

# Safe to fetch - IP has been verified
response = requests.get(result.url)
```

### Python + httpx (async)

```python
from url_jail import validate, Policy
import httpx

async def safe_fetch(url: str) -> str:
    result = await validate(url, Policy.PUBLIC_ONLY)
    async with httpx.AsyncClient() as client:
        response = await client.get(result.url)
        return response.text
```

### Rust + reqwest

For DNS rebinding protection, use reqwest's resolver override:

```rust
use url_jail::{validate, Policy};
use reqwest::Client;
use std::net::SocketAddr;

let result = validate(url, Policy::PublicOnly).await?;

// Tell reqwest to use verified IP for this host
// This preserves correct SNI/TLS handshake
let client = Client::builder()
    .resolve(&result.host, SocketAddr::new(result.ip, result.port))
    .build()?;

let response = client.get(&result.url).send().await?;
```

**Important:** Don't manually connect to the IP and set the Host header. For HTTPS, the TLS handshake requires SNI (Server Name Indication) to match the hostname. Use your client's resolver override API instead.

### Rust + hyper

```rust
use hyper::client::connect::dns::Name;

// Custom resolver that returns the verified IP
let connector = HttpConnector::new_with_resolver(
    VerifiedResolver::new(result.host.clone(), result.ip)
);
```

---

## 9. What's Blocked

### Hostname Blocklist (Checked Before DNS)

These hostnames are blocked before DNS resolution:

| Hostname | Description |
|----------|-------------|
| `metadata.google.internal` | GCP metadata |
| `metadata.azure.internal` | Azure metadata |

### IP Blocklist — Always Blocked (Both Policies)

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | Loopback (IPv4) |
| `::1` | Loopback (IPv6) |
| `169.254.0.0/16` | Link-local (IPv4) |
| `fe80::/10` | Link-local (IPv6) |
| `169.254.169.254` | AWS/GCP/Azure metadata |
| `fd00:ec2::254` | AWS metadata (IPv6) |
| `100.100.100.200` | Alibaba Cloud metadata |

### IP Blocklist — Blocked by `PublicOnly` (Default)

| Range | Description |
|-------|-------------|
| `10.0.0.0/8` | Private (Class A) |
| `172.16.0.0/12` | Private (Class B) |
| `192.168.0.0/16` | Private (Class C) |
| `fc00::/7` | Private (IPv6 ULA) |

---

## 10. Hostname Normalization

Prevents bypass tricks:

| Input | Normalized | Bypass Prevented |
|-------|------------|------------------|
| `EXAMPLE.COM` | `example.com` | Case sensitivity |
| `example.com.` | `example.com` | Trailing dot |
| `user:pass@example.com` | `example.com` | Authority confusion |
| `①②⑦.0.0.1` | Error | Unicode digit bypass |
| `[example.com]` | Error | Bracket confusion |
| `0177.0.0.1` | Error | Octal IP encoding |
| `2130706433` | Error | Decimal IP encoding |

---

## 11. IPv6 Handling

All representations of blocked IPs are caught:

```python
# These all map to loopback - all blocked:
"::1"
"0:0:0:0:0:0:0:1"  
"::ffff:127.0.0.1"           # IPv4-mapped
"0000:0000:0000:0000:0000:ffff:7f00:0001"

# These all map to metadata - all blocked:
"::ffff:169.254.169.254"
"0:0:0:0:0:ffff:a9fe:a9fe"
```

---

## 12. Error Types

### Rust

```rust
pub enum Error {
    /// IP address is blocked by policy
    SsrfBlocked { 
        url: String, 
        ip: IpAddr, 
        reason: String,
    },
    
    /// Invalid URL syntax or forbidden scheme
    InvalidUrl { 
        url: String, 
        reason: String,
    },
    
    /// DNS resolution failed
    DnsError { 
        host: String, 
        source: std::io::Error,
    },
}
```

### Python

```python
class UrlJailError(Exception):
    """Base class for url_jail errors"""
    pass

class SsrfBlocked(UrlJailError):
    """IP address is blocked by policy"""
    url: str
    ip: str
    reason: str

class InvalidUrl(UrlJailError):
    """Invalid URL syntax or forbidden scheme"""
    url: str
    reason: str

class DnsError(UrlJailError):
    """DNS resolution failed"""
    host: str
```

---

## 13. Integration with Tenuo

`url_jail` handles network safety. Tenuo handles authorization.

```python
from url_jail import validate_sync, Policy
from tenuo import Warrant

def fetch_tool(url: str, warrant: Warrant) -> str:
    # 1. Validate URL and resolve DNS (url_jail)
    result = validate_sync(url, Policy.PUBLIC_ONLY)
    
    # 2. Check authorization (tenuo)
    warrant.check("fetch", result.url)
    
    # 3. Fetch with verified URL
    return requests.get(result.url).text
```

---

## 14. Dependencies

### Rust

```toml
[dependencies]
url = "2"
ipnet = "2"
idna = "0.5"
thiserror = "1"
tokio = { version = "1", features = ["net"] }
hickory-resolver = "0.24"  # DNS resolution
```

Minimal. No HTTP client bundled.

### Python

```toml
[project]
dependencies = []  # No runtime deps - Rust does the work

[build-system]
requires = ["maturin>=1.0"]
```

---

## 15. Comparison

| | url_jail | requests | urllib |
|---|---------|----------|--------|
| SSRF protection | ✅ | ❌ | ❌ |
| Metadata blocking | ✅ | ❌ | ❌ |
| DNS rebinding info | ✅ | ❌ | ❌ |
| IPv6 normalization | ✅ | ❌ | ❌ |
| Hostname normalization | ✅ | ❌ | ❌ |
| Bring your own client | ✅ | N/A | N/A |

---

## 16. Limitations

- **Validation only** — Does not make HTTP requests
- **HTTP/HTTPS only** — Other schemes rejected
- **No redirect following** — Validate each URL in redirect chain yourself
- **Standard IP notation only** — Octal (`0177.0.0.1`) and decimal (`2130706433`) IPs are rejected

---

## 17. Checklist

### v0.1

- [ ] `SafeUrl` parser with normalization
- [ ] Hostname normalization (case, dots, userinfo)
- [ ] `Policy` enum (PublicOnly, AllowPrivate)
- [ ] IPv4 blocklist
- [ ] IPv6 blocklist (all representations)
- [ ] Metadata endpoint blocklist
- [ ] DNS resolution
- [ ] `validate()` async function
- [ ] `Validated` result struct
- [ ] Rust tests with bypass attempts
- [ ] Python bindings (`validate`, `validate_sync`)
- [ ] Python error types
- [ ] Documentation
- [ ] `cargo publish`
- [ ] `pip install url_jail` (maturin)

### v0.2

- [ ] Custom blocklists
- [ ] Custom allowlists  
- [ ] Timeout configuration
- [ ] Redirect chain validation helper
- [ ] Python `get()` / `get_sync()` fetch helpers (with proper socket pinning)

---

## 18. Test Cases

```python
# Should block
validate_sync("http://127.0.0.1/", Policy.PUBLIC_ONLY)           # Loopback
validate_sync("http://169.254.169.254/", Policy.PUBLIC_ONLY)     # Metadata
validate_sync("http://192.168.1.1/", Policy.PUBLIC_ONLY)         # Private
validate_sync("http://[::1]/", Policy.PUBLIC_ONLY)               # IPv6 loopback
validate_sync("http://[::ffff:127.0.0.1]/", Policy.PUBLIC_ONLY)  # IPv4-mapped
validate_sync("http://0177.0.0.1/", Policy.PUBLIC_ONLY)          # Octal encoding → InvalidUrl
validate_sync("http://2130706433/", Policy.PUBLIC_ONLY)          # Decimal encoding → InvalidUrl
validate_sync("http://localhost/", Policy.PUBLIC_ONLY)           # Resolves to 127.0.0.1
validate_sync("http://metadata.google.internal/", Policy.PUBLIC_ONLY)  # Hostname blocklist

# Should allow
validate_sync("https://example.com/", Policy.PUBLIC_ONLY)        # Public
validate_sync("https://93.184.216.34/", Policy.PUBLIC_ONLY)      # Direct public IP

# Should allow with AllowPrivate
validate_sync("http://192.168.1.1/", Policy.ALLOW_PRIVATE)       # Private OK
validate_sync("http://10.0.0.1/", Policy.ALLOW_PRIVATE)          # Private OK

# Should still block with AllowPrivate
validate_sync("http://127.0.0.1/", Policy.ALLOW_PRIVATE)         # Loopback always blocked
validate_sync("http://169.254.169.254/", Policy.ALLOW_PRIVATE)   # Metadata always blocked
```

---

## 19. README

```markdown
# url_jail

SSRF-safe URL validation for Python and Rust.

## The Problem

```python
# User input: "http://169.254.169.254/credentials"
response = requests.get(user_url)  # 💀 AWS credentials leaked
```

## The Solution

```python
from url_jail import validate_sync, Policy

result = validate_sync(user_url, Policy.PUBLIC_ONLY)
# Raises SsrfBlocked if URL points to internal/metadata IPs

response = requests.get(result.url)  # ✅ Safe
```

## Installation

```bash
pip install url_jail
```

```toml
[dependencies]
url_jail = "0.1"
```

## What's Blocked

- Cloud metadata endpoints (AWS, GCP, Azure)
- Private IPs (10.x, 172.16.x, 192.168.x)
- Loopback (127.x, localhost)
- IPv6 equivalents of all the above

## License

MIT OR Apache-2.0
```
