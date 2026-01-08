# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in `url_jail`, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainers directly or use GitHub's private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for the fix.

## Threat Model

### What url_jail Assumes

- **Attacker controls the URL string**: The primary threat is user-supplied URLs
- **Network is trusted between validation and connection**: No MITM during the request
- **DNS resolver is trusted**: Not poisoned or compromised
- **System clock is accurate**: For timeout calculations

### What url_jail Does NOT Assume

- **Attacker has local filesystem access**: We block `file://` scheme, but can't prevent local attacks
- **Attacker controls DNS responses**: DNS rebinding protection requires using the returned IP
- **All metadata endpoints are known**: New cloud providers may have unknown endpoints
- **HTTP client follows our guidance**: Protection requires using `Validated.ip` for connection

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    UNTRUSTED                                │
│  ┌─────────────┐                                            │
│  │ User Input  │ ─── URL string                             │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    url_jail                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ URL Parse   │→ │ DNS Resolve │→ │ IP Validate │→ Validated│
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED                                  │
│  ┌─────────────┐                                            │
│  │ HTTP Client │ ─── Must use Validated.ip, not re-resolve  │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

## Mitigates Similar Vulnerabilities

`url_jail` helps mitigate the same class of vulnerabilities as these known CVEs:

### CVE-2024-0243: LangChain RecursiveUrlLoader SSRF

**Severity**: High (CVSS 8.6)

The `RecursiveUrlLoader` component in LangChain allowed attackers to access unintended external domains and local resources, even with `prevent_outside=True`. Malicious HTML files could trigger the crawler to download files from internal networks or cloud metadata endpoints.

**How url_jail helps mitigate this**: By validating URLs against IP blocklists *after* DNS resolution, `url_jail` blocks requests to:
- Cloud metadata endpoints (`169.254.169.254`)
- Private network ranges (`10.x`, `172.16.x`, `192.168.x`)
- Loopback addresses (`127.0.0.1`, `localhost`)

### CVE-2025-2828: LangChain RequestsToolkit SSRF

**Severity**: High (CVSS 9.1)

The `RequestsToolkit` component lacked restrictions on remote addresses, allowing attackers to:
- Perform port scans on internal networks
- Access local services (databases, admin panels)
- Retrieve cloud instance metadata (AWS/GCP/Azure credentials)

**How url_jail helps mitigate this**: The `PublicOnly` policy (default) blocks private and internal IP ranges. IP encoding tricks (octal, hex, decimal) that bypass naive string-based filters are detected and rejected.

### Example Usage

```python
from url_jail import get_sync

# Instead of: requests.get(user_url)
# Use:
body = get_sync(user_url)  # Validates URL and all redirects
```

For LangChain specifically, wrap URL fetching with `url_jail` validation before passing to loaders or toolkits.

**Note**: `url_jail` is not a complete fix for these CVEs. Those require updates to LangChain itself. However, `url_jail` provides defense-in-depth against the same attack patterns.

## Security Model

`url_jail` aims to reduce SSRF attack surface by validating URLs and resolved IPs:

### What We Help Protect Against

| Threat | Mitigation |
|--------|------------|
| Cloud metadata theft | Blocks known metadata IPs: `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200` |
| Internal network scanning | Blocks private IPs with `PublicOnly` policy |
| Localhost access | Blocks `127.0.0.0/8`, `::1` |
| DNS rebinding | Returns verified IP (user must use it for connection) |
| Redirect bypass | `fetch()` validates each hop (when used) |
| IP encoding tricks | Rejects octal, hex, decimal, short-form encodings |
| IPv6 bypass | Handles IPv4-mapped IPv6, link-local, ULA |

### Limitations (What We Do NOT Protect Against)

- **Time-of-check/time-of-use (TOCTOU)**: If you don't use the returned IP immediately, DNS could change. Always connect right after validation.
- **DNS rebinding (if misused)**: Protection only works if you use `Validated.ip` for the connection, not a second DNS lookup.
- **Application-layer vulnerabilities**: We validate URLs, not request content or headers.
- **DNS cache poisoning**: Out of scope. Use DNSSEC at the resolver level.
- **Non-HTTP protocols**: Only `http://` and `https://` schemes are validated.
- **Malicious response content**: We don't inspect response bodies.
- **New/unknown metadata endpoints**: We block known endpoints; new cloud providers may have unknown ones.
- **Side-channel attacks**: Timing or error-based information leakage is not addressed.

### Best Practices

1. **Use the returned IP**: Always connect to `Validated.ip`, not DNS again
2. **Validate redirects**: Use `fetch()` or manually validate each redirect
3. **Set timeouts**: Configure `ValidateOptions.dns_timeout`
4. **Prefer PublicOnly**: Only use `AllowPrivate` when necessary

## Security Audits

This crate has not yet undergone a formal security audit. If you're using it in a security-critical context, consider:

1. Reviewing the source code
2. Running your own security tests
3. Sponsoring a professional audit

