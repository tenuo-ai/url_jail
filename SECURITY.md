# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
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

## Related CVEs

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

**Note**: `url_jail` is not a complete fix for these CVEs—those require updates to LangChain itself. However, `url_jail` provides defense-in-depth against the same attack patterns.

## Security Model

`url_jail` protects against Server-Side Request Forgery (SSRF) attacks by:

### What We Protect Against

| Threat | Protection |
|--------|------------|
| Cloud metadata theft | Block `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200` |
| Internal network scanning | Block private IPs with `PublicOnly` policy |
| Localhost access | Always block `127.0.0.0/8`, `::1` |
| DNS rebinding | Return verified IP for connection |
| Redirect bypass | `fetch()` validates each hop |
| IP encoding tricks | Reject octal, hex, decimal, short-form |
| IPv6 bypass | Handle IPv4-mapped IPv6, link-local, ULA |

### What We Do NOT Protect Against

- **Application-layer vulnerabilities**: We validate URLs, not request content
- **Time-of-check/time-of-use**: Connect immediately after validation
- **DNS cache poisoning**: Out of scope (use DNSSEC)
- **Non-HTTP protocols**: Only `http://` and `https://` are supported
- **Malicious response content**: We don't inspect response bodies

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

