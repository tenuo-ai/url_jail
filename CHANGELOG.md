# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-01-11

### Added

- Error helper methods on `Error`
  - `is_blocked()` - check if error is a security block (SSRF, hostname, redirect)
  - `is_retriable()` - check if error is temporary (DNS, timeout, HTTP)
  - `url()` - extract the URL that caused the error

- Comprehensive red team test suite (104 adversarial tests)
  - URL encoding attacks
  - Unicode/homoglyph bypasses
  - IPv6 edge cases
  - Redirect chain attacks
  - IP range boundary tests

- HTTPS limitation documentation for Python adapters
  - Detailed explanation in `adapters/README.md`
  - Comparison table of adapter capabilities
  - Microservices deployment guidance

- Threat model documentation in `SECURITY.md`
  - Trust boundary diagram
  - Explicit assumptions and non-assumptions

### Changed

- Improved error messages with more context
  - IP blocks now include CIDR range (e.g., "loopback address (127.0.0.0/8)")
  - Private IP errors suggest using `AllowPrivate` policy
  - IP encoding errors show the detected value and flag as "potential SSRF bypass attempt"
  - Custom policy errors reference the rule that blocked

- `HostnameBlocked` error display changed from "SSRF blocked" to "Hostname blocked"

- `InvalidUrl` error now includes the URL in the display format

## [0.1.0] - 2026-01-08

### Added

- Core URL validation with DNS resolution
  - `validate()` - async validation
  - `validate_sync()` - sync validation
  - `validate_with_options()` - async with custom timeout
  - `validate_custom()` - async with custom policy
  - `validate_custom_with_options()` - async with custom policy and timeout

- Policy system
  - `Policy::PublicOnly` - blocks private IPs, loopback, link-local, metadata
  - `Policy::AllowPrivate` - allows private IPs, blocks loopback and metadata

- Custom policy builder
  - `PolicyBuilder` for fine-grained control
  - `block_cidr()` / `allow_cidr()` for IP ranges
  - `block_host()` / `allow_host()` for hostname patterns

- IP blocklists
  - Loopback: `127.0.0.0/8`, `::1`
  - Link-local: `169.254.0.0/16`, `fe80::/10`
  - Unspecified: `0.0.0.0`, `::`
  - Cloud metadata: `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`
  - Private ranges (with `PublicOnly`): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`

- Hostname blocklists
  - `metadata.google.internal`
  - `metadata.goog`
  - `metadata.azure.internal`
  - `instance-data`

- IP encoding protection
  - Reject octal notation (`0177.0.0.1`)
  - Reject decimal notation (`2130706433`)
  - Reject hexadecimal notation (`0x7f000001`)
  - Reject short-form notation (`127.1`)
  - Handle IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
  - Block IPv4-compatible IPv6 (`::127.0.0.1`)

- HTTP fetch with redirect validation (feature: `fetch`)
  - `fetch()` - async fetch with redirect chain validation
  - `fetch_sync()` - sync version
  - `FetchResult` with response and redirect chain
  - Backslash in redirect URL rejected (prevents host override attacks)

- Python bindings (feature: `python`)
  - `validate()` / `validate_sync()`
  - `validate_custom_sync()`
  - `get()` / `get_sync()`
  - `Policy`, `PolicyBuilder`, `CustomPolicy`
  - Type stubs (`url_jail.pyi`)
  - Complete exception hierarchy: `UrlJailError`, `SsrfBlocked`, `HostnameBlocked`, `InvalidUrl`, `DnsError`, `Timeout`, `RedirectBlocked`, `TooManyRedirects`, `HttpError`

- Python HTTP client adapters
  - `safe_session()` - SSRF-safe requests.Session
  - `safe_httpx_client()` / `safe_httpx_async_client()` - httpx adapters
  - `safe_aiohttp_session()` - aiohttp adapter
  - `safe_urllib3_pool()` - urllib3 adapter
  - Optional dependencies: `url_jail[requests]`, `[httpx]`, `[aiohttp]`, `[urllib3]`, `[all]`

- Tracing support (feature: `tracing`)
  - Debug/warn logs for validation decisions

### Security

- DNS rebinding protection via verified IP return
- All DNS-returned IPs validated (not just first)
- Redirect chain validation with `fetch()`
- Backslash in redirect URL rejected (prevents host override via URL crate behavior)

[Unreleased]: https://github.com/tenuo-ai/url_jail/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tenuo-ai/url_jail/compare/v0.1.10...v0.2.0
[0.1.0]: https://github.com/tenuo-ai/url_jail/releases/tag/v0.1.0
