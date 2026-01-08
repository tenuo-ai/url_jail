# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  - Optional dependencies: `url_jail[requests]`, `[httpx]`, `[aiohttp]`, `[all]`

- Tracing support (feature: `tracing`)
  - Debug/warn logs for validation decisions

### Security

- DNS rebinding protection via verified IP return
- All DNS-returned IPs validated (not just first)
- Redirect chain validation with `fetch()`
- Backslash in redirect URL rejected (prevents host override via URL crate behavior)

[Unreleased]: https://github.com/tenuo-ai/url_jail/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tenuo-ai/url_jail/releases/tag/v0.1.0
