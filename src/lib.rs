//! # url_jail
//!
//! SSRF-safe URL validation for Rust and Python.
//!
//! `url_jail` validates URLs and resolved IPs to help mitigate Server-Side Request Forgery (SSRF).
//! Like [`path_jail`](https://crates.io/crates/path_jail) helps prevent path traversal, `url_jail`
//! reduces SSRF attack surface with a secure-by-default API.
//!
//! This library helps mitigate vulnerabilities similar to:
//! - **CVE-2024-0243**: LangChain RecursiveUrlLoader SSRF (CVSS 8.6)
//! - **CVE-2025-2828**: LangChain RequestsToolkit SSRF (CVSS 9.1)
//!
//! > **Note**: This library has not undergone a formal security audit.
//!
//! ## The Problem
//!
//! Standard HTTP clients trust DNS blindly, allowing attackers to:
//! - Steal cloud credentials via metadata endpoints (169.254.169.254)
//! - Scan internal networks
//! - Access localhost services
//! - Bypass firewalls
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use url_jail::{validate, Policy};
//!
//! # async fn example() -> Result<(), url_jail::Error> {
//! let result = validate("https://example.com/api", Policy::PublicOnly).await?;
//! println!("Safe to connect to {} ({})", result.host, result.ip);
//! # Ok(())
//! # }
//! ```
//!
//! ## Using with reqwest
//!
//! The returned [`Validated`] struct contains the verified IP address. Use it with
//! reqwest's resolver override to avoid a second DNS lookup (which could return a different IP):
//!
//! ```rust,ignore
//! use url_jail::{validate, Policy};
//! use reqwest::Client;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let v = validate("https://example.com/api", Policy::PublicOnly).await?;
//!
//!     let client = Client::builder()
//!         .resolve(&v.host, v.to_socket_addr())
//!         .build()?;
//!
//!     let response = client.get(&v.url).send().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Fetch with Redirect Validation
//!
//! For the safest approach, use the `fetch` feature which validates each redirect:
//!
//! ```rust,ignore
//! use url_jail::{fetch, Policy};
//!
//! let result = fetch("https://example.com/", Policy::PublicOnly).await?;
//! println!("Final response: {:?}", result.response.status());
//! println!("Redirect chain: {} hops", result.chain.len());
//! ```
//!
//! ## Policies
//!
//! | Policy | Allows | Blocks |
//! |--------|--------|--------|
//! | [`Policy::PublicOnly`] | Public IPs only | Private, loopback, link-local, metadata |
//! | [`Policy::AllowPrivate`] | Private + public | Loopback, metadata (for internal services) |
//!
//! ## Custom Policies
//!
//! Use [`PolicyBuilder`] for fine-grained control:
//!
//! ```rust
//! use url_jail::{PolicyBuilder, Policy};
//!
//! let policy = PolicyBuilder::new(Policy::AllowPrivate)
//!     .block_cidr("10.0.0.0/8")           // Block specific range
//!     .allow_cidr("10.1.0.0/16")          // But allow a subnet
//!     .block_host("*.internal.example.com")
//!     .build();
//! ```
//!
//! ## What's Blocked
//!
//! ### Always Blocked (Both Policies)
//! - Loopback: `127.0.0.0/8`, `::1`
//! - Link-local: `169.254.0.0/16`, `fe80::/10`
//! - Cloud metadata: `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`
//! - Metadata hostnames: `metadata.google.internal`, `metadata.goog`, etc.
//!
//! ### Blocked by PublicOnly (Default)
//! - Private IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
//! - Private IPv6: `fc00::/7` (Unique Local Addresses)
//!
//! ### IP Encoding Tricks Rejected
//! - Octal: `0177.0.0.1` (= 127.0.0.1)
//! - Decimal: `2130706433` (= 127.0.0.1)
//! - Hexadecimal: `0x7f000001` (= 127.0.0.1)
//! - Short-form: `127.1` (= 127.0.0.1)
//! - IPv4-mapped IPv6: `::ffff:127.0.0.1`
//!
//! ## Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `fetch` | `fetch()`, `fetch_sync()` with redirect chain validation |
//! | `verify` | `verify_fetcher()` connection-level smoke tests |
//! | `tracing` | Debug/warn logs for validation decisions |
//! | `python` | Python bindings via PyO3 |
//!
//! ## Error Handling
//!
//! All errors are returned via the [`Error`] enum. Use helper methods to categorize errors:
//!
//! ```rust
//! use url_jail::{validate_sync, Policy, Error};
//!
//! match validate_sync("http://127.0.0.1/", Policy::PublicOnly) {
//!     Ok(v) => println!("Safe: {}", v.ip),
//!     Err(e) if e.is_blocked() => {
//!         // Security rejection: SsrfBlocked, HostnameBlocked, RedirectBlocked
//!         println!("Blocked: {}", e);
//!         if let Some(url) = e.url() {
//!             println!("URL: {}", url);
//!         }
//!     }
//!     Err(e) if e.is_retriable() => {
//!         // Temporary error: DnsError, Timeout, HttpError
//!         // Retry with caution for untrusted URLs
//!         println!("Temporary: {}", e);
//!     }
//!     Err(e) => println!("Error: {}", e),
//! }
//! ```
//!
//! | Method | Returns `true` for |
//! |--------|-------------------|
//! | [`Error::is_blocked()`] | Security rejections (`SsrfBlocked`, `HostnameBlocked`, `RedirectBlocked`) |
//! | [`Error::is_retriable()`] | Temporary errors (`DnsError`, `Timeout`, `HttpError`) |
//! | [`Error::url()`] | Returns the URL that caused the error (if available) |
//!
//! ## Security Considerations
//!
//! **Important**: This library reduces attack surface but is not a complete SSRF solution.
//!
//! - **Use the returned IP**: You MUST connect to `Validated.ip`, not perform another DNS lookup
//! - **Connect immediately**: Time-of-check/time-of-use gaps allow DNS to change
//! - **Validate redirects**: Use `fetch()` to validate each redirect, or handle manually
//! - **All IPs checked**: If DNS returns multiple IPs, ALL are validated before allowing
//! - **Known endpoints only**: We block known cloud metadata IPs; unknown endpoints may exist
//!
//! See [SECURITY.md](https://github.com/tenuo-ai/url_jail/blob/main/SECURITY.md) for full details.

mod blocklist;
mod error;
mod policy;
mod policy_builder;
mod safe_url;
mod validate;

#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "fetch")]
mod fetch;

pub use error::Error;
pub use policy::Policy;
pub use policy_builder::{CustomPolicy, PolicyBuilder};
pub use safe_url::SafeUrl;
pub use validate::{
    validate, validate_custom, validate_custom_with_options, validate_sync, validate_with_options,
    ValidateOptions, Validated,
};

#[cfg(feature = "verify")]
pub use verify::{verify_fetcher, VerificationCase, VerificationReport};

#[cfg(feature = "fetch")]
pub use fetch::{fetch, fetch_sync, FetchResult};

#[cfg(feature = "python")]
mod python;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
fn url_jail(m: &Bound<'_, PyModule>) -> PyResult<()> {
    python::register(m)
}
