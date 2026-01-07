//! # airlock
//!
//! SSRF-safe URL validation for Rust and Python.
//!
//! `airlock` validates URLs and resolved IPs to prevent Server-Side Request Forgery (SSRF).
//! It does not make HTTP requests itself—it tells you whether a URL is safe to fetch
//! and which IP to connect to.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use airlock::{validate, Policy};
//!
//! # async fn example() -> Result<(), airlock::Error> {
//! let result = validate("https://example.com/api", Policy::PublicOnly).await?;
//! println!("Safe to connect to {} ({})", result.host, result.ip);
//! # Ok(())
//! # }
//! ```

mod blocklist;
mod error;
mod policy;
mod safe_url;
mod validate;

#[cfg(feature = "fetch")]
mod fetch;

pub use error::Error;
pub use policy::Policy;
pub use safe_url::SafeUrl;
pub use validate::{validate, validate_sync, Validated};

#[cfg(feature = "fetch")]
pub use fetch::{fetch, fetch_sync, FetchResult};

#[cfg(feature = "python")]
mod python;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
fn airlock(m: &Bound<'_, PyModule>) -> PyResult<()> {
    python::register(m)
}
