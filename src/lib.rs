//! # url_jail
//!
//! SSRF-safe URL validation for Rust and Python.
//!
//! `url_jail` validates URLs and resolved IPs to prevent Server-Side Request Forgery (SSRF).
//! It does not make HTTP requests itself—it tells you whether a URL is safe to fetch
//! and which IP to connect to.
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

mod blocklist;
mod error;
mod policy;
mod policy_builder;
mod safe_url;
mod validate;

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
