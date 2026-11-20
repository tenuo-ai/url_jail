//! Python bindings for url_jail.

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{
    Error, Policy as RustPolicy, Validated as RustValidated,
    VerificationCase as RustVerificationCase, VerificationReport as RustVerificationReport,
};

// Base exception
pyo3::create_exception!(url_jail, UrlJailError, PyException);

// SSRF-related exceptions
pyo3::create_exception!(url_jail, SsrfBlocked, UrlJailError);
pyo3::create_exception!(url_jail, HostnameBlocked, UrlJailError);

// URL/input errors
pyo3::create_exception!(url_jail, InvalidUrl, UrlJailError);
pyo3::create_exception!(url_jail, DnsError, UrlJailError);

// Timeout error
pyo3::create_exception!(url_jail, Timeout, UrlJailError);

// Fetch-related errors (always defined for API consistency)
pyo3::create_exception!(url_jail, RedirectBlocked, UrlJailError);
pyo3::create_exception!(url_jail, TooManyRedirects, UrlJailError);
pyo3::create_exception!(url_jail, HttpError, UrlJailError);

/// Policy enum for Python.
#[pyclass(name = "Policy", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyPolicy {
    #[pyo3(name = "PUBLIC_ONLY")]
    PublicOnly,
    #[pyo3(name = "ALLOW_PRIVATE")]
    AllowPrivate,
}

impl From<PyPolicy> for RustPolicy {
    fn from(p: PyPolicy) -> Self {
        match p {
            PyPolicy::PublicOnly => RustPolicy::PublicOnly,
            PyPolicy::AllowPrivate => RustPolicy::AllowPrivate,
        }
    }
}

/// Validated result for Python.
#[pyclass(name = "Validated")]
#[derive(Clone)]
pub struct PyValidated {
    #[pyo3(get)]
    pub ip: String,
    #[pyo3(get)]
    pub host: String,
    #[pyo3(get)]
    pub port: u16,
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
    pub https: bool,
}

impl From<RustValidated> for PyValidated {
    fn from(v: RustValidated) -> Self {
        Self {
            ip: v.ip.to_string(),
            host: v.host,
            port: v.port,
            url: v.url,
            https: v.https,
        }
    }
}

/// Connection-level result for one adversarial fetch test.
#[pyclass(name = "VerificationCase", frozen)]
#[derive(Clone)]
pub struct PyVerificationCase {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
    pub refused: bool,
    #[pyo3(get)]
    pub connections: usize,
}

impl From<RustVerificationCase> for PyVerificationCase {
    fn from(case: RustVerificationCase) -> Self {
        Self {
            name: case.name.to_string(),
            url: case.url,
            refused: case.refused,
            connections: case.connections,
        }
    }
}

#[pymethods]
impl PyVerificationCase {
    #[getter]
    fn passed(&self) -> bool {
        self.refused && self.connections == 0
    }
}

/// Connection-level results for a supplied Python fetch callback.
#[pyclass(name = "VerificationReport", frozen)]
#[derive(Clone)]
pub struct PyVerificationReport {
    cases: Vec<PyVerificationCase>,
}

impl From<RustVerificationReport> for PyVerificationReport {
    fn from(report: RustVerificationReport) -> Self {
        Self {
            cases: report.cases.into_iter().map(Into::into).collect(),
        }
    }
}

#[pymethods]
impl PyVerificationReport {
    #[getter]
    fn cases(&self) -> Vec<PyVerificationCase> {
        self.cases.clone()
    }

    #[getter]
    fn passed(&self) -> bool {
        self.cases.iter().all(PyVerificationCase::passed)
    }
}

/// Custom policy for fine-grained control.
#[pyclass(name = "CustomPolicy")]
#[derive(Clone)]
pub struct PyCustomPolicy {
    inner: crate::CustomPolicy,
}

/// Builder for creating custom policies.
#[pyclass(name = "PolicyBuilder")]
#[derive(Clone)]
pub struct PyPolicyBuilder {
    inner: crate::PolicyBuilder,
}

#[pymethods]
impl PyPolicyBuilder {
    /// Create a new PolicyBuilder with a base policy.
    #[new]
    fn new(base: PyPolicy) -> Self {
        Self {
            inner: crate::PolicyBuilder::new(base.into()),
        }
    }

    /// Block an IP range (CIDR notation).
    fn block_cidr(&self, cidr: &str) -> Self {
        Self {
            inner: self.inner.clone().block_cidr(cidr),
        }
    }

    /// Allow an IP range (CIDR notation), overriding base policy.
    fn allow_cidr(&self, cidr: &str) -> Self {
        Self {
            inner: self.inner.clone().allow_cidr(cidr),
        }
    }

    /// Block a hostname pattern (supports wildcards like *.internal.example.com).
    fn block_host(&self, pattern: &str) -> Self {
        Self {
            inner: self.inner.clone().block_host(pattern),
        }
    }

    /// Allow a hostname pattern.
    fn allow_host(&self, pattern: &str) -> Self {
        Self {
            inner: self.inner.clone().allow_host(pattern),
        }
    }

    /// Build the custom policy.
    fn build(&self) -> PyCustomPolicy {
        PyCustomPolicy {
            inner: self.inner.clone().build(),
        }
    }
}

/// Convert Rust error to Python exception.
/// Each error maps to a specific exception type with structured message.
fn to_py_err(e: Error) -> PyErr {
    match e {
        Error::SsrfBlocked { url, ip, reason } => {
            // Format: "url (ip) - reason" for easy parsing
            SsrfBlocked::new_err(format!("{} ({}) - {}", url, ip, reason))
        }
        Error::HostnameBlocked { url, host, reason } => {
            // Use dedicated HostnameBlocked exception
            HostnameBlocked::new_err(format!("{} ({}) - {}", url, host, reason))
        }
        Error::InvalidUrl { url, reason } => InvalidUrl::new_err(format!("{} - {}", url, reason)),
        Error::DnsError { host, message } => DnsError::new_err(format!("{} - {}", host, message)),
        Error::Timeout { message } => Timeout::new_err(message),
        #[cfg(feature = "fetch")]
        Error::RedirectBlocked {
            original_url,
            redirect_url,
            reason,
        } => {
            // Use dedicated RedirectBlocked exception
            RedirectBlocked::new_err(format!("{} -> {} - {}", original_url, redirect_url, reason))
        }
        #[cfg(feature = "fetch")]
        Error::TooManyRedirects { url, max } => {
            TooManyRedirects::new_err(format!("{} - max {} redirects", url, max))
        }
        #[cfg(feature = "fetch")]
        Error::HttpError { url, message } => HttpError::new_err(format!("{} - {}", url, message)),
    }
}

/// Validate a URL synchronously.
#[pyfunction]
#[pyo3(name = "validate_sync")]
fn py_validate_sync(url: &str, policy: PyPolicy) -> PyResult<PyValidated> {
    let result = crate::validate_sync(url, policy.into()).map_err(to_py_err)?;
    Ok(result.into())
}

/// Validate a URL asynchronously.
#[pyfunction]
#[pyo3(name = "validate")]
fn py_validate<'py>(py: Python<'py>, url: String, policy: PyPolicy) -> PyResult<Bound<'py, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let result = crate::validate(&url, policy.into())
            .await
            .map_err(to_py_err)?;
        Ok(PyValidated::from(result))
    })
}

/// Validate a URL with a custom policy synchronously.
#[pyfunction]
#[pyo3(name = "validate_custom_sync")]
fn py_validate_custom_sync(url: &str, policy: &PyCustomPolicy) -> PyResult<PyValidated> {
    // Need to run async in sync context
    let policy_clone = policy.inner.clone();
    let result = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(crate::validate_custom(url, &policy_clone)))
    } else {
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| UrlJailError::new_err(e.to_string()))?;
        rt.block_on(crate::validate_custom(url, &policy_clone))
    };
    result.map(PyValidated::from).map_err(to_py_err)
}

/// Verify a synchronous application's actual user-URL fetch path.
///
/// The callback is invoked with controlled loopback URLs. A test passes only
/// when the callback raises and the controlled listener observes no TCP
/// connection. Async callbacks are not accepted by this synchronous API.
#[pyfunction]
#[pyo3(name = "verify_fetcher")]
fn py_verify_fetcher(fetch: Bound<'_, PyAny>) -> PyResult<PyVerificationReport> {
    if !fetch.is_callable() {
        return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "fetch must be a callable accepting one URL argument",
        ));
    }

    let callback = fetch.unbind();
    let verify = || {
        crate::verify_fetcher(|url| {
            let result = Python::attach(|py| {
                callback
                    .bind(py)
                    .call1((url,))
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            });
            std::future::ready(result)
        })
    };

    let report = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(verify()))
    } else {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|error| UrlJailError::new_err(error.to_string()))?;
        runtime.block_on(verify())
    }
    .map_err(|error| UrlJailError::new_err(error.to_string()))?;

    Ok(report.into())
}

/// Fetch a URL and return the response body as a string.
/// This is the recommended way to safely fetch user-provided URLs.
#[cfg(feature = "fetch")]
#[pyfunction]
#[pyo3(name = "get", signature = (url, policy = None))]
fn py_get<'py>(
    py: Python<'py>,
    url: String,
    policy: Option<PyPolicy>,
) -> PyResult<Bound<'py, PyAny>> {
    let policy = policy.unwrap_or(PyPolicy::PublicOnly);
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let result = crate::fetch(&url, policy.into()).await.map_err(to_py_err)?;
        let body = result
            .response
            .text()
            .await
            .map_err(|e| UrlJailError::new_err(e.to_string()))?;
        Ok(body)
    })
}

/// Synchronous version of get().
#[cfg(feature = "fetch")]
#[pyfunction]
#[pyo3(name = "get_sync", signature = (url, policy = None))]
fn py_get_sync(url: &str, policy: Option<PyPolicy>) -> PyResult<String> {
    let policy = policy.unwrap_or(PyPolicy::PublicOnly).into();
    let result = crate::fetch_sync(url, policy).map_err(to_py_err)?;

    // Use tokio to read the body synchronously
    let body = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(async { result.response.text().await }))
    } else {
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| UrlJailError::new_err(e.to_string()))?;
        rt.block_on(async { result.response.text().await })
    };

    body.map_err(|e| UrlJailError::new_err(e.to_string()))
}

/// Register all Python bindings.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPolicy>()?;
    m.add_class::<PyValidated>()?;
    m.add_class::<PyVerificationCase>()?;
    m.add_class::<PyVerificationReport>()?;
    m.add_class::<PyPolicyBuilder>()?;
    m.add_class::<PyCustomPolicy>()?;
    m.add_function(wrap_pyfunction!(py_validate_sync, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate_custom_sync, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_fetcher, m)?)?;

    #[cfg(feature = "fetch")]
    {
        m.add_function(wrap_pyfunction!(py_get, m)?)?;
        m.add_function(wrap_pyfunction!(py_get_sync, m)?)?;
    }

    // Base exception
    m.add("UrlJailError", m.py().get_type::<UrlJailError>())?;

    // SSRF exceptions
    m.add("SsrfBlocked", m.py().get_type::<SsrfBlocked>())?;
    m.add("HostnameBlocked", m.py().get_type::<HostnameBlocked>())?;

    // Input/validation errors
    m.add("InvalidUrl", m.py().get_type::<InvalidUrl>())?;
    m.add("DnsError", m.py().get_type::<DnsError>())?;

    // Timeout
    m.add("Timeout", m.py().get_type::<Timeout>())?;

    // Fetch-related errors (always exposed for API consistency)
    m.add("RedirectBlocked", m.py().get_type::<RedirectBlocked>())?;
    m.add("TooManyRedirects", m.py().get_type::<TooManyRedirects>())?;
    m.add("HttpError", m.py().get_type::<HttpError>())?;

    Ok(())
}
