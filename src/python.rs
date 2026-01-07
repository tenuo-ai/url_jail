//! Python bindings for airlock.

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Error, Policy as RustPolicy, Validated as RustValidated};

pyo3::create_exception!(airlock, AirlockError, PyException);
pyo3::create_exception!(airlock, SsrfBlocked, AirlockError);
pyo3::create_exception!(airlock, InvalidUrl, AirlockError);
pyo3::create_exception!(airlock, DnsError, AirlockError);

/// Policy enum for Python.
#[pyclass(name = "Policy", eq, eq_int)]
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

/// Convert Rust error to Python exception.
fn to_py_err(e: Error) -> PyErr {
    match e {
        Error::SsrfBlocked { url, ip, reason } => {
            SsrfBlocked::new_err(format!("{} ({}) - {}", url, ip, reason))
        }
        Error::HostnameBlocked { url, host, reason } => {
            SsrfBlocked::new_err(format!("{} ({}) - {}", url, host, reason))
        }
        Error::InvalidUrl { url, reason } => InvalidUrl::new_err(format!("{} - {}", url, reason)),
        Error::DnsError { host, message } => DnsError::new_err(format!("{} - {}", host, message)),
        #[cfg(feature = "fetch")]
        Error::RedirectBlocked {
            original_url,
            redirect_url,
            reason,
        } => SsrfBlocked::new_err(format!(
            "{} redirected to blocked URL {} - {}",
            original_url, redirect_url, reason
        )),
        #[cfg(feature = "fetch")]
        Error::TooManyRedirects { url, max } => {
            AirlockError::new_err(format!("{} - too many redirects (max {})", url, max))
        }
        #[cfg(feature = "fetch")]
        Error::HttpError { url, message } => {
            AirlockError::new_err(format!("{} - HTTP error: {}", url, message))
        }
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
        let result = crate::fetch(&url, policy.into())
            .await
            .map_err(to_py_err)?;
        let body = result
            .response
            .text()
            .await
            .map_err(|e| AirlockError::new_err(e.to_string()))?;
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
        tokio::task::block_in_place(|| {
            handle.block_on(async { result.response.text().await })
        })
    } else {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| AirlockError::new_err(e.to_string()))?;
        rt.block_on(async { result.response.text().await })
    };

    body.map_err(|e| AirlockError::new_err(e.to_string()))
}

/// Register all Python bindings.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPolicy>()?;
    m.add_class::<PyValidated>()?;
    m.add_function(wrap_pyfunction!(py_validate_sync, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate, m)?)?;

    #[cfg(feature = "fetch")]
    {
        m.add_function(wrap_pyfunction!(py_get, m)?)?;
        m.add_function(wrap_pyfunction!(py_get_sync, m)?)?;
    }

    m.add("AirlockError", m.py().get_type::<AirlockError>())?;
    m.add("SsrfBlocked", m.py().get_type::<SsrfBlocked>())?;
    m.add("InvalidUrl", m.py().get_type::<InvalidUrl>())?;
    m.add("DnsError", m.py().get_type::<DnsError>())?;

    Ok(())
}
