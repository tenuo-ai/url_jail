//! Connection-level smoke tests for an application's URL fetch path.
//!
//! A case only passes when the supplied fetcher refuses a prohibited URL and a
//! controlled loopback listener observes no TCP connection. This tests a
//! fetcher's actual network behavior; a late exception after connecting does
//! not pass.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

/// Result of one controlled adversarial URL test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCase {
    /// Stable name for the test case.
    pub name: &'static str,
    /// The URL supplied to the fetcher.
    pub url: String,
    /// Whether the fetcher returned an error.
    pub refused: bool,
    /// TCP connections accepted by the controlled listener.
    pub connections: usize,
}

impl VerificationCase {
    /// A case passes only when the fetcher refused before it connected.
    pub fn passed(&self) -> bool {
        self.refused && self.connections == 0
    }
}

/// Connection-level results for a supplied URL fetcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Results in the order the cases ran.
    pub cases: Vec<VerificationCase>,
}

impl VerificationReport {
    /// Returns true only when every case passed.
    pub fn passed(&self) -> bool {
        self.cases.iter().all(VerificationCase::passed)
    }
}

struct ControlledListener {
    port: u16,
    connections: Arc<AtomicUsize>,
    accepted: mpsc::UnboundedReceiver<()>,
    task: JoinHandle<()>,
}

impl ControlledListener {
    async fn stop(&mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for ControlledListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn listener() -> std::io::Result<ControlledListener> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let connections = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&connections);
    let (accepted, receiver) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok((_stream, _address)) = listener.accept().await {
            observed.fetch_add(1, Ordering::Relaxed);
            let _ = accepted.send(());
        }
    });
    Ok(ControlledListener {
        port,
        connections,
        accepted: receiver,
        task,
    })
}

async fn run_case<F, Fut, T, E>(
    name: &'static str,
    host: &str,
    fetch: &F,
) -> std::io::Result<VerificationCase>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut listener = listener().await?;
    let url = format!("http://{host}:{}/url-jail-verification", listener.port);
    let refused = fetch(url.clone()).await.is_err();

    // A callback may return immediately after its TCP handshake. The listener
    // sends an event on accept, so wait for that event rather than relying on a
    // scheduler delay before deciding that no connection was made.
    if listener.connections.load(Ordering::Relaxed) == 0 {
        let _ = timeout(Duration::from_millis(100), listener.accepted.recv()).await;
    }
    let connections = Arc::clone(&listener.connections);
    listener.stop().await;

    Ok(VerificationCase {
        name,
        url,
        refused,
        connections: connections.load(Ordering::Relaxed),
    })
}

/// Verify an asynchronous application's actual user-URL fetch path.
///
/// The verifier creates controlled services on loopback only. The initial
/// suite exercises literal loopback and legacy decimal IPv4 spelling. It is a
/// smoke test for application wiring, not a replacement for egress controls.
pub async fn verify_fetcher<F, Fut, T, E>(fetch: F) -> std::io::Result<VerificationReport>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    Ok(VerificationReport {
        cases: vec![
            run_case("literal_loopback", "127.0.0.1", &fetch).await?,
            run_case("decimal_ipv4", "2130706433", &fetch).await?,
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate, Policy};

    #[tokio::test]
    async fn safe_fetcher_passes_without_connecting() {
        let report =
            verify_fetcher(
                |url| async move { validate(&url, Policy::PublicOnly).await.map(|_| ()) },
            )
            .await
            .unwrap();

        assert!(report.passed());
        assert_eq!(
            report
                .cases
                .iter()
                .map(|case| case.connections)
                .collect::<Vec<_>>(),
            vec![0, 0]
        );
    }

    #[tokio::test]
    async fn fetcher_that_connects_then_errors_fails() {
        let report = verify_fetcher(|url| async move {
            let address = url::Url::parse(&url).unwrap();
            tokio::net::TcpStream::connect(("127.0.0.1", address.port().unwrap()))
                .await
                .unwrap();
            Err::<(), String>("refused after connecting".to_string())
        })
        .await
        .unwrap();

        assert!(!report.passed());
        assert!(report.cases.iter().all(|case| case.connections == 1));
    }

    #[cfg(feature = "fetch")]
    #[tokio::test]
    async fn built_in_safe_fetcher_passes_without_connecting() {
        let report = verify_fetcher(|url| async move {
            crate::fetch(&url, Policy::PublicOnly).await.map(|_| ())
        })
        .await
        .unwrap();

        assert!(report.passed());
    }
}
