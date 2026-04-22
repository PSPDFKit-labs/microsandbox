//! Egress event publisher over Unix socket (`egress.sock`).
//!
//! Runs as a tokio task inside the runtime process. Receives [`EgressEvent`]s
//! from TLS proxy tasks via an mpsc channel, serializes them as length-prefixed
//! CBOR, and writes them to connected SDK clients over a Unix socket.
//!
//! In intercept mode, reads [`EgressDecision`]s back from the SDK client and
//! dispatches them to the waiting proxy tasks via oneshot channels.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time;

use super::event::{EgressAction, EgressDecision, EgressEvent};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Channel capacity for events from proxy tasks to the publisher.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A message from a TLS proxy task to the publisher.
pub enum ProxyMessage {
    /// An egress event that requires a decision from the SDK.
    Event {
        event: EgressEvent,
        /// Oneshot to send the SDK's decision back to the proxy.
        reply: oneshot::Sender<EgressDecision>,
    },
}

/// Configuration for the egress publisher.
pub struct PublisherConfig {
    /// Timeout for SDK to respond with a decision (milliseconds).
    pub intercept_timeout_ms: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Global event ID counter.
static NEXT_EVENT_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a unique event ID.
pub fn next_event_id() -> u64 {
    NEXT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
}

/// Spawn the publisher task.
///
/// Listens on `socket_path` for SDK client connections and relays events
/// from `event_rx` to connected clients.
pub fn spawn_publisher(
    handle: &tokio::runtime::Handle,
    socket_path: &Path,
    event_rx: mpsc::Receiver<ProxyMessage>,
    config: PublisherConfig,
    client_connected: Arc<AtomicBool>,
) {
    let socket_path = socket_path.to_path_buf();
    handle.spawn(async move {
        if let Err(e) =
            publisher_task(socket_path.as_ref(), event_rx, config, client_connected).await
        {
            tracing::debug!(error = %e, "egress publisher ended");
        }
    });
}

/// Core publisher task.
///
/// Events are processed serially: one event is sent to the SDK, and the
/// publisher waits for the decision (up to `intercept_timeout_ms`) before
/// dequeuing the next event. Under high concurrency, queued events may
/// experience head-of-line blocking — proxy tasks block on their oneshot
/// reply until the publisher processes their event. The channel capacity
/// (256) provides buffering, and `try_send` failures fail-open.
async fn publisher_task(
    socket_path: &Path,
    mut event_rx: mpsc::Receiver<ProxyMessage>,
    config: PublisherConfig,
    client_connected: Arc<AtomicBool>,
) -> io::Result<()> {
    // Remove stale socket if it exists.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::debug!(path = %socket_path.display(), "egress publisher listening");

    let mut client: Option<UnixStream> = None;
    let mut pending: HashMap<u64, oneshot::Sender<EgressDecision>> = HashMap::new();

    loop {
        tokio::select! {
            // Accept new SDK client connection.
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        tracing::debug!("egress: SDK client connected");
                        // Replace existing client (only one at a time).
                        client = Some(stream);
                        client_connected.store(true, Ordering::Relaxed);
                        // Clear pending decisions from previous client.
                        pending.clear();
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "egress: accept failed");
                    }
                }
            }

            // Receive event from proxy task.
            msg = event_rx.recv() => {
                let Some(ProxyMessage::Event { event, reply }) = msg else {
                    break; // Channel closed.
                };

                let event_id = event.id;

                // Serialize event as length-prefixed CBOR.
                let cbor = match cbor_encode(&event) {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::debug!(error = %e, "egress: CBOR encode failed");
                        let _ = reply.send(EgressDecision {
                            id: event_id,
                            action: EgressAction::PassThrough,
                        });
                        continue;
                    }
                };

                // Write to SDK client.
                if let Some(ref mut stream) = client {
                    if let Err(e) = write_frame(stream, &cbor).await {
                        tracing::debug!(error = %e, "egress: write to SDK client failed");
                        client = None;
                        client_connected.store(false, Ordering::Relaxed);
                        let _ = reply.send(EgressDecision {
                            id: event_id,
                            action: EgressAction::PassThrough,
                        });
                        continue;
                    }

                    // Store pending decision.
                    pending.insert(event_id, reply);

                    // Try to read a decision from the SDK client.
                    let timeout = time::Duration::from_millis(config.intercept_timeout_ms);
                    match time::timeout(timeout, read_frame(stream)).await {
                        Ok(Ok(frame_data)) => {
                            match cbor_decode::<EgressDecision>(&frame_data) {
                                Ok(decision) => {
                                    if let Some(reply) = pending.remove(&decision.id) {
                                        let _ = reply.send(decision);
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "egress: CBOR decode decision failed");
                                    if let Some(reply) = pending.remove(&event_id) {
                                        let _ = reply.send(EgressDecision {
                                            id: event_id,
                                            action: EgressAction::PassThrough,
                                        });
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(error = %e, "egress: read from SDK client failed");
                            client = None;
                            client_connected.store(false, Ordering::Relaxed);
                            if let Some(reply) = pending.remove(&event_id) {
                                let _ = reply.send(EgressDecision {
                                    id: event_id,
                                    action: EgressAction::PassThrough,
                                });
                            }
                        }
                        Err(_) => {
                            // Timeout — fail-open.
                            tracing::debug!(event_id, "egress: SDK decision timeout, passing through");
                            if let Some(reply) = pending.remove(&event_id) {
                                let _ = reply.send(EgressDecision {
                                    id: event_id,
                                    action: EgressAction::PassThrough,
                                });
                            }
                        }
                    }
                } else {
                    // No SDK client connected — pass through.
                    let _ = reply.send(EgressDecision {
                        id: event_id,
                        action: EgressAction::PassThrough,
                    });
                }
            }
        }
    }

    Ok(())
}

/// Write a length-prefixed frame to a Unix stream.
async fn write_frame(stream: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

/// Read a length-prefixed frame from a Unix stream.
async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 68 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "egress frame too large",
        ));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Encode a value as CBOR bytes.
fn cbor_encode<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(buf)
}

/// Decode a value from CBOR bytes.
fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> io::Result<T> {
    ciborium::from_reader(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::event::{EgressEventKind, HttpRequest};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn sample_event(id: u64) -> EgressEvent {
        EgressEvent {
            id,
            connection_id: 1,
            kind: EgressEventKind::Request(HttpRequest {
                method: "GET".into(),
                uri: "/test".into(),
                headers: vec![("Host".into(), "example.com".into())],
                body: None,
            }),
            sni: "example.com".into(),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443)),
            timestamp_ms: 1700000000000,
        }
    }

    fn temp_sock_path() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("egress_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        dir.join(format!(
            "egress_{}.sock",
            NEXT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn no_client_passes_through() {
        let sock = temp_sock_path();
        let (tx, rx) = mpsc::channel::<ProxyMessage>(16);
        let config = PublisherConfig {
            intercept_timeout_ms: 100,
        };

        let handle = tokio::runtime::Handle::current();
        spawn_publisher(&handle, &sock, rx, config, Arc::new(AtomicBool::new(false)));

        // Wait for listener to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send event with no client connected.
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ProxyMessage::Event {
            event: sample_event(100),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let decision = reply_rx.await.unwrap();
        assert_eq!(decision.action, EgressAction::PassThrough);

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn client_receives_event_and_replies() {
        let sock = temp_sock_path();
        let (tx, rx) = mpsc::channel::<ProxyMessage>(16);
        let config = PublisherConfig {
            intercept_timeout_ms: 5000,
        };

        let handle = tokio::runtime::Handle::current();
        spawn_publisher(&handle, &sock, rx, config, Arc::new(AtomicBool::new(false)));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect as SDK client.
        let mut client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Send event from proxy side.
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ProxyMessage::Event {
            event: sample_event(200),
            reply: reply_tx,
        })
        .await
        .unwrap();

        // Client reads the event frame.
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut frame = vec![0u8; len];
        client.read_exact(&mut frame).await.unwrap();

        // Verify it decodes as an EgressEvent.
        let event: EgressEvent = ciborium::from_reader(frame.as_slice()).unwrap();
        assert_eq!(event.id, 200);
        assert_eq!(event.sni, "example.com");

        // Client sends a Block decision back.
        let decision = EgressDecision {
            id: 200,
            action: EgressAction::Block,
        };
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&decision, &mut cbor_buf).unwrap();
        let len_bytes = (cbor_buf.len() as u32).to_be_bytes();
        client.write_all(&len_bytes).await.unwrap();
        client.write_all(&cbor_buf).await.unwrap();
        client.flush().await.unwrap();

        // Proxy should receive the Block decision.
        let result = reply_rx.await.unwrap();
        assert_eq!(result.action, EgressAction::Block);
        assert_eq!(result.id, 200);

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn timeout_falls_back_to_passthrough() {
        let sock = temp_sock_path();
        let (tx, rx) = mpsc::channel::<ProxyMessage>(16);
        let config = PublisherConfig {
            intercept_timeout_ms: 100, // very short timeout
        };

        let handle = tokio::runtime::Handle::current();
        spawn_publisher(&handle, &sock, rx, config, Arc::new(AtomicBool::new(false)));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect as SDK client but never reply.
        let _client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ProxyMessage::Event {
            event: sample_event(300),
            reply: reply_tx,
        })
        .await
        .unwrap();

        // Should get PassThrough after timeout.
        let decision = tokio::time::timeout(std::time::Duration::from_secs(2), reply_rx)
            .await
            .expect("timed out waiting for decision")
            .unwrap();

        assert_eq!(decision.action, EgressAction::PassThrough);

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn client_disconnect_passes_through() {
        let sock = temp_sock_path();
        let (tx, rx) = mpsc::channel::<ProxyMessage>(16);
        let config = PublisherConfig {
            intercept_timeout_ms: 5000,
        };

        let handle = tokio::runtime::Handle::current();
        spawn_publisher(&handle, &sock, rx, config, Arc::new(AtomicBool::new(false)));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and immediately disconnect.
        {
            let _client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send event — should get PassThrough since client is gone.
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ProxyMessage::Event {
            event: sample_event(400),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let decision = tokio::time::timeout(std::time::Duration::from_secs(2), reply_rx)
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(decision.action, EgressAction::PassThrough);

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn cbor_framing_length_prefix() {
        let sock = temp_sock_path();
        let (tx, rx) = mpsc::channel::<ProxyMessage>(16);
        let config = PublisherConfig {
            intercept_timeout_ms: 5000,
        };

        let handle = tokio::runtime::Handle::current();
        spawn_publisher(&handle, &sock, rx, config, Arc::new(AtomicBool::new(false)));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let (reply_tx, _reply_rx) = oneshot::channel();
        tx.send(ProxyMessage::Event {
            event: sample_event(500),
            reply: reply_tx,
        })
        .await
        .unwrap();

        // Read length prefix — must be u32 big-endian.
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;

        // Length must be reasonable (CBOR of a small event).
        assert!(len > 10, "frame length too small: {len}");
        assert!(len < 4096, "frame length too large: {len}");

        // Read exactly that many bytes.
        let mut frame = vec![0u8; len];
        client.read_exact(&mut frame).await.unwrap();

        // Must be valid CBOR.
        let event: EgressEvent = ciborium::from_reader(frame.as_slice()).unwrap();
        assert_eq!(event.id, 500);

        std::fs::remove_file(&sock).ok();
    }
}
